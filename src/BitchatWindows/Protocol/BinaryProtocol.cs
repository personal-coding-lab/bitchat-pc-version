using System.Buffers.Binary;
using System.IO.Compression;
using System.IO;

namespace BitchatWindows.Protocol;

/// <summary>
/// BitChat v1/v2 frame codec, ported from localPackages/BitFoundation.
/// All integer fields are big-endian. Parsing is bounded before allocations.
/// </summary>
public static class BinaryProtocol
{
    public const int V1HeaderSize = 14;
    public const int V2HeaderSize = 16;
    public const int SenderIdSize = 8;
    public const int RecipientIdSize = 8;
    public const int SignatureSize = 64;
    private const byte HasRecipient = 0x01;
    private const byte HasSignature = 0x02;
    private const byte IsCompressed = 0x04;
    private const byte HasRoute = 0x08;
    private const byte IsRsr = 0x10;

    public static byte[]? Encode(BitchatPacket packet, bool padding = true)
    {
        if (packet.Version is not (1 or 2) || packet.SenderId.Length == 0) return null;
        var payload = packet.Payload;
        var compressed = false;
        if (payload.Length >= 100 && payload.Distinct().Count() < Math.Min(payload.Length, 256) * .9)
        {
            var candidate = Compress(payload);
            if (candidate is { Length: > 0 } && candidate.Length < payload.Length) { payload = candidate; compressed = true; }
        }

        var lengthBytes = packet.Version == 2 ? 4 : 2;
        var payloadDataSize = checked(payload.Length + (compressed ? lengthBytes : 0));
        if ((packet.Version == 1 && payloadDataSize > ushort.MaxValue) || payloadDataSize > MaxPayload(packet.Type)) return null;
        var route = packet.Version == 2 ? packet.Route?.Select(NormalizeId).ToArray() ?? [] : [];
        if (route.Length > byte.MaxValue) return null;

        var flags = (byte)0;
        if (packet.RecipientId is not null) flags |= HasRecipient;
        if (packet.Signature is not null) flags |= HasSignature;
        if (compressed) flags |= IsCompressed;
        if (route.Length > 0) flags |= HasRoute;
        if (packet.IsRsr) flags |= IsRsr;

        var size = (packet.Version == 1 ? V1HeaderSize : V2HeaderSize) + SenderIdSize + payloadDataSize +
            (packet.RecipientId is null ? 0 : RecipientIdSize) + (route.Length == 0 ? 0 : 1 + route.Length * SenderIdSize) +
            (packet.Signature is null ? 0 : SignatureSize);
        var result = new byte[size];
        var offset = 0;
        result[offset++] = packet.Version; result[offset++] = packet.Type; result[offset++] = packet.Ttl;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset, 8), packet.Timestamp); offset += 8;
        result[offset++] = flags;
        if (packet.Version == 2) { BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)payloadDataSize); offset += 4; }
        else { BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), (ushort)payloadDataSize); offset += 2; }
        NormalizeId(packet.SenderId).CopyTo(result, offset); offset += SenderIdSize;
        if (packet.RecipientId is not null) { NormalizeId(packet.RecipientId).CopyTo(result, offset); offset += RecipientIdSize; }
        if (route.Length > 0) { result[offset++] = (byte)route.Length; foreach (var hop in route) { hop.CopyTo(result, offset); offset += SenderIdSize; } }
        if (compressed) { if (packet.Version == 2) { BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset, 4), (uint)packet.Payload.Length); offset += 4; } else { BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), (ushort)packet.Payload.Length); offset += 2; } }
        payload.CopyTo(result, offset); offset += payload.Length;
        if (packet.Signature is not null) NormalizeSignature(packet.Signature).CopyTo(result, offset);
        return padding ? Pad(result) : result;
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out BitchatPacket? packet)
    {
        if (TryDecodeCore(data, out packet)) return true;
        var unpadded = Unpad(data);
        return unpadded.Length != data.Length && TryDecodeCore(unpadded, out packet);
    }

    private static bool TryDecodeCore(ReadOnlySpan<byte> raw, out BitchatPacket? packet)
    {
        packet = null;
        if (raw.Length < V1HeaderSize + SenderIdSize) return false;
        var offset = 0; var version = raw[offset++];
        if (version is not (1 or 2)) return false;
        var header = version == 1 ? V1HeaderSize : V2HeaderSize;
        if (raw.Length < header + SenderIdSize) return false;
        var type = raw[offset++]; var ttl = raw[offset++]; var timestamp = BinaryPrimitives.ReadUInt64BigEndian(raw.Slice(offset, 8)); offset += 8;
        var flags = raw[offset++]; var lengthBytes = version == 2 ? 4 : 2;
        var payloadLength = version == 2 ? BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(offset, 4)) : BinaryPrimitives.ReadUInt16BigEndian(raw.Slice(offset, 2)); offset += lengthBytes;
        if (payloadLength > MaxPayload(type) || offset + SenderIdSize > raw.Length) return false;
        var sender = raw.Slice(offset, SenderIdSize).ToArray(); offset += SenderIdSize;
        byte[]? recipient = null;
        if ((flags & HasRecipient) != 0) { if (offset + RecipientIdSize > raw.Length) return false; recipient = raw.Slice(offset, RecipientIdSize).ToArray(); offset += RecipientIdSize; }
        List<byte[]>? route = null;
        if (version == 2 && (flags & HasRoute) != 0) { if (offset >= raw.Length) return false; var count = raw[offset++]; if (offset + count * SenderIdSize > raw.Length) return false; route = []; for (var i = 0; i < count; i++) { route.Add(raw.Slice(offset, SenderIdSize).ToArray()); offset += SenderIdSize; } }
        if (payloadLength > int.MaxValue || offset + (int)payloadLength > raw.Length) return false;
        byte[] payload;
        if ((flags & IsCompressed) != 0) { if (payloadLength < lengthBytes || offset + lengthBytes > raw.Length) return false; var originalSize = version == 2 ? BinaryPrimitives.ReadUInt32BigEndian(raw.Slice(offset, 4)) : BinaryPrimitives.ReadUInt16BigEndian(raw.Slice(offset, 2)); offset += lengthBytes; var compressedLength = (int)payloadLength - lengthBytes; if (originalSize > MaxPayload(type) || compressedLength <= 0 || originalSize > compressedLength * 1032L) return false; payload = Decompress(raw.Slice(offset, compressedLength), (int)originalSize); if (payload.Length != originalSize) return false; offset += compressedLength; }
        else { payload = raw.Slice(offset, (int)payloadLength).ToArray(); offset += (int)payloadLength; }
        byte[]? signature = null;
        if ((flags & HasSignature) != 0) { if (offset + SignatureSize > raw.Length) return false; signature = raw.Slice(offset, SignatureSize).ToArray(); }
        packet = new(type, sender, recipient, timestamp, payload, signature, ttl, version, route, (flags & IsRsr) != 0); return true;
    }

    // A private file is a 1 MiB file TLV plus up to two UInt16 metadata
    // values and the Noise authentication overhead. Match the mobile framed
    // file allowance rather than rejecting valid encrypted media at encode.
    private static int MaxPayload(byte type) => type switch { BitchatMessageType.FileTransfer or BitchatMessageType.NoiseEncrypted => 1_180_000, BitchatMessageType.CourierEnvelope or BitchatMessageType.NostrCarrier => 65_536, BitchatMessageType.RequestSync => 8192, BitchatMessageType.Fragment => 1280, BitchatMessageType.Announce or BitchatMessageType.AnnounceV2 or BitchatMessageType.Leave or BitchatMessageType.BoardPost or BitchatMessageType.PrekeyBundle or BitchatMessageType.VoiceFrame or BitchatMessageType.NoiseHandshake or BitchatMessageType.Ping or BitchatMessageType.Pong => 4096, _ => 131_072 };
    private static byte[] NormalizeId(byte[] bytes) { var result = new byte[SenderIdSize]; Array.Copy(bytes, result, Math.Min(bytes.Length, result.Length)); return result; }
    private static byte[] NormalizeSignature(byte[] bytes) { var result = new byte[SignatureSize]; Array.Copy(bytes, result, Math.Min(bytes.Length, result.Length)); return result; }
    private static byte[] Compress(byte[] bytes) { using var output = new MemoryStream(); using (var stream = new ZLibStream(output, CompressionLevel.SmallestSize, true)) stream.Write(bytes); return output.ToArray(); }
    private static byte[] Decompress(ReadOnlySpan<byte> bytes, int expectedSize) { try { using var input = new MemoryStream(bytes.ToArray()); using var stream = new ZLibStream(input, CompressionMode.Decompress); using var output = new MemoryStream(expectedSize); stream.CopyTo(output); return output.ToArray(); } catch (InvalidDataException) { return []; } }
    private static byte[] Pad(byte[] data) { var target = new[] { 256, 512, 1024, 2048 }.FirstOrDefault(block => data.Length + 16 <= block); if (target == 0 || target <= data.Length || target - data.Length > byte.MaxValue) return data; return [.. data, .. Enumerable.Repeat((byte)(target - data.Length), target - data.Length)]; }
    private static ReadOnlySpan<byte> Unpad(ReadOnlySpan<byte> data) { if (data.Length == 0) return data; var count = data[^1]; return count > 0 && count <= data.Length && data[^count..].ToArray().All(item => item == count) ? data[..^count] : data; }
}
