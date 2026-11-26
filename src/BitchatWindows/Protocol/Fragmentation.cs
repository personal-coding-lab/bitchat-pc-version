using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BitchatWindows.Protocol;

/// <summary>BitChat's 13-byte BLE fragment envelope and bounded reassembly store.</summary>
public sealed class FragmentAssembler
{
    private const int HeaderLength = 13;
    private const int MaxFragments = 10_000;
    private const int MaxAssemblies = 32;
    private readonly object _gate = new();
    private readonly Dictionary<FragmentKey, AssemblyState> _assemblies = [];

    public bool TryAppend(BitchatPacket fragment, out byte[]? completed)
    {
        completed = null;
        if (fragment.Type != BitchatMessageType.Fragment || fragment.Payload.Length < HeaderLength || fragment.SenderId.Length < 8) return false;
        var streamId = BinaryPrimitives.ReadUInt64BigEndian(fragment.Payload.AsSpan(0, 8));
        var index = BinaryPrimitives.ReadUInt16BigEndian(fragment.Payload.AsSpan(8, 2));
        var total = BinaryPrimitives.ReadUInt16BigEndian(fragment.Payload.AsSpan(10, 2));
        if (total is 0 or > MaxFragments || index >= total) return false;
        var key = new FragmentKey(BinaryPrimitives.ReadUInt64BigEndian(fragment.SenderId.AsSpan(0, 8)), streamId);
        var originalType = fragment.Payload[12]; var chunk = fragment.Payload[HeaderLength..];
        var limit = MaxFrameBytes(originalType);
        lock (_gate)
        {
            PruneExpired();
            if (!_assemblies.TryGetValue(key, out var state))
            {
                if (_assemblies.Count >= MaxAssemblies) _assemblies.Remove(_assemblies.MinBy(pair => pair.Value.CreatedAt).Key);
                state = new AssemblyState(total, originalType); _assemblies.Add(key, state);
            }
            if (state.Total != total || state.OriginalType != originalType) { _assemblies.Remove(key); return false; }
            var projected = state.TotalBytes - (state.Chunks.TryGetValue(index, out var old) ? old.Length : 0) + chunk.Length;
            if (projected > limit) { _assemblies.Remove(key); return false; }
            state.Chunks[index] = chunk; state.TotalBytes = projected; state.LastUpdatedAt = DateTimeOffset.UtcNow;
            if (state.Chunks.Count != total) return true;
            var output = new byte[state.TotalBytes]; var offset = 0;
            for (var i = 0; i < total; i++) { if (!state.Chunks.TryGetValue(i, out var part)) { _assemblies.Remove(key); return false; } part.CopyTo(output, offset); offset += part.Length; }
            _assemblies.Remove(key); completed = output; return true;
        }
    }

    public static IReadOnlyList<BitchatPacket> Fragment(BitchatPacket packet, int chunkSize = 469)
    {
        if (chunkSize < 64) throw new ArgumentOutOfRangeException(nameof(chunkSize));
        var encoded = BinaryProtocol.Encode(packet) ?? throw new InvalidOperationException("Packet cannot be encoded.");
        var total = (int)Math.Ceiling(encoded.Length / (double)chunkSize);
        if (total > ushort.MaxValue) throw new InvalidOperationException("Too many BLE fragments.");
        var streamId = RandomNumberGenerator.GetBytes(8); var result = new List<BitchatPacket>(total);
        for (var index = 0; index < total; index++)
        {
            var start = index * chunkSize; var count = Math.Min(chunkSize, encoded.Length - start);
            var payload = new byte[HeaderLength + count]; streamId.CopyTo(payload, 0);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(8, 2), (ushort)index);
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(10, 2), (ushort)total);
            payload[12] = packet.Type; encoded.AsSpan(start, count).CopyTo(payload.AsSpan(HeaderLength));
            result.Add(new BitchatPacket(BitchatMessageType.Fragment, packet.SenderId, packet.RecipientId, packet.Timestamp, payload, null, packet.Ttl, packet.Route is { Count: > 0 } ? (byte)2 : (byte)1, packet.Route, packet.IsRsr));
        }
        return result;
    }

    private void PruneExpired()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-2);
        foreach (var key in _assemblies.Where(pair => pair.Value.LastUpdatedAt < cutoff).Select(pair => pair.Key).ToArray()) _assemblies.Remove(key);
    }
    private static int MaxFrameBytes(byte type) => type switch { BitchatMessageType.FileTransfer or BitchatMessageType.NoiseEncrypted => 1_182_000, BitchatMessageType.CourierEnvelope or BitchatMessageType.NostrCarrier => 67_000, BitchatMessageType.RequestSync => 10_000, BitchatMessageType.Fragment => 3_500, BitchatMessageType.Announce or BitchatMessageType.AnnounceV2 or BitchatMessageType.Leave or BitchatMessageType.BoardPost or BitchatMessageType.PrekeyBundle or BitchatMessageType.VoiceFrame or BitchatMessageType.NoiseHandshake or BitchatMessageType.Ping or BitchatMessageType.Pong => 6_500, _ => 132_500 };
    private readonly record struct FragmentKey(ulong Sender, ulong Stream);
    private sealed class AssemblyState(ushort total, byte originalType)
    {
        public ushort Total { get; } = total; public byte OriginalType { get; } = originalType;
        public Dictionary<int, byte[]> Chunks { get; } = []; public int TotalBytes { get; set; }
        public DateTimeOffset CreatedAt { get; } = DateTimeOffset.UtcNow; public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
}
