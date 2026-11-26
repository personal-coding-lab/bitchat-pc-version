using System.Buffers.Binary;
using System.Security.Cryptography;
using BitchatWindows.Protocol;

namespace BitchatWindows.Services;

/// <summary>Bounded in-memory archive and REQUEST_SYNC responder for public mesh packets.</summary>
public sealed class GossipSync
{
    private const int MaxPackets = 500;
    private readonly object _gate = new();
    private readonly List<BitchatPacket> _packets = [];
    private readonly Dictionary<string, Queue<DateTimeOffset>> _requestHistory = [];

    public void Store(BitchatPacket packet)
    {
        if (packet.Type is not (BitchatMessageType.Announce or BitchatMessageType.Message)) return;
        lock (_gate)
        {
            var id = Convert.ToHexString(PacketId(packet));
            if (_packets.Any(item => Convert.ToHexString(PacketId(item)) == id)) return;
            _packets.Add(packet);
            if (_packets.Count > MaxPackets) _packets.RemoveRange(0, _packets.Count - MaxPackets);
        }
    }

    public IReadOnlyList<BitchatPacket>? GetMissing(BitchatPacket request)
    {
        if (!TryDecodeRequest(request.Payload, out var filter)) return null;
        var peer = Convert.ToHexString(request.SenderId);
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (!_requestHistory.TryGetValue(peer, out var history)) _requestHistory[peer] = history = [];
            while (history.Count > 0 && history.Peek() < now.AddSeconds(-30)) history.Dequeue();
            if (history.Count >= 6) return [];
            history.Enqueue(now);
            return _packets
                .Where(packet => IncludesType(filter.TypeFlags, packet.Type))
                .Where(packet => filter.SinceTimestamp is null || packet.Type == BitchatMessageType.Announce || packet.Timestamp >= filter.SinceTimestamp)
                .Where(packet => !Contains(filter, PacketId(packet)))
                .OrderBy(packet => packet.Timestamp)
                .ToArray();
        }
    }

    private static bool IncludesType(ulong? flags, byte type)
    {
        if (flags is null) return type is BitchatMessageType.Announce or BitchatMessageType.Message;
        var bit = type switch { BitchatMessageType.Announce => 0, BitchatMessageType.Message => 1, _ => -1 };
        return bit >= 0 && (flags.Value & (1UL << bit)) != 0;
    }

    private static byte[] PacketId(BitchatPacket packet)
    {
        var data = new byte[1 + packet.SenderId.Length + 8 + packet.Payload.Length];
        data[0] = packet.Type;
        packet.SenderId.CopyTo(data, 1);
        BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(1 + packet.SenderId.Length, 8), packet.Timestamp);
        packet.Payload.CopyTo(data, 1 + packet.SenderId.Length + 8);
        return SHA256.HashData(data)[..16];
    }

    private static bool TryDecodeRequest(ReadOnlySpan<byte> payload, out SyncFilter filter)
    {
        filter = default;
        if (payload.Length > 1024) return false;
        int? p = null; uint? m = null; byte[]? data = null; ulong? types = null; ulong? since = null;
        var offset = 0;
        while (offset + 3 <= payload.Length)
        {
            var tag = payload[offset++]; var length = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2)); offset += 2;
            if (offset + length > payload.Length) return false;
            var value = payload.Slice(offset, length); offset += length;
            switch (tag)
            {
                case 0x01 when value.Length == 1: p = value[0]; break;
                case 0x02 when value.Length == 4: m = BinaryPrimitives.ReadUInt32BigEndian(value); break;
                case 0x03: data = value.ToArray(); break;
                case 0x04 when value.Length is >= 1 and <= 8:
                    types = 0;
                    for (var index = 0; index < value.Length; index++) types |= (ulong)value[index] << (index * 8);
                    break;
                case 0x05 when value.Length == 8: since = BinaryPrimitives.ReadUInt64BigEndian(value); break;
            }
        }
        if (offset != payload.Length || p is null || p.Value < 1 || p.Value > 32 || m is null || m.Value <= 1 || data is null) return false;
        var parameter = p.Value;
        var modulus = m.Value;
        filter = new SyncFilter(parameter, modulus, data, types, since);
        return true;
    }

    private static bool Contains(SyncFilter filter, byte[] id)
    {
        var digest = SHA256.HashData(id);
        var hash = BinaryPrimitives.ReadUInt64BigEndian(digest.AsSpan(0, 8)) & 0x7FFF_FFFF_FFFF_FFFF;
        var candidate = hash % filter.Modulus;
        if (candidate == 0) candidate = 1;
        var reader = new BitReader(filter.Data); ulong accumulator = 0;
        while (reader.TryReadUnary(out var quotient) && reader.TryReadBits(filter.P, out var remainder))
        {
            accumulator += ((ulong)quotient << filter.P) + remainder + 1;
            if (accumulator >= filter.Modulus) return false;
            if (accumulator == candidate) return true;
            if (accumulator > candidate) return false;
        }
        return false;
    }

    private readonly record struct SyncFilter(int P, uint Modulus, byte[] Data, ulong? TypeFlags, ulong? SinceTimestamp);
    private sealed class BitReader(byte[] data)
    {
        private int _index;
        private int _bit;
        public bool TryReadUnary(out int value)
        {
            value = 0;
            while (TryReadBit(out var bit)) { if (bit == 0) return true; value++; }
            return false;
        }
        public bool TryReadBits(int count, out ulong value)
        {
            value = 0;
            for (var i = 0; i < count; i++) { if (!TryReadBit(out var bit)) return false; value = (value << 1) | (uint)bit; }
            return true;
        }
        private bool TryReadBit(out int value)
        {
            value = 0;
            if (_index >= data.Length) return false;
            value = (data[_index] >> (7 - _bit)) & 1;
            if (++_bit == 8) { _bit = 0; _index++; }
            return true;
        }
    }
}
