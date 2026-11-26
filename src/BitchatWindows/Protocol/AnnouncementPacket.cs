namespace BitchatWindows.Protocol;

/// <summary>TLV announce payload shared by BitChat BLE clients.</summary>
public sealed record AnnouncementPacket(
    string Nickname,
    byte[] NoisePublicKey,
    byte[] SigningPublicKey,
    IReadOnlyList<byte[]>? DirectNeighbors = null,
    byte[]? Capabilities = null,
    string? BridgeGeohash = null)
{
    private const byte NicknameTag = 0x01, NoiseKeyTag = 0x02, SigningKeyTag = 0x03, NeighborsTag = 0x04, CapabilitiesTag = 0x05, BridgeGeohashTag = 0x06;

    public byte[]? Encode()
    {
        var result = new List<byte>();
        if (!Add(result, NicknameTag, System.Text.Encoding.UTF8.GetBytes(Nickname)) || !Add(result, NoiseKeyTag, NoisePublicKey) || !Add(result, SigningKeyTag, SigningPublicKey)) return null;
        if (DirectNeighbors is { Count: > 0 }) { var bytes = DirectNeighbors.Take(10).SelectMany(id => id.Take(8)).ToArray(); if (bytes.Length == 0 || bytes.Length % 8 != 0 || !Add(result, NeighborsTag, bytes)) return null; }
        if (Capabilities is { Length: > 0 } && !Add(result, CapabilitiesTag, Capabilities)) return null;
        if (BridgeGeohash is not null) { var bytes = System.Text.Encoding.UTF8.GetBytes(BridgeGeohash); if (bytes.Length is 0 or > 12 || !Add(result, BridgeGeohashTag, bytes)) return null; }
        return result.ToArray();
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out AnnouncementPacket? packet)
    {
        packet = null; string? nickname = null, geohash = null; byte[]? noise = null, signing = null, capabilities = null; List<byte[]>? neighbors = null; var offset = 0;
        while (offset + 2 <= data.Length)
        {
            var tag = data[offset++]; var length = data[offset++]; if (offset + length > data.Length) return false;
            var value = data.Slice(offset, length).ToArray(); offset += length;
            switch (tag)
            {
                case NicknameTag: nickname = System.Text.Encoding.UTF8.GetString(value); break;
                case NoiseKeyTag: noise = value; break;
                case SigningKeyTag: signing = value; break;
                case NeighborsTag when length > 0 && length % 8 == 0: neighbors = Enumerable.Range(0, length / 8).Select(i => value.AsSpan(i * 8, 8).ToArray()).ToList(); break;
                case CapabilitiesTag: capabilities = value; break;
                case BridgeGeohashTag when length <= 12: geohash = System.Text.Encoding.UTF8.GetString(value); break;
            }
        }
        if (offset != data.Length || string.IsNullOrWhiteSpace(nickname) || noise is null || signing is null) return false;
        packet = new AnnouncementPacket(nickname, noise, signing, neighbors, capabilities, geohash); return true;
    }

    private static bool Add(List<byte> destination, byte tag, byte[] value)
    {
        if (value.Length > byte.MaxValue) return false;
        destination.Add(tag); destination.Add((byte)value.Length); destination.AddRange(value); return true;
    }
}
