using System.Text;

namespace BitchatWindows.Protocol;

/// <summary>BitChat Noise type 0x01 private-message TLV body shared with mobile clients.</summary>
public sealed record PrivateMessagePayload(string MessageId, string Content)
{
    private const byte MessageIdTag = 0x00;
    private const byte ContentTag = 0x01;

    public byte[]? Encode()
    {
        var id = Encoding.UTF8.GetBytes(MessageId);
        var content = Encoding.UTF8.GetBytes(Content);
        if (id.Length is 0 or > byte.MaxValue || content.Length > byte.MaxValue) return null;
        return [MessageIdTag, (byte)id.Length, .. id, ContentTag, (byte)content.Length, .. content];
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out PrivateMessagePayload? payload)
    {
        payload = null;
        string? id = null, content = null;
        var offset = 0;
        while (offset + 2 <= data.Length)
        {
            var tag = data[offset++];
            var length = data[offset++];
            if (offset + length > data.Length) return false;
            var value = data.Slice(offset, length);
            offset += length;
            switch (tag)
            {
                case MessageIdTag: id = Encoding.UTF8.GetString(value); break;
                case ContentTag: content = Encoding.UTF8.GetString(value); break;
                default: return false;
            }
        }
        if (offset != data.Length || string.IsNullOrEmpty(id) || content is null) return false;
        payload = new PrivateMessagePayload(id, content);
        return true;
    }
}
