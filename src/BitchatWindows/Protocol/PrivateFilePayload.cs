using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace BitchatWindows.Protocol;

/// <summary>
/// Wire-compatible BitChat private-media TLV. The enclosing Noise plaintext
/// begins with 0x20; this class represents the bytes after that discriminator.
/// </summary>
public sealed record PrivateFilePayload(string? FileName, ulong FileSize, string? MimeType, byte[] Content)
{
    public const int MaxContentBytes = 1 * 1024 * 1024;
    private const byte FileNameTag = 0x01;
    private const byte FileSizeTag = 0x02;
    private const byte MimeTypeTag = 0x03;
    private const byte ContentTag = 0x04;

    public byte[]? Encode()
    {
        if (Content.Length is 0 or > MaxContentBytes || FileSize != (ulong)Content.Length) return null;
        var name = FileName is null ? null : Encoding.UTF8.GetBytes(FileName);
        var mime = MimeType is null ? null : Encoding.UTF8.GetBytes(MimeType);
        if ((name?.Length ?? 0) > ushort.MaxValue || (mime?.Length ?? 0) > ushort.MaxValue) return null;
        using var stream = new MemoryStream(Content.Length + (name?.Length ?? 0) + (mime?.Length ?? 0) + 32);
        if (name is not null) WriteShortTlv(stream, FileNameTag, name);
        Span<byte> size = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(size, checked((uint)FileSize));
        WriteShortTlv(stream, FileSizeTag, size);
        if (mime is not null) WriteShortTlv(stream, MimeTypeTag, mime);
        stream.WriteByte(ContentTag);
        Span<byte> contentLength = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(contentLength, (uint)Content.Length);
        stream.Write(contentLength);
        stream.Write(Content);
        return stream.ToArray();
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out PrivateFilePayload? payload)
    {
        payload = null;
        string? name = null, mime = null;
        ulong? declaredSize = null;
        byte[]? content = null;
        var offset = 0;
        while (offset < data.Length)
        {
            var tag = data[offset++];
            int length;
            if (tag == ContentTag)
            {
                if (offset + 4 > data.Length) return false;
                length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset, 4)));
                offset += 4;
            }
            else
            {
                if (offset + 2 > data.Length) return false;
                length = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));
                offset += 2;
            }
            if (length < 0 || offset + length > data.Length) return false;
            var value = data.Slice(offset, length);
            offset += length;
            switch (tag)
            {
                case FileNameTag: if (name is not null) return false; name = Encoding.UTF8.GetString(value); break;
                case FileSizeTag:
                    if (declaredSize is not null || (length != 4 && length != 8)) return false;
                    ulong size = 0; foreach (var valueByte in value) size = (size << 8) | valueByte;
                    declaredSize = size; break;
                case MimeTypeTag: if (mime is not null) return false; mime = Encoding.UTF8.GetString(value); break;
                case ContentTag: if (content is not null || length is 0 or > MaxContentBytes) return false; content = value.ToArray(); break;
                default: return false;
            }
        }
        if (content is null || declaredSize is null || declaredSize != (ulong)content.Length) return false;
        payload = new PrivateFilePayload(name, declaredSize.Value, mime, content);
        return true;
    }

    private static void WriteShortTlv(Stream stream, byte tag, ReadOnlySpan<byte> value)
    {
        stream.WriteByte(tag);
        Span<byte> length = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)value.Length));
        stream.Write(length);
        stream.Write(value);
    }
}
