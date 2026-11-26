using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BitchatWindows.Protocol;

/// <summary>Post-handshake Noise transport with explicit 32-bit wire nonces and replay rejection.</summary>
public sealed class NoiseTransportSession
{
    private readonly byte[] _sendKey, _receiveKey;
    private uint _sendNonce;
    private readonly HashSet<uint> _seen = [];
    private uint _highest;
    public NoiseTransportSession(byte[] sendKey, byte[] receiveKey) { if (sendKey.Length != 32 || receiveKey.Length != 32) throw new ArgumentException("Noise transport keys must be 32 bytes."); _sendKey = sendKey; _receiveKey = receiveKey; }
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        if (_sendNonce == uint.MaxValue) throw new CryptographicException("Noise send nonce exhausted.");
        var nonce = _sendNonce++; var output = new byte[4 + plaintext.Length + 16]; BinaryPrimitives.WriteUInt32BigEndian(output, nonce);
        using var cipher = new ChaCha20Poly1305(_sendKey); cipher.Encrypt(Nonce(nonce), plaintext, output.AsSpan(4, plaintext.Length), output.AsSpan(4 + plaintext.Length, 16)); return output;
    }
    public byte[] Decrypt(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < 20) throw new CryptographicException("Noise transport packet too short.");
        var nonce = BinaryPrimitives.ReadUInt32BigEndian(packet[..4]);
        if ((_highest >= 1024 && nonce <= _highest - 1024) || _seen.Contains(nonce)) throw new CryptographicException("Noise replay detected.");
        var plain = new byte[packet.Length - 20]; using var cipher = new ChaCha20Poly1305(_receiveKey); cipher.Decrypt(Nonce(nonce), packet.Slice(4, plain.Length), packet[^16..], plain);
        _seen.Add(nonce); if (nonce > _highest) _highest = nonce; _seen.RemoveWhere(value => _highest >= 1024 && value <= _highest - 1024); return plain;
    }
    private static byte[] Nonce(uint nonce) { var result = new byte[12]; BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8, 4), nonce); return result; }
}
