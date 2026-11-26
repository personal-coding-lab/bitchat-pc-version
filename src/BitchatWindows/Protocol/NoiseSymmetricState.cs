using System.Security.Cryptography;

namespace BitchatWindows.Protocol;

/// <summary>Noise_XX_25519_ChaChaPoly_SHA256 symmetric state (Noise spec §5).</summary>
public sealed class NoiseSymmetricState
{
    private byte[] _ck;
    private byte[] _h;
    private byte[]? _key;
    private ulong _nonce;

    public NoiseSymmetricState(string protocolName = "Noise_XX_25519_ChaChaPoly_SHA256")
    {
        var name = System.Text.Encoding.ASCII.GetBytes(protocolName);
        _h = name.Length <= 32 ? [.. name, .. new byte[32 - name.Length]] : SHA256.HashData(name);
        _ck = (byte[])_h.Clone();
    }

    public void MixHash(ReadOnlySpan<byte> data) => _h = SHA256.HashData([.. _h, .. data.ToArray()]);
    public void MixKey(ReadOnlySpan<byte> ikm) { var output = Hkdf(_ck, ikm, 2); _ck = output[0]; _key = output[1]; _nonce = 0; }
    public byte[] EncryptAndHash(ReadOnlySpan<byte> plaintext)
    {
        var result = _key is null ? plaintext.ToArray() : Encrypt(_key, _nonce++, plaintext, _h);
        MixHash(result); return result;
    }
    public byte[] DecryptAndHash(ReadOnlySpan<byte> ciphertext)
    {
        var result = _key is null ? ciphertext.ToArray() : Decrypt(_key, _nonce++, ciphertext, _h);
        MixHash(ciphertext); return result;
    }
    public (byte[] sendKey, byte[] receiveKey) Split() { var output = Hkdf(_ck, [], 2); Clear(); return (output[0], output[1]); }
    public byte[] HandshakeHash => (byte[])_h.Clone();
    public void Clear() { CryptographicOperations.ZeroMemory(_ck); CryptographicOperations.ZeroMemory(_h); if (_key is not null) CryptographicOperations.ZeroMemory(_key); _key = null; _nonce = 0; }

    private static byte[][] Hkdf(byte[] salt, ReadOnlySpan<byte> ikm, int count)
    {
        using var extract = new HMACSHA256(salt); var tempKey = extract.ComputeHash(ikm.ToArray()); var output = new byte[count][]; var previous = Array.Empty<byte>();
        for (var i = 0; i < count; i++) { using var expand = new HMACSHA256(tempKey); previous = expand.ComputeHash([.. previous, (byte)(i + 1)]); output[i] = previous; }
        CryptographicOperations.ZeroMemory(tempKey); return output;
    }
    private static byte[] Encrypt(byte[] key, ulong nonce, ReadOnlySpan<byte> plaintext, byte[] associatedData)
    {
        var output = new byte[plaintext.Length + 16]; var nonceBytes = Nonce(nonce);
        using var cipher = new ChaCha20Poly1305(key); cipher.Encrypt(nonceBytes, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length, 16), associatedData); return output;
    }
    private static byte[] Decrypt(byte[] key, ulong nonce, ReadOnlySpan<byte> ciphertext, byte[] associatedData)
    {
        if (ciphertext.Length < 16) throw new CryptographicException("Noise ciphertext is too short.");
        var plain = new byte[ciphertext.Length - 16]; using var cipher = new ChaCha20Poly1305(key); cipher.Decrypt(Nonce(nonce), ciphertext[..^16], ciphertext[^16..], plain, associatedData); return plain;
    }
    private static byte[] Nonce(ulong nonce) { var result = new byte[12]; BitConverter.TryWriteBytes(result.AsSpan(4, 8), nonce); return result; }
}
