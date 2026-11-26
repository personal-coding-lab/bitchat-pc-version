using System.Security.Cryptography;
using System.IO;
using BitchatWindows.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BitchatWindows.Services;

/// <summary>Persistent X25519 + Ed25519 identity protected by Windows DPAPI.</summary>
public sealed class LocalIdentityStore
{
    private static readonly byte[] Entropy = System.Text.Encoding.UTF8.GetBytes("bitchat-windows-identity-v1");
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BitchatWindows", "identity.v1");

    public LocalIdentity LoadOrCreate()
    {
        try
        {
            if (File.Exists(_path)) return Decode(ProtectedData.Unprotect(File.ReadAllBytes(_path), Entropy, DataProtectionScope.CurrentUser));
        }
        catch (CryptographicException) { throw new InvalidOperationException("The Windows-protected BitChat identity cannot be read for this user."); }
        var x25519 = new X25519PrivateKeyParameters(new SecureRandom());
        var ed25519 = Ed25519PacketSigner.CreateNew();
        var identity = new LocalIdentity(x25519.GetEncoded(), x25519.GeneratePublicKey().GetEncoded(), ed25519.ExportPrivateKey(), ed25519.PublicKey);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllBytes(_path, ProtectedData.Protect(Encode(identity), Entropy, DataProtectionScope.CurrentUser));
        return identity;
    }

    public void Wipe()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }

    private static byte[] Encode(LocalIdentity identity) => [1, .. identity.X25519PrivateKey, .. identity.Ed25519PrivateKey];
    private static LocalIdentity Decode(byte[] data)
    {
        if (data.Length != 65 || data[0] != 1) throw new InvalidDataException("Invalid identity record.");
        var xprivate = data[1..33]; var eprivate = data[33..65]; var xkey = new X25519PrivateKeyParameters(xprivate, 0);
        var signer = Ed25519PacketSigner.FromPrivateKey(eprivate);
        return new LocalIdentity(xprivate, xkey.GeneratePublicKey().GetEncoded(), eprivate, signer.PublicKey);
    }
}

public sealed record LocalIdentity(byte[] X25519PrivateKey, byte[] X25519PublicKey, byte[] Ed25519PrivateKey, byte[] Ed25519PublicKey)
{
    public byte[] PeerId => SHA256.HashData(X25519PublicKey)[..8];
    public Ed25519PacketSigner PacketSigner => Ed25519PacketSigner.FromPrivateKey(Ed25519PrivateKey);
    public byte[] DeriveSharedSecret(byte[] remotePublicKey)
    {
        if (remotePublicKey.Length != 32) throw new ArgumentException("X25519 public keys must be 32 bytes.", nameof(remotePublicKey));
        var local = new X25519PrivateKeyParameters(X25519PrivateKey, 0);
        var remote = new X25519PublicKeyParameters(remotePublicKey, 0);
        var secret = new byte[32]; local.GenerateSecret(remote, secret, 0); return secret;
    }
}
