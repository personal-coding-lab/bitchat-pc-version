using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace BitchatWindows.Services;

/// <summary>DPAPI-protected, independent secp256k1 identity for Nostr relays.</summary>
public sealed class NostrIdentityStore
{
    private static readonly byte[] Entropy = System.Text.Encoding.UTF8.GetBytes("bitchat-windows-nostr-identity-v1");
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BitchatWindows", "nostr-identity.v1");

    public NostrIdentity LoadOrCreate()
    {
        try
        {
            if (File.Exists(_path))
            {
                var data = ProtectedData.Unprotect(File.ReadAllBytes(_path), Entropy, DataProtectionScope.CurrentUser);
                if (data.Length == 33 && data[0] == 1) return NostrIdentity.FromPrivateKey(data[1..]);
                throw new InvalidDataException("Invalid protected Nostr identity record.");
            }
        }
        catch (CryptographicException) { throw new InvalidOperationException("The Windows-protected Nostr identity cannot be read for this user."); }
        var identity = NostrIdentity.Create();
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllBytes(_path, ProtectedData.Protect([1, .. identity.PrivateKey], Entropy, DataProtectionScope.CurrentUser));
        return identity;
    }
}

public sealed record NostrIdentity(byte[] PrivateKey, string PublicKeyHex)
{
    public static NostrIdentity Create()
    {
        var n = NostrBip340.Domain.N;
        var scalar = Org.BouncyCastle.Utilities.BigIntegers.CreateRandomInRange(BigInteger.One, n.Subtract(BigInteger.One), new SecureRandom());
        return FromPrivateKey(NostrBip340.To32(scalar));
    }
    public static NostrIdentity FromPrivateKey(byte[] privateKey) => new(privateKey, Convert.ToHexString(NostrBip340.PublicKey(privateKey)).ToLowerInvariant());
}
