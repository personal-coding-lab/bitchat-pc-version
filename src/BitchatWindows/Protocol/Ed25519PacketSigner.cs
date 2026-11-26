using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace BitchatWindows.Protocol;

/// <summary>Ed25519 signatures over BitChat's canonical padded packet bytes.</summary>
public sealed class Ed25519PacketSigner
{
    private readonly Ed25519PrivateKeyParameters _privateKey;
    public byte[] PublicKey { get; }

    private Ed25519PacketSigner(Ed25519PrivateKeyParameters privateKey)
    {
        _privateKey = privateKey;
        PublicKey = privateKey.GeneratePublicKey().GetEncoded();
    }

    public static Ed25519PacketSigner CreateNew() => new(new Ed25519PrivateKeyParameters(new SecureRandom()));
    public static Ed25519PacketSigner FromPrivateKey(byte[] privateKey) => new(new Ed25519PrivateKeyParameters(privateKey, 0));
    public byte[] ExportPrivateKey() => _privateKey.GetEncoded();

    public BitchatPacket? Sign(BitchatPacket packet)
    {
        var signingBytes = CanonicalBytes(packet);
        if (signingBytes is null) return null;
        var signer = new Ed25519Signer(); signer.Init(true, _privateKey); signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
        return packet with { Signature = signer.GenerateSignature() };
    }

    public static bool Verify(BitchatPacket packet, byte[] publicKey)
    {
        if (packet.Signature is not { Length: 64 } || publicKey.Length != 32) return false;
        var signingBytes = CanonicalBytes(packet); if (signingBytes is null) return false;
        try
        {
            var verifier = new Ed25519Signer(); verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(signingBytes, 0, signingBytes.Length); return verifier.VerifySignature(packet.Signature);
        }
        catch (ArgumentException) { return false; }
    }

    private static byte[]? CanonicalBytes(BitchatPacket packet) => BinaryProtocol.Encode(packet with { Signature = null, Ttl = 0, IsRsr = false }, padding: true);
}
