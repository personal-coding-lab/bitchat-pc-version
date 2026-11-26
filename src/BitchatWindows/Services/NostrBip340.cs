using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace BitchatWindows.Services;

/// <summary>Minimal BIP-340 signer/verifier used by NIP-01 event envelopes.</summary>
public static class NostrBip340
{
    private static readonly X9ECParameters Curve = SecNamedCurves.GetByName("secp256k1") ?? throw new InvalidOperationException("secp256k1 unavailable");
    public static readonly ECDomainParameters Domain = new(Curve.Curve, Curve.G, Curve.N, Curve.H);

    public static byte[] PublicKey(byte[] privateKey)
    {
        var d = Scalar(privateKey); var point = Curve.G.Multiply(d).Normalize();
        return To32(point.AffineXCoord.ToBigInteger());
    }

    public static byte[] Sign(byte[] message32, byte[] privateKey, byte[]? auxiliaryRandom = null)
    {
        if (message32.Length != 32) throw new ArgumentException("Nostr event id must be 32 bytes.", nameof(message32));
        var d0 = Scalar(privateKey); var point = Curve.G.Multiply(d0).Normalize();
        var d = point.AffineYCoord.ToBigInteger().TestBit(0) ? Curve.N.Subtract(d0) : d0;
        var publicX = To32(point.AffineXCoord.ToBigInteger());
        var aux = auxiliaryRandom ?? RandomNumberGenerator.GetBytes(32);
        if (aux.Length != 32) throw new ArgumentException("BIP-340 auxiliary randomness must be 32 bytes.", nameof(auxiliaryRandom));
        var taggedAux = TaggedHash("BIP0340/aux", aux);
        var secret = To32(d); for (var i = 0; i < secret.Length; i++) secret[i] ^= taggedAux[i];
        var k0 = new BigInteger(1, TaggedHash("BIP0340/nonce", [.. secret, .. publicX, .. message32])).Mod(Curve.N);
        if (k0.SignValue == 0) throw new CryptographicException("BIP-340 nonce is zero.");
        var rPoint = Curve.G.Multiply(k0).Normalize();
        var k = rPoint.AffineYCoord.ToBigInteger().TestBit(0) ? Curve.N.Subtract(k0) : k0;
        var r = To32(rPoint.AffineXCoord.ToBigInteger());
        var e = new BigInteger(1, TaggedHash("BIP0340/challenge", [.. r, .. publicX, .. message32])).Mod(Curve.N);
        var s = k.Add(e.Multiply(d)).Mod(Curve.N);
        return [.. r, .. To32(s)];
    }

    public static bool Verify(byte[] message32, byte[] publicKey, byte[] signature)
    {
        if (message32.Length != 32 || publicKey.Length != 32 || signature.Length != 64) return false;
        var r = new BigInteger(1, signature[..32]); var s = new BigInteger(1, signature[32..]);
        if (r.CompareTo(Curve.Curve.Field.Characteristic) >= 0 || s.CompareTo(Curve.N) >= 0) return false;
        try
        {
            var point = Curve.Curve.DecodePoint([0x02, .. publicKey]).Normalize();
            var e = new BigInteger(1, TaggedHash("BIP0340/challenge", [.. signature[..32], .. publicKey, .. message32])).Mod(Curve.N);
            var result = Curve.G.Multiply(s).Subtract(point.Multiply(e)).Normalize();
            return !result.IsInfinity && !result.AffineYCoord.ToBigInteger().TestBit(0) && result.AffineXCoord.ToBigInteger().Equals(r);
        }
        catch { return false; }
    }

    public static byte[] To32(BigInteger value)
    {
        var raw = value.ToByteArrayUnsigned();
        if (raw.Length > 32) throw new ArgumentOutOfRangeException(nameof(value));
        return [.. new byte[32 - raw.Length], .. raw];
    }

    private static BigInteger Scalar(byte[] privateKey)
    {
        if (privateKey.Length != 32) throw new ArgumentException("Nostr secret key must be 32 bytes.", nameof(privateKey));
        var scalar = new BigInteger(1, privateKey);
        if (scalar.SignValue <= 0 || scalar.CompareTo(Curve.N) >= 0) throw new ArgumentException("Invalid Nostr secret key.", nameof(privateKey));
        return scalar;
    }
    private static byte[] TaggedHash(string tag, byte[] value)
    {
        var tagHash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(tag));
        return SHA256.HashData([.. tagHash, .. tagHash, .. value]);
    }
}
