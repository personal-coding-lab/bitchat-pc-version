using BitchatWindows.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

var signer = Ed25519PacketSigner.CreateNew();
var original = new BitchatPacket(BitchatMessageType.Message, [1,2,3,4,5,6,7,8], null, 1_700_000_000_000, System.Text.Encoding.UTF8.GetBytes(new string('x', 1_300)), null, 7);
var signed = signer.Sign(original) ?? throw new Exception("sign failed");
if (!Ed25519PacketSigner.Verify(signed, signer.PublicKey)) throw new Exception("signature rejected");
if (Ed25519PacketSigner.Verify(signed with { Payload = [1] }, signer.PublicKey)) throw new Exception("tampered packet accepted");
var fragments = FragmentAssembler.Fragment(signed, 200);
var assembler = new FragmentAssembler(); byte[]? complete = null;
foreach (var fragment in fragments.OrderByDescending(fragment => fragment.Payload[8])) assembler.TryAppend(fragment, out complete);
if (complete is null || !BinaryProtocol.TryDecode(complete, out var decoded) || decoded?.Payload.SequenceEqual(original.Payload) != true) throw new Exception("fragment round trip failed");
Console.WriteLine("Ed25519 signing and fragment round-trip passed.");

var aliceStatic = new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();
var bobStatic = new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();
var alice = new NoiseXXHandshake(NoiseRole.Initiator, aliceStatic);
var bob = new NoiseXXHandshake(NoiseRole.Responder, bobStatic);
var m1 = alice.WriteMessage();
if (bob.ReadMessage(m1).Length != 0) throw new Exception("Noise message 1 payload mismatch");
var m2 = bob.WriteMessage();
if (alice.ReadMessage(m2).Length != 0) throw new Exception("Noise message 2 payload mismatch");
var m3 = alice.WriteMessage();
if (bob.ReadMessage(m3).Length != 0 || !alice.IsComplete || !bob.IsComplete) throw new Exception("Noise XX did not complete");
var (aliceSend, aliceReceive) = alice.Split(); var (bobSend, bobReceive) = bob.Split();
if (!aliceSend.SequenceEqual(bobReceive) || !aliceReceive.SequenceEqual(bobSend)) throw new Exception("Noise split keys disagree");
var sender = new NoiseTransportSession(aliceSend, aliceReceive); var receiver = new NoiseTransportSession(bobSend, bobReceive);
var ciphertext = sender.Encrypt("private message"u8); if (!receiver.Decrypt(ciphertext).SequenceEqual("private message"u8)) throw new Exception("Noise transport decrypt failed");
try { receiver.Decrypt(ciphertext); throw new Exception("Noise replay accepted"); } catch (System.Security.Cryptography.CryptographicException) { }
Console.WriteLine("Noise XX handshake round-trip passed.");

// Canonical Noise_XX_25519_ChaChaPoly_SHA256 vector also exercised by the
// upstream BitChat test suite. This detects protocol-name, prologue, nonce,
// HKDF, and handshake token ordering drift that a self-consistent round trip
// cannot reveal.
static byte[] Hex(string value) => Convert.FromHexString(value);
static void ExpectEqual(byte[] actual, string expected, string name)
{
    if (!actual.SequenceEqual(Hex(expected))) throw new Exception($"Noise vector mismatch: {name}");
}
var vectorPrologue = Hex("4a6f686e2047616c74");
var vectorInitiator = new NoiseXXHandshake(
    NoiseRole.Initiator,
    Hex("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
    vectorPrologue,
    Hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"));
var vectorResponder = new NoiseXXHandshake(
    NoiseRole.Responder,
    Hex("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
    vectorPrologue,
    Hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"));
var vectorOne = vectorInitiator.WriteMessage(Hex("4c756477696720766f6e204d69736573"));
ExpectEqual(vectorOne, "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573", "message 1");
vectorResponder.ReadMessage(vectorOne);
var vectorTwo = vectorResponder.WriteMessage(Hex("4d757272617920526f746862617264"));
ExpectEqual(vectorTwo, "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f8814c7194e83f23dbd8d162c9326ad", "message 2");
vectorInitiator.ReadMessage(vectorTwo);
var vectorThree = vectorInitiator.WriteMessage(Hex("462e20412e20486179656b"));
ExpectEqual(vectorThree, "c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a80ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6ae769a1d95941d49b25030", "message 3");
vectorResponder.ReadMessage(vectorThree);
ExpectEqual(vectorInitiator.HandshakeHash, "c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e", "handshake hash");
if (!vectorInitiator.HandshakeHash.SequenceEqual(vectorResponder.HandshakeHash)) throw new Exception("Noise vector handshake hashes disagree");
Console.WriteLine("Noise XX canonical vector passed.");

var privatePayload = new PrivateMessagePayload("pm-android-compatible-1", "private hello");
var privateWire = privatePayload.Encode() ?? throw new Exception("private message TLV encode failed");
if (!PrivateMessagePayload.TryDecode(privateWire, out var decodedPrivate) || decodedPrivate != privatePayload)
    throw new Exception("private message TLV round trip failed");
if (PrivateMessagePayload.TryDecode([0x00, 0x02, (byte)'x'], out _))
    throw new Exception("truncated private message TLV accepted");
Console.WriteLine("Private-message TLV round-trip passed.");

var privateFile = new PrivateFilePayload("photo.jpg", 4, "image/jpeg", [1, 2, 3, 4]);
var privateFileWire = privateFile.Encode() ?? throw new Exception("private file TLV encode failed");
if (!PrivateFilePayload.TryDecode(privateFileWire, out var decodedFile) || decodedFile is null ||
    decodedFile.FileName != privateFile.FileName || decodedFile.FileSize != privateFile.FileSize ||
    decodedFile.MimeType != privateFile.MimeType || !decodedFile.Content.SequenceEqual(privateFile.Content))
    throw new Exception("private file TLV round trip failed");
if (PrivateFilePayload.TryDecode([0x04, 0, 0, 0, 1, 1], out _))
    throw new Exception("private file without declared size accepted");
Console.WriteLine("Private-file TLV round-trip passed.");

var largeEncrypted = new BitchatPacket(BitchatMessageType.NoiseEncrypted, [1,2,3,4,5,6,7,8], [8,7,6,5,4,3,2,1], 1_700_000_000_000, new byte[70_000], null, 7, 2);
var largeFragments = FragmentAssembler.Fragment(largeEncrypted);
var largeAssembler = new FragmentAssembler(); byte[]? largeComplete = null;
foreach (var fragment in largeFragments) largeAssembler.TryAppend(fragment, out largeComplete);
if (largeComplete is null || !BinaryProtocol.TryDecode(largeComplete, out var largeDecoded) || largeDecoded?.Version != 2 || largeDecoded.Payload.Length != 70_000)
    throw new Exception("v2 encrypted-media fragment round trip failed");
Console.WriteLine("V2 encrypted-media fragment round-trip passed.");
