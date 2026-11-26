using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace BitchatWindows.Protocol;

public enum NoiseRole { Initiator, Responder }

/// <summary>Noise XX handshake: e, ee, s, es, s, se.</summary>
public sealed class NoiseXXHandshake
{
    private readonly NoiseRole _role;
    private readonly X25519PrivateKeyParameters _staticPrivate;
    private readonly byte[] _staticPublic;
    private readonly NoiseSymmetricState _symmetric;
    private readonly byte[]? _predeterminedEphemeral;
    private bool _usedPredeterminedEphemeral;
    private X25519PrivateKeyParameters? _ephemeral;
    private byte[]? _remoteEphemeral;
    private byte[]? _remoteStatic;
    private int _step;

    public NoiseXXHandshake(NoiseRole role, byte[] localStaticPrivate, byte[]? prologue = null, byte[]? predeterminedEphemeral = null)
    {
        if (predeterminedEphemeral is { Length: not 32 }) throw new ArgumentException("Noise ephemeral private keys are 32 bytes.", nameof(predeterminedEphemeral));
        _role = role;
        _staticPrivate = new X25519PrivateKeyParameters(localStaticPrivate, 0);
        _staticPublic = _staticPrivate.GeneratePublicKey().GetEncoded();
        _predeterminedEphemeral = predeterminedEphemeral?.ToArray();
        _symmetric = new NoiseSymmetricState();
        if (prologue is { Length: > 0 }) _symmetric.MixHash(prologue);
    }
    public byte[]? RemoteStaticPublicKey => _remoteStatic;
    public byte[] HandshakeHash => _symmetric.HandshakeHash;
    public bool IsComplete => _step == 3;

    public byte[] WriteMessage(byte[]? payload = null)
    {
        payload ??= [];
        if ((_role == NoiseRole.Initiator && _step == 0) || (_role == NoiseRole.Responder && _step == 1)) return WriteEphemeralMessage(payload);
        if (_role == NoiseRole.Initiator && _step == 2) return WriteFinalMessage(payload);
        throw new InvalidOperationException("Not this handshake role's write turn.");
    }
    public byte[] ReadMessage(byte[] message)
    {
        if ((_role == NoiseRole.Responder && _step == 0) || (_role == NoiseRole.Initiator && _step == 1)) return ReadEphemeralMessage(message);
        if (_role == NoiseRole.Responder && _step == 2) return ReadFinalMessage(message);
        throw new InvalidOperationException("Not this handshake role's read turn.");
    }
    public (byte[] SendKey, byte[] ReceiveKey) Split()
    {
        if (!IsComplete) throw new InvalidOperationException("Handshake is incomplete.");
        var (first, second) = _symmetric.Split();
        return _role == NoiseRole.Initiator ? (first, second) : (second, first);
    }

    private byte[] WriteEphemeralMessage(byte[] payload)
    {
        _ephemeral = !_usedPredeterminedEphemeral && _predeterminedEphemeral is not null
            ? new X25519PrivateKeyParameters(_predeterminedEphemeral, 0)
            : new X25519PrivateKeyParameters(new SecureRandom());
        _usedPredeterminedEphemeral = true;
        var ep = _ephemeral.GeneratePublicKey().GetEncoded();
        var output = new List<byte>(ep); _symmetric.MixHash(ep);
        if (_role == NoiseRole.Initiator) { output.AddRange(_symmetric.EncryptAndHash(payload)); _step = 1; return output.ToArray(); }
        MixKey(Dh(_ephemeral, _remoteEphemeral!)); output.AddRange(_symmetric.EncryptAndHash(_staticPublic)); MixKey(Dh(_staticPrivate, _remoteEphemeral!)); output.AddRange(_symmetric.EncryptAndHash(payload)); _step = 2; return output.ToArray();
    }
    private byte[] ReadEphemeralMessage(byte[] message)
    {
        if (message.Length < 32) throw new CryptographicException("Noise message lacks an ephemeral key.");
        _remoteEphemeral = message[..32]; _symmetric.MixHash(_remoteEphemeral); var rest = message[32..];
        if (_role == NoiseRole.Responder) { _step = 1; return _symmetric.DecryptAndHash(rest); }
        MixKey(Dh(_ephemeral!, _remoteEphemeral)); if (rest.Length < 48) throw new CryptographicException("Noise message lacks encrypted static key.");
        _remoteStatic = _symmetric.DecryptAndHash(rest[..48]); if (_remoteStatic.Length != 32) throw new CryptographicException("Invalid remote static key.");
        MixKey(Dh(_ephemeral!, _remoteStatic)); _step = 2; return _symmetric.DecryptAndHash(rest[48..]);
    }
    private byte[] WriteFinalMessage(byte[] payload)
    {
        var output = new List<byte>(_symmetric.EncryptAndHash(_staticPublic)); MixKey(Dh(_staticPrivate, _remoteEphemeral!)); output.AddRange(_symmetric.EncryptAndHash(payload)); _step = 3; return output.ToArray();
    }
    private byte[] ReadFinalMessage(byte[] message)
    {
        if (message.Length < 48) throw new CryptographicException("Noise message lacks encrypted static key.");
        _remoteStatic = _symmetric.DecryptAndHash(message[..48]); if (_remoteStatic.Length != 32) throw new CryptographicException("Invalid remote static key.");
        MixKey(Dh(_ephemeral!, _remoteStatic)); _step = 3; return _symmetric.DecryptAndHash(message[48..]);
    }
    private void MixKey(byte[] material) { _symmetric.MixKey(material); System.Security.Cryptography.CryptographicOperations.ZeroMemory(material); }
    private static byte[] Dh(X25519PrivateKeyParameters privateKey, byte[] remote)
    {
        var secret = new byte[32]; privateKey.GenerateSecret(new X25519PublicKeyParameters(remote, 0), secret, 0); return secret;
    }
}
