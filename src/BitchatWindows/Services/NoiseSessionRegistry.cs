using BitchatWindows.Protocol;

namespace BitchatWindows.Services;

/// <summary>Owns one pending XX handshake or established transport per verified peer.</summary>
public sealed class NoiseSessionRegistry
{
    private readonly LocalIdentity _identity;
    private readonly Dictionary<string, NoiseXXHandshake> _pending = [];
    private readonly Dictionary<string, NoiseTransportSession> _sessions = [];
    public NoiseSessionRegistry(LocalIdentity identity) => _identity = identity;
    public byte[] Start(byte[] peerId)
    {
        var key = Convert.ToHexString(peerId); var state = new NoiseXXHandshake(NoiseRole.Initiator, _identity.X25519PrivateKey); _pending[key] = state; return state.WriteMessage();
    }
    public byte[]? ReceiveHandshake(byte[] peerId, byte[] payload)
    {
        var key = Convert.ToHexString(peerId);
        // A Noise XX first flight is the sender's 32-byte ephemeral key. If it
        // arrives again, restart the responder state so an abandoned attempt
        // cannot leave the peer waiting for a response to its new attempt.
        if (payload.Length == 32 || !_pending.TryGetValue(key, out var state))
        {
            state = new NoiseXXHandshake(NoiseRole.Responder, _identity.X25519PrivateKey);
            _pending[key] = state;
            DiagnosticLog.Write($"Noise responder started for {key}");
        }
        DiagnosticLog.Write($"Noise handshake received from {key}: {payload.Length} bytes");
        state.ReadMessage(payload);
        if (!state.IsComplete)
        {
            var response = state.WriteMessage();
            DiagnosticLog.Write($"Noise handshake response for {key}: {response.Length} bytes");
            // The initiator becomes complete while writing message 3. Promote
            // it immediately, otherwise it can never encrypt its first DM.
            if (state.IsComplete)
            {
                var promotedKeys = state.Split();
                _sessions[key] = new NoiseTransportSession(promotedKeys.SendKey, promotedKeys.ReceiveKey);
                _pending.Remove(key);
                DiagnosticLog.Write($"Noise transport established for {key}");
            }
            return response;
        }
        var keys = state.Split(); _sessions[key] = new NoiseTransportSession(keys.SendKey, keys.ReceiveKey); _pending.Remove(key); return null;
    }
    public bool TryEncrypt(byte[] peerId, byte[] plaintext, out byte[]? ciphertext) => _sessions.TryGetValue(Convert.ToHexString(peerId), out var session) ? (ciphertext = session.Encrypt(plaintext)) is not null : (ciphertext = null) is not null;
    public bool HasSession(byte[] peerId) => _sessions.ContainsKey(Convert.ToHexString(peerId));
    public bool TryDecrypt(byte[] peerId, byte[] ciphertext, out byte[]? plaintext)
    {
        plaintext = null; if (!_sessions.TryGetValue(Convert.ToHexString(peerId), out var session)) return false;
        try { plaintext = session.Decrypt(ciphertext); return true; } catch (System.Security.Cryptography.CryptographicException) { return false; }
    }
    public void Clear() { _pending.Clear(); _sessions.Clear(); }
}
