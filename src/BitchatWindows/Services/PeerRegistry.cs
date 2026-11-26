using BitchatWindows.Protocol;

namespace BitchatWindows.Services;

/// <summary>Thread-safe peer inventory. Announce data is untrusted until a future signature verifier authenticates it.</summary>
public sealed class PeerRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, MeshPeer> _peers = [];
    public MeshPeer Upsert(byte[] senderId, AnnouncementPacket announce, bool isVerified)
    {
        var id = Convert.ToHexString(senderId);
        lock (_gate)
        {
            var peer = new MeshPeer(id, announce.Nickname, announce.NoisePublicKey, announce.SigningPublicKey, DateTimeOffset.UtcNow, isVerified);
            _peers[id] = peer; return peer;
        }
    }
    public IReadOnlyList<MeshPeer> Snapshot() { lock (_gate) return _peers.Values.OrderBy(peer => peer.Nickname, StringComparer.OrdinalIgnoreCase).ToArray(); }
    public bool TryGet(byte[] senderId, out MeshPeer? peer)
    {
        lock (_gate) return _peers.TryGetValue(Convert.ToHexString(senderId), out peer);
    }

    public bool TryFind(string nicknameOrId, out MeshPeer? peer)
    {
        var query = nicknameOrId.Trim().TrimStart('@');
        lock (_gate)
        {
            peer = _peers.Values.FirstOrDefault(item =>
                item.Id.Equals(query, StringComparison.OrdinalIgnoreCase) ||
                item.Nickname.Equals(query, StringComparison.OrdinalIgnoreCase));
            return peer is not null;
        }
    }

    public static string Fingerprint(MeshPeer peer) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(peer.NoisePublicKey));
}

public sealed record MeshPeer(string Id, string Nickname, byte[] NoisePublicKey, byte[] SigningPublicKey, DateTimeOffset LastSeen, bool IsVerified);
