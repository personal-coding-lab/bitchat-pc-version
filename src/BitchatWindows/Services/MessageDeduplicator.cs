using System.Security.Cryptography;

namespace BitchatWindows.Services;

/// <summary>Bounded replay/dedup guard for mesh broadcast frames.</summary>
public sealed class MessageDeduplicator
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DateTimeOffset> _seen = [];
    public bool TryMark(byte[] frame)
    {
        var key = Convert.ToHexString(SHA256.HashData(frame)); var now = DateTimeOffset.UtcNow;
        lock (_gate)
        {
            foreach (var stale in _seen.Where(item => item.Value < now.AddMinutes(-10)).Select(item => item.Key).ToArray()) _seen.Remove(stale);
            if (_seen.ContainsKey(key)) return false;
            if (_seen.Count >= 4096) _seen.Remove(_seen.MinBy(item => item.Value).Key);
            _seen[key] = now; return true;
        }
    }
}
