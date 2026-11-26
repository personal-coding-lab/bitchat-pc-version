using System.Net.WebSockets;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using System.Text.Json;

namespace BitchatWindows.Services;

/// <summary>Bounded NIP-01 transport for BitChat's signed public geohash channel events.</summary>
public sealed class NostrGeoTransport : IDisposable
{
    private readonly NostrIdentity _identity;
    private ClientWebSocket? _socket;
    private CancellationTokenSource? _receiveCancellation;
    private Task? _receiveTask;
    private string? _subscriptionId;
    private bool _disposed;
    public event Action<string>? StatusChanged;
    public event Action<NostrGeoMessage>? MessageReceived;
    public bool IsConnected => _socket?.State == WebSocketState.Open;
    public string PublicKey => _identity.PublicKeyHex;

    public NostrGeoTransport(NostrIdentity identity) => _identity = identity;

    public async Task ConnectAsync(string relay = "wss://relay.damus.io")
    {
        ThrowIfDisposed();
        if (!Uri.TryCreate(relay, UriKind.Absolute, out var uri) || uri.Scheme is not ("wss" or "ws")) throw new ArgumentException("Relay URL must be ws:// or wss://.", nameof(relay));
        await DisconnectAsync();
        var socket = new ClientWebSocket(); socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        try
        {
            StatusChanged?.Invoke($"Nostr connecting to {uri.Host}…");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await socket.ConnectAsync(uri, timeout.Token);
            _socket = socket;
            _receiveCancellation = new CancellationTokenSource();
            _receiveTask = ReceiveLoopAsync(socket, _receiveCancellation.Token);
            StatusChanged?.Invoke($"Nostr connected to {uri.Host}");
        }
        catch { socket.Dispose(); throw; }
    }

    public async Task SubscribeAsync(string geohash)
    {
        ValidateGeohash(geohash); EnsureConnected();
        _subscriptionId = "bitchat-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
        await SendAsync(new object[] { "REQ", _subscriptionId, new Dictionary<string, object> { ["kinds"] = new[] { 20_000 }, ["#g"] = new[] { geohash }, ["limit"] = 100 } });
        StatusChanged?.Invoke($"Nostr subscribed to geohash {geohash}");
    }

    public async Task PublishAsync(string geohash, string nickname, string content)
    {
        ValidateGeohash(geohash); if (string.IsNullOrWhiteSpace(content) || Encoding.UTF8.GetByteCount(content) > 8_192) throw new ArgumentException("Geohash message must be 1–8192 UTF-8 bytes.", nameof(content));
        EnsureConnected();
        var tags = string.IsNullOrWhiteSpace(nickname)
            ? new List<string[]> { new[] { "g", geohash } }
            : new List<string[]> { new[] { "g", geohash }, new[] { "n", nickname } };
        var createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var canonical = JsonSerializer.Serialize(new object[] { 0, _identity.PublicKeyHex, createdAt, 20_000, tags, content });
        var id = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        var eventObject = new Dictionary<string, object>
        {
            ["id"] = Convert.ToHexString(id).ToLowerInvariant(), ["pubkey"] = _identity.PublicKeyHex, ["created_at"] = createdAt,
            ["kind"] = 20_000, ["tags"] = tags, ["content"] = content,
            ["sig"] = Convert.ToHexString(NostrBip340.Sign(id, _identity.PrivateKey)).ToLowerInvariant()
        };
        await SendAsync(new object[] { "EVENT", eventObject });
        StatusChanged?.Invoke("Nostr geohash message submitted to relay");
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];
        try
        {
            while (!cancellationToken.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                using var body = new MemoryStream(); WebSocketReceiveResult result;
                do
                {
                    result = await socket.ReceiveAsync(buffer, cancellationToken);
                    if (result.MessageType == WebSocketMessageType.Close) { StatusChanged?.Invoke("Nostr relay closed the connection"); return; }
                    if (body.Length + result.Count > 128 * 1024) { StatusChanged?.Invoke("Nostr relay frame exceeded 128 KiB and was dropped"); return; }
                    body.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);
                if (result.MessageType == WebSocketMessageType.Text) HandleFrame(Encoding.UTF8.GetString(body.ToArray()));
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { StatusChanged?.Invoke($"Nostr receive failed: {ex.Message}"); }
    }

    private void HandleFrame(string frame)
    {
        try
        {
            using var doc = JsonDocument.Parse(frame);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() < 3 || root[0].GetString() != "EVENT" || _subscriptionId is null || root[1].GetString() != _subscriptionId) return;
            var eventJson = root[2];
            if (!eventJson.TryGetProperty("kind", out var kind) || kind.GetInt32() != 20_000 || !eventJson.TryGetProperty("content", out var content) || !eventJson.TryGetProperty("pubkey", out var pubkey) || !eventJson.TryGetProperty("id", out var id) || !eventJson.TryGetProperty("sig", out var sig)) return;
            var tags = eventJson.TryGetProperty("tags", out var tagNode) && tagNode.ValueKind == JsonValueKind.Array ? tagNode.EnumerateArray().Select(tag => tag.EnumerateArray().Select(value => value.GetString() ?? string.Empty).ToArray()).ToArray() : [];
            var geohash = tags.FirstOrDefault(tag => tag.Length == 2 && tag[0] == "g")?[1];
            if (string.IsNullOrWhiteSpace(geohash) || !VerifyEvent(eventJson, id.GetString(), pubkey.GetString(), sig.GetString(), tags)) return;
            var nickname = tags.FirstOrDefault(tag => tag.Length == 2 && tag[0] == "n")?[1] ?? pubkey.GetString()![..12];
            MessageReceived?.Invoke(new NostrGeoMessage(geohash, nickname, content.GetString() ?? string.Empty, pubkey.GetString()!));
        }
        catch (Exception ex) { DiagnosticLog.Write($"Dropped invalid Nostr event: {ex.Message}"); }
    }

    private static bool VerifyEvent(JsonElement item, string? id, string? pubkey, string? signature, string[][] tags)
    {
        if (id is null || pubkey is null || signature is null || id.Length != 64 || pubkey.Length != 64 || signature.Length != 128) return false;
        try
        {
            var createdAt = item.GetProperty("created_at").GetInt64(); var content = item.GetProperty("content").GetString() ?? string.Empty;
            var canonical = JsonSerializer.Serialize(new object[] { 0, pubkey, createdAt, 20_000, tags, content });
            var calculated = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return Convert.ToHexString(calculated).Equals(id, StringComparison.OrdinalIgnoreCase) && NostrBip340.Verify(calculated, Convert.FromHexString(pubkey), Convert.FromHexString(signature));
        }
        catch { return false; }
    }

    private async Task SendAsync(object value)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value));
        await _socket!.SendAsync(bytes, WebSocketMessageType.Text, true, CancellationToken.None);
    }
    private static void ValidateGeohash(string value)
    {
        if (value.Length is < 1 or > 12 || value.Any(ch => !"0123456789bcdefghjkmnpqrstuvwxyz".Contains(char.ToLowerInvariant(ch)))) throw new ArgumentException("Invalid geohash.", nameof(value));
    }
    private void EnsureConnected() { if (!IsConnected) throw new InvalidOperationException("Nostr relay is not connected."); }
    public async Task DisconnectAsync()
    {
        _receiveCancellation?.Cancel();
        if (_socket is { State: WebSocketState.Open } socket) { try { await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None); } catch { } }
        _socket?.Dispose(); _socket = null; _receiveCancellation?.Dispose(); _receiveCancellation = null; _receiveTask = null; _subscriptionId = null;
    }
    public void Dispose() { if (_disposed) return; DisconnectAsync().GetAwaiter().GetResult(); _disposed = true; }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed record NostrGeoMessage(string Geohash, string Nickname, string Content, string PublicKey);
