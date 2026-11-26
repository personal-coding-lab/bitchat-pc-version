using System.Net.WebSockets;
using System.Text;

namespace BitchatWindows.Services;

/// <summary>Tests a relay WebSocket connection without publishing or subscribing.</summary>
public sealed class NostrRelayProbe : IDisposable
{
    private ClientWebSocket? _socket;
    public event Action<string>? StatusChanged;

    public async Task ConnectAsync()
    {
        DisposeSocket();
        _socket = new ClientWebSocket();
        _socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        var endpoint = new Uri("wss://relay.damus.io");
        try
        {
            StatusChanged?.Invoke($"Connecting to {endpoint.Host}…");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            await _socket.ConnectAsync(endpoint, timeout.Token);
            StatusChanged?.Invoke($"Connected · {endpoint.Host} (no events are sent)");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Connection failed: {ex.Message}");
            DisposeSocket();
        }
    }

    private void DisposeSocket()
    {
        _socket?.Dispose();
        _socket = null;
    }

    public void Dispose() => DisposeSocket();
}
