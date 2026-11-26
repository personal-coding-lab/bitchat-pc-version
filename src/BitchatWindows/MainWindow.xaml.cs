using System.Collections.ObjectModel;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using BitchatWindows.Protocol;
using BitchatWindows.Services;

namespace BitchatWindows;

public partial class MainWindow : Window
{
    private readonly WindowsBleScanner _scanner = new();
    private readonly WindowsGattMeshHost _meshHost = new();
    private readonly WindowsGattMeshClient _meshClient = new();
    private readonly FragmentAssembler _fragmentAssembler = new();
    private readonly PeerRegistry _peerRegistry = new();
    private readonly MessageDeduplicator _deduplicator = new();
    private readonly GossipSync _gossipSync = new();
    private readonly LocalIdentityStore _identityStore = new();
    private readonly NostrIdentityStore _nostrIdentityStore = new();
    private readonly ChatPreferencesStore _preferencesStore = new();
    private LocalIdentity? _identity;
    private NostrGeoTransport? _nostrTransport;
    private string? _geohashChannel;
    private NoiseSessionRegistry? _noiseSessions;
    private readonly NostrRelayProbe _relayProbe = new();
    private readonly ObservableCollection<string> _messages = [];
    private readonly Dictionary<string, List<string>> _roomHistory = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, PingRequest> _pendingPings = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _recentInboundPings = [];
    private readonly Dictionary<string, Queue<PendingSecurePayload>> _pendingPrivateMessages = new(StringComparer.Ordinal);
    private readonly HashSet<string> _sentPrivateMessageIds = new(StringComparer.Ordinal);
    private readonly HashSet<ulong> _meshConnectionAttempts = [];
    private readonly object _meshConnectionGate = new();
    private ChatPreferences _preferences = new();

    public MainWindow()
    {
        InitializeComponent();
        _preferences = _preferencesStore.Load();
        _preferences.Nickname = NormalizeNickname(_preferences.Nickname) ?? "Windows";
        _preferences.ActiveRoom = NormalizeRoom(_preferences.ActiveRoom) ?? "bluetooth";
        UpdateRoomTitle();
        try
        {
            _identity = _identityStore.LoadOrCreate();
            _noiseSessions = new NoiseSessionRegistry(_identity);
            DiagnosticLog.Write($"Protected identity ready: {Convert.ToHexString(_identity.PeerId)}");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write($"Identity unavailable: {ex.Message}");
        }
        try
        {
            _nostrTransport = new NostrGeoTransport(_nostrIdentityStore.LoadOrCreate());
            _nostrTransport.StatusChanged += status => DiagnosticLog.Write(status);
            _nostrTransport.MessageReceived += message => Dispatcher.Invoke(() =>
            {
                if (_geohashChannel?.Equals(message.Geohash, StringComparison.OrdinalIgnoreCase) == true)
                    AddRoomMessage("geo-" + message.Geohash, $"[geo] {message.Nickname}  ·  {message.Content}");
            });
        }
        catch (Exception ex) { DiagnosticLog.Write($"Nostr identity unavailable: {ex.Message}"); }
        MessagesList.ItemsSource = _messages;
        _scanner.PeerDiscovered += peer => DiagnosticLog.Write($"BLE advertisement discovered: {peer}");
        _scanner.StatusChanged += status => DiagnosticLog.Write($"BLE scan: {status}");
        _meshHost.FrameReceived += frame => Dispatcher.Invoke(() => HandleIncomingFrame(frame));
        _meshHost.CentralSubscribed += () => Dispatcher.Invoke(() => _ = SendAnnounceAsync());
        _scanner.BitchatDeviceDiscovered += device =>
        {
            DiagnosticLog.Write($"BitChat device discovered: {device.DisplayName}");
            _ = ConnectMeshPeerAsync(device);
        };
        _meshClient.StatusChanged += status => DiagnosticLog.Write($"BLE client: {status}");
        _meshClient.FrameReceived += frame => Dispatcher.Invoke(() => HandleIncomingFrame(frame));
        _relayProbe.StatusChanged += status => DiagnosticLog.Write($"Nostr relay: {status}");
        Loaded += async (_, _) => { await _meshHost.StartAsync(); await _scanner.StartAsync(); await SendAnnounceAsync(); };
        Closing += (_, _) => { _scanner.Dispose(); _meshHost.Dispose(); _meshClient.Dispose(); _relayProbe.Dispose(); _nostrTransport?.Dispose(); };
    }

    private async void Send_Click(object sender, RoutedEventArgs e) => await AddLocalMessageAsync();
    private async void MessageInput_KeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.Control) { e.Handled = true; await AddLocalMessageAsync(); } }
    private async Task AddLocalMessageAsync()
    {
        var text = MessageInput.Text.Trim();
        if (text.Length == 0) return;
        MessageInput.Clear();
        if (text.StartsWith('/'))
        {
            await ExecuteCommandAsync(text);
            return;
        }
        if (_identity is null) { DiagnosticLog.Write("Message not sent: protected identity unavailable"); return; }
        var wireText = FormatRoomMessage(_preferences.ActiveRoom, text);
        var packet = new BitchatPacket(BitchatMessageType.Message, _identity.PeerId, null, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), System.Text.Encoding.UTF8.GetBytes(wireText), null, 7);
        var signed = _identity.PacketSigner.Sign(packet);
        if (signed is null || !await BroadcastPacketAsync(signed)) { DiagnosticLog.Write("Message not sent: no BitChat BLE link available"); return; }
        _gossipSync.Store(signed);
        AddRoomMessage(_preferences.ActiveRoom, $"You  ·  {text}");
    }

    private async Task SendAnnounceAsync()
    {
        if (_identity is null) return;
        var payload = new AnnouncementPacket(_preferences.Nickname, _identity.X25519PublicKey, _identity.Ed25519PublicKey).Encode();
        if (payload is null) return;
        var packet = new BitchatPacket(BitchatMessageType.Announce, _identity.PeerId, null, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), payload, null, 7);
        var signed = _identity.PacketSigner.Sign(packet);
        if (signed is not null && await BroadcastPacketAsync(signed))
        {
            _gossipSync.Store(signed);
            DiagnosticLog.Write("Signed announce sent");
        }
    }

    private async Task<bool> BroadcastPacketAsync(BitchatPacket packet)
    {
        var frames = (BinaryProtocol.Encode(packet)?.Length ?? 0) > 469 ? FragmentAssembler.Fragment(packet) : [packet];
        var delivered = false;
        foreach (var framePacket in frames)
        {
            var frame = BinaryProtocol.Encode(framePacket, padding: false);
            if (frame is null) return false;
            delivered |= await _meshHost.NotifyAsync(frame);
            delivered |= await _meshClient.SendFrameAsync(frame);
        }
        return delivered;
    }

    private async Task ConnectMeshPeerAsync(NearbyBleDevice device)
    {
        if (_meshClient.IsConnected) return;
        lock (_meshConnectionGate)
        {
            if (!_meshConnectionAttempts.Add(device.Address)) return;
        }
        try
        {
            var connection = _meshClient.ConnectAsync(device.Address, device.AddressType);
            if (await Task.WhenAny(connection, Task.Delay(TimeSpan.FromSeconds(15))) != connection)
            {
                DiagnosticLog.Write($"BLE client connection timed out for {device.Address:X12}");
                await _meshClient.DisconnectAsync();
                lock (_meshConnectionGate) _meshConnectionAttempts.Remove(device.Address);
                return;
            }
            await connection;
            if (_meshClient.IsConnected) await SendAnnounceAsync();
            else lock (_meshConnectionGate) _meshConnectionAttempts.Remove(device.Address);
        }
        catch (Exception ex)
        {
            DiagnosticLog.Write($"BLE client connection failed for {device.Address:X12}: {ex.Message}");
            lock (_meshConnectionGate) _meshConnectionAttempts.Remove(device.Address);
        }
    }

    private async Task RelayBroadcastPacketAsync(BitchatPacket packet)
    {
        if (packet.Ttl <= 1) return;
        if (packet.RecipientId is not null && packet.Type is not (BitchatMessageType.Ping or BitchatMessageType.Pong)) return;
        if (packet.RecipientId is null && packet.Type is not (BitchatMessageType.Announce or BitchatMessageType.Message or BitchatMessageType.Fragment)) return;
        await BroadcastPacketAsync(packet with { Ttl = (byte)(packet.Ttl - 1) });
    }

    private async Task StartNoiseHandshakeAsync(byte[] peerId)
    {
        if (_identity is null || _noiseSessions is null) return;
        try
        {
            var payload = _noiseSessions.Start(peerId);
            var packet = new BitchatPacket(BitchatMessageType.NoiseHandshake, _identity.PeerId, peerId, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), payload, null, 7);
            if (await BroadcastPacketAsync(packet)) DiagnosticLog.Write("Noise handshake initiated");
        }
        catch (CryptographicException) { DiagnosticLog.Write("Noise handshake initiation failed"); }
    }

    private void HandleIncomingFrame(byte[] frame)
    {
        if (!_deduplicator.TryMark(frame)) return;
        if (!BinaryProtocol.TryDecode(frame, out var packet) || packet is null)
        {
            DiagnosticLog.Write($"Ignored invalid BLE frame: {frame.Length} bytes");
            return;
        }
        DiagnosticLog.Write($"BLE packet received: type 0x{packet.Type:X2}, {packet.Payload.Length} bytes");
        if (packet.Type != BitchatMessageType.Fragment)
        {
            var accepted = HandlePacket(packet);
            if (accepted || ShouldRelayDirectedPacket(packet)) _ = RelayBroadcastPacketAsync(packet);
            return;
        }
        _ = RelayBroadcastPacketAsync(packet);
        if (!_fragmentAssembler.TryAppend(packet, out var assembled))
        {
            DiagnosticLog.Write("Dropped invalid mesh fragment");
            return;
        }
        if (assembled is null) return;
        if (BinaryProtocol.TryDecode(assembled, out var reassembled) && reassembled is not null)
            HandlePacket(reassembled);
        else DiagnosticLog.Write("Dropped invalid reassembled mesh packet");
    }

    private bool HandlePacket(BitchatPacket packet)
    {
        if (packet.Type == BitchatMessageType.Announce && AnnouncementPacket.TryDecode(packet.Payload, out var announce) && announce is not null)
        {
            var verified = Ed25519PacketSigner.Verify(packet, announce.SigningPublicKey);
            var peer = _peerRegistry.Upsert(packet.SenderId, announce, verified);
            DiagnosticLog.Write($"Peer announce: {peer.Nickname}, verified={peer.IsVerified}");
            if (IsBlocked(peer))
            {
                DiagnosticLog.Write($"Blocked peer announce suppressed: {peer.Id}");
                return verified;
            }
            if (verified) _gossipSync.Store(packet);
            // Let the mobile client initiate XX after discovery. Simultaneous
            // initiations can replace each other's pending session before m3.
            return verified;
        }
        if (packet.Type == BitchatMessageType.Message)
        {
            if (!_peerRegistry.TryGet(packet.SenderId, out var peer) || peer is null || !peer.IsVerified || !Ed25519PacketSigner.Verify(packet, peer.SigningPublicKey))
            {
                DiagnosticLog.Write("Dropped unauthenticated public message");
                return false;
            }
            if (IsBlocked(peer))
            {
                DiagnosticLog.Write($"Blocked public message suppressed: {peer.Id}");
                return true;
            }
            var content = System.Text.Encoding.UTF8.GetString(packet.Payload);
            var (room, message) = ParseRoomMessage(content);
            AddRoomMessage(room, $"{peer.Nickname}  ·  {message}");
            _gossipSync.Store(packet);
            return true;
        }
        if (packet.Type == BitchatMessageType.RequestSync)
        {
            _ = RespondToSyncRequestAsync(packet);
            return false;
        }
        if (packet.Type == BitchatMessageType.Ping)
        {
            if (packet.RecipientId is null || _identity is null || !packet.RecipientId.SequenceEqual(_identity.PeerId) || packet.Payload.Length < 9 || !AllowInboundPing()) return false;
            _ = SendPongAsync(packet.SenderId, packet.Payload);
            DiagnosticLog.Write($"Ping received from {Convert.ToHexString(packet.SenderId)}");
            return false;
        }
        if (packet.Type == BitchatMessageType.Pong)
        {
            if (packet.RecipientId is null || _identity is null || !packet.RecipientId.SequenceEqual(_identity.PeerId) || packet.Payload.Length < 9) return false;
            var nonce = Convert.ToHexString(packet.Payload.AsSpan(0, 8));
            if (_pendingPings.TryRemove(nonce, out var request) && packet.SenderId.SequenceEqual(request.PeerId))
            {
                var hops = packet.Payload[8] >= packet.Ttl ? packet.Payload[8] - packet.Ttl + 1 : 0;
                AddSystemMessage($"ping {request.Nickname}: {(DateTimeOffset.UtcNow - request.Started).TotalMilliseconds:0} ms" + (hops > 0 ? $" · {hops} hop(s)" : string.Empty));
            }
            return false;
        }
        if (packet.Type == BitchatMessageType.NoiseHandshake)
        {
            if (_identity is null || _noiseSessions is null || packet.RecipientId is null || !packet.RecipientId.SequenceEqual(_identity.PeerId) || !_peerRegistry.TryGet(packet.SenderId, out var peer) || peer is null || !peer.IsVerified)
                return false;
            try
            {
                var response = _noiseSessions.ReceiveHandshake(packet.SenderId, packet.Payload);
                if (response is not null)
                {
                    var reply = new BitchatPacket(BitchatMessageType.NoiseHandshake, _identity.PeerId, packet.SenderId, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), response, null, 7);
                    _ = SendHandshakeReplyAndFlushAsync(reply, packet.SenderId);
                }
                else if (_noiseSessions.HasSession(packet.SenderId)) _ = FlushPendingPrivateMessagesAsync(packet.SenderId);
                DiagnosticLog.Write("Noise handshake packet processed");
                return false;
            }
            catch (Exception ex) { DiagnosticLog.Write($"Dropped invalid Noise handshake: {ex.Message}"); return false; }
        }
        if (packet.Type == BitchatMessageType.NoiseEncrypted)
        {
            if (_identity is null || _noiseSessions is null || packet.RecipientId is null || !packet.RecipientId.SequenceEqual(_identity.PeerId) || !_peerRegistry.TryGet(packet.SenderId, out var peer) || peer is null || !_noiseSessions.TryDecrypt(packet.SenderId, packet.Payload, out var plaintext) || plaintext is not { Length: > 1 }) return false;
            if (IsBlocked(peer)) { DiagnosticLog.Write($"Blocked private message suppressed: {peer.Id}"); return false; }
            if (plaintext[0] == 0x01 && PrivateMessagePayload.TryDecode(plaintext.AsSpan(1), out var message) && message is not null)
            {
                AddRoomMessage(_preferences.ActiveRoom, $"[private] {peer.Nickname}  ·  {message.Content}");
                _ = SendSecureAckAsync(peer, message.MessageId, 0x03);
            }
            else if (plaintext[0] is 0x20 or 0x09 && PrivateFilePayload.TryDecode(plaintext.AsSpan(1), out var file) && file is not null)
                SaveIncomingPrivateFile(peer, file);
            else if (plaintext[0] is 0x02 or 0x03 && TryReadAckId(plaintext.AsSpan(1), out var acknowledgedId))
            {
                if (_sentPrivateMessageIds.Remove(acknowledgedId))
                    AddSystemMessage(plaintext[0] == 0x03 ? "private message delivered" : "private message read");
                DiagnosticLog.Write($"Private acknowledgement received from {peer.Id}: type 0x{plaintext[0]:X2}");
            }
            else DiagnosticLog.Write($"Dropped invalid encrypted payload: type 0x{plaintext[0]:X2}");
            return false;
        }
        DiagnosticLog.Write($"Mesh packet: type 0x{packet.Type:X2}, {packet.Payload.Length} bytes");
        return false;
    }

    private async Task RespondToSyncRequestAsync(BitchatPacket request)
    {
        var packets = _gossipSync.GetMissing(request);
        if (packets is null) { DiagnosticLog.Write("Ignored invalid REQUEST_SYNC payload"); return; }
        if (packets.Count == 0) { DiagnosticLog.Write("REQUEST_SYNC has no missing public packets"); return; }
        DiagnosticLog.Write($"REQUEST_SYNC sending {packets.Count} public packet(s)");
        foreach (var packet in packets) await BroadcastPacketAsync(packet);
    }

    private async Task SendPongAsync(byte[] recipientId, byte[] payload)
    {
        if (_identity is null) return;
        var packet = new BitchatPacket(BitchatMessageType.Pong, _identity.PeerId, recipientId, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), payload, null, 7);
        await BroadcastPacketAsync(packet);
    }

    private async Task SendPingAsync(string target)
    {
        if (_identity is null) { AddSystemMessage("identity unavailable"); return; }
        if (!_peerRegistry.TryFind(target, out var peer) || peer is null) { AddSystemMessage($"'{target}' is not a known peer"); return; }
        if (IsBlocked(peer)) { AddSystemMessage($"{peer.Nickname} is blocked"); return; }
        var nonceBytes = RandomNumberGenerator.GetBytes(8);
        var payload = new byte[9];
        nonceBytes.CopyTo(payload, 0);
        payload[8] = 7;
        var nonce = Convert.ToHexString(nonceBytes);
        _pendingPings[nonce] = new PingRequest(DateTimeOffset.UtcNow, Convert.FromHexString(peer.Id), peer.Nickname);
        var packet = new BitchatPacket(BitchatMessageType.Ping, _identity.PeerId, Convert.FromHexString(peer.Id), (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), payload, null, 7);
        if (!await BroadcastPacketAsync(packet))
        {
            _pendingPings.TryRemove(nonce, out _);
            AddSystemMessage("ping not sent: no BitChat BLE link available");
        }
    }

    private async Task SendPrivateMessageAsync(string arguments)
    {
        if (_identity is null || _noiseSessions is null) { AddSystemMessage("identity unavailable"); return; }
        var parts = arguments.Split(' ', 2, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) { AddSystemMessage("usage: /msg <nickname|peer-id> <message>"); return; }
        if (!_peerRegistry.TryFind(parts[0], out var peer) || peer is null) { AddSystemMessage($"'{parts[0]}' is not a known peer"); return; }
        if (IsBlocked(peer)) { AddSystemMessage($"{peer.Nickname} is blocked"); return; }

        var messageId = Guid.NewGuid().ToString();
        var body = new PrivateMessagePayload(messageId, parts[1]).Encode();
        if (body is null) { AddSystemMessage("private message is limited to 255 UTF-8 bytes"); return; }
        var peerId = Convert.FromHexString(peer.Id);
        var plaintext = new byte[1 + body.Length];
        plaintext[0] = 0x01; // private-message discriminator used by BitChat Noise transport
        body.CopyTo(plaintext, 1);
        _sentPrivateMessageIds.Add(messageId);
        await SendOrQueueSecurePayloadAsync(peer, plaintext, $"[private → {peer.Nickname}]  ·  {parts[1]}");
    }

    private async Task SendPrivateFileAsync(string arguments)
    {
        var parts = arguments.Split(' ', 2, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) { AddSystemMessage("usage: /file <nickname|peer-id> <file path>"); return; }
        if (!_peerRegistry.TryFind(parts[0], out var peer) || peer is null) { AddSystemMessage($"'{parts[0]}' is not a known peer"); return; }
        if (IsBlocked(peer)) { AddSystemMessage($"{peer.Nickname} is blocked"); return; }
        try
        {
            var path = parts[1].Trim().Trim('"');
            var info = new FileInfo(path);
            if (!info.Exists) { AddSystemMessage("file not found"); return; }
            if (info.Length is <= 0 or > PrivateFilePayload.MaxContentBytes) { AddSystemMessage("file must be between 1 byte and 1 MiB"); return; }
            var content = await File.ReadAllBytesAsync(info.FullName);
            var body = new PrivateFilePayload(info.Name, (ulong)content.Length, MimeFor(info.Extension), content).Encode();
            if (body is null) { AddSystemMessage("file cannot be encoded for BitChat transfer"); return; }
            var plaintext = new byte[1 + body.Length]; plaintext[0] = 0x20; body.CopyTo(plaintext, 1);
            await SendOrQueueSecurePayloadAsync(peer, plaintext, $"[private file → {peer.Nickname}]  ·  {info.Name} ({content.Length:N0} bytes)");
        }
        catch (Exception ex) { DiagnosticLog.Write($"Private file preparation failed: {ex.Message}"); AddSystemMessage("file could not be read"); }
    }

    private async Task SendOrQueueSecurePayloadAsync(MeshPeer peer, byte[] plaintext, string displayLine)
    {
        if (_identity is null || _noiseSessions is null) { AddSystemMessage("identity unavailable"); return; }
        var peerId = Convert.FromHexString(peer.Id);
        if (!_noiseSessions.TryEncrypt(peerId, plaintext, out var ciphertext) || ciphertext is null)
        {
            var key = Convert.ToHexString(peerId);
            if (!_pendingPrivateMessages.TryGetValue(key, out var queue)) _pendingPrivateMessages[key] = queue = [];
            if (queue.Count >= 20) { AddSystemMessage($"private message queue for {peer.Nickname} is full"); return; }
            queue.Enqueue(new PendingSecurePayload(plaintext, displayLine));
            if (queue.Count == 1) await StartNoiseHandshakeAsync(peerId);
            AddSystemMessage($"secure session with {peer.Nickname} is starting; item queued");
            return;
        }
        var packet = new BitchatPacket(BitchatMessageType.NoiseEncrypted, _identity.PeerId, peerId, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), ciphertext, null, 7,
            ciphertext.Length > ushort.MaxValue ? (byte)2 : (byte)1);
        if (!await BroadcastPacketAsync(packet)) { AddSystemMessage("private message not sent: no BitChat BLE link available"); return; }
        AddRoomMessage(_preferences.ActiveRoom, displayLine);
    }

    private async Task SendSecureAckAsync(MeshPeer peer, string messageId, byte kind)
    {
        if (_identity is null || _noiseSessions is null) return;
        var peerId = Convert.FromHexString(peer.Id);
        var messageIdBytes = System.Text.Encoding.UTF8.GetBytes(messageId);
        if (messageIdBytes.Length is 0 or > 255 || !_noiseSessions.TryEncrypt(peerId, [kind, .. messageIdBytes], out var ciphertext) || ciphertext is null) return;
        var packet = new BitchatPacket(BitchatMessageType.NoiseEncrypted, _identity.PeerId, peerId, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), ciphertext, null, 7);
        if (!await BroadcastPacketAsync(packet)) DiagnosticLog.Write($"Private acknowledgement was not sent to {peer.Id}");
    }

    private async Task SendHandshakeReplyAndFlushAsync(BitchatPacket reply, byte[] peerId)
    {
        await BroadcastPacketAsync(reply);
        if (_noiseSessions?.HasSession(peerId) == true) await FlushPendingPrivateMessagesAsync(peerId);
    }

    private async Task FlushPendingPrivateMessagesAsync(byte[] peerId)
    {
        var key = Convert.ToHexString(peerId);
        if (!_pendingPrivateMessages.Remove(key, out var queued) || !_peerRegistry.TryGet(peerId, out var peer) || peer is null) return;
        while (queued.TryDequeue(out var item)) await SendOrQueueSecurePayloadAsync(peer, item.Plaintext, item.DisplayLine);
    }

    private bool ShouldRelayDirectedPacket(BitchatPacket packet) =>
        packet.RecipientId is not null && packet.Ttl > 1 &&
        packet.Type is BitchatMessageType.Ping or BitchatMessageType.Pong &&
        (_identity is null || !packet.RecipientId.SequenceEqual(_identity.PeerId));

    private bool AllowInboundPing()
    {
        lock (_recentInboundPings)
        {
            var cutoff = DateTimeOffset.UtcNow.AddSeconds(-10);
            while (_recentInboundPings.TryPeek(out var timestamp) && timestamp < cutoff) _recentInboundPings.Dequeue();
            if (_recentInboundPings.Count >= 5) return false;
            _recentInboundPings.Enqueue(DateTimeOffset.UtcNow);
            return true;
        }
    }

    private async Task ExecuteCommandAsync(string input)
    {
        var parts = input[1..].Split(' ', 2, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var command = parts.Length > 0 ? parts[0].ToLowerInvariant() : string.Empty;
        var argument = parts.Length > 1 ? parts[1] : string.Empty;
        switch (command)
        {
            case "id":
                var nickname = NormalizeNickname(argument);
                if (nickname is null) { AddSystemMessage("usage: /id <1–32 character name>"); break; }
                _preferences.Nickname = nickname;
                _preferencesStore.Save(_preferences);
                AddSystemMessage($"display ID changed to {nickname}");
                await SendAnnounceAsync();
                break;
            case "room":
            case "join":
                var room = NormalizeRoom(argument);
                if (room is null) { AddSystemMessage("usage: /room <name>"); break; }
                SwitchRoom(room);
                break;
            case "leave":
                SwitchRoom("bluetooth");
                break;
            case "rooms":
            case "channels":
                var rooms = _roomHistory.Keys.Append(_preferences.ActiveRoom).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(item => item);
                AddSystemMessage($"rooms: {string.Join(", ", rooms.Select(item => "#" + item))}");
                break;
            case "block":
                Block(argument);
                break;
            case "unblock":
                Unblock(argument);
                break;
            case "blocks":
                AddSystemMessage(_preferences.BlockedFingerprints.Count + _preferences.BlockedRoutingIds.Count == 0
                    ? "no blocked users"
                    : $"blocked users: {_preferences.BlockedFingerprints.Count + _preferences.BlockedRoutingIds.Count}");
                break;
            case "who":
            case "w":
                var peers = _peerRegistry.Snapshot().Where(peer => peer.IsVerified && !IsBlocked(peer)).Select(peer => peer.Nickname).OrderBy(name => name).ToArray();
                AddSystemMessage(peers.Length == 0 ? "no verified peers are online" : $"online: {string.Join(", ", peers)}");
                break;
            case "ping":
                if (string.IsNullOrWhiteSpace(argument)) AddSystemMessage("usage: /ping <nickname|peer-id>");
                else await SendPingAsync(argument);
                break;
            case "msg":
            case "m":
                await SendPrivateMessageAsync(argument);
                break;
            case "file":
                await SendPrivateFileAsync(argument);
                break;
            case "geo":
                await SetGeohashChannelAsync(argument);
                break;
            case "geosay":
                await SendGeohashMessageAsync(argument);
                break;
            case "geopub":
                AddSystemMessage(_nostrTransport is null ? "Nostr identity unavailable" : $"Nostr public key: {_nostrTransport.PublicKey}");
                break;
            case "help":
                AddSystemMessage("commands: /id <name>, /room <name> (or /join), /rooms, /leave, /who, /msg <name> <message>, /file <name> <path>, /ping <name>, /geo <geohash|off>, /geosay <message>, /geopub, /block <name|peer-id>, /unblock <name|peer-id>, /blocks");
                break;
            default:
                AddSystemMessage($"unknown command: /{command} — type /help");
                break;
        }
    }

    private void Block(string argument)
    {
        if (string.IsNullOrWhiteSpace(argument)) { AddSystemMessage("usage: /block <nickname|peer-id>"); return; }
        if (_peerRegistry.TryFind(argument, out var peer) && peer is not null)
        {
            _preferences.BlockedFingerprints.Add(PeerRegistry.Fingerprint(peer));
            _preferences.BlockedRoutingIds.Add(peer.Id);
            _preferencesStore.Save(_preferences);
            AddSystemMessage($"blocked {peer.Nickname}; their messages are hidden");
            return;
        }
        var routingId = argument.Trim().TrimStart('@');
        if (routingId.Length == 16 && routingId.All(Uri.IsHexDigit))
        {
            _preferences.BlockedRoutingIds.Add(routingId);
            _preferencesStore.Save(_preferences);
            AddSystemMessage($"blocked peer {routingId.ToUpperInvariant()}");
            return;
        }
        AddSystemMessage($"'{argument}' is not a known peer; use its 16-digit peer ID");
    }

    private async Task SetGeohashChannelAsync(string value)
    {
        if (_nostrTransport is null) { AddSystemMessage("Nostr identity unavailable"); return; }
        if (value.Trim().Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            _geohashChannel = null;
            if (_nostrTransport.IsConnected) await _nostrTransport.DisconnectAsync();
            AddSystemMessage("left Nostr geohash channel");
            return;
        }
        var geohash = value.Trim().ToLowerInvariant();
        try
        {
            if (!_nostrTransport.IsConnected) await _nostrTransport.ConnectAsync();
            await _nostrTransport.SubscribeAsync(geohash);
            _geohashChannel = geohash;
            SwitchRoom("geo-" + geohash);
            AddSystemMessage($"joined Nostr geohash {geohash}");
        }
        catch (Exception ex) { DiagnosticLog.Write($"Nostr geohash join failed: {ex.Message}"); AddSystemMessage("could not join Nostr geohash channel"); }
    }

    private async Task SendGeohashMessageAsync(string content)
    {
        if (_nostrTransport is null || string.IsNullOrWhiteSpace(_geohashChannel)) { AddSystemMessage("join a geohash first: /geo <geohash>"); return; }
        try
        {
            await _nostrTransport.PublishAsync(_geohashChannel, _preferences.Nickname, content.Trim());
            AddRoomMessage("geo-" + _geohashChannel, $"[geo] You  ·  {content.Trim()}");
        }
        catch (Exception ex) { DiagnosticLog.Write($"Nostr geohash publish failed: {ex.Message}"); AddSystemMessage("Nostr geohash message was not sent"); }
    }

    private void Unblock(string argument)
    {
        if (string.IsNullOrWhiteSpace(argument)) { AddSystemMessage("usage: /unblock <nickname|peer-id>"); return; }
        var removed = false;
        if (_peerRegistry.TryFind(argument, out var peer) && peer is not null)
        {
            removed |= _preferences.BlockedFingerprints.Remove(PeerRegistry.Fingerprint(peer));
            removed |= _preferences.BlockedRoutingIds.Remove(peer.Id);
        }
        var routingId = argument.Trim().TrimStart('@');
        if (routingId.Length == 16 && routingId.All(Uri.IsHexDigit)) removed |= _preferences.BlockedRoutingIds.Remove(routingId);
        if (removed) { _preferencesStore.Save(_preferences); AddSystemMessage($"unblocked {argument.Trim().TrimStart('@')}"); }
        else AddSystemMessage($"'{argument}' is not blocked or is not a known peer");
    }

    private bool IsBlocked(MeshPeer peer) => _preferences.BlockedRoutingIds.Contains(peer.Id) || _preferences.BlockedFingerprints.Contains(PeerRegistry.Fingerprint(peer));

    private void SwitchRoom(string room)
    {
        _preferences.ActiveRoom = room;
        _preferencesStore.Save(_preferences);
        UpdateRoomTitle();
        _messages.Clear();
        if (_roomHistory.TryGetValue(room, out var history)) foreach (var line in history) _messages.Add(line);
        AddSystemMessage($"joined #{room}");
    }

    private void UpdateRoomTitle() => RoomTitle.Text = "# " + _preferences.ActiveRoom;

    private void AddRoomMessage(string room, string line)
    {
        if (!_roomHistory.TryGetValue(room, out var history)) _roomHistory[room] = history = [];
        history.Add(line);
        if (history.Count > 500) history.RemoveRange(0, history.Count - 500);
        if (!room.Equals(_preferences.ActiveRoom, StringComparison.OrdinalIgnoreCase)) return;
        _messages.Add(line);
        MessagesList.ScrollIntoView(line);
    }

    private void AddSystemMessage(string text) => AddRoomMessage(_preferences.ActiveRoom, $"System  ·  {text}");

    private static string FormatRoomMessage(string room, string text) => room.Equals("bluetooth", StringComparison.OrdinalIgnoreCase) ? text : $"[#{room}] {text}";
    private static (string Room, string Message) ParseRoomMessage(string text)
    {
        if (text.StartsWith("[#", StringComparison.Ordinal) && text.IndexOf("] ", StringComparison.Ordinal) is var marker && marker is > 2)
        {
            var room = NormalizeRoom(text[2..marker]);
            if (room is not null) return (room, text[(marker + 2)..]);
        }
        return ("bluetooth", text);
    }
    private static string? NormalizeNickname(string value)
    {
        var name = value.Trim();
        return name.Length is > 0 and <= 32 && name.All(ch => !char.IsControl(ch)) ? name : null;
    }
    private static string? NormalizeRoom(string value)
    {
        var room = value.Trim().TrimStart('#');
        return room.Length is > 0 and <= 32 && room.All(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_') ? room.ToLowerInvariant() : null;
    }

    private void SaveIncomingPrivateFile(MeshPeer peer, PrivateFilePayload file)
    {
        try
        {
            var safeName = Path.GetFileName(string.IsNullOrWhiteSpace(file.FileName) ? "bitchat-file.bin" : file.FileName);
            if (string.IsNullOrWhiteSpace(safeName) || safeName is "." or "..") safeName = "bitchat-file.bin";
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "Bitchat");
            Directory.CreateDirectory(directory);
            var destination = Path.Combine(directory, safeName);
            if (File.Exists(destination)) destination = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(safeName)}-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}{Path.GetExtension(safeName)}");
            File.WriteAllBytes(destination, file.Content);
            AddRoomMessage(_preferences.ActiveRoom, $"[private file] {peer.Nickname}  ·  {Path.GetFileName(destination)} ({file.Content.Length:N0} bytes) saved to Downloads\\Bitchat");
            DiagnosticLog.Write($"Private file saved from {peer.Id}: {destination}");
        }
        catch (Exception ex) { DiagnosticLog.Write($"Incoming private file could not be saved: {ex.Message}"); }
    }

    private static string MimeFor(string extension) => extension.ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" => "image/jpeg", ".png" => "image/png", ".gif" => "image/gif", ".webp" => "image/webp",
        ".m4a" => "audio/mp4", ".mp3" => "audio/mpeg", ".wav" => "audio/wav", ".txt" => "text/plain",
        ".pdf" => "application/pdf", _ => "application/octet-stream"
    };

    private static bool TryReadAckId(ReadOnlySpan<byte> data, out string messageId)
    {
        messageId = string.Empty;
        if (data.Length is 0 or > 255) return false;
        messageId = System.Text.Encoding.UTF8.GetString(data);
        return Guid.TryParse(messageId, out _);
    }

    private sealed record PingRequest(DateTimeOffset Started, byte[] PeerId, string Nickname);
    private sealed record PendingSecurePayload(byte[] Plaintext, string DisplayLine);
}
