using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;

namespace BitchatWindows.Services;

/// <summary>
/// Windows BLE advertisement discovery. This intentionally performs discovery only:
/// BitChat mesh advertisements use an authenticated binary protocol that must be
/// implemented and verified before packets can be interpreted or relayed.
/// </summary>
public sealed class WindowsBleScanner : IDisposable
{
    public static readonly Guid BitchatServiceUuid = Guid.Parse("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    private BluetoothLEAdvertisementWatcher? _watcher;
    private bool _disposed;
    private readonly HashSet<ulong> _probedAddresses = [];
    private readonly Dictionary<ulong, DateTimeOffset> _publishedAddresses = [];
    private readonly object _probeGate = new();

    public event Action<string>? PeerDiscovered;
    public event Action<NearbyBleDevice>? BitchatDeviceDiscovered;
    public event Action<string>? StatusChanged;

    public Task StartAsync(bool restart = false)
    {
        ThrowIfDisposed();
        if (restart) Stop();
        if (_watcher is not null && _watcher.Status == BluetoothLEAdvertisementWatcherStatus.Started) return Task.CompletedTask;

        try
        {
            // Do not apply the service UUID filter to the Windows watcher.
            // Several BLE stacks put service UUIDs in the scan response rather
            // than the initial advertisement, and Windows can discard those
            // before the app receives them. We discover first, then verify the
            // BitChat GATT service during ConnectAsync.
            _watcher = new BluetoothLEAdvertisementWatcher { ScanningMode = BluetoothLEScanningMode.Active };
            _watcher.Received += OnReceived;
            _watcher.Stopped += OnStopped;
            _watcher.Start();
            StatusChanged?.Invoke("Scanning for Bluetooth LE advertisements…");
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke($"Bluetooth unavailable: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    private void OnReceived(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
    {
        var isBitchat = args.Advertisement.ServiceUuids.Contains(BitchatServiceUuid);
        var device = new NearbyBleDevice(args.BluetoothAddress, args.BluetoothAddressType, args.Advertisement.LocalName, args.RawSignalStrengthInDBm, isBitchat);
        if (isBitchat) PublishConfirmedDevice(device);
        else _ = ProbeForBitchatServiceAsync(device);
    }

    private async Task ProbeForBitchatServiceAsync(NearbyBleDevice candidate)
    {
        lock (_probeGate)
        {
            if (!_probedAddresses.Add(candidate.Address)) return;
        }
        try
        {
            using var device = await BluetoothLEDevice.FromBluetoothAddressAsync(candidate.Address, candidate.AddressType);
            if (device is null) return;
            var result = await device.GetGattServicesForUuidAsync(BitchatServiceUuid, BluetoothCacheMode.Uncached);
            if (result.Status == GattCommunicationStatus.Success && result.Services.Count > 0)
                PublishConfirmedDevice(candidate with { AdvertisesBitchatService = true });
        }
        catch { /* A non-BitChat device or an unreachable BLE peripheral is not shown. */ }
    }

    private void PublishConfirmedDevice(NearbyBleDevice device)
    {
        lock (_probeGate)
        {
            var now = DateTimeOffset.UtcNow;
            if (_publishedAddresses.TryGetValue(device.Address, out var publishedAt) && now - publishedAt < TimeSpan.FromMinutes(2)) return;
            _publishedAddresses[device.Address] = now;
            foreach (var expired in _publishedAddresses.Where(item => now - item.Value > TimeSpan.FromMinutes(10)).Select(item => item.Key).ToArray()) _publishedAddresses.Remove(expired);
        }
        PeerDiscovered?.Invoke(device.DisplayName);
        BitchatDeviceDiscovered?.Invoke(device);
    }

    private void OnStopped(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementWatcherStoppedEventArgs args) =>
        StatusChanged?.Invoke($"Scan stopped: {args.Error}");

    private void Stop()
    {
        if (_watcher is null) return;
        _watcher.Received -= OnReceived;
        _watcher.Stopped -= OnStopped;
        _watcher.Stop();
        _watcher = null;
        lock (_probeGate) { _probedAddresses.Clear(); _publishedAddresses.Clear(); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed record NearbyBleDevice(ulong Address, BluetoothAddressType AddressType, string Name, short Rssi, bool AdvertisesBitchatService)
{
    public string DisplayName => string.IsNullOrWhiteSpace(Name)
        ? $"{(AdvertisesBitchatService ? "BitChat" : "BLE")} · {Address:X12} · {Rssi} dBm"
        : $"{Name} · {Address:X12} · {Rssi} dBm{(AdvertisesBitchatService ? " · BitChat service" : "")}";
}
