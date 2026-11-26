using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;

namespace BitchatWindows.Services;

/// <summary>
/// BitChat's BLE peripheral role for Windows. It advertises the same mainnet
/// service/characteristic UUIDs as the upstream client and carries opaque
/// frames; cryptographic validation belongs to Protocol/ and Noise/.
/// </summary>
public sealed class WindowsGattMeshHost : IDisposable
{
    private readonly Guid _serviceUuid = WindowsBleScanner.BitchatServiceUuid;
    private static readonly Guid CharacteristicUuid = Guid.Parse("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
    private GattServiceProvider? _provider;
    private GattLocalCharacteristic? _characteristic;
    private bool _disposed;
    public event Action<string>? StatusChanged;
    public event Action<byte[]>? FrameReceived;
    /// <summary>Raised after a central subscribes to the mesh frame characteristic.</summary>
    public event Action? CentralSubscribed;

    private void Report(string status)
    {
        DiagnosticLog.Write($"BLE host: {status}");
        StatusChanged?.Invoke(status);
    }

    public async Task StartAsync()
    {
        ThrowIfDisposed();
        if (_provider is not null) return;
        try
        {
            Report("Starting BitChat BLE advertising…");
            var adapter = await BluetoothAdapter.GetDefaultAsync();
            if (adapter is null) { Report("BLE advertising unavailable: no Bluetooth adapter."); return; }
            Report($"Bluetooth adapter: {adapter.DeviceId}; peripheral role supported: {adapter.IsPeripheralRoleSupported}");
            if (!adapter.IsPeripheralRoleSupported) { Report("BLE advertising unavailable: this adapter/driver has no peripheral role support."); return; }
            var serviceResult = await GattServiceProvider.CreateAsync(_serviceUuid);
            if (serviceResult.Error != BluetoothError.Success || serviceResult.ServiceProvider is null) { Report($"GATT service creation failed: {serviceResult.Error}"); return; }
            _provider = serviceResult.ServiceProvider;
            var parameters = new GattLocalCharacteristicParameters
            {
                // Android's BitChat GATT server exposes the same frame
                // characteristic as readable, writable (with/without
                // response), and notifiable. Keeping that shape avoids
                // client-side capability rejection during service discovery.
                CharacteristicProperties = GattCharacteristicProperties.Read | GattCharacteristicProperties.Write | GattCharacteristicProperties.WriteWithoutResponse | GattCharacteristicProperties.Notify,
                WriteProtectionLevel = GattProtectionLevel.Plain,
                ReadProtectionLevel = GattProtectionLevel.Plain,
                StaticValue = CryptographicBuffer.CreateFromByteArray([1]),
                UserDescription = "BitChat mesh frames"
            };
            var characteristicResult = await _provider.Service.CreateCharacteristicAsync(CharacteristicUuid, parameters);
            if (characteristicResult.Error != BluetoothError.Success || characteristicResult.Characteristic is null) { Report($"GATT characteristic creation failed: {characteristicResult.Error}"); Stop(); return; }
            _characteristic = characteristicResult.Characteristic;
            _characteristic.WriteRequested += OnWriteRequested;
            _characteristic.SubscribedClientsChanged += OnSubscribedClientsChanged;
            _provider.StartAdvertising(new GattServiceProviderAdvertisingParameters { IsConnectable = true, IsDiscoverable = true });
            Report("Advertising BitChat BLE service");
        }
        catch (Exception ex) { Report($"BLE advertising unavailable: {ex.Message}"); Stop(); }
    }

    public async Task<bool> NotifyAsync(byte[] frame)
    {
        var characteristic = _characteristic;
        if (characteristic is null || frame.Length == 0 || characteristic.SubscribedClients.Count == 0) return false;
        try
        {
            var result = await characteristic.NotifyValueAsync(CryptographicBuffer.CreateFromByteArray(frame));
            Report($"BLE notification: {string.Join(", ", result.Select(item => item.Status))}; {frame.Length} bytes");
            return result.Count > 0 && result.Any(item => item.Status == GattCommunicationStatus.Success);
        }
        catch (Exception ex)
        {
            Report($"BLE notification failed: {ex.Message}; {frame.Length} bytes");
            return false;
        }
    }

    private async void OnWriteRequested(GattLocalCharacteristic sender, GattWriteRequestedEventArgs args)
    {
        var deferral = args.GetDeferral();
        try
        {
            var request = await args.GetRequestAsync();
            if (request?.Value is null) return;
            var reader = DataReader.FromBuffer(request.Value);
            var data = new byte[reader.UnconsumedBufferLength];
            reader.ReadBytes(data);
            FrameReceived?.Invoke(data);
        }
        catch (Exception ex) { Report($"BLE frame read failed: {ex.Message}"); }
        finally { deferral.Complete(); }
    }

    private void OnSubscribedClientsChanged(GattLocalCharacteristic sender, object args)
    {
        var count = sender.SubscribedClients.Count;
        Report($"BLE subscribers: {count}");
        if (count > 0) CentralSubscribed?.Invoke();
    }
    private void Stop()
    {
        if (_characteristic is not null) { _characteristic.WriteRequested -= OnWriteRequested; _characteristic.SubscribedClientsChanged -= OnSubscribedClientsChanged; }
        _provider?.StopAdvertising(); _characteristic = null; _provider = null;
    }
    public void Dispose() { if (_disposed) return; Stop(); _disposed = true; }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
