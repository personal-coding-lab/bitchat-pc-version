using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace BitchatWindows.Services;

/// <summary>
/// Central/client side only. It never advertises or hosts a GATT service.
/// It connects to a BitChat peripheral, subscribes to notifications, and
/// exchanges validated opaque frames with the protocol layer.
/// </summary>
public sealed class WindowsGattMeshClient : IDisposable
{
    private static readonly Guid CharacteristicUuid = Guid.Parse("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
    private BluetoothLEDevice? _device;
    private GattDeviceService? _service;
    private GattCharacteristic? _characteristic;
    private int _connectionGeneration;
    private bool _disposed;
    public ulong? ConnectedAddress { get; private set; }
    public bool IsConnected => _characteristic is not null;

    public event Action<string>? StatusChanged;
    public event Action<byte[]>? FrameReceived;

    public async Task ConnectAsync(ulong address, BluetoothAddressType addressType = BluetoothAddressType.Public)
    {
        ThrowIfDisposed();
        await DisconnectAsync();
        var generation = Volatile.Read(ref _connectionGeneration);
        BluetoothLEDevice? device = null;
        try
        {
            StatusChanged?.Invoke($"Connecting to {address:X12}…");
            device = await BluetoothLEDevice.FromBluetoothAddressAsync(address, addressType);
            if (device is null) { StatusChanged?.Invoke("Bluetooth device is no longer available."); return; }
            if (generation != Volatile.Read(ref _connectionGeneration)) return;
            var services = await device.GetGattServicesForUuidAsync(WindowsBleScanner.BitchatServiceUuid, BluetoothCacheMode.Uncached);
            if (services.Status != GattCommunicationStatus.Success || services.Services.Count == 0) { StatusChanged?.Invoke($"BitChat GATT service unavailable: {services.Status}"); return; }
            var service = services.Services[0];
            var characteristics = await service.GetCharacteristicsForUuidAsync(CharacteristicUuid, BluetoothCacheMode.Uncached);
            if (characteristics.Status != GattCommunicationStatus.Success || characteristics.Characteristics.Count == 0) { StatusChanged?.Invoke($"BitChat frame characteristic unavailable: {characteristics.Status}"); service.Dispose(); return; }
            var characteristic = characteristics.Characteristics[0];
            characteristic.ValueChanged += OnValueChanged;
            var configuration = (characteristic.CharacteristicProperties & GattCharacteristicProperties.Notify) != 0
                ? GattClientCharacteristicConfigurationDescriptorValue.Notify
                : GattClientCharacteristicConfigurationDescriptorValue.Indicate;
            var configured = await characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(configuration);
            if (configured != GattCommunicationStatus.Success && configuration == GattClientCharacteristicConfigurationDescriptorValue.Notify &&
                (characteristic.CharacteristicProperties & GattCharacteristicProperties.Indicate) != 0)
            {
                configuration = GattClientCharacteristicConfigurationDescriptorValue.Indicate;
                configured = await characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(configuration);
            }
            if (configured != GattCommunicationStatus.Success || generation != Volatile.Read(ref _connectionGeneration))
            {
                characteristic.ValueChanged -= OnValueChanged;
                service.Dispose();
                StatusChanged?.Invoke($"Notification subscription failed: {configured}");
                return;
            }
            _device = device; device = null;
            _service = service;
            _characteristic = characteristic;
            ConnectedAddress = address;
            StatusChanged?.Invoke($"Connected to {_device.Name ?? address.ToString("X12")} · {configuration.ToString().ToLowerInvariant()} enabled");
        }
        catch (Exception ex) { StatusChanged?.Invoke($"BLE connection failed: {ex.Message}"); }
        finally { device?.Dispose(); }
    }

    public async Task<bool> SendFrameAsync(byte[] frame)
    {
        if (_characteristic is null || frame.Length == 0) return false;
        var result = await _characteristic.WriteValueWithResultAsync(CryptographicBuffer.CreateFromByteArray(frame), GattWriteOption.WriteWithoutResponse);
        if (result.Status == GattCommunicationStatus.Success) return true;
        StatusChanged?.Invoke($"Frame write failed: {result.Status}");
        return false;
    }

    private void OnValueChanged(GattCharacteristic sender, GattValueChangedEventArgs args)
    {
        var reader = DataReader.FromBuffer(args.CharacteristicValue);
        var frame = new byte[reader.UnconsumedBufferLength];
        reader.ReadBytes(frame);
        FrameReceived?.Invoke(frame);
    }

    public Task DisconnectAsync()
    {
        Interlocked.Increment(ref _connectionGeneration);
        if (_characteristic is not null) _characteristic.ValueChanged -= OnValueChanged;
        _characteristic = null;
        _service?.Dispose();
        _service = null;
        _device?.Dispose();
        _device = null;
        ConnectedAddress = null;
        return Task.CompletedTask;
    }

    public void Dispose() { if (_disposed) return; DisconnectAsync().GetAwaiter().GetResult(); _disposed = true; }
    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}
