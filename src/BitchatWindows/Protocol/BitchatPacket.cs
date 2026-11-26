namespace BitchatWindows.Protocol;

/// <summary>
/// Wire-level BitChat mesh frame. This is intentionally independent of the
/// Windows BLE transport so frames can be validated before they reach UI code.
/// </summary>
public sealed record BitchatPacket(
    byte Type,
    byte[] SenderId,
    byte[]? RecipientId,
    ulong Timestamp,
    byte[] Payload,
    byte[]? Signature,
    byte Ttl,
    byte Version = 1,
    IReadOnlyList<byte[]>? Route = null,
    bool IsRsr = false);

public static class BitchatMessageType
{
    public const byte Announce = 0x01;
    public const byte Message = 0x02;
    public const byte Leave = 0x03;
    public const byte CourierEnvelope = 0x04;
    public const byte NoiseHandshake = 0x10;
    public const byte NoiseEncrypted = 0x11;
    public const byte Fragment = 0x20;
    public const byte RequestSync = 0x21;
    public const byte FileTransfer = 0x22;
    public const byte BoardPost = 0x23;
    public const byte PrekeyBundle = 0x24;
    public const byte GroupMessage = 0x25;
    public const byte Ping = 0x26;
    public const byte Pong = 0x27;
    public const byte NostrCarrier = 0x28;
    public const byte VoiceFrame = 0x29;
    public const byte AnnounceV2 = 0x2c;
}
