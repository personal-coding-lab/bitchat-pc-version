# BitChat Windows

Windows GUI port of BitChat's Bluetooth mesh client. The repository root holds
the self-contained `BitchatWindows.exe` distribution and its required runtime
files. Download the complete repository/release contents rather than moving
only the `.exe` file.

The buildable source is in [`src/BitchatWindows`](src/BitchatWindows). It
implements the BitChat BLE GATT service, signed public messages, Noise XX
private messages, private-media packets, chat commands, blocking, rooms, ping,
and gossip sync.

## Build

```powershell
cd src\BitchatWindows
dotnet build -c Release
dotnet run --project ProtocolSmokeTests\ProtocolSmokeTests.csproj -c Release
dotnet publish -c Release -r win-x64 --self-contained true -o ..\..\publish
```

it will be released executive file(.exe). but still converting

The application keeps logs in `%LOCALAPPDATA%\BitchatWindows\diagnostics.log`.
Received private files are written to `%USERPROFILE%\Downloads\Bitchat`.
