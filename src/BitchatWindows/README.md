# Bitchat for Windows — foundation build

An experimental native Windows GUI created from the public BitChat protocol source.

## Implemented

- WPF GUI, chat view, device list, local message composer
- Bluetooth Low Energy active advertisement discovery through Windows Runtime
- Nostr relay WebSocket connectivity probe
- Explicit separation between UI and transport services

## Deliberately disabled

This build **does not transmit chat content**. It does not yet implement BitChat's
authenticated BLE packet format, Noise sessions, multi-hop forwarding, Nostr event
signing/gift-wrap encryption, identity storage, or relay subscriptions. Therefore it
cannot safely interoperate with production BitChat clients yet.

## Build

```powershell
dotnet publish .\BitchatWindows.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\publish
```
