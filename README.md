# FIDO Universal 2nd Factor

This package supports NFC, USB and Webauthn Fido2 kays on iOS, Android, Windows, Linux, macOS, and Web.

## Getting Started

### Register

```dart
const u2f = U2fV2();
return await u2f.register(
  challenge: 'some random data',
  appId: 'example.com',
);
```

### Authenticate

```dart
const u2f = U2fV2();
return await u2f.authenticate(
  challenge: 'some random data',
  appId: 'example.com',
  keyHandles: [
    // ... a list of registered key handles
  ],
);
```

## Setup

Follow the [flutter_nfc_kit](https://pub.dev/packages/flutter_nfc_kit) package setup section.

On iOS, your new `Info.plist` lines should look like this:

```xml
<key>NFCReaderUsageDescription</key>
<string>Use NFC to authenticate with a security device</string>
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
  <string>A000000308</string>
  <string>A0000005272101</string>
  <string>A000000527471117</string>
  <string>A0000006472F0001</string>
</array>
```
