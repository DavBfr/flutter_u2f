# u2f

FIDO Universal 2nd Factor

This package supports NFC Fido2 kays on iOS and Android.

## Getting Started

### Register

```dart
final u2f = await U2fV2Nfc.poll();
try {
  return await u2f.register(
    challenge: 'some random data',
    appId: 'example.com',
  );
} finally {
  await u2f.dispose();
}
```

### Authenticate

```dart
final u2f = await U2fV2Nfc.poll();
try {
  return await u2f.authenticate(
    challenge: 'some random data',
    appId: 'example.com',
    keyHandles: [
      // ... a list of registered key handles
    ],
  );
} finally {
  await u2f.dispose();
}
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
