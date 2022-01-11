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
