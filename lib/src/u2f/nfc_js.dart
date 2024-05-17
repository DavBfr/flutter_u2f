// ignore_for_file: constant_identifier_names

enum NFCAvailability {
  not_supported,
  disabled,
  available,
}

enum NFCTagType {
  iso7816,
  iso15693,
  iso18092,
  mifare_classic,
  mifare_ultralight,
  mifare_desfire,
  mifare_plus,
  webusb,
  unknown,
}

// ignore: avoid_classes_with_only_static_members
class FlutterNfcKit {
  static Future<NFCAvailability> get nfcAvailability async =>
      NFCAvailability.not_supported;

  static Future<void> finish({
    String? iosAlertMessage,
    String? iosErrorMessage,
    bool? closeWebUSB,
  }) {
    throw UnimplementedError();
  }

  static Future<T> transceive<T>(T capdu, {Duration? timeout}) {
    throw UnimplementedError();
  }

  static Future<NFCTag> poll({
    Duration? timeout,
    bool androidPlatformSound = true,
    bool androidCheckNDEF = true,
    String iosAlertMessage = 'Hold your iPhone near the card',
    String iosMultipleTagMessage =
        'More than one tags are detected, please leave only one tag and try again.',
    bool readIso14443A = true,
    bool readIso14443B = true,
    bool readIso18092 = false,
    bool readIso15693 = true,
    bool probeWebUSBMagic = false,
  }) {
    throw UnimplementedError();
  }
}

class NFCTag {
  NFCTagType type = NFCTagType.iso7816;
}
