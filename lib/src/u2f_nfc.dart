import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'commands.dart';
import 'error.dart';
import 'log.dart';
import 'u2f_base.dart';

/// FIDO NFC Protocol Specification v1.0
/// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html

class U2fV2Nfc extends U2fV2 {
  const U2fV2Nfc._();

  static Future<U2fV2Nfc> poll({Duration? timeout}) async {
    final availability = await FlutterNfcKit.nfcAvailability;
    if (availability != NFCAvailability.available) {
      throw Exception('NFC not available on this device');
    }

    final tag = await FlutterNfcKit.poll(
      timeout: timeout,
      iosMultipleTagMessage: 'Multiple tags found!',
      iosAlertMessage: 'Scan your tag',
    );

    if (tag.type != NFCTagType.iso7816) {
      throw Exception('Not a U2F V2 tag');
    }

    const u2f = U2fV2Nfc._();

    try {
      await u2f.send(Uint8List.fromList(selectCommand));
    } on APDUError catch (e) {
      if (e.status == 0x6a82) {
        await u2f.send(Uint8List.fromList(selectCommandYubico));
      } else {
        rethrow;
      }
    }

    return u2f;
  }

  @override
  Future<Uint8List> send(Uint8List apdu) async {
    var cmd = apdu;
    var status = 0x6100;
    final data = BytesBuilder();

    while ((status & 0xff00) == 0x6100) {
      final resp = await FlutterNfcKit.transceive(cmd);
      log.finest(
          'REQ ${cmd.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
      log.finest(
          'RESP ${resp.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
      status = ((0xff & resp[resp.length - 2]) << 8) |
          (0xff & resp[resp.length - 1]);
      data.add(resp.sublist(0, resp.length - 2));
      cmd = Uint8List.fromList(getResponseCommand);
    }

    if (status != swNoError) {
      throw APDUError(status);
    }

    return data.toBytes();
  }

  @override
  Future<void> dispose() async {
    await FlutterNfcKit.finish();
    await super.dispose();
  }
}
