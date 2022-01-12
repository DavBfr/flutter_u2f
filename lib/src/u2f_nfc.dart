import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'commands.dart';
import 'log.dart';
import 'u2f_base.dart';

export 'package:flutter_nfc_kit/flutter_nfc_kit.dart' show NFCAvailability;

/// FIDO NFC Protocol Specification v1.0
/// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html

class U2fV2Nfc extends U2fV2 {
  const U2fV2Nfc._();

  static Stream<U2fV2Nfc> poll({Duration timeout = U2fV2.timeout}) async* {
    final tag = await FlutterNfcKit.poll(
      timeout: timeout,
      iosMultipleTagMessage: 'Multiple tags found!',
      iosAlertMessage: 'Scan your tag',
    );

    if (tag.type != NFCTagType.iso7816) {
      log.warning('Not a U2F V2 tag');
      return;
    }

    const u2f = U2fV2Nfc._();

    final result = await u2f.send(Uint8List.fromList(selectCommand));
    final status = (result[result.length - 2] << 8) | result[result.length - 1];

    if (status == 0x6a82) {
      await u2f.send(Uint8List.fromList(selectCommandYubico));
    }

    yield u2f;
  }

  static Future<NFCAvailability> availability() async {
    try {
      return await FlutterNfcKit.nfcAvailability;
    } catch (e) {
      log.warning('U2fV2Nfc: $e');
      return NFCAvailability.not_supported;
    }
  }

  @override
  Future<Uint8List> send(Uint8List apdu) async {
    var cmd = apdu;
    var status = 0x6100;
    final data = BytesBuilder();

    while ((status & 0xff00) == 0x6100) {
      final resp = await FlutterNfcKit.transceive(cmd);
      status = ((0xff & resp[resp.length - 2]) << 8) |
          (0xff & resp[resp.length - 1]);
      data.add(resp.sublist(0, resp.length - 2));
      cmd = Uint8List.fromList(getResponseCommand);
    }

    // Add the last status
    data.add([(status >> 8) & 0xff, status & 0xff]);

    return data.toBytes();
  }

  @override
  Future<void> dispose() async {
    await FlutterNfcKit.finish();
    await super.dispose();
  }
}
