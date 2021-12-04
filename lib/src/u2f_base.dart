import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

import 'commands.dart';
import 'log.dart';
import 'registration.dart';
import 'signature.dart';

/// FIDO U2F Raw Message Formats:
/// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html

abstract class U2fV2 {
  const U2fV2();

  static const _version = 'U2F_V2';

  @protected
  Future<Uint8List> send(Uint8List apdu);

  Future<String> version() async {
    final data = await send(Uint8List.fromList(getVersionCommand));
    return latin1.decode(data);
  }

  Future<U2fRegistration> register({
    required Uint8List challenge,
    required String appId,
    String? origin,
  }) async {
    if (await version() != _version) {
      throw Exception('Incompatible U2F version');
    }

    final appParam = sha256.convert(utf8.encode(appId)).bytes;

    final clientData = <String, String>{
      'typ': 'navigator.id.finishEnrollment',
      'challenge': base64Url.encode(challenge),
      'origin': origin ?? 'https://$appId',
    };
    final clientDataString = json.encode(clientData);
    final clientDataBytes = utf8.encode(clientDataString);
    final clientParam = sha256.convert(clientDataBytes).bytes;

    final apdu = Uint8List(5 + 32 + 32 + 1);
    apdu[1] = u2fRegister;
    apdu[4] = 64; // packet length
    apdu[69] = 0xff; // accept 256 byte response
    apdu.setAll(5, clientParam);
    apdu.setAll(5 + 32, appParam);
    final resp = await send(apdu);
    return U2fRegistration(
      registrationData: resp,
      clientData: Uint8List.fromList(clientDataBytes),
      appId: appId,
    );
  }

  Future<U2fSignature> authenticate({
    required String appId,
    required String keyHandle,
    required Uint8List challenge,
    String? origin,
  }) async {
    if (await version() != _version) {
      throw Exception('Incompatible U2F version');
    }

    final appParam = sha256.convert(utf8.encode(appId)).bytes;
    final keyHandleBytes = base64Url.decode(keyHandle);

    final clientData = <String, String>{
      'typ': 'navigator.id.getAssertion',
      'challenge': base64Url.encode(challenge),
      'origin': origin ?? 'https://$appId',
    };
    final clientDataString = json.encode(clientData);
    final clientDataBytes = utf8.encode(clientDataString);
    final clientParam = sha256.convert(clientDataBytes).bytes;

    final apdu = Uint8List(71 + keyHandleBytes.length);
    apdu[1] = u2fAuthenticate;
    apdu[2] = cbEnforceUserPresenceAndSign;
    apdu[4] = 65 + keyHandleBytes.length; // packet length
    apdu[apdu.length - 1] = 0xff; // accept 256 byte response
    apdu.setAll(5, clientParam);
    apdu.setAll(37, appParam);
    apdu[69] = keyHandleBytes.length;
    apdu.setAll(70, keyHandleBytes);
    final resp = await send(apdu);
    return U2fSignature(
      signatureData: resp,
      clientData: Uint8List.fromList(clientDataBytes),
      appId: appId,
    );
  }

  @mustCallSuper
  Future<void> dispose() async {
    log.fine('Finish U2F session');
  }
}
