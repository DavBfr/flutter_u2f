// ignore_for_file: require_trailing_commas

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';

import 'commands.dart';
import 'error.dart';
import 'log.dart';
import 'registration.dart';
import 'signature.dart';
import 'u2f_base.dart';

/// FIDO U2F Raw Message Formats:
/// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html

class _Fido2Response {
  const _Fido2Response(this.bytes, this.status);

  static const swNoError = 0x9000;
  static const swWrongData = 0x6A80;
  static const swConditionsNotSatisfied = 0x6985;
  // static const swCommandNotAllowed = 0x6986;
  // static const swInsNotSupported = 0x6D00;

  final Uint8List bytes;

  final int status;
}

typedef OnContinuePolling = bool Function();

abstract class U2fV2Fido2 extends U2fV2Base {
  U2fV2Fido2();

  static const _version = 'U2F_V2';
  static const delay = Duration(milliseconds: 400);
  static const timeout = Duration(seconds: 20);

  @protected
  Future<Uint8List> send(Uint8List apdu);

  @override
  @mustCallSuper
  Future<void> init() async {
    super.init();
    final v = await version();
    if (v != _version) {
      throw U2fException('Incompatible U2F version "$v"');
    }
  }

  Future<String> version() async {
    final data = await _sendFido2(u2fVersion, timeout: timeout);
    return latin1.decode(data.bytes);
  }

  Future<_Fido2Response> _sendFido2(
    int cmd, {
    int p1 = 0,
    int p2 = 0,
    List<int> data = const [],
    required Duration timeout,
  }) async {
    final apdu = Uint8List(7 + data.length);
    apdu[1] = cmd;
    apdu[2] = p1;
    apdu[3] = p2;
    apdu[4] = (data.length >> 16) & 0xff; // packet length MSB
    apdu[5] = (data.length >> 8) & 0xff; // packet length
    apdu[6] = data.length & 0xff; // packet length LSB
    apdu.setAll(7, data);
    log.finest(
        'SEND ${apdu.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    var resp = await send(apdu);
    var fr = _Fido2Response(resp.sublist(0, resp.lengthInBytes - 2),
        resp[resp.lengthInBytes - 2] << 8 | resp[resp.lengthInBytes - 1]);

    final stopWatch = Stopwatch()..start();
    try {
      while (fr.status == _Fido2Response.swConditionsNotSatisfied) {
        if (cancelOperations) {
          throw const U2fCancel('Cancel waiting for user presence');
        }
        // Requires user presence. Try again
        await Future.delayed(delay);
        if (stopWatch.elapsed > timeout) {
          throw const U2fTimeout('Timeout waiting for user presence');
        }
        resp = await send(apdu);
        fr = _Fido2Response(resp.sublist(0, resp.lengthInBytes - 2),
            resp[resp.lengthInBytes - 2] << 8 | resp[resp.lengthInBytes - 1]);
      }
    } finally {
      stopWatch.stop();
    }

    log.finest(
        'RECV (0x${fr.status.toRadixString(16).padLeft(4, '0')}) ${fr.bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join(':')}');
    return fr;
  }

  @override
  Future<U2fRegistration> register(
    String challenge,
    String appId,
    String origin,
    String name,
    String displayName,
    List<Uint8List> existingKeyHandles,
    Duration timeout,
  ) async {
    final appParam = sha256.convert(utf8.encode(appId)).bytes;

    final clientData = <String, String>{
      'typ': 'navigator.id.finishEnrollment',
      'challenge': challenge,
      'origin': origin,
    };
    final clientDataString = json.encode(clientData);
    final clientDataBytes = utf8.encode(clientDataString);
    final clientParam = sha256.convert(clientDataBytes).bytes;

    final resp = await _sendFido2(
      u2fRegister,
      data: clientParam + appParam,
      timeout: timeout,
    );
    return U2fRegistration(
      registrationData: resp.bytes,
      clientData: Uint8List.fromList(clientDataBytes),
      appId: appId,
    );
  }

  @override
  Future<U2fSignature> authenticate(
    String appId,
    List<Uint8List> keyHandles,
    String challenge,
    String origin,
    Duration timeout,
  ) async {
    final appParam = sha256.convert(utf8.encode(appId)).bytes;
    final clientData = <String, String>{
      'typ': 'navigator.id.getAssertion',
      'challenge': challenge,
      'origin': origin,
    };
    final clientDataString = json.encode(clientData);
    final clientDataBytes = utf8.encode(clientDataString);
    final clientParam = sha256.convert(clientDataBytes).bytes;

    Object? error;

    for (final keyHandle in keyHandles) {
      try {
        final resp = await _sendFido2(
          u2fAuthenticate,
          p1: cbEnforceUserPresenceAndSign,
          data: clientParam + appParam + [keyHandle.length] + keyHandle,
          timeout: timeout,
        );
        if (resp.status == _Fido2Response.swWrongData) {
          // Invalid key
          continue;
        }
        if (resp.status != _Fido2Response.swNoError) {
          throw APDUError(resp.status);
        }
        return U2fSignature(
          keyHandle: keyHandle,
          signatureData: resp.bytes,
          clientData: Uint8List.fromList(clientDataBytes),
          appId: appId,
        );
      } catch (e) {
        error = e;
      }
    }

    throw error ?? const U2fCancel('No more keyHandles');
  }
}
