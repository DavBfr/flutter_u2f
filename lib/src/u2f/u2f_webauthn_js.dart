// ignore_for_file: avoid_web_libraries_in_flutter

import 'dart:async';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';

import 'package:flutter/foundation.dart';
import 'package:web/web.dart' as web;

import 'registration.dart';
import 'signature.dart';
import 'u2f_base.dart';

class U2fV2Webauthn extends U2fV2Base {
  U2fV2Webauthn._();

  static Future<bool> availability() async {
    if (!kReleaseMode) return true;

    if (web.window.location.protocol != 'https:') {
      return false;
    } else if (RegExp(r'(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){4}')
        .hasMatch(web.window.location.hostname)) {
      return false;
    } else if (!web.window.navigator.hasProperty('credentials'.toJS).toDart) {
      return false;
    }

    return true;
  }

  static Stream<U2fV2Webauthn> poll() async* {
    yield U2fV2Webauthn._();
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
    final options = web.CredentialCreationOptions(
      publicKey: web.PublicKeyCredentialCreationOptions(
        rp: web.PublicKeyCredentialRpEntity(
          id: appId,
        )..name = 'U2F',
        user: web.PublicKeyCredentialUserEntity(
          displayName: displayName,
          id: Uint8List.fromList(name.codeUnits).buffer.toJS,
        )..name = name,
        challenge: Uint8List.fromList(challenge.codeUnits).buffer.toJS,
        pubKeyCredParams: [
          web.PublicKeyCredentialParameters(
            alg: -7,
            type: 'public-key',
          ),
        ].toJS,
        timeout: timeout.inSeconds,
        authenticatorSelection: web.AuthenticatorSelectionCriteria(
          residentKey: 'discouraged',
          requireResidentKey: false,
          userVerification: 'discouraged',
          authenticatorAttachment: 'cross-platform',
        ),
        excludeCredentials: [
          for (final key in existingKeyHandles)
            web.PublicKeyCredentialDescriptor(
              type: 'public-key',
              id: key.buffer.toJS,
            ),
        ].toJS,
        attestation: 'direct',
      ),
    );

    final newCredential = (await web.window.navigator.credentials
        .create(options)
        .toDart)! as web.PublicKeyCredential;

    final response =
        newCredential.response as web.AuthenticatorAttestationResponse;

    return U2fRegistration.fromWebauthn(
      clientData: response.clientDataJSON.toDart.asUint8List(),
      attestationObject: response.attestationObject.toDart.asUint8List(),
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
    final options = web.CredentialRequestOptions(
      publicKey: web.PublicKeyCredentialRequestOptions(
        challenge: Uint8List.fromList(challenge.codeUnits).buffer.toJS,
        timeout: timeout.inSeconds,
        rpId: appId,
        userVerification: 'discouraged',
        allowCredentials: [
          for (final key in keyHandles)
            web.PublicKeyCredentialDescriptor(
              type: 'public-key',
              id: key.buffer.toJS,
              transports: ['usb'.toJS, 'ble'.toJS, 'nfc'.toJS].toJS,
            ),
        ].toJS,
      ),
    );

    final assertedCredential = (await web.window.navigator.credentials
        .get(options)
        .toDart)! as web.PublicKeyCredential;

    final response =
        assertedCredential.response as web.AuthenticatorAssertionResponse;

    return U2fSignature.fromWebauthn(
      keyHandle: assertedCredential.rawId.toDart.asUint8List(),
      authenticatorData: response.authenticatorData.toDart.asUint8List(),
      clientData: response.clientDataJSON.toDart.asUint8List(),
      signature: response.signature.toDart.asUint8List(),
      appId: appId,
    );
  }
}
