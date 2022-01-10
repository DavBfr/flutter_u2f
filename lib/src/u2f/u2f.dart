// ignore_for_file: require_trailing_commas

import 'dart:async';
import 'dart:typed_data';

import 'package:async/async.dart';

import 'error.dart';
import 'log.dart';
import 'registration.dart';
import 'signature.dart';
import 'u2f_base.dart';
import 'u2f_fido2.dart';
import 'u2f_hid.dart';
import 'u2f_nfc.dart';
import 'u2f_webauthn_vm.dart'
    if (dart.library.js_interop) 'u2f_webauthn_js.dart';

enum U2fV2Methods { nfc, hid, webauthn }

class U2fV2 {
  const U2fV2({
    this.methods = const {
      U2fV2Methods.nfc,
      U2fV2Methods.hid,
      U2fV2Methods.webauthn,
    },
  });

  static const delay = Duration(milliseconds: 400);
  static const timeout = Duration(seconds: 20);

  final Set<U2fV2Methods> methods;

  Future<Set<U2fV2Methods>> checkAvailability() async {
    return <U2fV2Methods>{
      if (methods.contains(U2fV2Methods.nfc) &&
          await U2fV2Nfc.availability() == NFCAvailability.available)
        U2fV2Methods.nfc,
      if (methods.contains(U2fV2Methods.hid) && await U2fV2Hid.availability())
        U2fV2Methods.hid,
      if (methods.contains(U2fV2Methods.webauthn) &&
          await U2fV2Webauthn.availability())
        U2fV2Methods.webauthn,
    };
  }

  Stream<U2fV2Base> _poll({
    required Duration timeout,
    required OnContinuePolling onContinue,
  }) async* {
    final availableMethods = await checkAvailability();

    yield* StreamGroup.merge<U2fV2Base>([
      if (availableMethods.contains(U2fV2Methods.nfc))
        U2fV2Nfc.poll(
          timeout,
        ),
      if (availableMethods.contains(U2fV2Methods.hid))
        U2fV2Hid.poll(
          timeout,
          delay,
          onContinue,
        ),
      if (availableMethods.contains(U2fV2Methods.webauthn))
        U2fV2Webauthn.poll(),
    ]);
  }

  Future<U2fRegistration> register({
    required String challenge,
    required String appId,
    String? origin,
    String? name,
    String? displayName,
    List<Uint8List> existingKeyHandles = const [],
    Duration timeout = timeout,
  }) async {
    final devices = <U2fV2Base>[];
    final registration = Completer<U2fRegistration>();
    var canContinue = true;
    final ls = _poll(
      timeout: timeout,
      onContinue: () => canContinue,
    ).listen(
      (u2f) async {
        try {
          devices.add(u2f);
          await u2f.init();
          registration.complete(await u2f.register(
            challenge,
            appId,
            origin ?? 'https://$appId',
            name ?? appId,
            displayName ?? appId,
            existingKeyHandles,
            timeout,
          ));
        } catch (e) {
          log.info(e);
          if (devices.length == 1) {
            registration.completeError(e);
          }
        } finally {
          devices.remove(u2f);
          await u2f.dispose();
        }
      },
      onDone: () {
        if (devices.isEmpty && !registration.isCompleted) {
          registration.completeError(const U2fNoDevice('No device available'));
        }
      },
    );

    final reg = await registration.future;
    canContinue = false;
    for (final dev in devices) {
      dev.dispose();
    }
    ls.cancel();
    return reg;
  }

  Future<U2fSignature> authenticate({
    required String appId,
    required List<Uint8List> keyHandles,
    required String challenge,
    String? origin,
    Duration timeout = timeout,
  }) async {
    final devices = <U2fV2Base>[];
    final signature = Completer<U2fSignature>();
    var canContinue = true;
    final ls = _poll(
      timeout: timeout,
      onContinue: () => canContinue,
    ).listen(
      (u2f) async {
        try {
          devices.add(u2f);
          await u2f.init();
          signature.complete(await u2f.authenticate(
            appId,
            keyHandles,
            challenge,
            origin ?? 'https://$appId',
            timeout,
          ));
        } catch (e) {
          log.info(e);
          if (devices.length == 1) {
            signature.completeError(e);
          }
        } finally {
          devices.remove(u2f);
          await u2f.dispose();
        }
      },
      onDone: () {
        if (devices.isEmpty && !signature.isCompleted) {
          signature.completeError(const U2fNoDevice('No device available'));
        }
      },
    );
    final sig = await signature.future;
    canContinue = false;
    for (final dev in devices) {
      dev.dispose();
    }
    ls.cancel();
    return sig;
  }
}
