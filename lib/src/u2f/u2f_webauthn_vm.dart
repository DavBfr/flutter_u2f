import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../win/generated_bindings.dart';
import 'error.dart';
import 'registration.dart';
import 'signature.dart';
import 'u2f_base.dart';

const String _libName = 'u2f';

final DynamicLibrary _dylib = () {
  if (Platform.isWindows) {
    return DynamicLibrary.open('$_libName.dll');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

final _api = Api(_dylib);

class U2fV2Webauthn extends U2fV2Base {
  U2fV2Webauthn._();

  static Future<bool> availability() async {
    return Platform.isWindows;
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
    final clientDataJSON = {
      'challenge': challenge,
      'hashAlgorithm': 'SHA-256',
      'origin': origin,
      'type': 'webauthn.create',
    };

    final clientData =
        Uint8List.fromList(utf8.encode(json.encode(clientDataJSON)));

    final attestation = calloc<REGISTER_ATTESTATION>();

    final keyHandlePtr = malloc<KEY_HANDLE>(existingKeyHandles.length);

    for (final (index, key) in existingKeyHandles.indexed) {
      keyHandlePtr[index]
        ..size = key.length
        ..keyHandle = key.toNative().data;
    }

    final result = _api.RegisterFIDO2Token(
      clientData.length,
      clientData.toNative().data,
      appId.toNativeUtf16().cast(),
      name.toNativeUtf16().cast(),
      displayName.toNativeUtf16().cast(),
      existingKeyHandles.length,
      keyHandlePtr,
      timeout.inMilliseconds,
      attestation,
    );

    if (result != 0) {
      throw const U2fException('Unable to call Webauthn');
    }

    try {
      return U2fRegistration.fromWebauthn(
        clientData: clientData,
        attestationObject: Uint8List.fromList(
          attestation.ref.pbAttestationObject.asTypedList(
            attestation.ref.cbAttestationObject,
          ),
        ),
        appId: appId,
      );
    } finally {
      _api.FreeRegister(attestation);
      malloc.free(attestation);
      malloc.free(keyHandlePtr);
    }
  }

  @override
  Future<U2fSignature> authenticate(
    String appId,
    List<Uint8List> keyHandles,
    String challenge,
    String origin,
    Duration timeout,
  ) async {
    final clientDataJSON = {
      'challenge': challenge,
      'hashAlgorithm': 'SHA-256',
      'origin': origin,
      'type': 'webauthn.get',
    };

    final clientData =
        Uint8List.fromList(utf8.encode(json.encode(clientDataJSON)));

    final validate = calloc<VALIDATE_ATTESTATION>();

    final keyHandlePtr = malloc<KEY_HANDLE>(keyHandles.length);

    for (final (index, key) in keyHandles.indexed) {
      keyHandlePtr[index]
        ..size = key.length
        ..keyHandle = key.toNative().data;
    }

    final result = _api.ValidateFIDO2Tokens(
      clientData.length,
      clientData.toNative().data,
      appId.toNativeUtf16().cast(),
      keyHandles.length,
      keyHandlePtr,
      timeout.inMilliseconds,
      validate,
    );

    if (result != 0) {
      throw const U2fException('Unable to call Webauthn');
    }

    try {
      return U2fSignature.fromWebauthn(
        keyHandle: Uint8List.fromList(
          validate.ref.keyHandle.asTypedList(validate.ref.keyHandleLength),
        ),
        authenticatorData: Uint8List.fromList(
          validate.ref.authenticatorData
              .asTypedList(validate.ref.authenticatorDataLength),
        ),
        clientData: clientData,
        signature: Uint8List.fromList(
          validate.ref.signature.asTypedList(validate.ref.signatureLength),
        ),
        appId: appId,
      );
    } finally {
      _api.FreeValidate(validate);
      malloc.free(validate);
    }
  }
}

extension _Uint8ListPtr on Uint8List {
  _FinalizerWrapper toNative() {
    final pointer = malloc<Uint8>(length);
    for (var i = 0; i < length; i++) {
      pointer[i] = this[i];
    }
    return _FinalizerWrapper(pointer);
  }
}

class _FinalizerWrapper implements Finalizable {
  _FinalizerWrapper(this.data) {
    finalizer.attach(this, data.cast());
  }

  static final finalizer = NativeFinalizer(malloc.nativeFree);

  final Pointer<Uint8> data;
}
