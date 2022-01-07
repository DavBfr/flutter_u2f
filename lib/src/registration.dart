import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';

import 'signature.dart';

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#h3_registration-response-message-success

Map<dynamic, dynamic> _decodeCbor(Uint8List data) {
  final decoder = Cbor();
  decoder.decodeFromList(data);
  return decoder.getDecodedData()![0];
}

class U2fRegistration extends U2fSignature {
  U2fRegistration({
    required this.registrationData,
    required Uint8List clientData,
    required String appId,
  }) : super(
          keyHandle: Uint8List(0),
          signatureData: Uint8List(0),
          clientData: clientData,
          appId: appId,
        );

  factory U2fRegistration.fromWebauthn({
    required Uint8List clientData,
    required Uint8List attestationObject,
    required String appId,
  }) {
    final decodedAttestation = _decodeCbor(attestationObject);
    // print(decodedAttestation);

    final authDataBytes = Uint8List.fromList(decodedAttestation['authData']);
    final authData = authDataBytes.buffer.asByteData();
    // final flags = authData.getInt8(32);
    // final counter = authData.getUint32(33);

    // get the length of the credential ID
    final credentialIdLength = authData.getUint16(53);

    // get the public key object
    final publicKeyBytes = authDataBytes.sublist(55 + credentialIdLength);

    // the publicKeyBytes are encoded again as CBOR
    final publicKeyObject = _decodeCbor(publicKeyBytes);
    // 1: The 1 field describes the key type. The value of 2 indicates that the key type is in the Elliptic Curve format.
    // 3: The 3 field describes the algorithm used to generate authentication signatures. The -7 value indicates this authenticator will be using ES256.
    // -1: The -1 field describes this key's "curve type". The value 1 indicates the that this key uses the "P-256" curve.

    final registrationData = BytesBuilder();
    registrationData.addByte(0x05);
    registrationData.addByte(0x04);
    registrationData.add(publicKeyObject[-2]);
    registrationData.add(publicKeyObject[-3]);
    registrationData.addByte(credentialIdLength);
    registrationData.add(authDataBytes.sublist(55, 55 + credentialIdLength));
    if (decodedAttestation['fmt'] == 'fido-u2f') {
      registrationData.add(decodedAttestation['attStmt']['x5c'][0]);
      registrationData.add(decodedAttestation['attStmt']['sig']);
    }

    return U2fRegistration(
      appId: appId,
      clientData: clientData,
      registrationData: registrationData.toBytes(),
    );
  }

  final Uint8List registrationData;

  Uint8List get certificate {
    final cert = 67 + registrationData[66];
    final sign = ASN1Utils.decodeLength(registrationData.sublist(cert));
    return registrationData.sublist(cert, cert + sign + 4);
  }

  @override
  Uint8List get signatureData {
    final cert = 67 + registrationData[66];
    final sign = ASN1Utils.decodeLength(registrationData.sublist(cert));
    return Uint8List.fromList(
        [1, 0, 0, 0, 0] + registrationData.sublist(cert + sign + 4));
  }

  /// Decode a BigInt from bytes in big-endian encoding.
  /// Twos compliment.
  BigInt _decodeBigInt(Uint8List bytes) {
    return BigInt.parse(
        bytes.map((e) => e.toRadixString(16).padLeft(2, '0')).join(),
        radix: 16);
  }

  Uint8List get userPublicKeyBytes => registrationData.sublist(1, 65);

  ECPublicKey get userPublicKey {
    if (registrationData[1] != 0x04) {
      throw Exception('Only P-256 NIST elliptic curve supported');
    }
    final qx = _decodeBigInt(registrationData.sublist(2, 2 + 32));
    final qy = _decodeBigInt(registrationData.sublist(2 + 32, 2 + 32 + 32));
    final eccDomain = ECCurve_prime256v1();
    final q = eccDomain.curve.createPoint(qx, qy);
    return ECPublicKey(q, eccDomain);
  }

  @override
  Uint8List get keyHandle =>
      registrationData.sublist(67, 67 + registrationData[66]);

  ECPublicKey get certificatePublicKey {
    final x509 = ASN1Parser(certificate).nextObject() as ASN1Sequence;
    final tbs = x509.elements![0] as ASN1Sequence;
    final pk = tbs.elements![6] as ASN1Sequence;
    final kp =
        Uint8List.fromList((pk.elements![1] as ASN1BitString).stringValues!);

    if (kp[0] != 0x04) {
      throw Exception('Only P-256 NIST elliptic curve supported');
    }
    final qx = _decodeBigInt(kp.sublist(1, 1 + 32));
    final qy = _decodeBigInt(kp.sublist(1 + 32, 1 + 32 + 32));
    final eccDomain = ECCurve_prime256v1();
    final q = eccDomain.curve.createPoint(qx, qy);
    return ECPublicKey(q, eccDomain);
  }

  @override
  Uint8List get signedMessage => Uint8List.fromList([0] +
      sha256.convert(utf8.encode(appId)).bytes +
      sha256.convert(clientData).bytes +
      keyHandle +
      registrationData.sublist(1, 66));

  @override
  String toString() {
    final response = <String, String>{
      'registrationData': base64Url.encode(registrationData),
      'clientData': base64Url.encode(clientData),
    };
    return json.encode(response);
  }
}
