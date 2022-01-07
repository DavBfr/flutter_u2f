import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#authentication-response-message-success

class U2fSignature {
  const U2fSignature({
    required this.keyHandle,
    required this.signatureData,
    required this.clientData,
    required this.appId,
  });

  factory U2fSignature.fromWebauthn({
    required Uint8List keyHandle,
    required Uint8List authenticatorData,
    required Uint8List clientData,
    required Uint8List signature,
    required String appId,
  }) {
    final signatureData = BytesBuilder();
    signatureData.addByte(authenticatorData[32] & 1);
    signatureData.add(authenticatorData.sublist(33, 33 + 4));
    signatureData.add(signature);

    return U2fSignature(
      keyHandle: keyHandle,
      appId: appId,
      clientData: clientData,
      signatureData: signatureData.toBytes(),
    );
  }

  final Uint8List keyHandle;

  final Uint8List signatureData;

  final Uint8List clientData;

  final String appId;

  bool get userPresence => (signatureData[0] & 1) == 1;

  int get counter =>
      signatureData.buffer.asByteData(signatureData.offsetInBytes).getInt32(1);

  String get signature => base64Url.encode(signatureData.sublist(5));

  String get challenge => '';

  @override
  String toString() {
    final response = <String, String>{
      'keyHandle': base64Url.encode(keyHandle),
      'signatureData': base64Url.encode(signatureData),
      'clientData': base64Url.encode(clientData),
      'challenge': challenge,
      'appId': appId,
    };

    return json.encode(response);
  }

  Uint8List get signedMessage =>
      Uint8List.fromList(sha256.convert(utf8.encode(appId)).bytes +
          signatureData.sublist(0, 5) +
          sha256.convert(clientData).bytes);

  bool verifySignature(ECPublicKey publicKey) {
    final signer = ECDSASigner(SHA256Digest());
    signer.init(false, PublicKeyParameter(publicKey));
    final sign =
        ASN1Parser(signatureData.sublist(5)).nextObject() as ASN1Sequence;
    return signer.verifySignature(
      signedMessage,
      ECSignature(
        (sign.elements![0] as ASN1Integer).integer!,
        (sign.elements![1] as ASN1Integer).integer!,
      ),
    );
  }
}
