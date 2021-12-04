import 'dart:convert';
import 'dart:typed_data';

class U2fSignature {
  const U2fSignature({
    required this.signatureData,
    required this.clientData,
    required this.appId,
  });

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
      'signatureData': base64Url.encode(signatureData),
      'clientData': base64Url.encode(clientData),
      'challenge': challenge,
      'appId': appId,
    };

    return json.encode(response);
  }

  bool verifySignature(String publicKey) {
    return false;
  }
}
