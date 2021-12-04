import 'dart:convert';
import 'dart:typed_data';

class U2fSignature {
  const U2fSignature(
    this.signatureData,
    this.clientData,
    this.challenge,
    this.appId,
  );

  final Uint8List signatureData;
  final String clientData;
  final String challenge;
  final String appId;

  bool get userPresence => (signatureData[0] & 1) == 1;

  int get counter =>
      signatureData.buffer.asByteData(signatureData.offsetInBytes).getInt32(1);

  String get signature => base64Url.encode(signatureData.sublist(5));

  @override
  String toString() {
    final response = <String, String>{
      'signatureData': base64Url.encode(signatureData),
      'clientData': base64Url.encode(utf8.encode(clientData)),
      'challenge': challenge,
      'appId': appId,
    };

    return json.encode(response);
  }
}
