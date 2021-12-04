import 'dart:convert';
import 'dart:typed_data';

class U2fRegistration {
  const U2fRegistration(
    this.registrationData,
    this.clientData,
  );

  final Uint8List registrationData;

  final String clientData;

  String get userPublicKey => base64Url.encode(registrationData.sublist(1, 66));

  String get keyHandle =>
      base64Url.encode(registrationData.sublist(67, 67 + registrationData[66]));

  @override
  String toString() {
    final response = <String, String>{
      'registrationData': base64Url.encode(registrationData),
      'clientData': base64Url.encode(utf8.encode(clientData)),
    };
    return json.encode(response);
  }
}
