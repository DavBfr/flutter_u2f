import 'dart:convert';
import 'dart:typed_data';

import 'signature.dart';

class U2fRegistration extends U2fSignature {
  U2fRegistration({
    required this.registrationData,
    required Uint8List clientData,
    required String appId,
  }) : super(
          signatureData: Uint8List(0),
          clientData: clientData,
          appId: appId,
        );

  final Uint8List registrationData;

  String get userPublicKey => base64Url.encode(registrationData.sublist(1, 66));

  String get keyHandle =>
      base64Url.encode(registrationData.sublist(67, 67 + registrationData[66]));

  String get certificatePublicKey => throw UnimplementedError();

  @override
  String toString() {
    final response = <String, String>{
      'registrationData': base64Url.encode(registrationData),
      'clientData': base64Url.encode(clientData),
    };
    return json.encode(response);
  }
}
