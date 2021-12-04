import 'commands.dart';

class APDUError implements Exception {
  APDUError(this.status);

  final int status;

  @override
  String toString() {
    switch (status) {
      case swNoError:
        return 'The command completed successfully without error.';
      case swConditionsNotSatisfied:
        return 'The request was rejected due to test-of-user-presence being required.';
      case swWrongData:
        return 'The request was rejected due to an invalid key handle.';
      case swWrongLength:
        return 'The length of the request was invalid.';
      case swClaNotSupported:
        return 'The class byte of the request is not supported.';
      case swInsNotSupported:
        return 'The instruction of the request is not supported.';
      default:
        return 'APDU status: ${status.toRadixString(16)}';
    }
  }
}
