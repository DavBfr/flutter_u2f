import 'commands.dart';

class U2fException implements Exception {
  const U2fException(this.message);

  final String message;

  @override
  String toString() => message;
}

class APDUError extends U2fException {
  factory APDUError(int status) {
    switch (status) {
      case swNoError:
        return const APDUError._(
          'The command completed successfully without error.',
        );
      case swConditionsNotSatisfied:
        return const APDUError._(
          'The request was rejected due to test-of-user-presence being required.',
        );
      case swWrongData:
        return const APDUError._(
          'The request was rejected due to an invalid key handle.',
        );
      case swWrongLength:
        return const APDUError._('The length of the request was invalid.');
      case swClaNotSupported:
        return const APDUError._(
          'The class byte of the request is not supported.',
        );
      case swInsNotSupported:
        return const APDUError._(
          'The instruction of the request is not supported.',
        );
      default:
        return APDUError._('APDU status: ${status.toRadixString(16)}');
    }
  }

  const APDUError._(super.message);
}

class U2fCancel extends U2fException {
  const U2fCancel(super.message);
}

class U2fTimeout extends U2fCancel {
  const U2fTimeout(super.message);
}

class U2fNoDevice extends U2fException {
  const U2fNoDevice(super.message);
}
