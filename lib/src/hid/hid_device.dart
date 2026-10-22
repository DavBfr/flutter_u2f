import 'dart:typed_data';

abstract class HidDevice {
  const HidDevice({
    required this.vendorId,
    required this.productId,
    required this.serialNumber,
    required this.productName,
    this.usagePage,
    this.usage,
  });

  final int vendorId;
  final int productId;
  final String serialNumber;
  final String productName;
  final int? usagePage;
  final int? usage;

  Future<bool> open();

  Future<void> close();

  Stream<List<int>> read(int length, int duration);

  Future<bool> write(Uint8List bytes);

  Future<Uint8List> getFeatures(Uint8List input);

  Future<int> setFeatures(Uint8List input);
}
