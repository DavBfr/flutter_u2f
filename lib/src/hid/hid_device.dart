import 'dart:typed_data';

abstract class HidDevice {
  HidDevice({
    required this.vendorId,
    required this.productId,
    required this.serialNumber,
    required this.productName,
    this.usagePage,
    this.usage,
  });

  int vendorId;
  int productId;
  String serialNumber;
  String productName;
  int? usagePage;
  int? usage;

  Future<bool> open();

  Future<void> close();

  Stream<List<int>> read(int length, int duration);

  Future<void> write(Uint8List bytes);
}
