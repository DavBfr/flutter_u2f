import 'hid_device.dart';

abstract class HidInterface {
  const HidInterface();

  Future<List<HidDevice>> getDeviceList();

  bool get available;
}
