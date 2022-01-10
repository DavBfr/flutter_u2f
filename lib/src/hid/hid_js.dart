import 'hid_device.dart';
import 'hid_interface.dart';

final HidInterface hid = _HidApi();

class _HidApi extends HidInterface {
  @override
  Future<List<HidDevice>> getDeviceList() async {
    throw UnimplementedError();
  }

  @override
  bool get available => false;
}
