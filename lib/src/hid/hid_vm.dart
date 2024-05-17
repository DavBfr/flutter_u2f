import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'generated_bindings.dart';
import 'hid_device.dart';
import 'hid_interface.dart';

final HidInterface hid = _HidApi(Api(_dylib));

const String _libName = 'u2f';

final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open('$_libName.framework/$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libhidapi-hidraw.so.0');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

class _HidApi extends HidInterface {
  _HidApi(this._api);

  final Api _api;

  @override
  bool get available => true;

  @override
  Future<List<HidDevice>> getDeviceList() async {
    final devices = <HidDevice>[];
    final pointer = _api.enumerate(0, 0);
    var current = pointer;
    while (current.address != nullptr.address) {
      final ref = current.ref;
      devices.add(
        UsbDevice(
          _api,
          vendorId: ref.vendor_id,
          productId: ref.product_id,
          serialNumber: ref.serial_number.toDartString(),
          productName: ref.product_string.toDartString(),
          usagePage: ref.usage_page,
          usage: ref.usage,
        ),
      );
      current = ref.next;
    }
    _api.free_enumeration(pointer);
    return devices;
  }
}

class UsbDevice extends HidDevice {
  UsbDevice(
    this._api, {
    required super.vendorId,
    required super.productId,
    required super.serialNumber,
    required super.productName,
    required super.usagePage,
    required super.usage,
  });

  final Api _api;
  Pointer<hid_device>? _raw;
  bool isOpen = false;

  @override
  Future<bool> open() async {
    final pointer = _api.open(vendorId, productId, serialNumber.toPointer());
    if (pointer.address == nullptr.address) return false;
    final result = _api.set_nonblocking(pointer, 1);
    if (result == -1) return false;
    _raw = pointer;
    isOpen = true;
    return true;
  }

  @override
  Future<void> close() async {
    isOpen = false;
    final raw = _raw;
    if (raw != null) {
      _api.close(raw);
    }
  }

  @override
  Stream<Uint8List> read(int length, int duration) async* {
    final raw = _raw;
    if (raw == null) throw Exception();
    final buf = calloc<Uint8>(length);
    var count = 0;
    while (isOpen) {
      count = _api.read(raw, buf.cast(), length);
      if (count == -1) {
        break;
      } else if (count > 0) {
        yield buf.asTypedList(count);
      }
      await Future.delayed(Duration(milliseconds: duration));
    }
    calloc.free(buf);
  }

  @override
  Future<void> write(Uint8List bytes) async {
    final raw = _raw;
    if (raw == null) throw Exception();
    final buf = calloc<Uint8>(bytes.lengthInBytes);
    final u8Buf = buf.asTypedList(bytes.lengthInBytes);
    u8Buf.setRange(0, bytes.lengthInBytes, bytes);
    var offset = 0;
    while (isOpen && bytes.lengthInBytes - offset > 0) {
      final count = _api.write(
        raw,
        (buf + offset).cast(),
        bytes.lengthInBytes - offset,
      );
      if (count == -1) {
        break;
      } else {
        offset += count;
      }
    }
    calloc.free(buf);
  }
}

extension PointerToString on Pointer<WChar> {
  String toDartString() {
    final buffer = StringBuffer();
    var i = 0;
    while (true) {
      final char = (this + i).value;
      if (char == 0) {
        return buffer.toString();
      }
      buffer.writeCharCode(char);
      i++;
    }
  }
}

extension StringToPointer on String {
  Pointer<WChar> toPointer({Allocator allocator = malloc}) {
    final units = codeUnits;
    final result = allocator<Int32>(units.length + 1);
    final nativeString = result.asTypedList(units.length + 1);
    nativeString.setRange(0, units.length, units);
    nativeString[units.length] = 0;
    return result.cast();
  }
}
