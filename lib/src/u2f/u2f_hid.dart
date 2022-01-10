// ignore_for_file: unused_field

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import '../../hid.dart';
import 'error.dart';
import 'log.dart';
import 'u2f_fido2.dart';

/// FIDO U2F HID Protocol Specification
/// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html

class U2fV2Hid extends U2fV2Fido2 {
  U2fV2Hid._(this._device);

  final HidDevice _device;

  /// Frame type mask
  static const _typeMask = 0x80;

  /// Initial frame identifier
  static const _typeInit = 0x80;
  // Continuation frame identifier
  static const _typeCont = 0x00;

  /// Echo data through local processor only
  static const _u2fHidPing = _typeInit | 0x01;

  /// Send U2F message frame
  static const _u2FhidMsg = _typeInit | 0x03;

  /// Send lock channel command
  static const _u2FhidLock = _typeInit | 0x04;

  /// Channel initialization
  static const _u2fHidInit = _typeInit | 0x06;

  /// Send device identification wink
  static const _u2FhidWink = _typeInit | 0x08;

  /// Error response
  static const _u2FhidError = _typeInit | 0x3f;

  /// Keep alive
  static const _u2FhidKeepalive = _typeInit | 0x3b;

  /// First vendor defined command
  static const _u2FhidVendorFirst = _typeInit | 0x40;

  /// Last vendor defined command
  static const _u2FhidVendorLast = _typeInit | 0x7f;

  static const _errNone = 0x00; // No error
  static const _errInvalidCmd = 0x01; // Invalid command
  static const _errInvalidPar = 0x02; // Invalid parameter
  static const _errInvalidLen = 0x03; // Invalid message length
  static const _errInvalidSeq = 0x04; // Invalid message sequencing
  static const _errMsgTimeout = 0x05; // Message has timed out
  static const _errChannelBusy = 0x06; // Channel busy
  static const _errLockRequired = 0x0a; // Command requires channel lock
  static const _errSyncFail = 0x0b; // SYNC command failed
  static const _errOther = 0x7f; // Other unspecified error

  static const _capabilityWink = 0x01;
  static const _capabilityLock = 0x02;

  static const _u2FhidBroadcast = 0xffffffff;

  static final rnd = math.Random();

  var _version = '(uninitialized)';
  String get deviceVersion => _version;

  var _capabilities = 0;

  bool get canWink => _capabilities & _capabilityWink != 0;
  bool get canLock => _capabilities & _capabilityLock != 0;

  static Stream<U2fV2Hid> poll(
    Duration timeout,
    Duration delay,
    OnContinuePolling onContinue,
  ) async* {
    final stopWatch = Stopwatch()..start();
    try {
      var found = false;
      while (!found) {
        for (final dev in await hid.getDeviceList()) {
          if (dev.usagePage == 0xf1d0 && dev.usage == 1) {
            yield U2fV2Hid._(dev);
            found = true;
          }
        }
        if (!onContinue()) {
          return;
        }
        await Future.delayed(delay);
        if (stopWatch.elapsed > timeout) {
          return;
        }
      }
    } catch (e) {
      log.warning('U2fV2Hid: $e');
    } finally {
      stopWatch.stop();
    }
  }

  static Future<bool> availability() async {
    if (kIsWeb || (!Platform.isLinux && !Platform.isMacOS)) return false;
    if (!hid.available) return false;

    try {
      await hid.getDeviceList();
      return true;
    } catch (e, s) {
      log.warning('Usb HID not available', e, s);
      return false;
    }
  }

  Future<void> _write(List<int> bytes) async {
    // final w = Uint8List(64)..setAll(0, bytes);
    final w = Uint8List.fromList([0] + bytes);
    // print('WRITE $w');
    return _device.write(w);
  }

  StreamSubscription<List<int>>? _streamReader;
  final buffer = <Uint8List>[];
  final _completers = <Completer<void>>[];

  Future<Uint8List> _read() async {
    while (buffer.isEmpty) {
      final c = Completer<void>();
      _completers.add(c);
      await c.future;
      _completers.remove(c);
    }

    return buffer.removeAt(0);
  }

  var _channelId = _u2FhidBroadcast;

  Future<Uint8List> _send(int cmd, [List<int> data = const []]) async {
    var remaining = data.length;
    const packetSize = 64; // self.descriptor.report_size_out
    var seq = 0;

    // Send request
    var header = Uint8List(7);
    header.buffer.asByteData()
      ..setUint32(0, _channelId)
      ..setUint8(4, cmd)
      ..setUint16(5, remaining);

    while (remaining > 0 || seq == 0) {
      final start = data.length - remaining;
      final size = math.min(remaining, packetSize - header.lengthInBytes);
      // print('remaining: $remaining size: $size start: $start');
      final body = data.sublist(start, start + size);
      remaining -= size;

      final packet = header + body;
      // print('SEND PACKET: $packet');
      _write(packet + List<int>.filled(packetSize - packet.length, 0));
      header = Uint8List(5);
      header.buffer.asByteData()
        ..setUint32(0, _channelId)
        ..setUint8(4, 0x7F & seq);
      seq++;
    }

    // Read response
    seq = 0;
    final response = BytesBuilder();
    var rLen = 0;

    while (true) {
      final recv = await _read();
      var start = 4;

      final buf = recv.buffer.asByteData();

      final rChannel = buf.getUint32(0);

      if (rChannel != _channelId) {
        throw const U2fException('Wrong channel');
      }

      if (response.isEmpty) {
        // Initialization packet
        final rCmd = buf.getUint8(4);
        rLen = buf.getUint16(5);

        start += 3;
        if (rCmd == _u2FhidError) {
          throw U2fException('Error ${buf.getUint8(7)}');
        } else if (rCmd != cmd) {
          throw const U2fException('invalid command');
        }
      } else {
        // Continuation packet
        final rSeq = buf.getUint8(4);
        // recv = recv[1:]
        start++;
        if (rSeq != seq) {
          throw const U2fException('Wrong sequence number');
        }
        seq++;
      }

      response.add(recv.sublist(start));
      if (response.length >= rLen) {
        break;
      }
    }

    return response.toBytes().sublist(0, rLen);
  }

  @override
  Future<void> init() async {
    final r = await _device.open();
    if (!r) {
      throw const U2fException('Unable to open device');
    }

    if (_streamReader != null) {
      return super.init();
    }

    _streamReader = _device.read(64, 50).listen((event) {
      buffer.add(Uint8List.fromList(event));
      for (final e in _completers) {
        e.complete();
      }
    });

    final rndBytes = List<int>.generate(8, (index) => rnd.nextInt(256));
    final result = await _send(_u2fHidInit, rndBytes);

    for (var index = 0; index < rndBytes.length; index++) {
      if (rndBytes[index] != result[index]) {
        throw const U2fException('Error initializing HID device');
      }
    }

    final buf = result.buffer.asByteData(result.offsetInBytes);
    _channelId = buf.getUint32(8);
    // final protocol = buf.getUint8(12);
    _version = '${buf.getUint8(13)}.${buf.getUint8(14)}.${buf.getUint8(15)}';
    _capabilities = buf.getUint8(16);

    return super.init();
  }

  @override
  Future<Uint8List> send(Uint8List apdu) {
    return _send(_u2FhidMsg, apdu);
  }

  Future<void> ping() async {
    await _send(_u2fHidPing, [0x48, 0x65, 0x6c, 0x6c, 0x6f]);
  }

  Future<void> wink() async {
    final r = await _device.open();
    if (!r) {
      throw const U2fException('Unable to open device');
    }
    await _send(_u2FhidWink);
  }

  @override
  Future<void> dispose() async {
    if (_streamReader != null) {
      _streamReader?.cancel();
      _streamReader = null;
      await _device.close();
    }
    await super.dispose();
  }
}
