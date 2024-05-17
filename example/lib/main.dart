// ignore_for_file: avoid_print
// ignore_for_file: implementation_imports

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:logging/logging.dart';
import 'package:u2f/hid.dart';
import 'package:u2f/u2f.dart';

void main() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    print('${record.level.name}: ${record.time}: ${record.message}');
  });

  const u2f = U2fV2();
  runApp(const App(u2f: u2f));
}

class App extends StatelessWidget {
  const App({super.key, required this.u2f});

  final U2fV2 u2f;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('FIDO2 Plugin example app'),
        ),
        body: Row(
          children: [
            Flexible(child: HidDemo(u2f: u2f)),
            const VerticalDivider(),
            Flexible(
              flex: 2,
              child: U2fDemo(
                u2f: u2f,
                challenge: 'F_YaN22CtYQPkmFiEF9a3Q',
                appId: 'localhost',
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class U2fDemo extends StatefulWidget {
  const U2fDemo({
    super.key,
    required this.u2f,
    required this.challenge,
    required this.appId,
  });

  final U2fV2 u2f;

  final String challenge;

  final String appId;

  @override
  State<U2fDemo> createState() => _U2fDemoState();
}

class _U2fDemoState extends State<U2fDemo> {
  U2fRegistration? registration;
  int? counter;
  String? error;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: [
          Text('registration: ${registration?.keyHandle}'),
          OutlinedButton(
            onPressed: _enroll,
            child: const Text('Enroll'),
          ),
          if (counter != null) Text('Counter: $counter'),
          if (error != null)
            Text(
              'Error: $error',
              style: const TextStyle(color: Colors.red),
            ),
          OutlinedButton(
            onPressed: registration != null ? _verify : null,
            child: const Text('Verify'),
          ),
        ],
      ),
    );
  }

  Future<String> _getMessage() async {
    final methods = await widget.u2f.checkAvailability();

    final text = StringBuffer('Please ');

    for (final m in methods) {
      switch (m) {
        case U2fV2Methods.nfc:
          text.writeln('scan your security key');
          break;
        case U2fV2Methods.hid:
          text.writeln('press the button on your security key');
          break;
        case U2fV2Methods.webauthn:
          text.writeln('press the button on your security key');
          break;
      }
    }

    return text.toString();
  }

  Future<void> _enroll() async {
    setState(() {
      error = null;
    });

    try {
      final result = await progress<U2fRegistration?>(
        text: Text(await _getMessage()),
        result: () async {
          final registration = await widget.u2f.register(
            challenge: widget.challenge,
            appId: widget.appId,
          );
          return registration;
        }(),
      );

      if (result == null) {
        print('error');
        return;
      }

      print('registrationData: ${base64.encode(result.registrationData)}');
      print('clientData: ${base64.encode(result.clientData)}');
      try {
        print(
          'Verified: ${result.verifySignature(result.certificatePublicKey)}',
        );
      } catch (e) {
        print('Verified: $e');
      }

      setState(() {
        registration = result;
      });
    } catch (e) {
      setState(() {
        error = e.toString();
      });
    }
  }

  Future<void> _verify() async {
    setState(() {
      error = null;
    });

    try {
      final result = await progress<U2fSignature?>(
        text: Text(await _getMessage()),
        result: () async {
          final signature = await widget.u2f.authenticate(
            challenge: widget.challenge,
            appId: widget.appId,
            keyHandles: [registration!.keyHandle],
          );
          return signature;
        }(),
      );

      if (result == null) {
        print('error');
        return;
      }

      print('Client Data: ${base64.encode(result.clientData)}');
      print('Signature: ${base64.encode(result.signatureData)}');
      print('Verified: ${result.verifySignature(registration!.userPublicKey)}');

      setState(() {
        counter = result.counter;
      });
    } catch (e) {
      setState(() {
        error = e.toString();
      });
    }
  }

  Future<T?> progress<T>({
    required Future<T?> result,
    Widget? text,
  }) async {
    final innerContext = Completer<BuildContext>();

    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (BuildContext context) {
        innerContext.complete(context);
        return AlertDialog(
          title: const Text('U2F'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              if (text != null) text,
              const CircularProgressIndicator(),
            ],
          ),
        );
      },
    );

    try {
      return await result;
    } finally {
      final dialogContext = await innerContext.future;
      if (dialogContext.mounted) {
        Navigator.pop(dialogContext);
      }
    }
  }
}

class HidDemo extends StatefulWidget {
  const HidDemo({super.key, required this.u2f});

  final U2fV2 u2f;

  @override
  State<HidDemo> createState() => _HidDemoState();
}

class _HidDemoState extends State<HidDemo> {
  List<HidDevice> _hidDevices = const [];
  late Timer _timer;
  Set<U2fV2Methods> _methods = const {};

  @override
  void initState() {
    super.initState();
    _listDevices();
    _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
      _listDevices();
    });
  }

  @override
  void dispose() {
    _timer.cancel();
    super.dispose();
  }

  Future<void> _listDevices() async {
    _methods = await widget.u2f.checkAvailability();

    if (_methods.contains(U2fV2Methods.hid)) {
      _hidDevices = (await hid.getDeviceList())
          .where((e) => e.usagePage == 0xf1d0)
          .toList()
        ..sort((a, b) => a.usage?.compareTo(b.usage ?? 0) ?? 0)
        ..sort((a, b) => a.usagePage?.compareTo(b.usagePage ?? 0) ?? 0)
        ..sort((a, b) => a.productId.compareTo(b.productId))
        ..sort((a, b) => a.vendorId.compareTo(b.vendorId))
        ..sort((a, b) => a.productName.compareTo(b.productName));
    }

    if (!mounted) return;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      children: [
        if (_methods.contains(U2fV2Methods.nfc))
          const ListTile(
            leading: Icon(Icons.nfc),
            title: Text('Near Field Communication'),
          ),
        if (_methods.contains(U2fV2Methods.webauthn))
          const ListTile(
            leading: Icon(Icons.security),
            title: Text('WebAuthn'),
          ),
        for (final device in _hidDevices)
          ListTile(
            leading: const Icon(Icons.usb),
            title: Text(device.productName),
            subtitle: Text(
              '${device.vendorId.toRadixString(16).padLeft(4, '0')}:${device.productId.toRadixString(16).padLeft(4, '0')}   ${device.serialNumber}',
            ),
          ),
      ],
    );
  }
}
