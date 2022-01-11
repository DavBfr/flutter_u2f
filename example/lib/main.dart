// ignore_for_file: avoid_print

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:logging/logging.dart';
import 'package:u2f/u2f.dart';

void main() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    print('${record.level.name}: ${record.time}: ${record.message}');
  });

  runApp(MaterialApp(
    home: Scaffold(
      appBar: AppBar(
        title: const Text('Plugin example app'),
      ),
      body: const MyApp(),
    ),
  ));
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  U2fRegistration? registration;
  int? counter;

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
          Text('Counter: $counter'),
          OutlinedButton(
            onPressed: registration != null ? _verify : null,
            child: const Text('Verify'),
          ),
        ],
      ),
    );
  }

  Future<void> _enroll() async {
    final result = await progress<U2fRegistration?>(
        text: const Text('Please scan your U2F key'),
        result: () async {
          final u2f = await U2fV2.poll().first;
          try {
            await u2f.init();
            return await u2f.register(
              challenge: 'F_YaN22CtYQPkmFiEF9a3Q',
              appId: 'example.com',
            );
          } finally {
            await u2f.dispose();
          }
        }());

    if (result == null) {
      print('error');
      return;
    }

    print('registrationData: ${base64.encode(result.registrationData)}');
    print('clientData: ${base64.encode(result.clientData)}');
    print('Verified: ${result.verifySignature(result.certificatePublicKey)}');

    setState(() {
      registration = result;
    });
  }

  Future<void> _verify() async {
    final result = await progress<U2fSignature?>(
        text: const Text('Please scan your U2F key'),
        result: () async {
          final u2f = await U2fV2.poll().first;
          try {
            await u2f.init();
            return await u2f.authenticate(
              challenge: 'F_YaN22CtYQPkmFiEF9a3Q',
              appId: 'example.com',
              keyHandles: [registration!.keyHandle],
            );
          } finally {
            await u2f.dispose();
          }
        }());

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
      Navigator.pop(dialogContext);
    }
  }
}
