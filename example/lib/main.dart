import 'dart:async';
import 'dart:convert';
import 'dart:developer' as developer;

import 'package:flutter/material.dart';
import 'package:logging/logging.dart';
import 'package:u2f/u2f.dart';

final log = Logger('nfc');

Future<void> main() async {
  runApp(MaterialApp(
    home: NfcTest(),
  ));
}

class NfcTest extends StatelessWidget {
  NfcTest({Key? key}) : super(key: key) {
    Logger.root.level = Level.ALL;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.purple,
        title: const Text('NFC Test'),
      ),
      body: Column(
        children: [
          const Expanded(child: Logs()),
          Container(
            padding: const EdgeInsets.symmetric(vertical: 8),
            color: Colors.purple,
            child: const SafeArea(
              child: Scan(),
            ),
          ),
        ],
      ),
    );
  }
}

class Logs extends StatefulWidget {
  const Logs({Key? key}) : super(key: key);

  @override
  State<Logs> createState() => _LogsState();
}

class _LogsState extends State<Logs> {
  StreamSubscription<LogRecord>? subscription;
  ScrollController listScrollController = ScrollController();

  final _data = <String>[];

  @override
  void initState() {
    _init();
    super.initState();
  }

  void _log(record) {
    setState(() {
      _data.add(record.message);
    });

    Future.delayed(const Duration(milliseconds: 300), () {
      final position = listScrollController.position.maxScrollExtent;
      listScrollController.jumpTo(position);
    });

    developer.log(
      record.message,
      name: record.loggerName,
      error: record.error,
      level: record.level.value,
      stackTrace: record.stackTrace,
      time: record.time,
      zone: record.zone,
      sequenceNumber: record.sequenceNumber,
    );
  }

  void _init() {
    subscription?.cancel();
    Logger.root.level = Level.ALL;
    subscription = Logger.root.onRecord.listen(_log);
  }

  @override
  void reassemble() {
    _init();
    super.reassemble();
  }

  @override
  void dispose() {
    super.dispose();
    subscription?.cancel();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.black,
      child: DefaultTextStyle(
        style: const TextStyle(
          color: Colors.white,
          fontFamily: 'Courier',
          fontSize: 18,
        ),
        child: ListView(
          controller: listScrollController,
          children: [
            ..._data.map(Text.new),
          ],
        ),
      ),
    );
  }
}

class Scan extends StatefulWidget {
  const Scan({Key? key}) : super(key: key);

  @override
  State<Scan> createState() => _ScanState();
}

class _ScanState extends State<Scan> {
  U2fRegistration? registration;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: [
        ElevatedButton(
          onPressed: _enroll,
          child: const Text('Enroll'),
        ),
        ElevatedButton(
          onPressed: registration != null ? _verify : null,
          child: const Text('Verify'),
        ),
      ],
    );
  }

  Future<T?> progress<T>({
    required Future<T?> result,
    required BuildContext context,
    Widget? text,
  }) async {
    final innerContext = Completer<BuildContext>();

    unawaited(showDialog<void>(
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
    ));

    try {
      return await result;
    } finally {
      final dialogContext = await innerContext.future;
      // ignore: use_build_context_synchronously
      Navigator.pop(dialogContext);
    }
  }

  Future<void> _enroll() async {
    log.info('=== ENROLL ===');
    final result = await progress<U2fRegistration?>(
        context: context,
        text: const Text('Please scan your U2F key'),
        result: () async {
          final u2f = await U2fV2.poll().first;
          try {
            await u2f.init();
            return await u2f.register(
              challenge: 'F_YaN22CtYQPkmFiEF9a3Q',
              appId: 'example.com',
            );
          } catch (e, s) {
            log.severe('Error: $e', e, s);
          } finally {
            await u2f.dispose();
          }
        }());

    if (result == null) {
      log.info('Error: No data');
      return;
    }

    log.info('registrationData: ${base64.encode(result.registrationData)}');
    log.info('clientData: ${base64.encode(result.clientData)}');
    log.info(
        'Verified: ${result.verifySignature(result.certificatePublicKey)}');

    setState(() {
      registration = result;
    });
  }

  Future<void> _verify() async {
    log.info('=== VERIFY ===');
    final result = await progress<U2fSignature?>(
        context: context,
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
          } catch (e, s) {
            log.severe('Error: $e', e, s);
          } finally {
            await u2f.dispose();
          }
        }());

    if (result == null) {
      log.info('error');
      return;
    }

    log.info('Client Data: ${base64.encode(result.clientData)}');
    log.info('Signature: ${base64.encode(result.signatureData)}');
    log.info(
        'Verified: ${result.verifySignature(registration!.userPublicKey)}');
    log.info('Counter value: ${result.counter}');
  }
}
