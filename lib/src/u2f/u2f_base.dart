// ignore_for_file: require_trailing_commas

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'log.dart';
import 'registration.dart';
import 'signature.dart';

abstract class U2fV2Base {
  U2fV2Base();

  bool _cancelOperations = false;
  bool get cancelOperations => _cancelOperations;

  @mustCallSuper
  Future<void> init() async {}

  Future<U2fRegistration> register(
    String challenge,
    String appId,
    String origin,
    String name,
    String displayName,
    List<Uint8List> existingKeyHandles,
    Duration timeout,
  );

  Future<U2fSignature> authenticate(
    String appId,
    List<Uint8List> keyHandles,
    String challenge,
    String origin,
    Duration timeout,
  );

  @mustCallSuper
  Future<void> dispose() async {
    log.fine('Finish U2F session');
    _cancelOperations = true;
  }
}
