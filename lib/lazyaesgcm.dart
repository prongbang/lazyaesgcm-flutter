library lazyaesgcm;

import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';

abstract class LazyAesGcm {
  /// Constructs a LazyAesGcm.
  LazyAesGcm();

  static LazyAesGcm instance = LazyAesGcm256();

  Future<String> encrypt(String plaintext, String key);

  Future<String> decrypt(String ciphertext, String key);
}

class LazyAesGcm256 implements LazyAesGcm {
  final algorithm = AesGcm.with256bits();

  @override
  Future<String> encrypt(String plaintext, String key) async {
    final nonce = algorithm.newNonce();
    final secretKey = SecretKey(hex.decode(key));
    final secretBox = await algorithm.encrypt(
      utf8.encode(plaintext),
      nonce: nonce,
      secretKey: secretKey,
    );
    return hex.encode(secretBox.concatenation());
    ;
  }

  @override
  Future<String> decrypt(String ciphertext, String key) async {
    final cipherBytes = hex.decode(ciphertext);
    final secretKey = SecretKey(hex.decode(key));
    final secretBox = SecretBox.fromConcatenation(
      cipherBytes,
      nonceLength: algorithm.nonceLength,
      macLength: algorithm.macAlgorithm.macLength,
    );
    final decrypted = await algorithm.decrypt(secretBox, secretKey: secretKey);
    return utf8.decode(decrypted);
  }
}
