import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lazyaesgcm/keypair.dart';

import 'package:lazyaesgcm/lazyaesgcm.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late LazyAesGcm lazyAesGcm;

  setUp(() {
    lazyAesGcm = LazyAesGcm.instance;
  });

  test('Should return ciphertext when encrypt success', () async {
    // Given
    const sharedKey =
        'e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d';
    const plaintext =
        '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}';

    // When
    final actual = await lazyAesGcm.encrypt(plaintext, sharedKey);

    // Then
    expect(actual, isNotNull);
    debugPrint(actual);
  });

  test('Should return plaintext when decrypt success', () async {
    // Given
    const sharedKey =
        'e4f7fe3c8b4066490f8ffde56f080c70629ff9731b60838015027c4687303b1d';
    const ciphertext =
        '84d685b20c1a647d1bdfddd575fe506163e2215142df6494f9430619e24271240bea94340ed26651573fd125328d9b18d63d6f464f0f7024474ac3864fea59f34dbdbfd5119de23985a0c8549440626dae5d54c00c3171b58f084dda82656c34ecf1de4eb11b33b208a52cac97eb78d88987a4cdd79b11a0713857563df328bfbb52d1c0c04ba931ec';
    const plaintext =
        '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}';

    // When
    final actual = await lazyAesGcm.decrypt(ciphertext, sharedKey);

    // Then
    expect(actual, plaintext);
  });

  test(
    'Should return ciphertext and plaintext when encrypt and decrypt success',
    () async {
      // Given
      final clientKp = await KeyPair.newKeyPair();
      final serverKp = await KeyPair.newKeyPair();
      final clientSharedKey = await clientKp.sharedKey(serverKp.pk);
      const plaintext =
          '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}';

      // When
      final actualCipherText =
          await lazyAesGcm.encrypt(plaintext, clientSharedKey);
      final actualPlainText =
          await lazyAesGcm.decrypt(actualCipherText, clientSharedKey);

      // Then
      expect(actualPlainText, plaintext);
    },
  );
}
