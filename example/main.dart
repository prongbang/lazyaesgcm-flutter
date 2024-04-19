import 'package:lazyaesgcm/keypair.dart';
import 'package:lazyaesgcm/lazyaesgcm.dart';

void main() async {
  final lazyaesgcm = LazyAesGcm.instance;

  // Generate KeyPair
  final clientKeyPair = await KeyPair.newKeyPair();
  final serverKeyPair = await KeyPair.newKeyPair();

  // Key Exchange
  final clientSharedKey = await clientKeyPair.sharedKey(serverKeyPair.pk);
  final serverSharedKey = await serverKeyPair.sharedKey(clientKeyPair.pk);

  // Payload
  const message = 'Hello lazyaesgcm';

  // Encrypt with client
  final ciphertext = await lazyaesgcm.encrypt(message, clientSharedKey);

  // Decrypt with server
  final plaintext = await lazyaesgcm.decrypt(ciphertext, serverSharedKey);

  // Output
  print('Output: $plaintext'); // Output: Hello lazyaesgcm
}
