import 'dart:math';
import 'dart:typed_data';
import 'package:asn1lib/asn1lib.dart';
import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';

class CryptoHelper {
  final ECDomainParameters _domainParams = ECDomainParameters('secp256k1');

  // Generate Key Pair
  AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
    var keyParams = ECKeyGeneratorParameters(_domainParams);
    var secureRandom = FortunaRandom();
    var random = Random.secure();
    var seed = List<int>.generate(32, (_) => random.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seed)));
    var rngParams = ParametersWithRandom(keyParams, secureRandom);
    var keyGenerator = ECKeyGenerator();
    keyGenerator.init(rngParams);
    return keyGenerator.generateKeyPair();
  }

  // Sign message hash
  ECSignature sign(Uint8List messageHash, PrivateKey privateKey) {
    var signer = ECDSASigner(null, HMac(SHA256Digest(), 64));
    signer.init(true, PrivateKeyParameter<ECPrivateKey>(privateKey));

    return signer.generateSignature(messageHash) as ECSignature;
  }

  // Verify signature
  bool verify(
      Uint8List messageHash, ECSignature signature, PublicKey publicKey) {
    var verifier = ECDSASigner(null, HMac(SHA256Digest(), 64));
    verifier.init(false, PublicKeyParameter<ECPublicKey>(publicKey));

    return verifier.verifySignature(messageHash, signature);
  }

  // Hash message
  hashMessage(String message) {
    return SHA256Digest().process(Uint8List.fromList(message.codeUnits));
  }

  // Convert public key to hex
  String publicKeyToHex(ECPublicKey publicKey) {
    return hex.encode(publicKey.Q!.getEncoded(false));
  }

  // Convert DER encoded signature to hex
  String encodeECSignatureToDER(ECSignature signature) {
    var r = ASN1Integer(signature.r);
    var s = ASN1Integer(signature.s);

    var sequence = ASN1Sequence();
    sequence.add(r);
    sequence.add(s);

    return hex.encode(sequence.encodedBytes);
  }

  // Convert hex encoded signature to DER
  String privateKeyToHex(ECPrivateKey privateKey) {
    return privateKey.d!.toRadixString(16);
  }

  // Convert hex encoded signature to DER
  String messageHashToHex(Uint8List messageHash) {
    return hex.encode(messageHash);
  }

  // Convert signature to hex
  String signatureToHex(ECSignature signature) {
    return signature.r.toRadixString(16) + signature.s.toRadixString(16);
  }
}
