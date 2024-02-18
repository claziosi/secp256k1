import 'dart:math';
import 'package:dart/cryptohelper.dart';
import 'package:flutter/material.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/ecc/api.dart';

import 'package:http/http.dart' as http;
import 'dart:convert'; // For JSON encoding/decoding

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('ECDSA secp256k1 Example')),
        body: const MyHomePage(),
      ),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final CryptoHelper cryptoHelper = CryptoHelper();

  String privateKeyStr = '';
  String publicKeyStr = '';
  String messageHashStr = '';
  String signatureDERStr = '';
  String signatureStr = '';
  String verificationResult = '';
  String validateDERBackend = '';
  String validateCompactBackend = '';

  Future<void> _generateAndSign() async {
    // Nonce to be synchronized between client and server
    var nonce = "30450221009137c8489f844822843868d77f93c288ea64427005";

    // Generate Key Pair
    AsymmetricKeyPair<PublicKey, PrivateKey> keyPair =
        cryptoHelper.generateKeyPair();

    // Update Private Key
    setState(() {
      privateKeyStr =
          cryptoHelper.privateKeyToHex(keyPair.privateKey as ECPrivateKey);
    });

    // Update Public Key
    setState(() {
      publicKeyStr =
          cryptoHelper.publicKeyToHex(keyPair.publicKey as ECPublicKey);
    });

    // Generate a random message string
    var random = Random.secure();
    var messageInt = List<int>.generate(32, (_) => random.nextInt(256));
    var messageStr = String.fromCharCodes(messageInt);

    // messagehash from Hello World!
    var message =
        cryptoHelper.messageHashToHex(cryptoHelper.hashMessage(messageStr));

    // Convert string variable into UInt8List
    var messageHash = cryptoHelper.hashMessage(message + nonce);
    // Concatenate message hash and nonce

    // Update Message Hash
    setState(() {
      messageHashStr = message;
    });

    // Sign the hash with private key
    ECSignature signature = cryptoHelper.sign(messageHash, keyPair.privateKey);

    // Convert signature to DER format for display purposes
    String derEncodedSignature = cryptoHelper.encodeECSignatureToDER(signature);
    setState(() {
      signatureStr = derEncodedSignature;
    });

    // Verify Signature with public key
    bool isVerified =
        cryptoHelper.verify(messageHash, signature, keyPair.publicKey);

    // Send signature to backend for verification
    bool isValidateCompactBackend = await validateSignatureOnBackend(
        messageHashStr, signatureStr, publicKeyStr);
    setState(() {
      validateCompactBackend = isValidateCompactBackend ? 'Valid' : 'Invalid';
    });

    // Update Verification Result
    setState(() {
      verificationResult = isVerified ? 'Valid' : 'Invalid';
    });
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          ElevatedButton(
            onPressed: _generateAndSign,
            child: const Text("Generate Keys and Sign"),
          ),
          const SizedBox(height: 20), // Add spacing between button and text
          if (privateKeyStr.isNotEmpty)
            InfoCard(title: "Private Key", content: privateKeyStr),
          if (publicKeyStr.isNotEmpty)
            InfoCard(title: "Public Key", content: publicKeyStr),
          if (messageHashStr.isNotEmpty)
            InfoCard(title: "Message Hash (SHA-256)", content: messageHashStr),
          if (signatureStr.isNotEmpty)
            InfoCard(
                title: "Signature in Hexadecimal Format",
                content: signatureStr),
          if (verificationResult.isNotEmpty)
            InfoCard(
                title: "Signature Verification Result (in App)",
                content: verificationResult),
          if (validateCompactBackend.isNotEmpty)
            InfoCard(
                title: "Signature Verification Result (on Backend)",
                content: validateCompactBackend),
        ],
      ),
    );
  }
}

// A custom widget to display information with a title and content.
class InfoCard extends StatelessWidget {
  const InfoCard({Key? key, required this.title, required this.content})
      : super(key: key);

  final String title;
  final String content;

  @override
  Widget build(BuildContext context) {
    return Card(
        elevation: 5.0,
        margin: const EdgeInsets.symmetric(vertical: 8.0),
        child: ListTile(
          title:
              Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
          subtitle: SelectableText(content),
        ));
  }
}

Future<bool> validateSignatureOnBackend(
  String messageHashHex,
  String signatureHex,
  String publicKeyHex,
) async {
  final url = Uri.parse('http://localhost:8080/auth');

  final tokenStr = "$publicKeyHex:$signatureHex:$messageHashHex";
  final token = base64.encode(utf8.encode(tokenStr));
  print('Token: $token');

  try {
    final response = await http.get(
      url,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token'
      },
    );

    if (response.statusCode == 200) {
      print('Request successful. Response body: ${response.body}');
      // Handle response here if necessary (e.g., parse JSON)
      return response.body == 'Authenticated';
    } else {
      print(
          'Request failed with status: ${response.statusCode}. Response body: ${response.body}');
      return false;
    }
  } catch (e) {
    print("Error sending request to backend: $e");
    return false;
  }
}
