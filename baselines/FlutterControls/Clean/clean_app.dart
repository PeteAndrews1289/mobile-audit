// Source-only negative control for the narrow Flutter patterns.
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

final secureStorage = FlutterSecureStorage();

Future<void> saveToken(String token) async {
  await secureStorage.write(key: 'auth_token', value: token);
}

Future<void> fetchProfile() async {
  await http.get(Uri.parse('https://example.invalid/profile'));
}

Future<void> saveDisplaySetting() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('cardNote', 'draft');
  await prefs.setInt('tokenCount', 3);
}

void recordLoginAttempt() {
  // AES(key, mode: AESMode.ecb) is a comment, not executed code.
  print('Login attempt completed');
}
