import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:sembast/sembast.dart';
import 'package:sembast/sembast_io.dart';
import 'package:sembast/utils/sembast_import_export.dart';
import 'package:synchronized/synchronized.dart';

import 'portable_backup.dart';

/// A versioned, authenticated codec. Each record receives a fresh random nonce.
class DatabaseEncryptionCodec extends AsyncContentCodecBase {
  DatabaseEncryptionCodec(List<int> key) : _key = SecretKey(key);

  final SecretKey _key;
  final AesGcm _cipher = AesGcm.with256bits();

  @override
  Future<String> encodeAsync(Object? input) async {
    final box = await _cipher.encrypt(
      utf8.encode(jsonEncode(input)),
      secretKey: _key,
    );
    return base64Encode(box.concatenation());
  }

  @override
  Future<Object?> decodeAsync(String encoded) async {
    final bytes = base64Decode(encoded);
    final box = SecretBox.fromConcatenation(
      bytes,
      nonceLength: 12,
      macLength: 16,
    );
    final clear = await _cipher.decrypt(box, secretKey: _key);
    return jsonDecode(utf8.decode(clear));
  }
}

/// Serializes initialization and retains one open handle per database.
class SecureDatabaseManager {
  SecureDatabaseManager({
    required this.readKey,
    required this.writeKey,
    this.readRecoveryKey,
    this.writeRecoveryKey,
  });

  final Future<String?> Function() readKey;
  final Future<void> Function(String) writeKey;
  final Future<String?> Function(String)? readRecoveryKey;
  final Future<void> Function(String, String)? writeRecoveryKey;
  final _lock = Lock();
  final Map<String, Database> _open = {};

  SembastCodec _codec(String? encodedKey) {
    if (encodedKey == null) {
      throw StateError('Database encryption key unavailable.');
    }
    final key = base64Decode(encodedKey);
    if (key.length != 32) throw StateError('Invalid database encryption key.');
    return SembastCodec(
      signature: 'imun-aes-gcm-v1',
      codec: DatabaseEncryptionCodec(key),
    );
  }

  /// Restores a verified portable backup while the startup database is closed.
  /// Publish the new database only after its key and records can be read back.
  Future<void> recover(String legacyPath, Map<String, Object?> data) =>
      _lock.synchronized(() async {
        final read = readRecoveryKey;
        final write = writeRecoveryKey;
        if (read == null || write == null || _open.containsKey(legacyPath)) {
          throw StateError('Startup recovery is unavailable.');
        }
        final random = Random.secure();
        final generation = List.generate(
          16,
          (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
        ).join();
        final directory = await Directory('$legacyPath.recovery').create();
        final path = '${directory.path}/$generation.db';
        final pending = File('${directory.path}/$generation.pending');
        final encodedKey = base64Encode(
          List<int>.generate(32, (_) => random.nextInt(256)),
        );

        try {
          await write(generation, encodedKey);
          final persisted = await read(generation);
          if (persisted != encodedKey) {
            throw StateError('Could not save recovery key.');
          }
          final codec = _codec(persisted);
          final db = await databaseFactoryIo.openDatabase(path, codec: codec);
          final String expected;
          try {
            await PortableBackup().restore(db, data);
            expected = jsonEncode(await exportDatabase(db));
          } finally {
            await db.close();
          }
          final reopened = await databaseFactoryIo.openDatabase(
            path,
            codec: codec,
          );
          try {
            if (jsonEncode(await exportDatabase(reopened)) != expected) {
              throw StateError('Restored database verification failed.');
            }
          } finally {
            await reopened.close();
          }
          await pending.writeAsString(generation, flush: true);
          await pending.rename('${directory.path}/active');
        } catch (_) {
          await databaseFactoryIo.deleteDatabase(path);
          if (await pending.exists()) await pending.delete();
          rethrow;
        }
      });

  Future<Database> open(String legacyPath) => _lock.synchronized(() async {
    final existing = _open[legacyPath];
    if (existing != null) return existing;

    final directory = '$legacyPath.recovery';
    final active = File('$directory/active');
    if (await active.exists()) {
      final generation = await active.readAsString();
      if (!RegExp(r'^[a-f0-9]{32}$').hasMatch(generation)) {
        throw StateError('Invalid recovery database identifier.');
      }
      final path = '$directory/$generation.db';
      if (!await File(path).exists()) {
        throw StateError('Recovered database file is missing.');
      }
      final codec = _codec(await readRecoveryKey?.call(generation));
      final db = await databaseFactoryIo.openDatabase(path, codec: codec);
      _open[legacyPath] = db;
      return db;
    }

    final securePath = '$legacyPath.secure';
    final tempPath = '$securePath.migrating';
    final secureFile = File(securePath);
    final legacyFile = File(legacyPath);
    var encodedKey = await readKey();
    if (encodedKey == null) {
      if (await secureFile.exists()) {
        throw StateError(
          'Database encryption key unavailable; existing data was preserved.',
        );
      }
      final random = Random.secure();
      encodedKey = base64Encode(
        List<int>.generate(32, (_) => random.nextInt(256)),
      );
      await writeKey(encodedKey);
      // Verify the key was persisted before creating encrypted data.
      if (await readKey() != encodedKey) {
        throw StateError('Could not save database encryption key.');
      }
    }
    final codec = _codec(encodedKey);

    if (!await secureFile.exists() && await legacyFile.exists()) {
      // A failed attempt leaves the source untouched; the temporary copy is
      // never treated as authoritative and can safely be recreated.
      await databaseFactoryIo.deleteDatabase(tempPath);
      final oldDb = await databaseFactoryIo.openDatabase(legacyPath);
      Map<String, Object?> exported;
      try {
        exported = await exportDatabase(oldDb);
      } finally {
        await oldDb.close();
      }
      final newDb = await importDatabase(
        exported,
        databaseFactoryIo,
        tempPath,
        codec: codec,
      );
      try {
        if (jsonEncode(await exportDatabase(newDb)) != jsonEncode(exported)) {
          throw StateError('Database migration verification failed.');
        }
      } finally {
        await newDb.close();
      }
      // Verify that the encrypted file is independently readable before the
      // atomic rename; the original is still available if anything fails.
      final verifyDb = await databaseFactoryIo.openDatabase(
        tempPath,
        codec: codec,
      );
      try {
        if (jsonEncode(await exportDatabase(verifyDb)) !=
            jsonEncode(exported)) {
          throw StateError('Encrypted database verification failed.');
        }
      } finally {
        await verifyDb.close();
      }
      await File(tempPath).rename(securePath);
    }

    final db = await databaseFactoryIo.openDatabase(securePath, codec: codec);
    try {
      // If interrupted after the rename, verify the encrypted copy on the next
      // launch before removing the old plaintext file.
      if (await legacyFile.exists()) {
        final legacy = await databaseFactoryIo.openDatabase(legacyPath);
        try {
          if (jsonEncode(await exportDatabase(legacy)) !=
              jsonEncode(await exportDatabase(db))) {
            throw StateError(
              'Legacy and encrypted databases differ; both were preserved.',
            );
          }
        } finally {
          await legacy.close();
        }
        await databaseFactoryIo.deleteDatabase(legacyPath);
      }
      _open[legacyPath] = db;
      return db;
    } catch (_) {
      await db.close();
      rethrow;
    }
  });

  Future<void> close() => _lock.synchronized(() async {
    for (final db in _open.values) {
      await db.close();
    }
    _open.clear();
  });
}

final _secureStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(resetOnError: false),
);
FlutterSecureStorage _recoveryStorage(String generation) =>
    FlutterSecureStorage(
      aOptions: AndroidOptions(
        resetOnError: false,
        storageNamespace: 'imun_recovery_$generation',
      ),
    );

final secureDatabaseManager = SecureDatabaseManager(
  readKey: () => _secureStorage.read(key: 'imun_database_key_v1'),
  writeKey: (value) =>
      _secureStorage.write(key: 'imun_database_key_v1', value: value),
  readRecoveryKey: (generation) =>
      _recoveryStorage(generation).read(key: 'imun_recovery_$generation'),
  writeRecoveryKey: (generation, value) => _recoveryStorage(
    generation,
  ).write(key: 'imun_recovery_$generation', value: value),
);
