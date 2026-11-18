# อิ่มอุ่น

Flutter application for tracking meals and nutrition.

## iOS development

The project was migrated and built with Flutter 3.44.9, Dart 3.12.2 and Xcode 27.1. The iOS deployment target is 15.0. Install the Flutter SDK and Xcode, then run:

```sh
flutter pub get
flutter build ios --simulator
```

Before distributing, set a unique Bundle Identifier and select the owner's Apple Developer team in `ios/Runner.xcworkspace`. Configure signing and test the release on physical devices. The current `com.example.projectMom` identifier is a placeholder and cannot be treated as a production identifier. Store submission also requires privacy disclosures and review of the nutrition content.

## Android development and release

The Android project targets API 36 and uses Gradle 8.13 with JDK 21. Configure Flutter to use a compatible JDK if the Android Studio JDK is newer, then build a test APK with `flutter build apk --debug`.
The application ID remains `com.example.project_mom` for compatibility with the supplied APK. Before publishing an update, verify the existing Play Console app ID, its latest version code, and the signing or upload key. Changing the application ID creates a separate app. Version `1.0.1+2` is newer than the supplied APK, but must also be higher than any version already uploaded to Play Console.

For a Play Store release, configure Play App Signing and create `android/key.properties` using the appropriate existing upload key, or a new key only when appropriate for a new app:

```properties
storePassword=<store password>
keyPassword=<key password>
keyAlias=<key alias>
storeFile=<absolute path to keystore>
```

Keep the key and passwords secure and backed up. These files must not be committed. Then run `flutter build appbundle --release` and verify the signed bundle before uploading it. Without `key.properties`, the release build is unsigned and cannot be uploaded as a release.

## Security and privacy status

- Health records are stored locally in the app's Sembast database. Application logs containing these records and calculation results have been removed.
- On iOS, the app applies the `completeUntilFirstUserAuthentication` file protection class to its Documents directory and existing immediate children at launch. Verify this on a physical, passcode-protected device; this is OS file protection and is not application-level database encryption.
- On Android, application data is in internal app storage and cleartext HTTP is disabled. Platform protection depends on the device and OS; it is not application-level database encryption.
- Local records use AES-256-GCM with a random key stored through the platform secure-storage plugin. On first open the app creates and verifies an encrypted copy before removing the previous plaintext database. Interrupted migrations are retried and missing keys do not cause an existing encrypted database to be overwritten.
- The app can export a manually initiated, password-protected backup using PBKDF2-HMAC-SHA256 and AES-256-GCM and restore it transactionally. Users must retain both the backup file and password; forgotten passwords cannot be recovered.
- Android excludes app documents and preferences from system backup and device transfer. Export a portable backup and keep it outside the app with its password before reinstalling or changing devices. If an older system backup restores an unreadable database, choose **กู้คืนจากไฟล์สำรอง** on the Android startup error screen. The app opens the verified backup under a new device key and preserves the original database file. Test the workflow on a physical Android device before production rollout.
- This is not a security audit. Before release, review all dependencies, verify privacy manifests and network/backup behavior on real devices, check signing and key management, and publish an accurate privacy policy.
