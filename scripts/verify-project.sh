#!/usr/bin/env sh
set -eu
for f in settings.gradle.kts build.gradle.kts app/build.gradle.kts app/src/main/AndroidManifest.xml; do test -f "$f" || exit 1; done
! grep -R 'android:debuggable="true"' app/src/main/AndroidManifest.xml >/dev/null 2>&1
grep -q 'android:allowBackup="false"' app/src/main/AndroidManifest.xml
grep -q 'android:usesCleartextTraffic="false"' app/src/main/AndroidManifest.xml
grep -q 'foregroundServiceType="mediaProjection"' app/src/main/AndroidManifest.xml
echo "PROJECT SECURITY CHECKS: PASS"
