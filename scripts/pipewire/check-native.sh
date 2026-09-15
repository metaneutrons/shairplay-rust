#!/usr/bin/env bash
set -euo pipefail

# Native architecture, real RTSP sockets; no live audio runs during compilation.
meson setup /tmp/pw-sanitized /tmp/pipewire --buildtype=debugoptimized \
    -Db_sanitize=address,undefined -Db_ndebug=true -Dauto_features=disabled \
    '-Dsession-managers=[]' -Draop=enabled -Dtests=enabled \
    -Dspa-plugins=enabled -Dsupport=enabled -Ddbus=disabled -Dflatpak=disabled \
    -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled
meson compile -C /tmp/pw-sanitized -j 4 \
    pw-test-raop-iovec pw-test-raop-rtsp-client pw-test-raop-auth
ASAN_OPTIONS=halt_on_error=1:exitcode=86 UBSAN_OPTIONS=halt_on_error=1:exitcode=87 \
    LSAN_OPTIONS=exitcode=88 meson test -C /tmp/pw-sanitized --no-rebuild \
    --print-errorlogs pw-test-raop-iovec pw-test-raop-rtsp-client pw-test-raop-auth
mkdir -p /opt/pipewire/share/qualification
cp /tmp/pw-sanitized/meson-logs/testlog.txt \
    /opt/pipewire/share/qualification/native-sanitizers.txt
rm -rf /tmp/pw-sanitized
