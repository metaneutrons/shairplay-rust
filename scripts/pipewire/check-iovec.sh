#!/usr/bin/env bash
set -euo pipefail

# Called after installation, while the pinned source/config headers still exist.
export PKG_CONFIG_PATH=/opt/pipewire/lib/pkgconfig
export LD_LIBRARY_PATH=/opt/pipewire/lib
read -r -a flags <<< "$(pkg-config --cflags --libs libpipewire-0.3 openssl)"
cc -D_GNU_SOURCE -Werror=implicit-function-declaration -O1 -g \
    -ffunction-sections -fdata-sections -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I/tmp/pw-build -I/tmp/pipewire/src/modules \
    /tmp/qualification/test-raop-iovec.c \
    /tmp/pipewire/src/modules/module-raop/rtsp-client.c \
    /tmp/pw-build/src/modules/libpipewire-module-rtp-common-lib.a "${flags[@]}" \
    -Wl,--gc-sections -lm -o /tmp/test-raop-iovec
status=0
result=$(/tmp/test-raop-iovec) || status=$?
patch=null
case "$PIPEWIRE_VARIANT" in
    baseline)
        [[ $status == 1 && $result == '{"cases":354,"failures":352}' ]]
        ;;
    iovec-fix)
        [[ $status == 0 && $result == '{"cases":354,"failures":0}' ]]
        patch="\"$(sha256sum /tmp/qualification/raop-iovec.patch | cut -d ' ' -f 1)\""
        ;;
    *) exit 2 ;;
esac
test_sha=$(sha256sum /tmp/qualification/test-raop-iovec.c | cut -d ' ' -f 1)
source_sha=$(sha256sum /tmp/pipewire/src/modules/module-raop-sink.c | cut -d ' ' -f 1)
mkdir -p /opt/pipewire/share/qualification
printf '{"variant":"%s","patch_sha256":%s,"callback_sha256":"%s","regression_sha256":"%s","regression":%s}\n' \
    "$PIPEWIRE_VARIANT" "$patch" "$source_sha" "$test_sha" "$result" \
    | tee /opt/pipewire/share/qualification/sender.json
rm /tmp/test-raop-iovec
