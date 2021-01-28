#!/bin/bash

set -e
if [ "$DEBUG" == 1 ]; then
    set -x
    COMMON_OPTS="--debug"
fi

if [ "0$(tput colors 2> /dev/null)" -ge 16 ]; then
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    GREEN='\033[0;32m'
    NC='\033[0m'
fi

localdir="$(readlink -f "$(dirname "$0")")"

QUBES_OPTS="$COMMON_OPTS --builder mock"
QUBES_OPTS="$QUBES_OPTS --extra-repository-file $localdir/repos/qubes-r4.repo --extra-repository-key $localdir/keys/RPM-GPG-KEY-qubes-4-primary"
#QUBES_OPTS="$QUBES_OPTS --gpg-verify --gpg-verify-key $localdir/keys/RPM-GPG-KEY-qubes-4-primary"

echo_info() {
    echo -e "${BLUE}[I]${NC} $*" >&2
}

echo_ok() {
    echo -e "${GREEN}[I]${NC} $*" >&2
}

echo_err() {
    echo -e "${RED}[E]${NC} $*" >&2
}

get_srcpkgname() {
python3 - "$1" <<EOL
import sys
import koji
res = koji.parse_NVRA(sys.argv[1])
print(res['name'])
EOL
}

get_srcpkgver() {
python3 - "$1" <<EOL
import sys
import koji
res = koji.parse_NVRA(sys.argv[1])
print(res['version'] + '-' + res['release'])
EOL
}

do_build() {
    buildinfo="$1"
    parsed_name="$(basename "$buildinfo" | sed 's/.buildinfo//')"
    package="$(get_srcpkgname "$parsed_name")"
    version="$(get_srcpkgver "$parsed_name")"
    output="/tmp/sources/$package/$version"
    DEBREBUILD_OPTS="$QUBES_OPTS"
    if [[ "$buildinfo" =~ .unreproducible$ ]]; then
        DEBREBUILD_OPTS="$DEBREBUILD_OPTS --no-checksums-verification"
    fi
    "$localdir"/../rpmreproduce.py $DEBREBUILD_OPTS --output "$output" "$buildinfo" || return 1
    cd "$output"
    ln -sf $package*.buildinfo buildinfo
    ln -sf rebuild*.link metadata
}

buildinfos=("$localdir"/data/*.buildinfo*)
#buildinfos+=(
#    "https://deb.qubes-os.org/r4.1/vm/pool/main/libc/libcomps/libcomps_0.1.15-2+deb11u1_amd64.buildinfo"
#    "https://deb.qubes-os.org/r4.1/vm/pool/main/q/qubes-gui-agent/qubes-gui-agent_4.1.15-1+deb11u1_amd64.buildinfo"
#)
failed_buildinfos=()

for f in ${buildinfos[*]}; do
    bn_buildinfo="$(basename "$f")"
    echo_info "DEBREBUILD: $bn_buildinfo"
    if do_build "$f"; then
        echo_ok "SUCCESS: $f"
    else
        failed_buildinfos+=("$bn_buildinfo")
        echo_err "FAIL: $f"
    fi
done

if [ -n "${failed_buildinfos[*]}" ]; then
    echo_err "The following buildinfo failed to rebuild: ${failed_buildinfos[*]}"
fi
