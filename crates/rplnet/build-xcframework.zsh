#!/bin/zsh
# Build RPLNet.xcframework and the release bundle the RenPyLinter app pins.
#
#   crates/rplnet/build-xcframework.zsh <output-dir>
#
# Output: <output-dir>/rplnet-<version>-ios.tar.gz, containing
#   RPLNet.xcframework/      ios-arm64 and ios-arm64-simulator static libraries
#                            with the rplnetFFI C header and module map
#   Sources/rplnet.swift     UniFFI Swift bindings, compiled into the app
#   build-info.json          what was built, from which commit, with which tools
#   SHA256SUMS               every other file of the bundle
#
# In each slice the Rust and C objects are merged into one relocatable object
# in which only the UniFFI entry points (`_uniffi_*`, `_ffi_*`) stay global.
# Everything else (std, steamroom, ring, zstd, ...) becomes private extern: still
# resolvable within the app's static link, never exported, and local in the
# linked app, so its Release link (STRIP_STYLE = non-global, -export_dynamic)
# neither exports nor keeps those symbols. Debug information is dropped from the object, and so is
# the LLVM bitcode that Rust embeds in the objects of its prebuilt standard
# library (`__LLVM,__bitcode`, written by Rust's LLVM, which Apple's tools
# cannot read; `nm` runs with --no-llvm-bc for that reason).
#
# Only objects marked MH_SUBSECTIONS_VIA_SYMBOLS are merged: one unmarked input
# leaves the whole merged object unmarked, and the app's linker can then not
# dead-strip it symbol by symbol (it kept 9.8 MB instead of what is used). The
# unmarked objects are hand-written assembly (compiler-rt's LSE atomics, ring's
# perlasm); they go into the archive unchanged and reach the symbols they need
# from the merged object as private externs.
#
# The working tree must be clean unless RPLNET_ALLOW_DIRTY=1 (local trials);
# a dirty build is marked in build-info.json and its version string.

set -euo pipefail

crate_dir=${0:A:h}
workspace=${crate_dir:h:h}
output=${1:?usage: build-xcframework.zsh <output-dir>}
output=${output:A}

deployment_target=18.6
profile=rplnet-release
typeset -A slices=(
  aarch64-apple-ios     "ios-arm64 ios iphoneos"
  aarch64-apple-ios-sim "ios-arm64-simulator ios-simulator iphonesimulator"
)

cd $workspace

source_commit=$(git rev-parse HEAD)
dirty=false
if [[ -n $(git status --porcelain) ]]; then
  if [[ ${RPLNET_ALLOW_DIRTY:-0} != 1 ]]; then
    print -u2 "error: working tree is not clean; commit first or set RPLNET_ALLOW_DIRTY=1"
    exit 1
  fi
  dirty=true
  source_commit="$source_commit-dirty"
fi
version=$(cargo metadata --format-version 1 --no-deps --locked \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "rplnet"))')

work=$(mktemp -d "${TMPDIR:-/tmp}/rplnet-xcframework.XXXXXX")
trap 'rm -rf $work' EXIT

# The deployment target applies to Rust and to C code built by cc (ring,
# zstd); without it the C objects target the SDK's own iOS version.
export IPHONEOS_DEPLOYMENT_TARGET=$deployment_target
export RPLNET_SOURCE_COMMIT=$source_commit

for target in ${(k)slices}; do
  cargo build --locked -p rplnet --profile $profile --target $target
done

for target in ${(k)slices}; do
  read -r slice platform sdk <<< "${slices[$target]}"
  archive=target/$target/$profile/librplnet.a
  sdk_version=$(xcrun --sdk $sdk --show-sdk-version)
  mkdir -p $work/$slice

  members=$work/$slice/members
  mkdir -p $members/merged $members/asm
  if [[ -n $(ar -t $archive | sort | uniq -d) ]]; then
    print -u2 "error: $archive has duplicate member names; extracting it would lose objects"
    exit 1
  fi
  (cd $members && ar -x $workspace/$archive)
  for object in $members/*.o; do
    if otool -hv $object | tail -1 | grep -q SUBSECTIONS_VIA_SYMBOLS; then
      mv $object $members/merged/
    else
      mv $object $members/asm/
    fi
  done
  print -l $members/merged/*.o > $work/$slice/merged.filelist
  asm_objects=($members/asm/*.o(N))

  nm --no-llvm-bc -gUj $members/merged/*.o | grep -E '^_(uniffi|ffi)_' | sort -u > $work/$slice/exported.txt
  if [[ ! -s $work/$slice/exported.txt ]]; then
    print -u2 "error: $archive defines no UniFFI symbols"
    exit 1
  fi

  xcrun ld -r -arch arm64 \
    -platform_version $platform $deployment_target $sdk_version \
    -S \
    -keep_private_externs \
    -exported_symbols_list $work/$slice/exported.txt \
    -filelist $work/$slice/merged.filelist \
    -o $work/$slice/rplnet.o
  if ! otool -hv $work/$slice/rplnet.o | tail -1 | grep -q SUBSECTIONS_VIA_SYMBOLS; then
    print -u2 "error: $slice merged object lost MH_SUBSECTIONS_VIA_SYMBOLS; it could not be dead-stripped"
    exit 1
  fi
  if otool -l $work/$slice/rplnet.o | grep -q 'segname __LLVM'; then
    print -u2 "error: $slice still carries embedded LLVM bitcode"
    exit 1
  fi
  xcrun libtool -static -no_warning_for_no_symbols -o $work/$slice/librplnet.a $work/$slice/rplnet.o $asm_objects

  # Gate: the merged object's only global (not private extern) definitions are
  # the entry points, and the assembly objects define no Rust symbols (those
  # would stay global in the app).
  nm --no-llvm-bc -m $work/$slice/rplnet.o | grep -v '(undefined)' \
    | grep ' external ' | grep -v 'private external' | awk '{print $NF}' | sort -u > $work/$slice/globals.txt
  if ! diff -q $work/$slice/exported.txt $work/$slice/globals.txt > /dev/null; then
    print -u2 "error: $slice merged object exports symbols beyond the list:"
    comm -13 $work/$slice/exported.txt $work/$slice/globals.txt | head -20 >&2
    exit 1
  fi
  if (( ${#asm_objects} )) && nm --no-llvm-bc -gUj $asm_objects | grep -q '^__R'; then
    print -u2 "error: $slice assembly objects define Rust symbols"
    exit 1
  fi
done

# Bindings are generated from the device library (identical for both slices).
cargo run --locked -q -p rplnet-bindgen --bin uniffi-bindgen -- generate \
  --library target/aarch64-apple-ios/$profile/librplnet.a \
  --language swift \
  --out-dir $work/bindings
mkdir -p $work/headers
cp $work/bindings/rplnetFFI.h $work/headers/
cp $work/bindings/rplnetFFI.modulemap $work/headers/module.modulemap

bundle=$work/rplnet-$version-ios
mkdir -p $bundle/Sources
xcodebuild -create-xcframework \
  -library $work/ios-arm64/librplnet.a -headers $work/headers \
  -library $work/ios-arm64-simulator/librplnet.a -headers $work/headers \
  -output $bundle/RPLNet.xcframework > /dev/null
cp $work/bindings/rplnet.swift $bundle/Sources/rplnet.swift

python3 - $bundle $version $source_commit $dirty $deployment_target $profile <<'PY'
import json, subprocess, sys
bundle, version, commit, dirty, deployment_target, profile = sys.argv[1:]
def tool(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
metadata = json.loads(tool("cargo", "metadata", "--format-version", "1", "--locked"))
uniffi = sorted({p["version"] for p in metadata["packages"] if p["name"] == "uniffi"})
info = {
    "schema": 1,
    "package": "rplnet",
    "version": version,
    "source_commit": commit,
    "dirty": dirty == "true",
    "deployment_target": deployment_target,
    "profile": profile,
    "slices": {"ios-arm64": "aarch64-apple-ios", "ios-arm64-simulator": "aarch64-apple-ios-sim"},
    "rustc": tool("rustc", "--version"),
    "uniffi": uniffi,
    "xcode": tool("xcodebuild", "-version").splitlines()[0],
}
with open(f"{bundle}/build-info.json", "w") as f:
    json.dump(info, f, indent=2)
    f.write("\n")
PY

(cd $bundle && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
  | while read -r file; do shasum -a 256 "$file"; done > SHA256SUMS)

mkdir -p $output
tarball=$output/rplnet-$version-ios.tar.gz
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs -czf $tarball -C $bundle .
print "built $tarball ($source_commit)"
