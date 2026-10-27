#!/bin/sh
# Type-check styx and styx-runtime for Linux, Windows and macOS from Linux.
# `cargo check` never links, so C dependencies (aws-lc-sys) are built with a
# stub compiler/archiver that emits empty objects. This is not a native build.
# usage: cross-check.sh [linux|win|mac|all]   (uses the caller's Rust env)
set -u
stub="${CARGO_TARGET_DIR:-target}/stub-cc"
mkdir -p "$stub"
cat > "$stub/cc" <<'CC'
#!/bin/sh
out=""; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a";; esac
  case "$a" in -Fo*|/Fo*) out="${a#?Fo}";; esac
  prev="$a"
done
case "$*" in *--version*|*-dumpversion*) echo "stub 1.0"; exit 0;; esac
[ -n "$out" ] && : > "$out"
exit 0
CC
cat > "$stub/ar" <<'AR'
#!/bin/sh
o=""
for a in "$@"; do case "$a" in -out:*|-OUT:*|/OUT:*|/out:*) o="${a#*:}";; esac; done
[ -z "$o" ] && for a in "$@"; do case "$a" in *.a|*.lib) o="$a"; break;; esac; done
[ -n "$o" ] && printf '!<arch>\n' > "$o"
exit 0
AR
chmod +x "$stub/cc" "$stub/ar"
export CC_x86_64_pc_windows_msvc="$stub/cc" AR_x86_64_pc_windows_msvc="$stub/ar"
export CC_x86_64_apple_darwin="$stub/cc" AR_x86_64_apple_darwin="$stub/ar"
status=0
run() {
  echo "== $1"
  cargo check --locked -p styx-runtime -p styx --all-targets $2 --message-format short 2>&1 \
    | grep -E '^(src|error)|Finished' | sort -u
  cargo check --locked -p styx-runtime -p styx --all-targets $2 --message-format short >/dev/null 2>&1 || status=1
}
case "${1:-all}" in
  linux) run linux "";;
  win) run win "--target x86_64-pc-windows-msvc";;
  mac) run mac "--target x86_64-apple-darwin";;
  all) run linux ""; run win "--target x86_64-pc-windows-msvc"; run mac "--target x86_64-apple-darwin";;
  *) echo "usage: $0 [linux|win|mac|all]" >&2; exit 2;;
esac
exit $status
