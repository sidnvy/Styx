#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-status}"
case "$cmd" in
  start|stop|status|selftest) ;;
  *)
    printf 'usage: %s [start|stop|status|selftest]\n' "$0" >&2
    exit 2
    ;;
esac

adb_args=()
if [[ -n "${STYX_ANDROID_DEVICE:-}" ]]; then
  adb_args=(-s "$STYX_ANDROID_DEVICE")
fi

run_adb() {
  adb "${adb_args[@]}" "$@"
}

resolve_apk() {
  local path
  path="$(run_adb shell "pm path com.styx.host" | head -n 1 | cut -d: -f2 | tr -d '\r')"
  if [[ -z "$path" ]]; then
    echo "com.styx.host is not installed on target device" >&2
    exit 1
  fi
  printf '%s' "$path"
}

case "$cmd" in
  selftest)
    apk="$(resolve_apk)"
    run_adb shell "CLASSPATH='$apk' app_process / com.styx.host.vdisplay.VDisplayHelperMain --self-test"
    ;;
  start)
    apk="$(resolve_apk)"
    run_adb shell "
      set -e
      if [ -f /data/local/tmp/styx-vdisplay.pid ]; then
        old=\$(cat /data/local/tmp/styx-vdisplay.pid 2>/dev/null || true)
        if [ -n \"\$old\" ] && kill -0 \"\$old\" 2>/dev/null; then
          kill \"\$old\" 2>/dev/null || true
          sleep 1
        fi
      fi
      for p in \$(pgrep -x styx-vdisplay 2>/dev/null || true); do
        [ \"\$p\" != \"\$\$\" ] && kill \"\$p\" 2>/dev/null || true
      done
      rm -f /data/local/tmp/styx-vdisplay.pid
      setsid nohup env CLASSPATH='$apk' app_process / com.styx.host.vdisplay.VDisplayHelperMain </dev/null >/data/local/tmp/styx-vdisplay.log 2>&1 &
      echo \$! > /data/local/tmp/styx-vdisplay.pid
    "
    sleep 2
    run_adb shell "
      pid=\$(cat /data/local/tmp/styx-vdisplay.pid 2>/dev/null || true)
      if [ -z \"\$pid\" ] || ! kill -0 \"\$pid\" 2>/dev/null; then
        cat /data/local/tmp/styx-vdisplay.log 2>/dev/null || true
        exit 1
      fi
      ps -p \"\$pid\" -o pid,uid,args
      tail -n 10 /data/local/tmp/styx-vdisplay.log 2>/dev/null || true
    "
    ;;
  stop)
    run_adb shell "
      if [ -f /data/local/tmp/styx-vdisplay.pid ]; then
        pid=\$(cat /data/local/tmp/styx-vdisplay.pid 2>/dev/null || true)
        if [ -n \"\$pid\" ]; then
          kill \"\$pid\" 2>/dev/null || true
        fi
        rm -f /data/local/tmp/styx-vdisplay.pid
      fi
      for p in \$(pgrep -x styx-vdisplay 2>/dev/null || true); do
        [ \"\$p\" != \"\$\$\" ] && kill \"\$p\" 2>/dev/null || true
      done
    "
    ;;
  status)
    run_adb shell "
      pid=\$(cat /data/local/tmp/styx-vdisplay.pid 2>/dev/null || true)
      if [ -n \"\$pid\" ] && kill -0 \"\$pid\" 2>/dev/null; then
        ps -p \"\$pid\" -o pid,uid,args
      else
        echo 'styx-vdisplay: not running'
      fi
      tail -n 10 /data/local/tmp/styx-vdisplay.log 2>/dev/null || true
    "
    ;;
esac
