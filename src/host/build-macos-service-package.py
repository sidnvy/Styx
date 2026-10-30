#!/usr/bin/env python3
"""Build one developer-unsigned, profile-bound launchd administrator review package.

No installation, signing, C07 mutation or readiness claim. Installer checkpoints
are cooperative observations, not an atomic transaction with the original Core.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shlex
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

LIMIT = 256 * 1024
PIN = "cb06529011b4c35ffc79f76440beeb88c6e3615e60d993d1485b5be45b307819"
REQUEST_FIELDS = set("schema kind uid username role state_dir state_root canonical_sha256 transaction_id revision definition_path definition_plist definition_sha256 label executable_path executable_sha256 runtime_selection".split())
REPAIR_FIELDS = {"old_definition_sha256", "old_definition_identity", "old_runtime_selection", "original_registration"}
LIFECYCLE_FIELDS = {"action", "original_desired", "original_definition_identity", "original_registration", "original_enabled"}
OBSERVATION_FIELDS = set("path program username arguments pid runs last_exit_code signaled_exit state".split())
REPORT_FIELDS = set("schema operation configuration_only revision desired definition_path definition_plist uid label requires_initial_disabled runtime_selection os operations_replayed transaction_observation installation_request_v1".split())
PLIST_FIELDS = {"Label", "ProgramArguments", "UserName", "WorkingDirectory", "EnvironmentVariables", "RunAtLoad", "KeepAlive", "ProcessType"}


def require(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def closed(value, fields, code):
    require(isinstance(value, dict) and set(value) == fields, code)


def integer(value, minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, "integer_bound")
    return value


def text(value, limit=4096):
    require(isinstance(value, str) and 0 < len(value.encode()) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in value), "bounded_text")
    return value


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "sha256_shape")
    return value


def path(value):
    text(value)
    p = PurePosixPath(value)
    require(value.startswith("/") and value != "/" and str(p) == value and all(v not in (".", "..") for v in value.split("/")[1:]) and "//" not in value, "absolute_normal_path")
    return p


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= LIMIT, "report_bound")
    return json.loads(raw, object_pairs_hook=pairs)


def validate(report):
    closed(report, REPORT_FIELDS, "closed_service_report")
    request = report["installation_request_v1"]
    require(isinstance(request, dict), "installation_request_required")
    repair = request.get("kind") == "launchd_failed_registration_repair"
    lifecycle = request.get("kind") == "launchd_registered_lifecycle"
    closed(request, REQUEST_FIELDS | (LIFECYCLE_FIELDS if lifecycle else REPAIR_FIELDS if repair else set()), "closed_installation_request")
    operation = request["action"] if lifecycle else "prepare_runtime_repair" if repair else "prepare_first_start"
    require(report["schema"] == 1 and type(report["schema"]) is int and report["operation"] == operation and report["configuration_only"] is True and report["operations_replayed"] is False, "configuration_only_report_required")
    require(type(request["schema"]) is int and request["schema"] == 1 and request["kind"] == ("launchd_registered_lifecycle" if lifecycle else "launchd_failed_registration_repair" if repair else "launchd_first_start"), "service_install_kind_required")
    role = request["role"]
    require(role == "gateway" if repair else role in ["gateway", "host"], "service_install_role_refused")
    require(report["os"] == request["original_registration"] if repair or lifecycle else report["os"] is None, "registration_report_binding")
    uid = integer(request["uid"], 1, (1 << 32) - 1)
    user = text(request["username"], 128)
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", user), "closed_username")
    root = request["state_root"]
    closed(root, {"device", "inode", "uid"}, "closed_state_root")
    integer(root["device"]); integer(root["inode"], 1); require(integer(root["uid"], 1, (1 << 32) - 1) == uid, "original_uid_binding")
    state = path(request["state_dir"])
    sha(request["canonical_sha256"]); sha(request["executable_sha256"]); sha(request["definition_sha256"])
    tx = text(request["transaction_id"], 128)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tx), "transaction_shape")
    integer(request["revision"], 1)
    label = "app.styx.native.%d.%s.%s" % (uid, digest(("styx-native-system-service-v1:%d:%d:%d" % (root["device"], root["inode"], uid)).encode())[:32], role)
    require(request["label"] == label and request["definition_path"] == "/Library/LaunchDaemons/" + label + ".plist", "fixed_profile_label_and_destination")
    exe = path(request["executable_path"])
    require(not any(part.endswith(".app") for part in exe.parts), "stable_non_app_runtime_required")
    selection = request["runtime_selection"]
    payload = validate_selection(selection, uid)
    require(exe == payload / "bin/styx", "fixed_native_entrypoint")
    require(isinstance(request["definition_plist"], str), "definition_text_required")
    raw = request["definition_plist"].encode()
    require(0 < len(raw) <= 65536 and digest(raw) == request["definition_sha256"], "definition_exact_hash")
    tree = ET.fromstring(raw)
    # plistlib accepts duplicate dictionary keys; reject them before decoding.
    for node in tree.iter("dict"):
        children = list(node); require(len(children) % 2 == 0, "plist_pairs")
        keys = [children[i].text for i in range(0, len(children), 2)]
        require(all(children[i].tag == "key" for i in range(0, len(children), 2)) and len(keys) == len(set(keys)), "duplicate_plist_key")
    plist = plistlib.loads(raw)
    closed(plist, PLIST_FIELDS, "closed_launchd_keys")
    require(plist["Label"] == label and plist["ProgramArguments"] == [str(exe), "__service-run", "--state-dir", str(state), "--role", role] and plist["UserName"] == user, "fixed_original_uid_command")
    home = path(plist["WorkingDirectory"])
    require(plist["EnvironmentVariables"] == {"HOME": str(home), "PATH": "/usr/bin:/bin"} and plist["RunAtLoad"] is True and plist["KeepAlive"] is False and plist["ProcessType"] == "Background", "fixed_launchd_policy")
    for key in ["uid", "revision", "label", "definition_path", "definition_plist", "runtime_selection"]:
        require(report[key] == request[key], "report_request_binding")
    require(report["requires_initial_disabled"] is True, "original_definition_contract")
    expected_desired = {"gateway": None, "host": None}
    expected_desired[role] = {"manager": "persistent_service", "run": "running", "autostart": "enabled"}
    if lifecycle:
        original = request["original_desired"]
        closed(original, {"manager", "run", "autostart"}, "closed_original_desired")
        require(original["manager"] == "persistent_service" and original["run"] in ["running", "stopped"] and original["autostart"] in ["enabled", "disabled"], "registered_original_intent")
        target = dict(original); action = request["action"]
        require(action in ["start", "enable", "disable", "uninstall"], "registered_lifecycle_action")
        if action == "start":
            require(original["run"] == "stopped", "start_original_stopped")
            target["run"] = "running"
        elif action in ["enable", "disable"]:
            value = "enabled" if action == "enable" else "disabled"
            require(original["autostart"] != value, "autostart_original_transition")
            target["autostart"] = value
        else:
            require(original["run"] == "stopped" and original["autostart"] == "disabled", "uninstall_original_stopped_disabled")
        require(type(request["original_enabled"]) is bool and request["original_enabled"] == (original["autostart"] == "enabled"), "original_enabled_intent_binding")
        expected_desired[role] = target
    require(report["desired"] == expected_desired, "fresh_single_role_running_enabled")
    observed = report["transaction_observation"]
    closed(observed, {"status", "state_scope", "transaction_id", "revision", "canonical_raw_sha256", "receipt"}, "committed_target_observation")
    require(observed["status"] == "committed" and observed["state_scope"] == "committed_target" and observed["transaction_id"] == tx and observed["revision"] == request["revision"] and observed["canonical_raw_sha256"] == request["canonical_sha256"] and isinstance(observed["receipt"], dict), "original_committed_target_binding")
    if repair:
        old_payload = validate_selection(request["old_runtime_selection"], uid)
        require(request["old_runtime_selection"] != selection, "different_runtime_required")
        sha(request["old_definition_sha256"])
        old = request["old_definition_identity"]
        closed(old, {"device", "inode", "uid", "mode", "links"}, "closed_old_definition_identity")
        integer(old["device"]); integer(old["inode"], 1)
        require(integer(old["uid"]) == 0 and integer(old["links"]) == 1, "original_root_definition_required")
        require(integer(old["mode"], 0, 0o7777) & 0o022 == 0, "original_definition_mode")
        obs = request["original_registration"]
        closed(obs, OBSERVATION_FIELDS, "closed_original_registration")
        require(obs["path"] == request["definition_path"] and obs["username"] == user and obs["program"] == str(old_payload / "bin/styx") and obs["arguments"] == [obs["program"], "__service-run", "--state-dir", str(state), "--role", "gateway"], "original_registration_command")
        integer(obs["runs"], 1)
        require(obs["pid"] is None and obs["state"] == "not running" and type(obs["signaled_exit"]) is bool, "failed_inactive_original_required")
        if obs["last_exit_code"] is not None: integer(obs["last_exit_code"], -(1 << 31), (1 << 31) - 1)
        require(obs["signaled_exit"] or (obs["last_exit_code"] is not None and obs["last_exit_code"] != 0), "known_failed_generation_required")
    if lifecycle:
        old = request["original_definition_identity"]
        closed(old, {"device", "inode", "uid", "mode", "links"}, "closed_original_definition_identity")
        integer(old["device"]); integer(old["inode"], 1)
        require(integer(old["uid"]) == 0 and integer(old["links"]) == 1 and integer(old["mode"], 0, 0o7777) & 0o022 == 0, "original_root_definition_required")
        obs = request["original_registration"]
        closed(obs, OBSERVATION_FIELDS, "closed_original_registration")
        require(obs["path"] == request["definition_path"] and obs["username"] == user and obs["program"] == str(exe) and obs["arguments"] == plist["ProgramArguments"], "original_registration_command")
        integer(obs["runs"], 1)
        require(type(obs["signaled_exit"]) is bool, "original_signal_observation")
        if obs["last_exit_code"] is not None: integer(obs["last_exit_code"], -(1 << 31), (1 << 31) - 1)
        if original["run"] == "running":
            integer(obs["pid"], 1, (1 << 31) - 1)
            require(obs["state"] == "running" and action in ["enable", "disable"], "original_running_generation_required")
        else:
            require(obs["pid"] is None and obs["state"] == "not running" and obs["last_exit_code"] == 0 and not obs["signaled_exit"], "original_signed_clean_exit_required")
    return request


def validate_selection(selection, uid):
    closed(selection, {"schema", "payload_path", "payload_root", "manifest_sha256", "publisher_file", "publisher_spki_sha256"}, "closed_runtime_selection")
    require(type(selection["schema"]) is int and selection["schema"] == 1, "runtime_selection_schema")
    payload = path(selection["payload_path"]); path(selection["publisher_file"])
    require(not any(part.endswith(".app") for part in payload.parts), "stable_non_app_runtime_required")
    closed(selection["payload_root"], {"platform", "device", "inode", "uid"}, "closed_payload_root")
    pr = selection["payload_root"]
    require(pr["platform"] == "macos" and integer(pr["uid"], 1, (1 << 32) - 1) == uid, "original_macos_payload_owner")
    integer(pr["device"]); integer(pr["inode"], 1)
    sha(selection["manifest_sha256"])
    require(selection["publisher_spki_sha256"] == PIN, "original_macos_publisher_required")
    return payload


def checkpoints(request):
    q = shlex.quote
    uid = request["uid"]
    selection = request["runtime_selection"]
    paths = [plistlib.loads(request["definition_plist"].encode())["WorkingDirectory"], request["state_dir"], selection["payload_path"], str(PurePosixPath(request["executable_path"]).parent), str(PurePosixPath(selection["publisher_file"]).parent)]
    directories = set()
    for value in paths:
        p = path(value)
        directories.update(str(v) for v in [p, *p.parents] if str(v) != "/")
    lines = ["# Cooperative observations only; no original C07/execution lease or CAS."]
    for directory in sorted(directories, key=lambda x: (len(PurePosixPath(x).parts), x)):
        lines += ["check_directory " + q(directory)]
    root = request["state_root"]; payload = selection["payload_root"]
    lines += ["[ \"$(/usr/bin/id -u " + q(request["username"]) + ")\" = " + q(str(uid)) + " ] || fail account_changed"]
    for loc, ident in [(request["state_dir"], root), (selection["payload_path"], payload)]:
        lines += ["[ \"$(/usr/bin/stat -f '%d:%i:%u' " + q(loc) + ")\" = " + q("%d:%d:%d" % (ident["device"], ident["inode"], ident["uid"])) + " ] || fail original_root_changed"]
    for loc, expected in [(str(PurePosixPath(request["state_dir"]) / "state.json"), request["canonical_sha256"]), (request["executable_path"], request["executable_sha256"]), (str(PurePosixPath(selection["payload_path"]) / "manifest.json"), selection["manifest_sha256"])]:
        lines += ["check_file " + q(loc) + " " + q(expected)]
    return "\n".join(lines) + "\n"


def registration_check_program(request):
    # Match native parse_print's authority subset; OS text is never evaluated.
    obs = request["original_registration"]
    literal = lambda value: json.dumps(str(value), ensure_ascii=False)
    expected = {"path": obs["path"], "program": obs["program"], "username": obs["username"], "runs": str(obs["runs"]), "state": obs["state"]}
    if obs["pid"] is not None: expected["pid"] = str(obs["pid"])
    init = ["expected[%s]=%s;" % (literal(k), literal(v)) for k, v in expected.items()]
    init += ["argument[%d]=%s;" % (i, literal(v)) for i, v in enumerate(obs["arguments"], 1)]
    init += ["expected_exit=%s; has_exit=%d; expected_signal=%d;" % (literal(obs["last_exit_code"] if obs["last_exit_code"] is not None else ""), obs["last_exit_code"] is not None, obs["signaled_exit"])]
    return "BEGIN { depth=0; " + " ".join(init) + " }\n" + r'''
function die() { failed=1; exit 1 }
function equal(a,b) { return ("x" a)==("x" b) }
{
 line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
 if (length(line)>4096) die()
 if (NR==1) { if (!equal(line, HEADER)) die(); depth=1; next }
 if (depth==0) die()
 if (collecting) {
  if (line=="}") { collecting=0; depth--; completed=1; next }
  if (index(line,"{") || index(line,"}") || ++argc>8 || !equal(line,argument[argc])) die()
  next
 }
 if (line=="}") { if (--depth<0) die(); next }
 if (depth==1 && line=="arguments = {") {
  if (completed || collecting) die(); collecting=1; depth++; next
 }
 if (depth==1) {
  split_at=index(line," = ")
  if (split_at) {
   key=substr(line,1,split_at-1); value=substr(line,split_at+3)
   if (key in expected || key=="pid" || key=="last exit code" || key=="last terminating signal") {
    if (seen[key]++) die()
    if (key=="pid" && !(key in expected)) die()
    else if (key=="last exit code") { if (!has_exit || !equal(value,expected_exit)) die() }
    else if (key=="last terminating signal") { if ((value!="0")!=expected_signal) die() }
    else if (!equal(value,expected[key])) die()
   }
  }
 }
 if (substr(line,length(line),1)=="{") { if (++depth>16) die() }
}
END {
 if (failed || NR<2 || depth!=0 || collecting || !completed || argc!=6) exit 1
 for (key in expected) if (seen[key]!=1) exit 1
 if (seen["last exit code"]!=has_exit || (expected_signal && !seen["last terminating signal"])) exit 1
}
'''.replace("HEADER", literal("system/" + request["label"] + " = {"))


def repair_checkpoints(request):
    q = shlex.quote
    old = request["old_definition_identity"]
    dest = q(request["definition_path"])
    expected = "%d:%d:%d:%o:%d" % (old["device"], old["inode"], old["uid"], old["mode"], old["links"])
    return "[ ! -L " + dest + " ] && [ -f " + dest + " ] || fail old_definition_type\n" + '[ "$(/usr/bin/stat -f \'%d:%i:%u:%Lp:%l\' ' + dest + ')" = ' + q(expected) + ' ] || fail old_definition_identity\n' + '[ "$(/bin/ls -lde ' + dest + ' | /usr/bin/wc -l | /usr/bin/tr -d \' \\t\')" = 1 ] || fail old_definition_acl\n' + "actual=$(/usr/bin/shasum -a 256 " + dest + ") || fail old_definition_hash_unknown\ncase \"$actual\" in " + q(request["old_definition_sha256"] + " ") + "*) ;; *) fail old_definition_hash_changed;; esac\n"


def inspect_original_registration(request):
    q = shlex.quote
    return "observation=$(/bin/launchctl print " + q("system/" + request["label"]) + " 2>&1) || fail original_registration_unknown\n" + '[ "${#observation}" -le 65536 ] || fail original_registration_bound\n' + '/usr/bin/printf \'%s\\n\' "$observation" | /usr/bin/awk ' + q(registration_check_program(request)) + ' || fail original_registration_changed\nunset observation\n'


def disabled_check_program(label, enabled):
    # Match the native print-disabled parser, including launchd's enabled default.
    return "BEGIN { label=" + json.dumps(label) + "; wanted=" + ("1" if enabled else "0") + "; value=1 }\n" + r'''
function die() { failed=1; exit 1 }
{
 line=$0; sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
 if (!length(line)) next
 if (!opened) { if (line!="disabled services = {") die(); opened=1; next }
 if (closed) die()
 if (line=="}") { closed=1; next }
 at=index(line," => "); if (!at) die()
 name=substr(line,1,at-1); flag=substr(line,at+4); sub(/,$/,"",flag)
 if (substr(name,1,1)!="\"" || substr(name,length(name),1)!="\"" || length(name)<3) die()
 if (flag!="true" && flag!="false") die()
 if (substr(name,2,length(name)-2)==label) { if (seen++) die(); value=(flag=="false") }
}
END { if (failed || !opened || !closed || value!=wanted) exit 1 }
'''


def inspect_original_enabled(request, enabled):
    return "disabled=$(/bin/launchctl print-disabled system 2>&1) || fail disabled_map_unknown\n" + '[ "${#disabled}" -le 65536 ] || fail disabled_map_bound\n' + '/usr/bin/printf \'%s\\n\' "$disabled" | /usr/bin/awk ' + shlex.quote(disabled_check_program(request["label"], enabled)) + ' || fail original_enabled_changed\nunset disabled\n'


def lifecycle_scripts(request, prologue, common, destination_checks):
    q = shlex.quote; label = request["label"]; dest = request["definition_path"]
    original = repair_checkpoints(dict(request, old_definition_identity=request["original_definition_identity"], old_definition_sha256=request["definition_sha256"]))
    registration = inspect_original_registration(request)
    enabled = inspect_original_enabled(request, request["original_enabled"])
    guard = common + destination_checks + original + registration + enabled + original + common
    pre = prologue + guard + "exit 0\n"
    post = prologue + guard + "# One explicitly authorized administrator operation; no retry or fallback.\n"
    action = request["action"]
    command = "kickstart" if action == "start" else "bootout" if action == "uninstall" else action
    post += "/bin/launchctl " + command + " " + q("system/" + label) + " || fail " + command + "_unknown_do_not_replay\n"
    if action == "uninstall":
        post += "job_absent " + q(label) + "\n" + common + destination_checks + original
        post += "/bin/rm -- " + q(dest) + " || fail remove_definition_unknown_do_not_replay\n"
        post += "[ ! -e " + q(dest) + " ] && [ ! -L " + q(dest) + " ] || fail definition_removal_unknown\njob_absent " + q(label) + "\n" + common
        post += "/usr/bin/printf '%s\\n' 'styx_OS_uninstalled_C07_persistent_stopped_disabled_preserved'\n"
    elif action in ["enable", "disable"]:
        post += common + original + registration + inspect_original_enabled(request, action == "enable") + original
        post += "/usr/bin/printf '%s\\n' 'styx_autostart_observed_run_intent_preserved_readiness_NOT_PROVEN'\n"
    else:
        post += common + original
        post += "/usr/bin/printf '%s\\n' 'styx_start_dispatched_readiness_NOT_PROVEN'\n"
    return pre.encode(), (post + "exit 0\n").encode()

def scripts(request):
    q = shlex.quote
    label = request["label"]; dest = request["definition_path"]
    prologue = """#!/bin/sh
set -efu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset ENV BASH_ENV CDPATH
fail() { /usr/bin/printf '%s\\n' "styx_development_service_install_$1" >&2; exit 1; }
[ "$(/usr/bin/id -u)" = 0 ] || fail root_installer_required
# Alternate-volume installation must not act on this booted launchd instance.
[ "${3:-/}" = / ] || fail alternate_volume_not_supported
""" + "original_uid=" + q(str(request["uid"])) + "\n" + """check_directory() {
 [ ! -L "$1" ] && [ -d "$1" ] || fail directory_prefix_changed
 owner=$(/usr/bin/stat -f '%u' "$1")
 [ "$owner" = 0 ] || [ "$owner" = "$original_uid" ] || fail directory_owner_changed
 mode=$(/usr/bin/stat -f '%Lp' "$1")
 case "$mode" in ''|*[!0-7]*) fail directory_mode_unknown;; esac
 [ "$((0$mode & 0022))" = 0 ] || fail writable_directory_prefix
}
check_file() {
 [ ! -L "$1" ] && [ -f "$1" ] || fail file_type_changed
 [ "$(/usr/bin/stat -f '%l:%u' "$1")" = "1:$original_uid" ] || fail file_alias_or_owner_changed
 actual=$(/usr/bin/shasum -a 256 "$1") || fail hash_unknown
 case "$actual" in "$2 "*) ;; *) fail file_hash_changed;; esac
}
job_absent() {
 # Only the explicit not-found diagnostic counts as absent. Other nonzero
 # outcomes are Unknown and must never cause an automatic install replay.
 if observation=$(/bin/launchctl print "system/$1" 2>&1); then fail existing_launchd_job; fi
 expected_missing='Could not find service "'"$1"'" in domain for system'
 case "$observation" in
  "$expected_missing"|"Bad request.
$expected_missing") ;;
  *) fail launchd_absence_unknown;;
 esac
}
"""
    common = checkpoints(request)
    destination_checks = """check_directory /Library
check_directory /Library/LaunchDaemons
"""
    if request["kind"] == "launchd_registered_lifecycle":
        return lifecycle_scripts(request, prologue, common, destination_checks)
    pre = prologue + common + destination_checks + "[ ! -e " + q(dest) + " ] && [ ! -L " + q(dest) + " ] || fail existing_definition\njob_absent " + q(label) + "\n" + common + "exit 0\n"
    post = prologue + common + destination_checks + "[ ! -L " + q(dest) + " ] && [ -f " + q(dest) + " ] || fail installed_definition_type\n[ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l' " + q(dest) + ")\" = '0:0:644:1' ] || fail installed_definition_metadata\nactual=$(/usr/bin/shasum -a 256 " + q(dest) + ") || fail installed_definition_hash_unknown\ncase \"$actual\" in " + q(request["definition_sha256"] + " ") + "*) ;; *) fail installed_definition_hash_changed;; esac\njob_absent " + q(label) + "\n" + common
    if request["kind"] == "launchd_failed_registration_repair":
        original = repair_checkpoints(request)
        observation = inspect_original_registration(request)
        pre = prologue + common + destination_checks + original + observation + original
        pre += "# One authorized retirement attempt of this exact failed registration.\n/bin/launchctl disable " + q("system/" + label) + " || fail disable_unknown_do_not_replay\n"
        pre += common + original + observation + original
        pre += "/bin/launchctl bootout " + q("system/" + label) + " || fail bootout_unknown_do_not_replay\n"
        pre += "job_absent " + q(label) + "\n" + common + original + "exit 0\n"
    post += "# Exactly one explicit first-at-boot enable and one bootstrap. No fallback.\n/bin/launchctl enable " + q("system/" + label) + " || fail enable_unknown_do_not_replay\n/bin/launchctl bootstrap system " + q(dest) + " || fail bootstrap_unknown_do_not_replay\n/usr/bin/printf '%s\\n' 'styx_registration_dispatched_readiness_NOT_PROVEN'\nexit 0\n"
    return pre.encode(), post.encode()


def write_new(pathname, raw, mode):
    with pathname.open("xb") as output:
        os.chmod(pathname, mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def build(report_file, output, version, prepare_only=False):
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,2}", version), "pkg_numeric_version")
    report_file = Path(report_file).absolute(); output = Path(output).absolute()
    require(report_file.is_file() and not report_file.is_symlink() and report_file.stat().st_size <= LIMIT, "regular_bounded_report")
    original = report_file.read_bytes(); request = validate(decode(original))
    require(prepare_only or sys.platform == "darwin", "native_pkgbuild_required")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    payload = output / "payload"; script_dir = output / "scripts"
    (payload / "Library/LaunchDaemons").mkdir(parents=True, mode=0o755)
    for directory in [payload, payload / "Library", payload / "Library/LaunchDaemons"]:
        directory.chmod(0o755)
    script_dir.mkdir(mode=0o700)
    plist = request["definition_plist"].encode(); pre, post = scripts(request)
    lifecycle = request["kind"] == "launchd_registered_lifecycle"
    if not lifecycle:
        write_new(payload / "Library/LaunchDaemons" / (request["label"] + ".plist"), plist, 0o644)
    write_new(script_dir / "preinstall", pre, 0o755); write_new(script_dir / "postinstall", post, 0o755)
    write_new(output / "installation-report.json", original, 0o600)
    pkg = output / ("StyxService-" + request["action"] + "-development-unsigned.pkg" if lifecycle else "StyxGateway-failed-registration-repair-development-unsigned.pkg" if request["kind"] == "launchd_failed_registration_repair" else "StyxGateway-first-start-development-unsigned.pkg")
    command = ["/usr/bin/pkgbuild"] + (["--nopayload"] if lifecycle else ["--root", str(payload), "--ownership", "recommended"]) + ["--scripts", str(script_dir), "--identifier", request["label"] + ".development", "--version", version, "--install-location", "/", str(pkg)]
    receipt = {"schema": 1, "status": "PREPARED_NOT_BUILT", "developer_unsigned": True, "installer_signing": "NOT_PERFORMED_NO_IDENTITY", "input_sha256": digest(original), "builder_sha256": digest(Path(__file__).read_bytes()), "native_manifest_sha256": request["runtime_selection"]["manifest_sha256"], "definition_sha256": digest(plist), "preinstall_sha256": digest(pre), "postinstall_sha256": digest(post), "source_transaction_id": request["transaction_id"], "canonical_revision": request["revision"], "state_root": request["state_root"], "uid": request["uid"], "label": request["label"], "runtime_selection": request["runtime_selection"], "command": command, "actual_wait": False, "package_built": False, "installation_performed": False, "registration_dispatched": False, "readiness": "NOT_PROVEN", "atomic_C07_OS_transaction": False, "installation_kind": request["kind"], "limitation": "Cooperative pre/post observations only. The original signed service must authenticate current scope/C07/runtime on startup. Changed state or lost registration result is never replayed."}
    try:
        if not prepare_only:
            receipt["pkgbuild_tool_sha256"] = digest(Path("/usr/bin/pkgbuild").read_bytes())
            start = time.monotonic()
            with (output / "pkgbuild.stdout.log").open("xb") as out, (output / "pkgbuild.stderr.log").open("xb") as err:
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
                code = child.wait()
            receipt.update(actual_wait=True, exit_code=code, elapsed_seconds=time.monotonic() - start, stdout_sha256=digest((output / "pkgbuild.stdout.log").read_bytes()), stderr_sha256=digest((output / "pkgbuild.stderr.log").read_bytes()))
            require(code == 0 and pkg.is_file() and not pkg.is_symlink(), "pkgbuild_failed")
            receipt.update(status="BUILT_DEVELOPER_UNSIGNED_NOT_INSTALLED", package_built=True, package_sha256=digest(pkg.read_bytes()), package_bytes=pkg.stat().st_size)
        require(report_file.read_bytes() == original, "original_report_changed")
    except Exception:
        receipt["status"] = "FAIL_PARTIAL_OUTPUT_PRESERVED"
        raise
    finally:
        write_new(output / "receipt.json", (json.dumps(receipt, indent=2) + "\n").encode(), 0o600)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True, help="Numeric Apple package version, distinct from runtime provenance")
    parser.add_argument("--prepare-only", action="store_true", help="Generate reviewable payload/scripts, never invoke pkgbuild")
    args = parser.parse_args()
    try:
        report = build(args.request_report, args.output, args.version, args.prepare_only)
        print(json.dumps({"status": report["status"], "receipt": str(args.output.absolute() / "receipt.json"), "readiness": "NOT_PROVEN"}))
    except (ValueError, OSError, json.JSONDecodeError, plistlib.InvalidFileException, ET.ParseError):
        print(json.dumps({"status": "FAIL", "error": "native_service_package_input_or_build_refused", "readiness": "NOT_PROVEN"}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
