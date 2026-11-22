"""Check LuLu policy and prepare files for its built-in rule importer."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import plistlib
import re
import subprocess

from src.proxy_config import PORT

INSTALL_DIRECTORY = Path("/Library/Objective-See/LuLu")
BUNDLE = "/Applications/Claude.app"
FOLDER = BUNDLE + "/*"
EXECUTABLE = BUNDLE + "/Contents/MacOS/Claude"
EXPECTED = {
    (FOLDER, "*", "*", 0, 1),
    (FOLDER, "127.0.0.1", str(PORT), 1, 1),
    (EXECUTABLE, "*", "*", 0, 2),
}
EXTENSION = "com.objective-see.lulu.extension"
SYSTEM_REGISTRATION = re.compile(
    rf"(?m)^\s*\*\s+\*\s+VBG97UB4TA\s+{re.escape(EXTENSION)}\s+[^\n]*\[activated enabled\]\s*$"
)
SYSTEM_PROCESS = re.compile(
    rf"(?m)^\s*0\s+/Library/SystemExtensions/[0-9A-Fa-f-]+/"
    rf"{re.escape(EXTENSION)}\.systemextension/Contents/MacOS/{re.escape(EXTENSION)}\s*$"
)


def filter_is_active(check_registration=True):
    # In LuLu 4.5.5+ the provider exits when its content filter stops. macOS can
    # still list a stopped filter's system extension as installed and enabled.
    try:
        processes = subprocess.run(["/bin/ps", "-ww", "-A", "-o", "uid=,comm="],
                                   capture_output=True, text=True, timeout=2, check=True)
        if not SYSTEM_PROCESS.search(processes.stdout):
            return False
        if not check_registration:
            return True
        extensions = subprocess.run(["/usr/bin/systemextensionsctl", "list"], capture_output=True,
                                    text=True, timeout=2, check=True)
        return bool(SYSTEM_REGISTRATION.search(extensions.stdout))
    except (OSError, subprocess.SubprocessError):
        return False


def rules_in_archive(data, *, export_values=False):
    archive = plistlib.loads(data)
    if archive["$archiver"] != "NSKeyedArchiver":
        raise ValueError("Unsupported LuLu rules archive")
    objects = archive["$objects"]

    def resolve(item):
        return objects[item.data] if isinstance(item, plistlib.UID) else item

    def json_value(item):
        value = resolve(item)
        if not isinstance(value, dict):
            if value == "$null":
                return None
            if isinstance(value, (str, int, float, bool)):
                return value
        elif "NS.keys" in value:
            if len(value["NS.keys"]) != len(value["NS.objects"]):
                raise ValueError("Invalid LuLu rule dictionary")
            return {resolve(k): json_value(v) for k, v in zip(value["NS.keys"], value["NS.objects"])}
        elif "NS.objects" in value:
            return [json_value(v) for v in value["NS.objects"]]
        elif "NS.time" in value:
            epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
            return (epoch + timedelta(seconds=value["NS.time"])).strftime("%Y-%m-%dT%H:%M:%S%z")
        raise ValueError("Unsupported LuLu rule value")

    root = resolve(archive["$top"]["root"])
    for group in map(resolve, root["NS.objects"]):
        for key, value in zip(group["NS.keys"], group["NS.objects"]):
            if resolve(key) != "rules":
                continue
            for item in resolve(value)["NS.objects"]:
                yield {key: (json_value(value) if export_values else resolve(value))
                       for key, value in resolve(item).items() if key != "$class"}


def _active_profile(install_dir):
    default = (install_dir / "preferences.plist").read_bytes()
    preferences = plistlib.loads(default)
    if profile := preferences.get("currentProfile"):
        directory = Path(profile).resolve()
        directory.relative_to((install_dir / "Profiles").resolve())
        return directory, default, (directory / "preferences.plist").read_bytes()
    return install_dir, default, default


def _compatible(preferences):
    return (preferences.get("disabled") is False and preferences.get("allowLocalHost") is False
            and not any(preferences.get(key) for key in ("allowDNS", "allowInstalled", "useAllowList", "blockMode")))


def _statement(rule):
    return tuple(rule[key] for key in ("path", "endpointAddr", "endpointPort", "action", "scope"))


def _protected_statement(rule):
    if (rule.get("type") == 3 and rule.get("isDisabled") in (None, 0, "$null")
            and not rule.get("isEndpointAddrRegex") and rule.get("expiration") in (None, "$null")
            and rule.get("pid") in (None, "$null") and _statement(rule) in EXPECTED):
        return _statement(rule)
    return None


def _conflicting_allow(rule):
    if rule["action"] != 1 or rule.get("isDisabled") not in (None, 0, "$null"):
        return False
    path = rule["path"]
    return (path in ("*", BUNDLE) or path.startswith(BUNDLE + "/")
            or (path.endswith("/*") and BUNDLE.startswith(path[:-1]))) and (
                _statement(rule) not in EXPECTED or rule.get("isEndpointAddrRegex"))


def _snapshot(install_dir):
    directory, default, preferences = _active_profile(install_dir)
    rules = (directory / "rules.plist").read_bytes()
    # Frame separate inputs so that a profile switch or a rule/settings edit
    # during the file dialog invalidates the prepared import.
    items = (str(directory).encode(), default, preferences, rules)
    token = sha256(b"".join(sha256(item).digest() for item in items)).hexdigest()
    return token, plistlib.loads(preferences), rules


def import_snapshot(install_dir=INSTALL_DIRECTORY):
    return _snapshot(install_dir)[0]


def prepare_import(bundled, install_dir=INSTALL_DIRECTORY):
    token, preferences, archive = _snapshot(install_dir)
    if not _compatible(preferences):
        return {"status": "settings"}
    template = [rule for rules in bundled.values() for rule in rules]
    if len(template) != len(EXPECTED) or {_protected_statement(rule) for rule in template} != EXPECTED:
        raise ValueError("Invalid ClaudeGuard rule template")

    current = list(rules_in_archive(archive, export_values=True))
    if any(_conflicting_allow(rule) for rule in current):
        return {"status": "conflict"}
    present = {_protected_statement(rule) for rule in current}
    if EXPECTED.issubset(present):
        return {"status": "ready"}

    managed_ids = {rule["uuid"] for rule in template}
    result = {}
    imported_keys = {"key", "uuid", "path", "name", "endpointAddr", "endpointPort", "type", "scope", "action",
                     "creation", "expiration", "endpointHost", "csInfo", "isDisabled", "isEndpointAddrRegex"}
    for rule in current:
        if rule["type"] != 3:
            continue  # LuLu's user-only import retains built-in and passive rules.
        values = {key: value for key, value in rule.items() if value is not None}
        if (not values.keys() <= imported_keys
                or any(not isinstance(values.get(key), str) for key in
                       ("key", "uuid", "path", "name", "endpointAddr", "endpointPort"))
                or any(not isinstance(values.get(key), int) for key in ("type", "scope", "action"))):
            raise ValueError("An existing LuLu rule cannot be preserved by import")
        if rule.get("uuid") in managed_ids and _protected_statement(rule) is None:
            continue  # Replace disabled/stale rules previously installed by ClaudeGuard.
        result.setdefault(rule["key"], []).append(values)
    for rule in template:
        if _statement(rule) not in present:
            result.setdefault(rule["key"], []).append(rule)
    return {"status": "import", "snapshot": token, "rules": result}


def verify_import(imported, install_dir=INSTALL_DIRECTORY):
    if not has_desktop_policy(install_dir):
        return False
    _, _, archive = _snapshot(install_dir)
    current = {rule["uuid"]: rule for rule in rules_in_archive(archive, export_values=True)}
    return all(rule["uuid"] in current and all(current[rule["uuid"]].get(key) == value for key, value in rule.items())
               for rules in imported.values() for rule in rules)


def has_desktop_policy(install_dir=INSTALL_DIRECTORY):
    try:
        directory, _, preferences = _active_profile(install_dir)
        if not _compatible(plistlib.loads(preferences)):
            return False
        rules = list(rules_in_archive((directory / "rules.plist").read_bytes()))
        return EXPECTED.issubset({_protected_statement(rule) for rule in rules}) and not any(
            _conflicting_allow(rule) for rule in rules)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, plistlib.InvalidFileException):
        return False
