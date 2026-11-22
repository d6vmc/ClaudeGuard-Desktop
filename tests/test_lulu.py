"""Exercise the persisted LuLu policy checks using its documented rule values."""
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

from src.lulu import has_desktop_policy, import_snapshot, prepare_import, verify_import


RULE_FILE = Path(__file__).parents[1] / "packaging/lulu-desktop/ClaudeGuard-LuLu-rules.json"


class LuLuPolicyTests(unittest.TestCase):
    def test_imported_rules_and_settings_are_required(self):
        groups = json.loads(RULE_FILE.read_text())
        with tempfile.TemporaryDirectory() as folder:
            root_dir = Path(folder)
            preferences = {"disabled": False, "allowLocalHost": False, "allowDNS": False,
                           "allowInstalled": False, "useAllowList": False}
            for change in ({}, {"allowLocalHost": True}, {"allowDNS": True}, {"useAllowList": True},
                           {"allowInstalled": True}, {"disabled": True}):
                with self.subTest(change=change):
                    (root_dir / "preferences.plist").write_bytes(plistlib.dumps(dict(preferences, **change)))
                    (root_dir / "rules.plist").write_bytes(archive(groups))
                    self.assertEqual(has_desktop_policy(root_dir), not change)
            (root_dir / "preferences.plist").write_bytes(plistlib.dumps(preferences))
            altered = json.loads(RULE_FILE.read_text())
            exception = {**altered["/Applications/Claude.app/*"][1], "endpointAddr": "203.0.113.1"}
            altered["/Applications/Claude.app/*"].append(exception)
            (root_dir / "rules.plist").write_bytes(archive(altered))
            self.assertFalse(has_desktop_policy(root_dir))
            groups.pop("/Applications/Claude.app/Contents/MacOS/Claude")
            (root_dir / "rules.plist").write_bytes(archive(groups))
            self.assertFalse(has_desktop_policy(root_dir))

    def test_import_preserves_other_user_rules_and_does_not_duplicate_existing_policy(self):
        template = json.loads(RULE_FILE.read_text())
        bundle = "/Applications/Claude.app/*"
        other = "/Applications/Example.app/Contents/MacOS/Example"
        existing = dict(template[bundle][0], key=other, path=other, name="Example", uuid="example",
                        isDisabled=1, csInfo={"id": "example", "authorities": ["Example Authority"]})
        matching = dict(template[bundle][1], uuid="previous-allow")
        built_in = dict(existing, type=1, uuid="built-in")
        with tempfile.TemporaryDirectory() as folder:
            root_dir = Path(folder)
            prefs = root_dir / "preferences.plist"
            rules = root_dir / "rules.plist"
            prefs.write_bytes(plistlib.dumps({"disabled": False, "allowLocalHost": False}))
            rules.write_bytes(archive({bundle: [matching], other: [existing, built_in]}))
            prepared = prepare_import(template, root_dir)
            self.assertEqual(prepared["status"], "import")
            self.assertEqual(prepared["snapshot"], import_snapshot(root_dir))
            self.assertEqual(prepared["rules"][other], [existing])
            self.assertEqual(prepared["rules"][bundle], [matching, template[bundle][0]])
            rules.write_bytes(archive(prepared["rules"]))
            self.assertNotEqual(prepared["snapshot"], import_snapshot(root_dir))
            self.assertEqual(prepare_import(template, root_dir), {"status": "ready"})
            self.assertTrue(verify_import(prepared["rules"], root_dir))
            remaining = {path: group for path, group in prepared["rules"].items() if path != other}
            rules.write_bytes(archive(remaining))
            self.assertTrue(has_desktop_policy(root_dir))
            self.assertFalse(verify_import(prepared["rules"], root_dir))

    def test_import_refuses_conflicting_allows_and_incompatible_settings(self):
        template = json.loads(RULE_FILE.read_text())
        bundle = "/Applications/Claude.app/*"
        competing_allow = dict(template[bundle][1], endpointAddr="*", endpointPort="*", uuid="broad")
        with tempfile.TemporaryDirectory() as folder:
            root_dir = Path(folder)
            prefs = root_dir / "preferences.plist"
            (root_dir / "rules.plist").write_bytes(archive({bundle: [competing_allow]}))
            prefs.write_bytes(plistlib.dumps({"disabled": False, "allowLocalHost": False}))
            self.assertEqual(prepare_import(template, root_dir), {"status": "conflict"})
            prefs.write_bytes(plistlib.dumps({"disabled": False, "allowLocalHost": True}))
            self.assertEqual(prepare_import(template, root_dir), {"status": "settings"})


def archive(groups):
    objects = ["$null"]

    def reference(value):
        objects.append(value)
        return plistlib.UID(len(objects) - 1)

    def encode(value):
        if isinstance(value, dict):
            return reference({"NS.keys": [reference(k) for k in value],
                              "NS.objects": [encode(v) for v in value.values()]})
        if isinstance(value, list):
            return reference({"NS.objects": [encode(v) for v in value]})
        return reference(value)

    encoded = []
    for rules in groups.values():
        entries = [reference({k: encode(v) for k, v in rule.items()}) for rule in rules]
        encoded.append(reference({"NS.keys": [reference("rules")],
                                  "NS.objects": [reference({"NS.objects": entries})]}))
    root = reference({"NS.objects": encoded})
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$top": {"root": root}, "$objects": objects},
                          fmt=plistlib.FMT_BINARY)
