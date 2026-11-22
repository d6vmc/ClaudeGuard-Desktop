#!/usr/bin/env python3
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")))

from src.config import ConfigManager
from src.integrity import repair
from src.network_guard import sync_hosts_file

def main():
    if len(sys.argv) < 2:
        return
    cmd = sys.argv[1]
    config = ConfigManager()
    from src import trace_timing as trace
    trace.configure(config.config, os.path.dirname(config.path) if hasattr(config, "path") else None)

    if cmd == "proxy_save":
        from src.proxy import save_profile
        try:
            # Persist only. The daemon enforces the new configuration asynchronously.
            # Waiting for DNS/root acknowledgement here freezes the settings window.
            text = sys.stdin.read(65537)
            if len(sys.argv) > 2:
                save_profile(config, text, exit_ip=sys.argv[2])
            else:
                save_profile(config, text)
        except json.JSONDecodeError:
            print("Invalid JSON. Paste one complete outbound object.", file=sys.stderr)
            sys.exit(1)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
        except Exception:
            print("Could not save proxy settings. Check the profile and configuration file permissions.", file=sys.stderr)
            sys.exit(1)
    elif cmd in ("managed_ssh_save", "managed_xray_save", "managed_run", "managed_toggle", "desktop_pac_save"):
        from src import desktop_pac, managed_proxy
        import subprocess
        try:
            if cmd == "managed_run":
                managed_proxy.run(config, sys.argv[2])
            elif cmd == "managed_toggle":
                if not config.config.get("managed_proxy"):
                    raise ValueError("Configure an SSH or VLESS/REALITY profile first.")
                config.config["proxy_enabled"] = sys.argv[2] == "start"
                config.save_config()
            elif cmd == "desktop_pac_save":
                desktop_pac.apply(config, sys.stdin.read(4096))
            else:
                kind = "ssh" if cmd == "managed_ssh_save" else "xray"
                managed_proxy.save(config, kind, json.loads(sys.stdin.read(65537)))
        except (KeyError, TypeError, IndexError, json.JSONDecodeError):
            print("The managed proxy settings are incomplete or invalid.", file=sys.stderr)
            sys.exit(1)
        except ValueError as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            print("ClaudeGuard could not apply the local settings. Check the SSH host or the macOS network settings.", file=sys.stderr)
            sys.exit(1)
    elif cmd == "lulu_check":
        from src.lulu import filter_is_active, has_desktop_policy
        if not filter_is_active(check_registration=False):
            print("The LuLu content filter is not running.", file=sys.stderr)
            sys.exit(1)
        if not has_desktop_policy():
            print("The active LuLu profile no longer enforces the Claude Desktop rules.", file=sys.stderr)
            sys.exit(1)
    elif cmd in ("lulu_import_prepare", "lulu_import_snapshot", "lulu_import_verify"):
        from pathlib import Path
        from src.lulu import filter_is_active, import_snapshot, prepare_import, verify_import
        try:
            if cmd == "lulu_import_snapshot":
                print(import_snapshot())
            elif cmd == "lulu_import_verify":
                imported = json.loads(Path(sys.argv[2]).read_text())
                if not filter_is_active(check_registration=False) or not verify_import(imported):
                    sys.exit(1)
            elif not filter_is_active():
                print(json.dumps({"status": "inactive"}))
            else:
                template = json.loads(Path(sys.argv[2]).read_text())
                print(json.dumps(prepare_import(template)))
        except (OSError, TypeError, ValueError, KeyError, IndexError):
            sys.exit(1)
    elif cmd == "proxy_check":
        from src.proxy import prepare, probe, profile_id
        import time
        from src.proxy_egress import validate_exit_ip
        from pathlib import Path
        result = {"profile_id": profile_id(config), "ok": False, "ip": "", "error": "Proxy is disconnected"}
        # A queued proxy check may start after the user has already selected
        # VPN. Do not wait for a stopped proxy or apply its failure policy.
        if config.config.get("connection_mode") != "proxy":
            result["error"] = "Connection mode changed"
            print(json.dumps(result), flush=True)
            return
        try:
            if not config.config.get("proxy_profile"):
                raise ValueError("Proxy is not configured")
            if not config.config.get("proxy_enabled", True):
                raise ValueError("Proxy is disconnected")
            if not config.protection_enabled:
                raise ValueError("Protection is disabled")
            expected = validate_exit_ip(config.config.get('expected_exit_ip'))
            cache = Path(config.path).parent / "proxy-health.json"
            try:
                previous = json.loads(cache.read_text())
            except (OSError, ValueError):
                previous = {}
            last_prepared = previous.get("prepared_at") if isinstance(previous, dict) else None
            if (not isinstance(last_prepared, (int, float)) or not 0 <= time.time() - last_prepared < 60
                    or previous.get("profile") != result["profile_id"]):
                ip = prepare(config)
                cache.write_text(json.dumps({"profile": profile_id(config), "prepared_at": time.time()}))
            else:
                ip = probe(expected)
            result.update(ok=True, ip=ip, error="", verified_at=time.time())
        except Exception as error:
            result["error"] = str(error)
            current = ConfigManager()
            if (current.config.get("connection_mode") != "proxy"
                    or not current.config.get("protection_enabled", True)
                    or profile_id(current) != result["profile_id"]):
                result["error"] = "Connection settings changed"
                print(json.dumps(result), flush=True)
                return
            # A failed startup/probe must still install ordinary blocking, even
            # when the proxy profile itself is invalid or conflicts with a VPN.
            if hasattr(config, "path"):
                try:
                    (Path(config.path).parent / "proxy-health.json").unlink(missing_ok=True)
                except OSError:
                    pass
            ok, message = sync_hosts_file(True, current)
            if not ok:
                result["error"] += "; " + message
        print(json.dumps(result), flush=True)
    elif cmd == "sync_hosts":
        block_claude = sys.argv[2].lower() == "true" if len(sys.argv) > 2 else False
        ok, message = sync_hosts_file(block_claude_domains=block_claude, config=config)
        if not ok:
            print(message, file=sys.stderr, flush=True)
            sys.exit(1)

    elif cmd == "integrity":
        # Called by the daemon on a timer; logs only real changes so the normal
        # case stays quiet.
        report = repair(config)
        for change in report["changed"]:
            print(f"[ClaudeGuard] repaired: {change}", flush=True)

if __name__ == "__main__":
    main()
