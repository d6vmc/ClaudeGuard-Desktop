"""Install the domain-scoped PAC through macOS network preferences."""
import base64
import subprocess

from src.proxy_config import PORT

NETWORK_SETUP = "/usr/sbin/networksetup"
PAC = f'''function FindProxyForURL(url, host) {{
    host = host.toLowerCase().replace(/[.]$/, "");
    var domains = ["claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com", "hcaptcha.com"];
    for (var i = 0; i < domains.length; i++) {{
        if (host === domains[i] || dnsDomainIs(host, "." + domains[i])) {{
            return "PROXY 127.0.0.1:{PORT}";
        }}
    }}
    return "DIRECT";
}}
'''
URL = "data:application/x-ns-proxy-autoconfig;base64," + base64.b64encode(PAC.encode()).decode()


def service_proxy(service):
    status = subprocess.check_output([NETWORK_SETUP, "-getautoproxyurl", service], text=True, timeout=4)
    settings = dict(line.split(": ", 1) for line in status.splitlines() if ": " in line)
    if "URL" not in settings or settings.get("Enabled") not in ("Yes", "No"):
        raise ValueError("Could not read proxy settings for the selected macOS network services.")
    return settings["URL"], settings["Enabled"] == "Yes"


def apply(config, names):
    services = list(dict.fromkeys(name.strip() for name in names.split(",") if name.strip()))
    if not services or len(services) > 5:
        raise ValueError("Enter one to five macOS network service names, such as Wi-Fi, Happ.")
    existing = subprocess.check_output([NETWORK_SETUP, "-listallnetworkservices"], text=True, timeout=4)
    if any(service not in existing.splitlines()[1:] for service in services):
        raise ValueError("A network service was not found. Enter its name as shown in macOS Network settings.")
    old = {service: service_proxy(service) for service in services}
    accepted = {URL, config.config.get("desktop_pac_url")}
    if any(enabled and url not in accepted for url, enabled in old.values()):
        raise ValueError("A selected network service already uses another PAC. Review it in macOS Network settings.")
    changed = []
    previous = dict(config.config.get("desktop_pac_previous", {}))
    try:
        for service, (url, enabled) in old.items():
            if (url, enabled) == (URL, True):
                continue
            changed.append(service)
            subprocess.run([NETWORK_SETUP, "-setautoproxyurl", service, URL], capture_output=True, timeout=5, check=True)
            subprocess.run([NETWORK_SETUP, "-setautoproxystate", service, "on"], capture_output=True, timeout=5, check=True)
            previous.setdefault(service, [url, enabled] if url not in accepted else ["", False])
        config.config["desktop_pac_url"] = URL
        config.config["desktop_pac_services"] = services
        config.config["desktop_pac_previous"] = previous
        config.save_config()
    except (OSError, subprocess.SubprocessError):
        for service in reversed(changed):
            url, enabled = old[service]
            subprocess.run([NETWORK_SETUP, "-setautoproxyurl", service, "" if url == "(null)" else url],
                           capture_output=True, timeout=5)
            subprocess.run([NETWORK_SETUP, "-setautoproxystate", service, "on" if enabled else "off"],
                           capture_output=True, timeout=5)
        raise ValueError("macOS could not save proxy settings for the selected services.") from None


def restore(settings):
    expected = settings.get("desktop_pac_url")
    previous = settings.get("desktop_pac_previous", {})
    if not expected or not previous:
        return
    lines = subprocess.check_output([NETWORK_SETUP, "-listallnetworkservices"], text=True, timeout=4).splitlines()
    services = {name.removeprefix("*") for name in lines[1:]}
    for service, (old_url, old_enabled) in previous.items():
        if service not in services:
            continue
        current_url, current_enabled = service_proxy(service)
        if current_url != expected:
            continue
        try:
            subprocess.run([NETWORK_SETUP, "-setautoproxyurl", service, "" if old_url == "(null)" else old_url],
                           capture_output=True, timeout=5, check=True)
            subprocess.run([NETWORK_SETUP, "-setautoproxystate", service, "on" if old_enabled else "off"],
                           capture_output=True, timeout=5, check=True)
        except (OSError, subprocess.SubprocessError):
            subprocess.run([NETWORK_SETUP, "-setautoproxyurl", service, current_url], capture_output=True, timeout=5)
            subprocess.run([NETWORK_SETUP, "-setautoproxystate", service, "on" if current_enabled else "off"],
                           capture_output=True, timeout=5)
            raise
