"""
MAC address vendor lookup using the IEEE OUI (Organizationally Unique Identifier) database.

Educational note:
  The first 3 octets (24 bits) of a MAC address identify the manufacturer.
  For example, AA:BB:CC:xx:xx:xx — AA:BB:CC is the OUI assigned by IEEE
  to a specific vendor.  This lets us display friendly names like "Apple"
  or "Dell" next to raw MAC addresses on the dashboard.

  A full OUI database has ~30 000 entries.  We ship a curated subset of
  common vendors and fall back to "Unknown" for the rest.
"""

from __future__ import annotations

# Curated subset of common OUI prefixes → vendor names.
# Format: first 3 octets uppercased, colon-separated.
_OUI_TABLE: dict[str, str] = {
    # --- Hypervisors / Virtual ---
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:1C:14": "VMware",
    "00:0F:4B": "Oracle VirtualBox",
    "08:00:27": "Oracle VirtualBox",
    "0A:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3E": "Xen",
    "00:15:5D": "Microsoft Hyper-V",
    "02:42:AC": "Docker Container",
    "AA:BB:CC": "Simulated Device",
    "DD:EE:FF": "Simulated Device",
    # --- Apple ---
    "A4:83:E7": "Apple",
    "3C:22:FB": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "00:1B:63": "Apple",
    "D8:30:62": "Apple",
    "14:98:77": "Apple",
    "38:F9:D3": "Apple",
    "70:56:81": "Apple",
    "A8:5C:2C": "Apple",
    "BC:52:B7": "Apple",
    "F8:4D:89": "Apple",
    "28:6A:BA": "Apple",
    "64:A2:F9": "Apple",
    "78:7B:8A": "Apple",
    # --- Samsung ---
    "00:07:AB": "Samsung",
    "8C:77:12": "Samsung",
    "B4:79:A7": "Samsung",
    "E4:7D:BD": "Samsung",
    "50:01:D9": "Samsung",
    "AC:5F:3E": "Samsung",
    "34:14:5F": "Samsung",
    "C0:97:27": "Samsung",
    # --- Intel ---
    "00:1B:21": "Intel",
    "68:05:CA": "Intel",
    "3C:97:0E": "Intel",
    "A0:36:9F": "Intel",
    "48:51:B7": "Intel",
    "8C:EC:4B": "Intel",
    "34:13:E8": "Intel",
    # --- Cisco ---
    "00:1A:A1": "Cisco",
    "00:1B:0D": "Cisco",
    "00:26:0B": "Cisco",
    "00:23:33": "Cisco",
    "00:40:96": "Cisco",
    "58:97:1E": "Cisco",
    "F0:29:29": "Cisco",
    "C8:F9:F9": "Cisco",
    # --- Dell ---
    "00:14:22": "Dell",
    "18:A9:9B": "Dell",
    "F8:DB:88": "Dell",
    "B0:83:FE": "Dell",
    "24:B6:FD": "Dell",
    # --- HP ---
    "00:17:A4": "HP",
    "3C:D9:2B": "HP",
    "B4:B5:2F": "HP",
    "10:60:4B": "HP",
    "94:57:A5": "HP",
    "30:E1:71": "HP",
    # --- Lenovo ---
    "00:06:1B": "Lenovo",
    "28:D2:44": "Lenovo",
    "98:FA:9B": "Lenovo",
    "E8:2A:44": "Lenovo",
    # --- Raspberry Pi ---
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    # --- TP-Link ---
    "50:C7:BF": "TP-Link",
    "C0:25:E9": "TP-Link",
    "EC:08:6B": "TP-Link",
    "60:32:B1": "TP-Link",
    "14:EB:B6": "TP-Link",
    # --- Netgear ---
    "00:1E:2A": "Netgear",
    "C4:3D:C7": "Netgear",
    "B0:7F:B9": "Netgear",
    "84:1B:5E": "Netgear",
    # --- Ubiquiti ---
    "04:18:D6": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    # --- ASUS ---
    "00:1A:92": "ASUS",
    "04:92:26": "ASUS",
    "1C:87:2C": "ASUS",
    "AC:9E:17": "ASUS",
    # --- Google / Nest ---
    "F4:F5:D8": "Google",
    "54:60:09": "Google",
    "A4:77:33": "Google",
    "18:D6:C7": "Google Nest",
    "64:16:66": "Google Nest",
    # --- Amazon / Ring / Echo ---
    "F0:F0:A4": "Amazon",
    "44:65:0D": "Amazon",
    "FC:65:DE": "Amazon",
    "74:C2:46": "Amazon",
    "38:F7:3D": "Amazon Echo",
    "4C:EF:C0": "Amazon Echo",
    # --- Sonos ---
    "5C:AA:FD": "Sonos",
    "B8:E9:37": "Sonos",
    "00:0E:58": "Sonos",
    # --- Espressif (ESP32/ESP8266 — common in IoT) ---
    "24:0A:C4": "Espressif (IoT)",
    "30:AE:A4": "Espressif (IoT)",
    "A4:CF:12": "Espressif (IoT)",
    "CC:50:E3": "Espressif (IoT)",
    "84:CC:A8": "Espressif (IoT)",
    # --- Tuya / Smart Home ---
    "D8:F1:5B": "Tuya IoT",
    "10:D5:61": "Tuya IoT",
    # --- Philips Hue ---
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    # --- Ring ---
    "6C:2B:59": "Ring",
    "94:A1:A2": "Ring",
    # --- Roku ---
    "B0:A7:37": "Roku",
    "D8:31:34": "Roku",
    "AC:3A:7A": "Roku",
    # --- Synology ---
    "00:11:32": "Synology",
    # --- QNAP ---
    "00:08:9B": "QNAP",
    # --- Hikvision (cameras) ---
    "C0:56:E3": "Hikvision",
    "54:C4:15": "Hikvision",
    "28:57:BE": "Hikvision",
    # --- Dahua (cameras) ---
    "3C:EF:8C": "Dahua",
    "A0:BD:1D": "Dahua",
    # --- Xiaomi ---
    "28:6C:07": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "7C:1C:68": "Xiaomi",
    # --- Huawei ---
    "00:E0:FC": "Huawei",
    "48:46:FB": "Huawei",
    "88:53:95": "Huawei",
    # --- Sony ---
    "00:04:1F": "Sony",
    "FC:0F:E6": "Sony",
    "78:C8:81": "Sony",
    # --- LG ---
    "00:1C:62": "LG",
    "A8:23:FE": "LG",
    "BC:F5:AC": "LG",
    # --- Brother (printers) ---
    "00:80:77": "Brother",
    "30:05:5C": "Brother",
    # --- Canon (printers) ---
    "00:1E:8F": "Canon",
    "18:0C:AC": "Canon",
    # --- Epson (printers) ---
    "00:26:AB": "Epson",
    "64:EB:8C": "Epson",
    # --- Microsoft / Xbox ---
    "7C:1E:52": "Microsoft",
    "28:18:78": "Microsoft Xbox",
    "00:50:F2": "Microsoft",
    # --- Nintendo ---
    "00:1F:32": "Nintendo",
    "E8:4E:CE": "Nintendo",
    "34:AF:2C": "Nintendo",
}

# Vendor → likely device type mapping
_VENDOR_DEVICE_TYPES: dict[str, str] = {
    "Cisco": "router",
    "TP-Link": "router",
    "Netgear": "router",
    "Ubiquiti": "access_point",
    "ASUS": "router",
    "HP": "client",
    "Dell": "client",
    "Lenovo": "client",
    "Apple": "client",
    "Samsung": "phone",
    "Xiaomi": "phone",
    "Huawei": "phone",
    "Google Nest": "iot",
    "Amazon Echo": "iot",
    "Amazon": "iot",
    "Espressif (IoT)": "iot",
    "Tuya IoT": "iot",
    "Philips Hue": "iot",
    "Ring": "camera",
    "Hikvision": "camera",
    "Dahua": "camera",
    "Synology": "nas",
    "QNAP": "nas",
    "Brother": "printer",
    "Canon": "printer",
    "Epson": "printer",
    "Sonos": "iot",
    "Roku": "smart_tv",
    "Sony": "smart_tv",
    "LG": "smart_tv",
    "Google": "iot",
    "Raspberry Pi": "iot",
    "Microsoft Xbox": "client",
    "Nintendo": "client",
    "Simulated Device": "unknown",
    "VMware": "server",
    "Oracle VirtualBox": "server",
    "QEMU/KVM": "server",
    "Docker Container": "server",
    "Microsoft Hyper-V": "server",
}


def lookup_vendor(mac: str) -> str:
    """
    Return the vendor name for a MAC address, or "Unknown".

    Args:
        mac: MAC address in any common format (colon or dash separated).

    Educational note:
      We normalise the MAC to uppercase, colon-separated format and
      then extract the first three octets for the OUI lookup.
    """
    normalised = mac.upper().replace("-", ":").replace(".", ":")
    oui = normalised[:8]  # "AA:BB:CC"
    return _OUI_TABLE.get(oui, "Unknown")


def guess_device_type(mac: str, vendor: str | None = None) -> str:
    """
    Guess the device type from its vendor name.

    Educational note:
      Device type inference from vendor is heuristic — a Cisco MAC
      could be a switch, router, or phone. But it's a useful starting
      point for network inventory.
    """
    if vendor is None:
        vendor = lookup_vendor(mac)
    return _VENDOR_DEVICE_TYPES.get(vendor, "unknown")


def is_vm_mac(mac: str) -> bool:
    """
    Heuristic: returns True if the MAC belongs to a known hypervisor / VM vendor.

    Educational note:
      Virtual machines are assigned MAC addresses from their hypervisor's
      OUI range.  Knowing whether a device is virtual helps students
      distinguish lab traffic from real hardware on the network.
    """
    vendor = lookup_vendor(mac)
    vm_keywords = {"VMware", "VirtualBox", "QEMU", "KVM", "Xen", "Hyper-V", "Docker"}
    return any(kw in vendor for kw in vm_keywords)
