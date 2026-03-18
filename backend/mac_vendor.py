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
    # Apple
    "A4:83:E7": "Apple",
    "3C:22:FB": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "00:1B:63": "Apple",
    "D8:30:62": "Apple",
    # Samsung
    "00:07:AB": "Samsung",
    "8C:77:12": "Samsung",
    "B4:79:A7": "Samsung",
    # Intel
    "00:1B:21": "Intel",
    "68:05:CA": "Intel",
    "3C:97:0E": "Intel",
    # Cisco
    "00:1A:A1": "Cisco",
    "00:1B:0D": "Cisco",
    "00:26:0B": "Cisco",
    # Dell
    "00:14:22": "Dell",
    "18:A9:9B": "Dell",
    "F8:DB:88": "Dell",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # TP-Link
    "50:C7:BF": "TP-Link",
    "C0:25:E9": "TP-Link",
    # Netgear
    "00:1E:2A": "Netgear",
    "C4:3D:C7": "Netgear",
    # Ubiquiti
    "04:18:D6": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    # Espressif (ESP32/ESP8266 — common in IoT labs)
    "24:0A:C4": "Espressif (IoT)",
    "30:AE:A4": "Espressif (IoT)",
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
