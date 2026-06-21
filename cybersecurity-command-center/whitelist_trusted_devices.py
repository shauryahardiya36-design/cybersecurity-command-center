from core.database import ScanDatabase

db = ScanDatabase()

trusted_devices = {
    "192.168.1.1": "Router",
    "192.168.1.2": "Smart Device",
    "192.168.1.3": "Smart Device",
    "192.168.1.4": "Home Device",
    "192.168.1.11": "Home Device",
    "192.168.1.14": "Home Device",
}

print("[ WHITELISTING TRUSTED HOME DEVICES ]\n")

for ip, device_name in trusted_devices.items():
    db.add_whitelist(ip, reason=f"Trusted home network - {device_name}")
    print(f"✓ Whitelisted {ip} ({device_name})")

print(f"\n✅ Successfully whitelisted {len(trusted_devices)} devices")
print("\nWhitelisted IPs:")
whitelist = db.get_whitelist()
for ip, info in whitelist.items():
    print(f"  - {ip}: {info['reason']}")