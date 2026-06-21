class DeviceFingerprinter:
    """Identify OS and device type."""
    
    @staticmethod
    def identify_os(open_ports, banners):
        """Guess OS from ports."""
        os_signatures = {
            "Windows": [135, 139, 445, 3389],
            "Linux": [22, 80, 443, 3306],
            "macOS": [22, 80, 443, 5900],
            "iOS/Android": [5353, 5900],
        }
        
        for os_name, sig_ports in os_signatures.items():
            if any(p in open_ports for p in sig_ports):
                return os_name
        return "Unknown"
    
    @staticmethod
    def identify_device_type(banners):
        """Identify device type."""
        banner_text = " ".join(str(b) for b in banners.values()).lower()
        
        keywords = {
            "NAS": ["synology", "qnap", "freenas"],
            "Printer": ["hp", "canon", "xerox"],
            "Smart TV": ["lg", "samsung", "sony", "roku"],
            "IoT": ["arduino", "raspberry", "embedded"],
            "Server": ["apache", "nginx", "iis"],
        }
        
        for device_type, kws in keywords.items():
            if any(kw in banner_text for kw in kws):
                return device_type
        
        return "Unknown Device"