import socket  # socket programs help that it listens for a server sockets!
ports = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}
def scan_ports(target):
    results = []
    open_ports = []
    results.append(f"\nScanning target: {target}\n")

    for port,service in ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        
        result = s.connect_ex((target,port))

        if result == 0:
            results.append(f"Port:{port} is Open!! Service name: {service}")
            open_ports.append(port)
        s.close()
    
    return results, open_ports

if __name__ == "__main__":
    target_ip = input("Enter target IP or domain: ")
    scan_results, open_ports = scan_ports(target_ip)
    for line in scan_results:
        print(line)
    print("Open ports list:", open_ports)