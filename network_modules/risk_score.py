def calculate_risk(open_ports):
    score = 0
    risk_factors = {
        21: ("FTP", 20),      # File Transfer Protocol - insecure
        22: ("SSH", 15),      # Secure Shell - can be risky if misconfigured
        23: ("Telnet", 25),   # Telnet - very insecure
        25: ("SMTP", 10),     # Simple Mail Transfer Protocol
        80: ("HTTP", 10),     # HyperText Transfer Protocol - unencrypted
        110: ("POP3", 15),    # Post Office Protocol - insecure
        143: ("IMAP", 15),    # Internet Message Access Protocol - insecure
        3306: ("MySQL", 40),  # MySQL Database - high risk if exposed
        3389: ("RDP", 30),    # Remote Desktop Protocol
        8080: ("HTTP-Alt", 10) # Alternative HTTP port
    }

    for port in open_ports:
        if port in risk_factors:
            service, points = risk_factors[port]
            score += points
            print(f"Port {port} ({service}) adds {points} risk points")

    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level

if __name__ == "__main__":
    ports_input = input("Enter open ports (comma-separated, e.g., 21,80,3306): ")
    try:
        open_ports = [int(p.strip()) for p in ports_input.split(',') if p.strip()]
        score, level = calculate_risk(open_ports)
        print(f"\nTotal Risk Score: {score}")
        print(f"Risk Level: {level}")
    except ValueError:
        print("Invalid input. Please enter numbers separated by commas.")