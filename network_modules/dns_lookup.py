import socket

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return "DNS lookup failed"

if __name__ == "__main__":
    domain = input("Enter the domain name to lookup: ")
    result = dns_lookup(domain)
    print(f"IP address for {domain}: {result}")