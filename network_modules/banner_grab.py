import socket

def banner_grab(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # Increased timeout for better reliability
        s.connect((host, port))
        s.send(b"Hello\r\n")
        banner = s.recv(1024)
        s.close()
        # Try to decode, fallback to repr if fails
        try:
            return banner.decode('utf-8', errors='ignore').strip()
        except UnicodeDecodeError:
            return repr(banner)
    except socket.timeout:
        return "Connection timed out"
    except ConnectionRefusedError:
        return "Connection refused"
    except OSError as e:
        return f"Network error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    host = input("Enter host (IP or domain): ")
    port = input("Enter port: ")
    try:
        port = int(port)
    except ValueError:
        print("Invalid port number")
        exit(1)
    result = banner_grab(host, port)
    print(f"Banner for {host}:{port}: {result}")