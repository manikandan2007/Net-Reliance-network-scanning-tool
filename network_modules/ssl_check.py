import ssl
import socket

def ssl_info(host, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get('issuer', 'Unknown')
                subject = cert.get('subject', 'Unknown')
                expiry = cert.get('notAfter', 'Unknown')
                return {
                    'Issuer': issuer,
                    'Subject': subject,
                    'Expiry': expiry
                }
    except ssl.SSLError as e:
        return {"Error": f"SSL error: {str(e)}"}
    except socket.timeout:
        return {"Error": "Connection timed out"}
    except ConnectionRefusedError:
        return {"Error": "Connection refused"}
    except Exception as e:
        return {"Error": f"An error occurred: {str(e)}"}

if __name__ == "__main__":
    host = input("Enter host (domain): ")
    port_input = input("Enter port (default 443): ").strip()
    port = int(port_input) if port_input else 443
    result = ssl_info(host, port)
    if isinstance(result, dict) and 'Error' in result:
        print(result['Error'])
    else:
        print("SSL Certificate Info:")
        for key, value in result.items():
            print(f"{key}: {value}")