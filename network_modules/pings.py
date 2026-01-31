import subprocess
import platform

def ping_host(host):
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "2", host]
    else:
        command = ["ping", "-c", "2", host]

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return f"Reachable\n{result.stdout.strip()}"
    else:
        return f"Unreachable\n{result.stderr.strip()}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python pings.py <host>")
        sys.exit(1)
    host = sys.argv[1]
    print(ping_host(host))