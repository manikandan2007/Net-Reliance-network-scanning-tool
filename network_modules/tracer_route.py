import subprocess
import platform
import sys

def traceroute(host):
    if platform.system().lower() == "windows":
        command = ["tracert", host]
    else:
        command = ["traceroute", host]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Traceroute failed: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "Traceroute timed out"
    except FileNotFoundError:
        return "Traceroute command not found. Please ensure it's installed."
    except Exception as e:
        return f"An error occurred: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = input("Enter the host for traceroute: ")
    result = traceroute(host)
    print(result)