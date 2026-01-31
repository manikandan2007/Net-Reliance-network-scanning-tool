import requests

def get_headers(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=10)
        return dict(r.headers)
    except requests.exceptions.RequestException as e:
        return {"Error": f"Unable to fetch headers: {str(e)}"}
    except Exception as e:
        return {"Error": f"An unexpected error occurred: {str(e)}"}

if __name__ == "__main__":
    url = input("Enter URL: ")
    headers = get_headers(url)
    print("HTTP Headers:")
    for key, value in headers.items():
        print(f"{key}: {value}")