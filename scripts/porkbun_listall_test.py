# datei scripts porkbun_listall_test py
# zeigt porkbun domain listall
import json
import requests
import sys

API_KEY = "pk1_9375818a4a3f55f11328e1f408d4c239cf4af27cebc7b8a6a6d406f37170c51e"
SECRET_KEY = "sk1_1903e46f3b64a0fe800a156c38bd143adb46ba74c2262fae3165293c12a048ca"

URL = "https://api.porkbun.com/api/json/v3/domain/listAll"
HEADERS = {"Content-Type": "application/json"}

PAYLOAD = {
    "secretapikey": SECRET_KEY,
    "apikey": API_KEY,
    "start": "0",
    "includeLabels": "yes",
}


def main():
    try:
        resp = requests.post(URL, json=PAYLOAD, headers=HEADERS, timeout=15)
    except requests.exceptions.RequestException as e:
        print("Request failed:", e, file=sys.stderr)
        sys.exit(2)

    print(f"HTTP {resp.status_code}")
    content_type = resp.headers.get("Content-Type", "")
    # Try to parse JSON, otherwise print text (truncated)
    if "application/json" in content_type or resp.text.strip().startswith("{"):
        try:
            data = resp.json()
            print(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception as e:
            print("Failed to decode JSON response:", e, file=sys.stderr)
            print(resp.text)
            sys.exit(3)
    else:
        text = resp.text or ""
        print("Non-JSON response (truncated):")
        print((text[:1000] + "...[truncated]") if len(text) > 1000 else text)


if __name__ == "__main__":
    main()
