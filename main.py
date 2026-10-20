import requests

url = "https://stat.ripe.net/data/country-resource-list/data.json"

response = requests.get(url, params={"resource": "gh"}, timeout=30)
response.raise_for_status()
payload = response.json()

if payload.get("status") != "ok":
    raise RuntimeError(f"RIPEstat request failed: {payload.get('messages')}")

asns = payload["data"]["resources"]["asn"]

print(f"Total ASNs: {len(asns)}")
print(asns)
