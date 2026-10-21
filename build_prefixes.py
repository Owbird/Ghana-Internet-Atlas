import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ipaddress
import json
from datetime import datetime, timezone


url = "https://stat.ripe.net/data/country-resource-list/data.json"

response = requests.get(url, params={"resource": "gh"}, timeout=30)
response.raise_for_status()
payload = response.json()

if payload.get("status") != "ok":
    raise RuntimeError(f"RIPEstat request failed: {payload.get('messages')}")

asns = payload["data"]["resources"]["asn"]

print(f"Total ASNs: {len(asns)}")

asn = asns[0]

response = requests.get(
    "https://stat.ripe.net/data/announced-prefixes/data.json",
    params={"resource": f"AS{asn}"},
    timeout=30,
)
response.raise_for_status()
payload = response.json()

if payload.get("status") != "ok":
    raise RuntimeError(f"RIPEstat request failed: {payload.get('messages')}")

prefixes = payload["data"]["prefixes"]

print(f"AS{asn}: {len(prefixes)} prefixes")
print("Query window:", payload["data"].get("query_starttime"),
      "to", payload["data"].get("query_endtime"))

starttime = payload["data"]["query_starttime"]
endtime = payload["data"]["query_endtime"]

session = requests.Session()
session.mount(
    "https://",
    HTTPAdapter(max_retries=Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )),
)

asn_prefixes = {}
asn_names = {}
asn_name_failures = {}
failures = {}

for i, asn in enumerate(asns, start=1):
    asn_names[asn] = None
    try:
        response = session.get(
            "https://stat.ripe.net/data/as-overview/data.json",
            params={"resource": f"AS{asn}"},
            timeout=30,
        )
        response.raise_for_status()
        overview = response.json()

        if overview.get("status") != "ok":
            raise RuntimeError(overview.get("messages"))

        # RIPEstat returns null for ASNs without a registered holder.
        asn_names[asn] = overview["data"]["holder"]
    except (requests.RequestException, ValueError, KeyError, RuntimeError) as exc:
        asn_name_failures[asn] = str(exc)

    try:
        response = session.get(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={
                "resource": f"AS{asn}",
                "starttime": starttime,
                "endtime": endtime,
            },
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()

        if result.get("status") != "ok":
            raise RuntimeError(result.get("messages"))

        # Retain timelines and the relationship between ASN and prefix.
        asn_prefixes[asn] = result["data"]["prefixes"]

    except (requests.RequestException, ValueError, KeyError, RuntimeError) as exc:
        failures[asn] = str(exc)

    print(f"\rFetched {i}/{len(asns)} ASNs | failures: {len(failures)}",
          end="", flush=True)

session.close()

ipv4_networks = {
    ipaddress.ip_network(entry["prefix"])
    for entries in asn_prefixes.values()
    for entry in entries
    if ipaddress.ip_network(entry["prefix"]).version == 4
}

ipv4_ranges = list(ipaddress.collapse_addresses(ipv4_networks))
total_ips = sum(network.num_addresses for network in ipv4_ranges)

print(f"\n\nASNs collected: {len(asn_prefixes):,}")
print(f"ASNs with no prefixes: {sum(not p for p in asn_prefixes.values()):,}")
print(f"Failed ASNs: {len(failures):,}")
print(f"Failed ASN name lookups: {len(asn_name_failures):,}")
print(f"Unique IPv4 prefixes: {len(ipv4_networks):,}")
print(f"Merged IPv4 ranges: {len(ipv4_ranges):,}")
print(f"Unique IPv4 addresses: {total_ips:,}")

if failures:
    print("\nFailures:", failures)

if asn_name_failures:
    print("\nASN name lookup failures:", asn_name_failures)

checkpoint = {
    "collected_at": datetime.now(timezone.utc).isoformat(),
    "query_starttime": starttime,
    "query_endtime": endtime,
    "asns": asns,
    "asn_names": asn_names,
    "asn_name_failures": asn_name_failures,
    "asn_prefixes": asn_prefixes,
    "failures": failures,
    "ipv4_ranges": [str(network) for network in ipv4_ranges],
    "total_ipv4_addresses": total_ips,
}

with open("ghana_routes.json", "w") as f:
    json.dump(checkpoint, f, indent=2)

print("Saved ghana_routes.json")
