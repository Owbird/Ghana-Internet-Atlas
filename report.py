#!/usr/bin/env python3
"""Generate an offline HTML report from the Ghana Internet Atlas database.

Usage:
    python report.py
    python report.py --run 1
    python report.py --output reports/atlas.html --host-limit 2000
    python report.py --max-ports 100

Safe to run while collectors are running. Reads a consistent PostgreSQL snapshot.
No network requests or third-party packages are required.

Hosts reporting more than --max-ports open ports are almost always tarpits,
honeypots or middleboxes that answer on every port. They are flagged and
excluded from the port statistics so that a single host cannot dominate them.

When the route snapshot contains asn_prefixes, every address is attributed to
the most specific announced prefix covering it (longest-prefix match) and a
per-network table is added to the report.
"""

import argparse
import heapq
import html
import ipaddress
import json
import re
import atlas_db
import psycopg
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


UNATTRIBUTED = "Unattributed"

PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS name service",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IPsec IKE",
    541: "FortiGate management (FGFM)",
    554: "RTSP (cameras/media)",
    587: "SMTP submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    1434: "SQL Server Browser",
    1521: "Oracle",
    1701: "L2TP",
    1723: "PPTP",
    1883: "MQTT",
    2000: "MikroTik bandwidth test",
    2375: "Docker",
    3000: "Alternate web",
    3128: "Proxy (Squid)",
    3306: "MySQL",
    3389: "RDP",
    4500: "IPsec NAT-T",
    5060: "SIP",
    5357: "Windows web services (WSD)",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    7547: "TR-069 (CWMP)",
    8000: "Alternate web",
    8080: "Alternate HTTP",
    8081: "Alternate HTTP",
    8291: "MikroTik Winbox",
    8443: "Alternate HTTPS",
    8728: "MikroTik API",
    8729: "MikroTik API (TLS)",
    9200: "Elasticsearch",
    10443: "Alternate HTTPS",
    27017: "MongoDB",
}


def esc(value):
    return html.escape(str(value), quote=True)


def percent(numerator, denominator):
    return 100 * numerator / denominator if denominator else 0.0


def port_label(port):
    return f"{port} · {PORT_NAMES.get(port, 'Unclassified')}"


def strings(value):
    """Normalize a JSON list to unique, nonempty strings."""
    if not isinstance(value, list):
        return []
    return sorted({
        item.strip()
        for item in value
        if isinstance(item, str) and item.strip()
    })


def port_list(value):
    if not isinstance(value, list):
        return []
    return sorted({
        item for item in value
        if type(item) is int and 1 <= item <= 65535
    })


def load_snapshot(path):
    if not path.exists():
        return None

    with path.open(encoding="utf-8") as handle:
        snapshot = json.load(handle)

    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot must contain a JSON object.")

    # Recalculate the unique address count rather than trusting a saved total.
    if "ipv4_ranges" in snapshot:
        networks = list(ipaddress.collapse_addresses(
            ipaddress.IPv4Network(prefix)
            for prefix in snapshot["ipv4_ranges"]
        ))
        snapshot["total_ipv4_addresses"] = sum(
            network.num_addresses for network in networks
        )
        snapshot["merged_range_count"] = len(networks)

    return snapshot


def asn_sort_key(asn):
    text = str(asn)
    return (0, int(text), text) if text.isdigit() else (1, 0, text)


def build_attribution(snapshot):
    """Return (lookup, owned) for longest-prefix attribution.

    lookup(ip) returns a label such as "AS30986" (or "AS1 / AS2" when several
    ASNs announce the identical prefix) or None. owned maps each label to the
    number of addresses it announces that are not covered by a more specific
    announcement, so the per-network totals do not overlap.
    """
    if not snapshot:
        return None, {}

    raw = snapshot.get("asn_prefixes")
    if not isinstance(raw, dict):
        return None, {}

    origins = {}
    for asn, entries in raw.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            prefix = entry.get("prefix") if isinstance(entry, dict) else None
            try:
                network = ipaddress.ip_network(prefix)
            except (TypeError, ValueError):
                continue
            if network.version == 4:
                origins.setdefault(network, set()).add(str(asn))

    if not origins:
        return None, {}

    labels = {
        network: " / ".join(
            f"AS{asn}" for asn in sorted(asns, key=asn_sort_key)
        )
        for network, asns in origins.items()
    }

    owned = Counter()
    for network, label in labels.items():
        children = [
            other for other in labels
            if other.prefixlen > network.prefixlen
            and other.subnet_of(network)
        ]
        covered = sum(
            child.num_addresses
            for child in ipaddress.collapse_addresses(children)
        )
        owned[label] += network.num_addresses - covered

    index = {}
    for network, label in labels.items():
        index.setdefault(network.prefixlen, {})[
            int(network.network_address)
        ] = label

    lengths = sorted(index, reverse=True)

    def lookup(ip):
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
        for length in lengths:
            mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
            label = index[length].get(value & mask)
            if label:
                return label
        return None

    return lookup, dict(owned)


def new_network_stats():
    return {
        "resolved": 0,
        "records": 0,
        "errors": 0,
        "cve_hosts": 0,
        "anomalous": 0,
        "ports": Counter(),
    }


def read_database(path, host_limit, max_ports, lookup=None, connection=None):
    result = {
        "statuses": Counter(),
        "ports": Counter(),
        "cpes": Counter(),
        "tags": Counter(),
        "cves": Counter(),
        "port_counts": Counter(),
        "networks": {},
        "valid_records": 0,
        "malformed_records": 0,
        "anomalous_hosts": 0,
        "anomalous_ports": 0,
        "max_cves_per_host": 0,
        "hosts_with_cves": 0,
        "eol_hosts": 0,
        "hosts_with_names": 0,
        "first_saved": None,
        "last_saved": None,
        "error_messages": Counter(),
    }

    host_heap = []

    # A server cursor streams a consistent, read-only PostgreSQL snapshot.
    from contextlib import nullcontext
    supplied_connection = connection is not None
    with nullcontext(connection) if supplied_connection else atlas_db.connect() as connection:
        if not supplied_connection:
            connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        from psycopg.rows import tuple_row
        cursor = connection.cursor(name='report_observations', row_factory=tuple_row)
        cursor.itersize = 1000
        cursor.execute("""
            SELECT host(ip), status, payload, error, fetched_at
            FROM observations WHERE run_id=%s
        """, (path,))
        for ip, status, raw, error, saved_at in cursor:
            result["statuses"][str(status)] += 1

            label = (lookup(str(ip)) if lookup else None) or UNATTRIBUTED
            network = result["networks"].setdefault(
                label, new_network_stats()
            )

            if status in ("ok", "no_data"):
                network["resolved"] += 1

            if saved_at:
                stamp = str(saved_at)
                first = result["first_saved"]
                last = result["last_saved"]
                result["first_saved"] = min(first, stamp) if first else stamp
                result["last_saved"] = max(last, stamp) if last else stamp

            if status in ("retry", "exhausted"):
                network["errors"] += 1
                # Limit retained error text to keep the report manageable.
                result["error_messages"][str(error or "Unspecified")[:200]] += 1

            if status != "ok":
                continue

            try:
                record = raw if isinstance(raw, dict) else json.loads(raw)
                if not isinstance(record, dict):
                    raise ValueError("Payload is not an object")
            except (TypeError, ValueError):
                result["malformed_records"] += 1
                continue

            ports = port_list(record.get("ports"))
            cpes = strings(record.get("cpes"))
            tags = strings(record.get("tags"))
            cves = strings(record.get("vulns"))
            names = strings(record.get("hostnames"))
            anomalous = len(ports) > max_ports

            result["valid_records"] += 1
            result["cpes"].update(cpes)
            result["tags"].update(tags)
            result["cves"].update(cves)
            result["hosts_with_cves"] += bool(cves)
            result["hosts_with_names"] += bool(names)
            result["eol_hosts"] += "eol-product" in tags
            result["max_cves_per_host"] = max(
                result["max_cves_per_host"], len(cves)
            )

            network["records"] += 1
            network["cve_hosts"] += bool(cves)

            if anomalous:
                # Likely a tarpit, honeypot or middlebox. Keep it visible in
                # the host explorer but out of the port statistics.
                result["anomalous_hosts"] += 1
                result["anomalous_ports"] += len(ports)
                network["anomalous"] += 1
            else:
                result["ports"].update(ports)
                result["port_counts"][len(ports)] += 1
                network["ports"].update(ports)

            host = {
                "ip": str(ip),
                "asn": label,
                "ports": ports,
                "names": names,
                "cpes": cpes,
                "tags": tags,
                "cves": cves,
                "anomalous": anomalous,
                "saved_at": str(saved_at or ""),
            }

            # Keep a bounded sample with the most reported ports.
            # This is an inspection sample, not a risk ranking.
            item = (len(ports), str(ip), host)

            if len(host_heap) < host_limit:
                heapq.heappush(host_heap, item)
            elif item[:2] > host_heap[0][:2]:
                heapq.heapreplace(host_heap, item)

        cursor.close()

    result["hosts"] = [
        item[2]
        for item in sorted(host_heap, reverse=True)
    ]
    return result


def card(label, value, detail, tone=""):
    return f"""
    <article class="metric {esc(tone)}">
      <div class="metric-label">{esc(label)}</div>
      <div class="metric-value">{esc(value)}</div>
      <div class="metric-detail">{esc(detail)}</div>
    </article>
    """


def bars(counter, denominator, limit=12, labeler=str, tone=""):
    if not counter:
        return '<p class="empty">No observations yet.</p>'

    maximum = max(counter.values())
    rows = []

    for key, count in counter.most_common(limit):
        width = 100 * count / maximum
        share = percent(count, denominator)

        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">
            <span title="{esc(labeler(key))}">{esc(labeler(key))}</span>
            <strong>{count:,}<small>{share:.1f}%</small></strong>
          </div>
          <div class="bar-track">
            <div class="bar-fill {esc(tone)}" style="width:{width:.3f}%"></div>
          </div>
        </div>
        """)

    return "".join(rows)


def panel(title, description, content):
    return f"""
    <section class="panel">
      <h2>{esc(title)}</h2>
      <p class="section-description">{esc(description)}</p>
      {content}
    </section>
    """


def chips(items, tone=""):
    if not items:
        return '<span class="muted">None reported</span>'

    return "".join(
        f'<span class="chip {esc(tone)}">{esc(item)}</span>'
        for item in items
    )


def networks_section(data, owners, asn_names=None):
    """Per-network table for the networks reached so far."""
    if not owners:
        return ""

    asn_names = asn_names if isinstance(asn_names, dict) else {}
    stats = data["networks"]
    scanned = sorted(
        (
            (label, entry) for label, entry in stats.items()
            if entry["resolved"]
        ),
        key=lambda pair: -pair[1]["resolved"],
    )
    unreached = sum(
        1 for label in owners
        if not stats.get(label, {}).get("resolved")
    )

    rows = []
    for label, entry in scanned:
        network_label = " / ".join(
            f"{asn} ({name})" if name else asn
            for asn in label.split(" / ")
            for name in [asn_names.get(asn.removeprefix("AS"))]
        )
        announced = owners.get(label)
        progress = (
            f"{percent(entry['resolved'], announced):.1f}%"
            if announced else "—"
        )
        top_ports = [
            f"{port} {PORT_NAMES.get(port, '')}".strip()
            for port, _ in entry["ports"].most_common(3)
        ]

        rows.append(f"""
        <tr>
          <td>{esc(network_label)}</td>
          <td class="num">{announced:,}</td>
          <td class="num">{entry['resolved']:,}</td>
          <td class="num">{esc(progress)}</td>
          <td class="num">{entry['records']:,}</td>
          <td class="num">{percent(entry['records'], entry['resolved']):.1f}%</td>
          <td class="num">{entry['cve_hosts']:,}</td>
          <td>{chips(top_ports)}</td>
        </tr>
        """ if announced else f"""
        <tr>
          <td>{esc(network_label)}</td>
          <td class="num">—</td>
          <td class="num">{entry['resolved']:,}</td>
          <td class="num">—</td>
          <td class="num">{entry['records']:,}</td>
          <td class="num">{percent(entry['records'], entry['resolved']):.1f}%</td>
          <td class="num">{entry['cve_hosts']:,}</td>
          <td>{chips(top_ports)}</td>
        </tr>
        """)

    if not rows:
        return ""

    table = (
        '<div class="table-wrap"><table><thead><tr>'
        '<th>Network (ASN and name)</th><th class="num">Announced addresses</th>'
        '<th class="num">Resolved</th><th class="num">Progress</th>'
        '<th class="num">Records</th><th class="num">Hit rate</th>'
        '<th class="num">Hosts with CVE labels</th><th>Most common ports</th>'
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )

    return f"""
    <section class="panel host-section">
      <h2>Networks reached so far</h2>
      <p class="section-description">
        Each address is attributed to the most specific announced prefix
        covering it. Announced addresses exclude space covered by a more
        specific announcement from another network. __UNREACHED__ further
        networks have not been reached yet, so these figures describe only
        the networks listed here.
      </p>
      {table}
    </section>
    """.replace("__UNREACHED__", f"{unreached:,}")


def build_report(data, snapshot, db_name, owners, max_ports):
    statuses = data["statuses"]
    found = statuses["ok"]
    no_data = statuses["no_data"]
    errors = statuses["retry"] + statuses["exhausted"]
    resolved = found + no_data
    stored = sum(statuses.values())
    valid = data["valid_records"]
    port_hosts = valid - data["anomalous_hosts"]

    target = None
    if snapshot:
        value = snapshot.get("total_ipv4_addresses")
        if type(value) is int and value >= 0:
            target = value

    generated = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    hit_rate = percent(found, resolved)
    cve_share = percent(data["hosts_with_cves"], valid)
    port_observations = sum(data["ports"].values())

    metrics = [
        card(
            "Addresses resolved",
            f"{resolved:,}",
            "Successful lookups + confirmed database misses",
        ),
        card(
            "InternetDB records",
            f"{found:,}",
            f"{hit_rate:.1f}% of resolved lookups",
            "green",
        ),
        card(
            "No database record",
            f"{no_data:,}",
            "A database miss does not establish that an IP is offline",
        ),
        card(
            "Lookup errors",
            f"{errors:,}",
            "Retryable and exhausted failures; see distributed collection details",
            "amber" if errors else "",
        ),
        card(
            "Hosts with CVE labels",
            f"{data['hosts_with_cves']:,}",
            f"{cve_share:.1f}% of readable host records",
            "amber",
        ),
        card(
            "Unique reported CVEs",
            f"{len(data['cves']):,}",
            "Distinct source-reported identifiers",
        ),
    ]

    notes = []

    if target is not None:
        coverage = percent(resolved, target)
        progress_width = min(100, coverage)
        pending = max(0, target - stored)

        coverage_text = (
            f"{resolved:,} / {target:,} target addresses resolved "
            f"({coverage:.2f}%). "
            f"{pending:,} addresses have no saved row."
        )

        if stored > target:
            notes.append(
                "The database contains more rows than the snapshot's target "
                "count. Coverage may refer to different collection scopes."
            )

        progress = f"""
        <section class="coverage">
          <div class="coverage-heading">
            <h2>Collection progress</h2>
            <strong>{coverage:.2f}%</strong>
          </div>
          <div class="progress-track">
            <div style="width:{progress_width:.3f}%"></div>
          </div>
          <p>{esc(coverage_text)}</p>
        </section>
        """

        notes.append(
            "Coverage uses this run’s seeded IPv4 scope. Imported legacy "
            "addresses are checked against that scope."
        )
    else:
        progress = """
        <section class="coverage">
          <h2>Collection progress</h2>
          <p>No address target available. Supply ghana_routes.json to show
          coverage and remaining addresses.</p>
        </section>
        """

    notes.extend([
        "This report summarizes saved InternetDB observations. A reported "
        "port does not prove the service is reachable now.",
        "CVE labels are source-reported associations, not confirmed "
        "exploitable vulnerabilities. Counts do not measure severity.",
        "Percentages in the port charts use readable host records that are "
        "within the port threshold as their denominator. Percentages in the "
        "software, tag and CVE charts use all readable host records. A host "
        "can appear in several bars.",
        "The collection proceeds in address order. Partial results describe "
        "only the networks reached so far and are not a representative "
        "sample of Ghana's networks. Hit rates from one network should not "
        "be extrapolated to others.",
        "Saved timestamps are the collector's saved timestamp "
        "(UTC), not Shodan's original observation time.",
    ])

    if data["anomalous_hosts"]:
        notes.append(
            f"{data['anomalous_hosts']:,} host(s) reported more than "
            f"{max_ports} open ports "
            f"({data['anomalous_ports']:,} port observations in total). "
            "Such hosts are typically tarpits, honeypots or middleboxes "
            "that answer on every port. They remain in the host explorer "
            "but are excluded from the port statistics."
        )

    if data["malformed_records"]:
        notes.append(
            f"{data['malformed_records']:,} successful rows contained unreadable "
            "JSON payloads. They count toward lookup coverage but are excluded "
            "from host analytics."
        )

    if snapshot:
        notes.append(
            "Route observation window: "
            f"{snapshot.get('query_starttime', 'unknown')} to "
            f"{snapshot.get('query_endtime', 'unknown')}. "
            "Prefixes observed during a window may include withdrawn routes."
        )

    panels = [
        panel(
            "Reported ports",
            "Hosts per port, excluding hosts above the port threshold. "
            "Service names are conventional hints, not verified protocol "
            "identification.",
            bars(data["ports"], port_hosts, labeler=port_label),
        ),
        panel(
            "Software fingerprints",
            "Exact CPE identifiers reported by InternetDB, counted once per host.",
            bars(data["cpes"], valid, tone="purple"),
        ),
        panel(
            "Reported CVE associations",
            "Hosts carrying each CVE label. Identical counts across many CVEs "
            "usually mean one software stack. No exploitability or severity "
            "ranking is implied.",
            bars(data["cves"], valid, tone="amber"),
        ),
        panel(
            "Host tags",
            "Tags attached to readable host records.",
            bars(data["tags"], valid, tone="green"),
        ),
    ]

    distribution = Counter()
    for count, hosts in data["port_counts"].items():
        bucket = (
            "0 ports" if count == 0 else
            "1 port" if count == 1 else
            "2–5 ports" if count <= 5 else
            "6–10 ports" if count <= 10 else
            "11–20 ports" if count <= 20 else
            "21+ ports"
        )
        distribution[bucket] += hosts

    distribution_rows = "".join(
        f"<tr><td>{esc(bucket)}</td><td>{distribution[bucket]:,}</td>"
        f"<td>{percent(distribution[bucket], port_hosts):.1f}%</td></tr>"
        for bucket in [
            "0 ports", "1 port", "2–5 ports",
            "6–10 ports", "11–20 ports", "21+ ports",
        ]
    )

    panels.append(panel(
        "Ports per host",
        f"Distribution across readable host records with at most "
        f"{max_ports} reported ports.",
        '<table><thead><tr><th>Reported ports</th><th>Hosts</th>'
        '<th>Share</th></tr></thead><tbody>'
        + distribution_rows + "</tbody></table>",
    ))

    facts = [
        ("Readable host records", f"{valid:,}"),
        (
            f"Hosts above {max_ports} ports (excluded from port statistics)",
            f"{data['anomalous_hosts']:,}",
        ),
        ("Host-port observations", f"{port_observations:,}"),
        ("Distinct port numbers", f"{len(data['ports']):,}"),
        ("Hosts with hostnames", f"{data['hosts_with_names']:,}"),
        ("Hosts tagged end-of-life", f"{data['eol_hosts']:,}"),
        (
            "Most CVE labels on one host",
            f"{data['max_cves_per_host']:,}",
        ),
        ("First saved lookup (UTC)", data["first_saved"] or "No rows yet"),
        ("Last saved lookup (UTC)", data["last_saved"] or "No rows yet"),
    ]

    if snapshot:
        facts.extend([
            ("ASNs in snapshot", f"{len(snapshot.get('asns', [])):,}"),
            (
                "Merged IPv4 ranges",
                str(snapshot.get("merged_range_count", "Unknown")),
            ),
        ])

    panels.append(panel(
        "Dataset facts",
        "Counts and timestamps from this report's consistent database view.",
        '<dl class="facts">' + "".join(
            f"<div><dt>{esc(label)}</dt><dd>{esc(value)}</dd></div>"
            for label, value in facts
        ) + "</dl>",
    ))

    host_rows = []
    for host in data["hosts"]:
        if host["anomalous"]:
            ports_cell = chips(
                [
                    f"{len(host['ports']):,} ports reported · "
                    f"above the {max_ports}-port threshold"
                ],
                "amber",
            )
            port_detail = (
                "<h4>Reported ports (first 40)</h4>"
                + chips([str(p) for p in host["ports"][:40]])
            )
        else:
            ports_cell = chips([str(p) for p in host["ports"]])
            port_detail = ""

        details = (
            "<details><summary>Inspect record</summary>"
            "<div class='record-details'>"
            + port_detail
            + "<h4>Software fingerprints</h4>"
            + chips(host["cpes"])
            + "<h4>Reported CVEs</h4>"
            + chips(host["cves"], "amber")
            + "<h4>Tags</h4>"
            + chips(host["tags"])
            + f"<p class='muted'>Lookup saved: {esc(host['saved_at'])}</p>"
            + "</div></details>"
        )

        host_rows.append(f"""
        <tr class="host-row">
          <td><code>{esc(host['ip'])}</code></td>
          <td>{esc(host['asn'])}</td>
          <td class="hostnames">{esc(', '.join(host['names']) or '—')}</td>
          <td>{ports_cell}</td>
          <td>{len(host['cves']):,}</td>
          <td>{details}</td>
        </tr>
        """)

    error_section = ""
    if data["error_messages"]:
        error_section = panel(
            "Lookup errors",
            "Most frequent saved error messages.",
            "<table><thead><tr><th>Error</th><th>Addresses</th></tr>"
            "</thead><tbody>" + "".join(
                f"<tr><td>{esc(message)}</td><td>{count:,}</td></tr>"
                for message, count in data["error_messages"].most_common(10)
            ) + "</tbody></table>",
        )

    other_statuses = {
        status: count
        for status, count in statuses.items()
        if status not in {"ok", "no_data", "retry", "exhausted"}
    }
    if other_statuses:
        notes.append(
            "Additional statuses excluded from resolved coverage: "
            + ", ".join(
                f"{status}: {count:,}"
                for status, count in sorted(other_statuses.items())
            )
        )

    template = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ghana Internet Atlas · Collection report</title>
<style>
:root{
  color-scheme:dark;
  --bg:#0b1018;--panel:#131c29;--line:#263347;
  --text:#edf2fa;--muted:#9baec5;--blue:#69b5ff;
  --green:#67dab4;--amber:#f3c575;--purple:#bdabff
}
*{box-sizing:border-box}
body{
  margin:0;background:var(--bg);color:var(--text);
  font:15px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif
}
main{max-width:1440px;margin:auto;padding:46px 28px 70px}
header{padding-bottom:28px;border-bottom:1px solid var(--line)}
.eyebrow{
  color:var(--green);font-size:12px;font-weight:750;
  letter-spacing:.18em;text-transform:uppercase
}
.flag{display:flex;gap:5px;margin-bottom:20px}
.flag span{width:34px;height:5px;border-radius:5px;background:#d65c66}
.flag span:nth-child(2){background:#edca64}
.flag span:nth-child(3){background:#69c7a1}
h1{font-size:clamp(32px,5vw,58px);letter-spacing:-.045em;line-height:1.12;margin:12px 0}
h2{font-size:19px;letter-spacing:-.025em;margin:0 0 8px}
h4{margin:14px 0 5px}
.subtitle{max-width:760px;color:var(--muted);font-size:17px}
.meta{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:12px}
.meta span{
  padding:5px 10px;border:1px solid var(--line);
  border-radius:100px;overflow-wrap:anywhere
}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:26px 0}
.metric,.panel,.coverage{
  background:var(--panel);border:1px solid var(--line);border-radius:16px
}
.metric{padding:23px}
.metric-label{color:var(--muted);font-size:13px}
.metric-value{font-size:37px;font-weight:750;letter-spacing:-.045em;margin:6px 0}
.metric-detail{color:var(--muted);font-size:12px}
.metric.green .metric-value{color:var(--green)}
.metric.amber .metric-value{color:var(--amber)}
.coverage{padding:25px;margin-bottom:24px}
.coverage-heading{display:flex;align-items:center;justify-content:space-between}
.coverage-heading strong{color:var(--green)}
.coverage p{color:var(--muted);font-size:13px;margin-bottom:0}
.progress-track{height:12px;background:#243145;border-radius:20px;overflow:hidden;margin:16px 0}
.progress-track>div{height:100%;background:linear-gradient(90deg,var(--blue),var(--green))}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}
.panel{padding:25px;min-width:0}
.section-description{color:var(--muted);font-size:13px;margin:0 0 23px}
.bar-row{margin:16px 0}
.bar-label{display:flex;justify-content:space-between;align-items:start;gap:15px;font-size:13px}
.bar-label>span{min-width:0;overflow-wrap:anywhere}
.bar-label strong{white-space:nowrap}
.bar-label small{display:inline-block;min-width:55px;text-align:right;color:var(--muted);font-weight:400}
.bar-track{height:6px;background:#233045;border-radius:8px;margin-top:7px;overflow:hidden}
.bar-fill{height:100%;background:var(--blue);border-radius:8px}
.bar-fill.green{background:var(--green)}
.bar-fill.purple{background:var(--purple)}
.bar-fill.amber{background:var(--amber)}
.empty,.muted{color:var(--muted)}
.facts{margin:0}
.facts>div{display:flex;justify-content:space-between;gap:20px;padding:10px 0;border-bottom:1px solid var(--line)}
dt{color:var(--muted);font-size:13px}
dd{margin:0;font-size:13px;text-align:right;overflow-wrap:anywhere}
.host-section{margin:24px 0}
.toolbar{display:flex;gap:16px;justify-content:space-between;align-items:center;flex-wrap:wrap;margin:16px 0}
input{
  width:min(100%,440px);padding:12px 15px;background:var(--bg);
  border:1px solid #405774;border-radius:9px;color:var(--text);font:inherit
}
input:focus{outline:2px solid var(--blue);outline-offset:2px}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;text-align:left}
th{color:var(--muted);font-weight:500;padding:12px 10px;border-bottom:1px solid #40516b}
td{padding:13px 10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th.num,td.num{text-align:right;font-variant-numeric:tabular-nums}
.host-row:hover{background:#192638}
.hostnames{min-width:150px;max-width:260px}
code{color:var(--blue)}
.chip{
  display:inline-block;font:11px/1.5 ui-monospace,monospace;
  padding:3px 7px;background:#24354b;border-radius:5px;
  margin:2px 3px 2px 0;overflow-wrap:anywhere;max-width:100%
}
.chip.amber{background:#3d3324;color:var(--amber)}
summary{cursor:pointer;color:var(--blue);white-space:nowrap}
.record-details{min-width:240px;max-width:500px}
.notes{margin-top:24px}
.notes li{color:var(--muted);font-size:13px;margin:10px 0}
footer{margin-top:25px;color:var(--muted);font-size:12px}
[hidden]{display:none!important}
@media(max-width:850px){.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}}
@media(max-width:520px){main{padding:25px 14px}.metrics{grid-template-columns:1fr}.metric-value{font-size:32px}}
@media print{
  :root{color-scheme:light;--bg:white;--panel:white;--text:#111;--muted:#444;--line:#ccc}
  main{padding:10px}.metric,.panel{break-inside:avoid}.toolbar{display:none}
  .grid{display:block}.panel{margin-bottom:15px}
}
</style>
</head>
<body>
<main>
<header>
  <div class="flag" aria-hidden="true"><span></span><span></span><span></span></div>
  <div class="eyebrow">Ghana Internet Atlas / Collection report</div>
  <h1>A view of the<br>observed internet.</h1>
  <p class="subtitle">Collection coverage, reported services and software
  fingerprints across the address space in this dataset.</p>
  <div class="meta">
    <span>Generated: __GENERATED__</span>
    <span>Source: __DATABASE__</span>
    <span>Offline report · No external assets</span>
  </div>
</header>
<div class="metrics">__METRICS__</div>
__PROGRESS__
__NETWORKS__
<div class="grid">__PANELS__</div>
<section class="panel host-section">
  <h2>Host explorer</h2>
  <p class="section-description">
    Showing __HOST_COUNT__ of __VALID_COUNT__ readable records, selected by
    descending reported port count. This is an inspection sample, not a risk
    ranking. Increase --host-limit to include more records.
  </p>
  <div class="toolbar">
    <label for="search" class="muted">Search the included records</label>
    <input id="search" type="search"
      placeholder="IP, network, hostname, port, CPE, tag or CVE"
      autocomplete="off">
    <span id="matches" class="muted" aria-live="polite"></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>IP address</th><th>Network</th><th>Hostnames</th>
        <th>Reported ports</th><th>CVE labels</th><th>Details</th>
      </tr></thead>
      <tbody id="hosts">__HOST_ROWS__</tbody>
    </table>
    <p id="no-matches" class="empty" hidden>No matching records.</p>
  </div>
</section>
__ERRORS__
<section class="panel notes">
  <h2>Reading this report</h2>
  <ul>__NOTES__</ul>
</section>
<footer>
  Built from a consistent, read-only PostgreSQL view. Regenerate this report to
  include newly committed collector results.
</footer>
</main>
<script>
const rows = Array.from(document.querySelectorAll(".host-row"));
const indexed = rows.map(row => ({
  row,
  text: row.textContent.toLowerCase()
}));
const search = document.getElementById("search");
const matches = document.getElementById("matches");
const empty = document.getElementById("no-matches");

function filter() {
  const terms = search.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  let visible = 0;
  for (const item of indexed) {
    const show = terms.every(term => item.text.includes(term));
    item.row.hidden = !show;
    if (show) visible++;
  }
  matches.textContent = `${visible.toLocaleString()} / ${rows.length.toLocaleString()} shown`;
  empty.hidden = visible !== 0;
}
let timer;
search.addEventListener("input", () => {
  clearTimeout(timer);
  timer = setTimeout(filter, 120);
});
filter();
</script>
</body>
</html>
"""

    replacements = {
        "__GENERATED__": esc(generated),
        "__DATABASE__": esc(db_name),
        "__METRICS__": "".join(metrics),
        "__PROGRESS__": progress,
        "__NETWORKS__": distributed_section(data) + networks_section(
            data, owners, snapshot.get("asn_names") if snapshot else None
        ),
        "__PANELS__": "".join(panels),
        "__HOST_COUNT__": f"{len(data['hosts']):,}",
        "__VALID_COUNT__": f"{valid:,}",
        "__HOST_ROWS__": "".join(host_rows),
        "__ERRORS__": error_section,
        "__NOTES__": "".join(f"<li>{esc(note)}</li>" for note in notes),
    }

    # One-pass substitution prevents inserted data from being interpreted
    # as template placeholders.
    pattern = "|".join(re.escape(key) for key in replacements)
    return re.sub(pattern, lambda match: replacements[match.group()], template)


def distributed_section(data):
    info = data['distributed']
    rows = ''.join(
        f"<tr><td>{esc(w['hostname'])}</td><td>{esc(w['instance'])}</td>"
        f"<td>{esc(w['health'])}</td><td>{esc(w['heartbeat'])}</td>"
        f"<td>{w['requests']:,}</td><td>{w['saved']:,}</td>"
        f"<td>{esc(w['host_rate']) + '/s' if 'host_rate' in w else '—'}</td>"
        f"<td>{str(round(float(w['host_pause']), 1)) + 's' if 'host_pause' in w else '—'}</td></tr>"
        for w in info['workers']
    )
    counts = info['counts']
    terminal = sum(counts.get(key, 0) for key in ('ok', 'no_data', 'exhausted'))
    return panel(
        'Distributed collection',
        f"Run {info['run']} · {terminal:,}/{info['total']:,} terminal addresses · "
        f"{counts.get('retry', 0):,} awaiting retry · "
        f"{counts.get('exhausted', 0):,} exhausted · "
        "Rate budgets and cooldowns apply independently to each hostname. "
        "Worker counts below are per process; repeated host settings are shared.",
        '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Instance</th>'
        '<th>Health</th><th>Last heartbeat</th><th>Requests</th><th>Saved</th>'
        '<th>Host budget</th><th>Host cooldown</th>'
        '</tr></thead><tbody>'+rows+'</tbody></table></div>',
    )


def main():
    parser = argparse.ArgumentParser(description='Generate a read-only PostgreSQL collection report.')
    parser.add_argument('--run', type=int, help='Defaults to the single active run')
    parser.add_argument('--output', type=Path, default=Path('ghana_report.html'))
    parser.add_argument('--host-limit', type=int, default=500)
    parser.add_argument('--max-ports', type=int, default=100)
    args = parser.parse_args()
    if args.host_limit < 1 or args.max_ports < 1:
        parser.error('Limits must be positive')
    if args.output.suffix.lower() != '.html':
        parser.error('Output must be an .html file')
    try:
        # All report queries share a consistent transaction, including metadata.
        with atlas_db.connect() as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            run = atlas_db.selected_run(db, args.run)
            snapshot = run['snapshot']
            lookup, owners = build_attribution(snapshot)
            data = read_database(run['id'], args.host_limit, args.max_ports, lookup, connection=db)
            counts = {r['status']: r['count'] for r in db.execute(
                'SELECT status,count FROM run_counts WHERE run_id=%s', (run['id'],))}
            workers = db.execute("""SELECT *, CASE WHEN state='stopped' THEN 'stopped'
                WHEN heartbeat<now()-interval '90 seconds' THEN 'stale' ELSE 'healthy' END AS health
                FROM workers WHERE run_id=%s ORDER BY hostname,started_at""", (run['id'],)).fetchall()
            if db.execute("SELECT to_regclass('host_pacing') AS name").fetchone()['name']:
                hosts = {r['hostname']: r for r in db.execute('''SELECT hostname,rate,
                    greatest(0,extract(epoch FROM cooldown_until-clock_timestamp())) AS pause FROM host_pacing''')}
                for worker in workers:
                    host = hosts.get(worker['hostname'])
                    if host:
                        worker.update(host_rate=host['rate'], host_pause=host['pause'])
            data['distributed'] = dict(run=run['id'], total=run['total'], counts=counts,
                workers=workers)
            snapshot['total_ipv4_addresses'] = run['total']
            snapshot['merged_range_count'] = db.execute('SELECT count(*) AS n FROM lookup_ranges WHERE run_id=%s', (run['id'],)).fetchone()['n']
            document = build_report(data, snapshot, f"PostgreSQL run {run['id']}", owners, args.max_ports)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent,
                                         suffix='.tmp', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(document)
        try:
            os.replace(temporary, args.output)
        finally:
            temporary.unlink(missing_ok=True)
        print(f'Report: {args.output.resolve()}')
    except (ValueError, psycopg.Error, OSError) as exc:
        print(f'Report failed: {type(exc).__name__}; check configuration and selected run.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
