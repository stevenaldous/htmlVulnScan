#!/usr/bin/env bash
# =============================================================================
#  nmap_vuln_scan.sh — Automated Nmap Vulnerability Scanner with HTML Report
#
#  Script location : /scripts/nmap_vuln_scan.sh
#  Scan output     : /scans/<target>_<timestamp>/
#
#  Usage:
#    sudo /scripts/nmap_vuln_scan.sh <target> [options]
#
#  Examples:
#    sudo /scripts/nmap_vuln_scan.sh 192.168.1.0/24
#    sudo /scripts/nmap_vuln_scan.sh 10.0.0.5 -o /custom/scan/folder
#    sudo /scripts/nmap_vuln_scan.sh scanme.nmap.org --ports 22,80,443
#
#  Options:
#    -o, --output DIR     Override default output directory (default: /scans)
#    -p, --ports PORTS    Comma-separated ports or ranges (default: top 1000)
#    -t, --timing N       Nmap timing template 0-5 (default: 3)
#    -h, --help           Show this help message
#
#  Requirements:
#    - nmap with vulners/vulscan/vuln scripts
#    - Run as root (required for SYN scan and OS detection)
#    - xdg-utils (optional, for auto-opening the report)
#    - Run install.sh once to create /scripts and /scans with correct permissions
# =============================================================================

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
SCAN_BASE_DIR="/scans"
PORTS=""           # empty = nmap default (top 1000)
TIMING=3
TARGET=""

# ── Argument parsing ──────────────────────────────────────────────────────────
usage() {
  grep '^#  ' "$0" | sed 's/^#  //'
  exit 0
}

[[ $# -eq 0 ]] && { error "No target specified."; usage; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)           usage ;;
    -o|--output)         SCAN_BASE_DIR="$2"; shift 2 ;;
    -p|--ports)          PORTS="$2";        shift 2 ;;
    -t|--timing)         TIMING="$2";       shift 2 ;;
    -*)                  die "Unknown option: $1" ;;
    *)                   TARGET="$1";       shift ;;
  esac
done

[[ -z "$TARGET" ]] && die "Target is required."

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  die "This script must be run as root (sudo) for SYN scan and OS detection."
fi

# ── Dependency check ──────────────────────────────────────────────────────────
command -v nmap &>/dev/null || die "nmap is not installed. Install with: apt install nmap"

# ── Setup scan directory ──────────────────────────────────────────────────────
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
SAFE_TARGET=$(echo "$TARGET" | tr '/:' '__')
SCAN_DIR="${SCAN_BASE_DIR}/${SAFE_TARGET}_${TIMESTAMP}"

mkdir -p "$SCAN_DIR"
# World-readable so all GUI file-manager users can browse reports
chmod 755 "$SCAN_BASE_DIR"
chmod 755 "$SCAN_DIR"

RAW_XML="${SCAN_DIR}/raw_scan.xml"
RAW_TXT="${SCAN_DIR}/raw_scan.txt"
HTML_REPORT="${SCAN_DIR}/report.html"
SUMMARY_JSON="${SCAN_DIR}/summary.json"

# ── Build nmap command ────────────────────────────────────────────────────────
NMAP_ARGS=(-sS -sV -O --osscan-guess -A)
NMAP_ARGS+=(--script "vuln,vulners,auth,default,safe")
NMAP_ARGS+=(-T"$TIMING")
NMAP_ARGS+=(--reason)
NMAP_ARGS+=(-oX "$RAW_XML" -oN "$RAW_TXT")

[[ -n "$PORTS" ]] && NMAP_ARGS+=(-p "$PORTS") || NMAP_ARGS+=(--top-ports 1000)

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║         NMAP VULNERABILITY SCANNER                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
info "Target   : ${BOLD}$TARGET${RESET}"
info "Output   : ${BOLD}$SCAN_DIR${RESET}"
info "Timing   : T${TIMING}"
[[ -n "$PORTS" ]] && info "Ports    : $PORTS" || info "Ports    : top 1000"
info "Started  : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ── Run scan ──────────────────────────────────────────────────────────────────
info "Launching nmap scan — this may take several minutes…"
START_EPOCH=$(date +%s)

set +e
nmap "${NMAP_ARGS[@]}" "$TARGET" 2>&1 | tee /tmp/nmap_live_output.txt
NMAP_EXIT=${PIPESTATUS[0]}
set -e

END_EPOCH=$(date +%s)
DURATION=$(( END_EPOCH - START_EPOCH ))

if [[ $NMAP_EXIT -ne 0 ]]; then
  warn "nmap exited with code $NMAP_EXIT — report may be partial."
fi

chmod 644 "$RAW_XML" "$RAW_TXT" 2>/dev/null || true

# ── Parse XML → variables ─────────────────────────────────────────────────────
info "Parsing scan results…"

parse_xml() {
  python3 - "$RAW_XML" "$SUMMARY_JSON" <<'PYEOF'
import sys, json, xml.etree.ElementTree as ET
from datetime import datetime

xml_file   = sys.argv[1]
json_file  = sys.argv[2]

try:
    tree = ET.parse(xml_file)
except Exception as e:
    print(f"XML parse error: {e}", file=sys.stderr)
    sys.exit(1)

root = tree.getroot()

run_info = {
    "args":      root.get("args", ""),
    "start":     root.get("startstr", ""),
    "version":   root.get("version", ""),
}

# Run stats
runstats = root.find("runstats/finished")
run_info["elapsed"]  = runstats.get("elapsed", "?") if runstats is not None else "?"
run_info["summary"]  = runstats.get("summary", "")  if runstats is not None else ""

hosts = []
total_open = 0
total_vuln = 0

for host in root.findall("host"):
    status_el = host.find("status")
    if status_el is None or status_el.get("state") != "up":
        continue

    # Addresses
    addrs = {}
    for addr in host.findall("address"):
        addrs[addr.get("addrtype")] = addr.get("addr")

    # Hostnames
    hostnames = [h.get("name") for h in host.findall("hostnames/hostname") if h.get("name")]

    # OS
    os_matches = []
    for osm in host.findall("os/osmatch"):
        os_matches.append({"name": osm.get("name", ""), "accuracy": osm.get("accuracy", "")})

    # Ports
    ports = []
    for port in host.findall("ports/port"):
        state_el = port.find("state")
        if state_el is None:
            continue
        state = state_el.get("state", "")
        service_el = port.find("service")
        service = {}
        if service_el is not None:
            service = {
                "name":    service_el.get("name", ""),
                "product": service_el.get("product", ""),
                "version": service_el.get("version", ""),
                "extrainfo": service_el.get("extrainfo", ""),
                "tunnel":  service_el.get("tunnel", ""),
            }

        # Scripts / vulns
        scripts = []
        vulns   = []
        for script in port.findall("script"):
            sid    = script.get("id", "")
            sout   = script.get("output", "")
            entry  = {"id": sid, "output": sout, "tables": []}

            # Walk tables for structured vuln data
            for table in script.findall(".//table[@key]"):
                t_key = table.get("key", "")
                t_data = {}
                for elem in table:
                    k = elem.get("key", "")
                    v = elem.text or ""
                    if k:
                        t_data[k] = v
                if t_data:
                    entry["tables"].append({"key": t_key, "data": t_data})
                    # Treat as vuln if it has a state/risk field
                    state_val = t_data.get("state", "").upper()
                    risk_val  = t_data.get("risk factor", "").upper()
                    if "VULNERABLE" in state_val or risk_val in ("HIGH","CRITICAL","MEDIUM"):
                        vulns.append({
                            "id":    t_key,
                            "title": t_data.get("title", t_key),
                            "state": t_data.get("state", ""),
                            "risk":  t_data.get("risk factor", ""),
                            "desc":  t_data.get("description", ""),
                            "refs":  [v for k,v in t_data.items() if "ref" in k.lower() or "url" in k.lower() or "ids" == k.lower()],
                            "cvss":  t_data.get("cvss", ""),
                            "script": sid,
                        })

            # Fallback: plain-text vuln mentions
            if not entry["tables"] and ("VULNERABLE" in sout.upper() or "CVE-" in sout.upper()):
                vulns.append({
                    "id":    sid,
                    "title": sid,
                    "state": "VULNERABLE",
                    "risk":  "",
                    "desc":  sout[:500],
                    "refs":  [],
                    "cvss":  "",
                    "script": sid,
                })

            scripts.append(entry)

        total_open += 1 if state == "open" else 0
        total_vuln += len(vulns)

        ports.append({
            "portid":  port.get("portid"),
            "proto":   port.get("protocol"),
            "state":   state,
            "reason":  state_el.get("reason", ""),
            "service": service,
            "scripts": scripts,
            "vulns":   vulns,
        })

    hosts.append({
        "ipv4":      addrs.get("ipv4", ""),
        "ipv6":      addrs.get("ipv6", ""),
        "mac":       addrs.get("mac", ""),
        "hostnames": hostnames,
        "os":        os_matches,
        "ports":     ports,
        "vuln_count": sum(len(p["vulns"]) for p in ports),
    })

data = {
    "run_info":    run_info,
    "hosts":       hosts,
    "total_hosts": len(hosts),
    "total_open":  total_open,
    "total_vuln":  total_vuln,
}

with open(json_file, "w") as f:
    json.dump(data, f, indent=2)

print(f"Parsed {len(hosts)} host(s), {total_open} open port(s), {total_vuln} vulnerability finding(s).")
PYEOF
}

parse_xml
chmod 644 "$SUMMARY_JSON" 2>/dev/null || true

# ── Generate HTML report ──────────────────────────────────────────────────────
info "Generating HTML report…"

python3 - "$SUMMARY_JSON" "$HTML_REPORT" "$TARGET" "$TIMESTAMP" <<'PYEOF'
import sys, json, html as html_mod, re
from datetime import datetime

json_file   = sys.argv[1]
html_file   = sys.argv[2]
target      = sys.argv[3]
timestamp   = sys.argv[4]

with open(json_file) as f:
    data = json.load(f)

def e(s): return html_mod.escape(str(s))

def risk_class(risk):
    r = str(risk).upper()
    if r in ("CRITICAL",):    return "risk-critical"
    if r in ("HIGH",):        return "risk-high"
    if r in ("MEDIUM",):      return "risk-medium"
    if r in ("LOW",):         return "risk-low"
    return "risk-info"

def severity_from_cvss(cvss):
    try:
        v = float(cvss)
        if v >= 9.0: return "CRITICAL"
        if v >= 7.0: return "HIGH"
        if v >= 4.0: return "MEDIUM"
        return "LOW"
    except:
        return ""

# ── Stats ──────────────────────────────────────────────────────────────────────
total_hosts = data["total_hosts"]
total_open  = data["total_open"]
total_vuln  = data["total_vuln"]
scan_args   = e(data["run_info"].get("args", ""))
scan_start  = e(data["run_info"].get("start", ""))
elapsed     = e(data["run_info"].get("elapsed", ""))
nmap_ver    = e(data["run_info"].get("version", ""))

dt_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Host cards HTML ────────────────────────────────────────────────────────────
host_cards = ""
for idx, host in enumerate(data["hosts"]):
    ip      = e(host.get("ipv4") or host.get("ipv6") or "Unknown")
    mac     = e(host.get("mac", ""))
    hnames  = ", ".join(e(h) for h in host.get("hostnames", [])) or "—"
    os_list = host.get("os", [])
    os_str  = e(os_list[0]["name"] + f" ({os_list[0]['accuracy']}% confidence)") if os_list else "—"
    vcount  = host["vuln_count"]
    vcls    = "vuln-badge-red" if vcount > 0 else "vuln-badge-green"

    open_ports  = [p for p in host["ports"] if p["state"] == "open"]
    other_ports = [p for p in host["ports"] if p["state"] != "open"]

    # Port rows
    port_rows = ""
    for p in sorted(open_ports + other_ports, key=lambda x: int(x["portid"] or 0)):
        svc     = p["service"]
        svc_str = " ".join(filter(None, [svc.get("name",""), svc.get("product",""),
                                          svc.get("version",""), svc.get("extrainfo","")]))
        pstate  = p["state"]
        pcls    = "state-open" if pstate == "open" else ("state-closed" if pstate == "closed" else "state-filtered")
        pv      = len(p["vulns"])
        pvcls   = "port-vuln-yes" if pv > 0 else ""

        # Vuln detail rows beneath port
        vuln_detail = ""
        for v in p["vulns"]:
            risk = v.get("risk") or severity_from_cvss(v.get("cvss","")) or "INFO"
            rcls = risk_class(risk)
            cvss_badge = f'<span class="cvss-badge">{e(v["cvss"])}</span>' if v.get("cvss") else ""
            refs_html = ""
            for r in (v.get("refs") or []):
                for token in str(r).split():
                    if token.startswith("http"):
                        refs_html += f'<a class="ref-link" href="{e(token)}" target="_blank">{e(token[:60])}{"…" if len(token)>60 else ""}</a> '
                    elif token.startswith("CVE-"):
                        refs_html += f'<a class="ref-link cve-link" href="https://nvd.nist.gov/vuln/detail/{e(token)}" target="_blank">{e(token)}</a> '
            desc_short = (v.get("desc") or "")[:400]
            vuln_detail += f'''
            <tr class="vuln-row">
              <td colspan="5">
                <div class="vuln-card {rcls}">
                  <div class="vuln-header">
                    <span class="vuln-id">{e(v["id"])}</span>
                    <span class="vuln-title">{e(v["title"])}</span>
                    <span class="risk-pill {rcls}">{e(risk)}</span>
                    {cvss_badge}
                    <span class="script-tag">{e(v["script"])}</span>
                  </div>
                  {"<p class='vuln-desc'>" + e(desc_short) + ("…" if len(v.get("desc","")) > 400 else "") + "</p>" if desc_short else ""}
                  {"<div class='vuln-refs'>" + refs_html + "</div>" if refs_html else ""}
                </div>
              </td>
            </tr>'''

        port_rows += f'''
        <tr class="{pvcls}">
          <td class="port-num">{e(p["portid"])}<span class="proto">/{e(p["proto"])}</span></td>
          <td><span class="state-badge {pcls}">{e(pstate)}</span></td>
          <td class="reason-col">{e(p.get("reason",""))}</td>
          <td class="service-col">{e(svc_str)}</td>
          <td class="vuln-count-col">{"<span class='has-vulns'>⚠ " + str(pv) + " finding" + ("s" if pv!=1 else "") + "</span>" if pv > 0 else "—"}</td>
        </tr>
        {vuln_detail}'''

    host_cards += f'''
    <div class="host-card" id="host-{idx}">
      <div class="host-header" onclick="toggleHost({idx})">
        <div class="host-title">
          <span class="host-ip">{ip}</span>
          {f'<span class="host-mac">MAC: {mac}</span>' if mac else ""}
          <span class="host-names">{hnames}</span>
        </div>
        <div class="host-meta">
          <span class="os-str">{os_str}</span>
          <span class="{vcls}">{vcount} vuln{"s" if vcount!=1 else ""}</span>
          <span class="open-count">{len(open_ports)} open</span>
          <span class="chevron" id="chev-{idx}">▼</span>
        </div>
      </div>
      <div class="host-body" id="body-{idx}">
        <table class="port-table">
          <thead>
            <tr>
              <th>Port</th><th>State</th><th>Reason</th><th>Service / Version</th><th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {port_rows if port_rows else "<tr><td colspan='5' class='no-ports'>No ports found.</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>'''

if not host_cards:
    host_cards = '<p class="no-hosts">No live hosts were found. The target may be offline or firewalled.</p>'

# ── Full HTML ──────────────────────────────────────────────────────────────────
html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nmap Vuln Report — {e(target)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {{
    --bg:        #0a0d12;
    --surface:   #111620;
    --surface2:  #161c28;
    --border:    #1e2a3a;
    --accent:    #00e5ff;
    --accent2:   #ff3d71;
    --green:     #00e676;
    --yellow:    #ffd740;
    --red:       #ff3d71;
    --critical:  #b71c1c;
    --high:      #e53935;
    --medium:    #fb8c00;
    --low:       #fdd835;
    --text:      #cdd8e8;
    --muted:     #faf9f6;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Rajdhani', sans-serif;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 15px;
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse 80% 40% at 50% -10%, rgba(0,229,255,.06) 0%, transparent 70%),
      repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,229,255,.03) 40px),
      repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,229,255,.03) 40px);
  }}

  /* ── Header ── */
  header {{
    background: linear-gradient(135deg, #060b12 0%, #0d1826 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px 20px;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .logo {{ display: flex; align-items: center; gap: 14px; }}
  .logo-icon {{
    width: 46px; height: 46px;
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: grid; place-items: center;
    font-size: 22px;
    box-shadow: 0 0 18px rgba(0,229,255,.3);
  }}
  h1 {{
    font-family: var(--sans);
    font-size: 1.9rem;
    font-weight: 700;
    letter-spacing: .06em;
    color: #fff;
    text-transform: uppercase;
  }}
  h1 span {{ color: var(--accent); }}
  .header-meta {{ text-align: right; font-family: var(--mono); font-size: .78rem; color: var(--muted); line-height: 1.8; }}
  .header-meta b {{ color: var(--accent); }}

  /* ── Stats strip ── */
  .stats-bar {{
    display: flex; gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat {{
    flex: 1; background: var(--surface);
    padding: 18px 24px;
    display: flex; flex-direction: column; gap: 4px;
    transition: background .2s;
  }}
  .stat:hover {{ background: var(--surface2); }}
  .stat-value {{
    font-family: var(--mono);
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-label {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }}
  .sv-hosts  {{ color: var(--accent); }}
  .sv-ports  {{ color: var(--green); }}
  .sv-vulns  {{ color: var(--red); }}
  .sv-time   {{ color: var(--yellow); }}

  /* ── Main ── */
  main {{ max-width: 1400px; margin: 0 auto; padding: 28px 28px 60px; }}

  .section-title {{
    font-family: var(--sans);
    font-size: 1rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .12em;
    color: var(--muted);
    border-left: 3px solid var(--accent);
    padding-left: 12px;
    margin: 28px 0 16px;
  }}

  /* ── Host card ── */
  .host-card {{
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 14px;
    overflow: hidden;
    background: var(--surface);
    transition: box-shadow .2s;
  }}
  .host-card:hover {{ box-shadow: 0 0 0 1px var(--accent), 0 4px 24px rgba(0,229,255,.07); }}
  .host-header {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px;
    cursor: pointer;
    background: var(--surface2);
    user-select: none;
    flex-wrap: wrap; gap: 8px;
  }}
  .host-title {{ display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }}
  .host-ip {{ font-family: var(--mono); font-size: 1.1rem; color: #fff; letter-spacing: .04em; }}
  .host-mac {{ font-family: var(--mono); font-size: .72rem; color: var(--muted); }}
  .host-names {{ font-size: .82rem; color: var(--muted); font-style: italic; }}
  .host-meta {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .os-str {{ font-size: .78rem; color: var(--muted); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .vuln-badge-red  {{ background: rgba(255,61,113,.15); color: var(--red);   border: 1px solid var(--red);   border-radius: 20px; padding: 2px 10px; font-size: .75rem; font-weight: 600; }}
  .vuln-badge-green{{ background: rgba(0,230,118,.1);  color: var(--green); border: 1px solid var(--green); border-radius: 20px; padding: 2px 10px; font-size: .75rem; font-weight: 600; }}
  .open-count {{ font-size: .75rem; color: var(--muted); }}
  .chevron {{ color: var(--accent); font-size: .9rem; transition: transform .25s; }}
  .chevron.up {{ transform: rotate(180deg); }}

  /* ── Body ── */
  .host-body {{ display: none; padding: 0; }}
  .host-body.open {{ display: block; }}

  /* ── Port table ── */
  .port-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  .port-table thead tr {{ background: rgba(0,229,255,.05); border-bottom: 1px solid var(--border); }}
  .port-table th {{ padding: 9px 14px; text-align: left; font-size: .7rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); font-weight: 600; }}
  .port-table td {{ padding: 8px 14px; border-bottom: 1px solid rgba(30,42,58,.6); vertical-align: top; }}
  .port-table tr:last-child td {{ border-bottom: none; }}
  .port-table tr.port-vuln-yes td:first-child {{ border-left: 2px solid var(--red); }}
  .port-num {{ font-family: var(--mono); color: var(--accent); font-size: .88rem; white-space: nowrap; }}
  .proto {{ color: var(--muted); font-size: .75rem; }}
  .reason-col {{ font-family: var(--mono); font-size: .75rem; color: var(--muted); }}
  .service-col {{ color: var(--text); }}
  .no-ports {{ text-align: center; padding: 20px; color: var(--muted); font-style: italic; }}

  .state-badge {{ display: inline-block; border-radius: 4px; padding: 1px 8px; font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }}
  .state-open     {{ background: rgba(0,230,118,.15); color: var(--green); border: 1px solid rgba(0,230,118,.4); }}
  .state-closed   {{ background: rgba(84,110,122,.12); color: var(--muted); border: 1px solid var(--border); }}
  .state-filtered {{ background: rgba(255,215,64,.1);  color: var(--yellow); border: 1px solid rgba(255,215,64,.3); }}

  .has-vulns {{ color: var(--red); font-size: .78rem; font-weight: 600; }}
  .vuln-count-col {{ white-space: nowrap; }}

  /* ── Vuln card ── */
  .vuln-row td {{ padding: 4px 14px 10px 30px !important; background: rgba(0,0,0,.25); }}
  .vuln-card {{ border-left: 3px solid var(--border); border-radius: 4px; padding: 10px 14px; background: rgba(0,0,0,.2); }}
  .vuln-card.risk-critical {{ border-left-color: #b71c1c; background: rgba(183,28,28,.06); }}
  .vuln-card.risk-high     {{ border-left-color: #e53935; background: rgba(229,57,53,.06); }}
  .vuln-card.risk-medium   {{ border-left-color: #fb8c00; background: rgba(251,140,0,.06); }}
  .vuln-card.risk-low      {{ border-left-color: #fdd835; background: rgba(253,216,53,.04); }}
  .vuln-card.risk-info     {{ border-left-color: var(--accent); }}

  .vuln-header {{ display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }}
  .vuln-id     {{ font-family: var(--mono); font-size: .78rem; color: var(--muted); }}
  .vuln-title  {{ font-size: .85rem; font-weight: 600; color: #fff; flex: 1; min-width: 120px; }}
  .script-tag  {{ font-family: var(--mono); font-size: .67rem; background: rgba(0,229,255,.08); color: var(--accent); border: 1px solid rgba(0,229,255,.2); border-radius: 3px; padding: 1px 6px; }}
  .vuln-desc   {{ font-size: 1rem; color: var(--muted); line-height: 1.5; margin-top: 4px; white-space: pre-wrap; }}
  .vuln-refs   {{ margin-top: 6px; display: flex; flex-wrap: wrap; gap: 6px; }}
  .ref-link    {{ font-family: var(--mono); font-size: .7rem; color: var(--accent); text-decoration: none; background: rgba(0,229,255,.06); padding: 2px 6px; border-radius: 3px; word-break: break-all; }}
  .ref-link:hover {{ background: rgba(0,229,255,.15); }}
  .cve-link    {{ color: var(--yellow); background: rgba(255,215,64,.08); }}

  .risk-pill {{ display: inline-block; border-radius: 20px; padding: 1px 9px; font-size: .68rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }}
  .risk-pill.risk-critical {{ background: rgba(183,28,28,.3); color: #ef9a9a; border: 1px solid #b71c1c; }}
  .risk-pill.risk-high     {{ background: rgba(229,57,53,.25); color: #ef9a9a; border: 1px solid #e53935; }}
  .risk-pill.risk-medium   {{ background: rgba(251,140,0,.2);  color: #ffcc80; border: 1px solid #fb8c00; }}
  .risk-pill.risk-low      {{ background: rgba(253,216,53,.15); color: #fff176; border: 1px solid #fdd835; }}
  .risk-pill.risk-info     {{ background: rgba(0,229,255,.1);  color: var(--accent); border: 1px solid rgba(0,229,255,.3); }}

  .cvss-badge {{ font-family: var(--mono); font-size: .72rem; background: rgba(255,255,255,.07); border: 1px solid var(--border); border-radius: 3px; padding: 1px 6px; color: var(--yellow); }}

  /* ── Scan args ── */
  .cmd-block {{
    font-family: var(--mono); font-size: .75rem;
    background: #060a0f; border: 1px solid var(--border);
    border-radius: 6px; padding: 14px 18px;
    color: var(--muted); word-break: break-all; line-height: 1.7;
  }}

  /* ── No hosts ── */
  .no-hosts {{ text-align: center; padding: 40px; color: var(--muted); font-style: italic; font-size: 1.1rem; }}

  /* ── Footer ── */
  footer {{
    text-align: center;
    padding: 24px;
    color: var(--muted);
    font-size: .72rem;
    font-family: var(--mono);
    border-top: 1px solid var(--border);
  }}

  /* ── Filter bar ── */
  .filter-bar {{ display: flex; gap: 10px; margin-bottom: 18px; flex-wrap: wrap; }}
  .filter-btn {{
    padding: 6px 16px; border-radius: 20px;
    border: 1px solid var(--border);
    background: var(--surface); color: var(--muted);
    cursor: pointer; font-family: var(--sans); font-size: .8rem;
    transition: all .15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent); color: var(--accent);
    background: rgba(0,229,255,.08);
  }}

  @media (max-width: 700px) {{
    header {{ padding: 18px; }}
    main   {{ padding: 16px; }}
    .stat  {{ padding: 14px; }}
    .stat-value {{ font-size: 1.8rem; }}
    h1 {{ font-size: 1.3rem; }}
  }}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <h1>Nmap <span>Vuln</span> Report</h1>
      <div style="font-size:.8rem;color:var(--muted);font-family:var(--mono);margin-top:2px;">
        Target: <b style="color:var(--accent)">{e(target)}</b>
      </div>
    </div>
  </div>
  <div class="header-meta">
    <div>Scan started: <b>{scan_start}</b></div>
    <div>Report generated: <b>{dt_str}</b></div>
    <div>Nmap version: <b>{nmap_ver}</b></div>
    <div>Duration: <b>{elapsed}s</b></div>
  </div>
</header>

<div class="stats-bar">
  <div class="stat">
    <span class="stat-value sv-hosts">{total_hosts}</span>
    <span class="stat-label">Hosts Up</span>
  </div>
  <div class="stat">
    <span class="stat-value sv-ports">{total_open}</span>
    <span class="stat-label">Open Ports</span>
  </div>
  <div class="stat">
    <span class="stat-value sv-vulns">{total_vuln}</span>
    <span class="stat-label">Vuln Findings</span>
  </div>
  <div class="stat">
    <span class="stat-value sv-time">{elapsed}s</span>
    <span class="stat-label">Scan Duration</span>
  </div>
</div>

<main>
  <p class="section-title">Hosts &amp; Findings</p>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterHosts('all',this)">All Hosts</button>
    <button class="filter-btn" onclick="filterHosts('vuln',this)">⚠ Vulnerable Only</button>
    <button class="filter-btn" onclick="expandAll()">Expand All</button>
    <button class="filter-btn" onclick="collapseAll()">Collapse All</button>
  </div>

  <div id="hosts-container">
    {host_cards}
  </div>

  <p class="section-title">Scan Command</p>
  <div class="cmd-block">{scan_args}</div>
</main>

<footer>
  Generated by nmap_vuln_scan.sh &nbsp;|&nbsp; nmap {nmap_ver} &nbsp;|&nbsp; {dt_str}
</footer>

<script>
  const hosts = document.querySelectorAll('.host-card');

  function toggleHost(idx) {{
    const body = document.getElementById('body-' + idx);
    const chev = document.getElementById('chev-' + idx);
    body.classList.toggle('open');
    chev.classList.toggle('up');
  }}

  function expandAll() {{
    document.querySelectorAll('.host-body').forEach(b => b.classList.add('open'));
    document.querySelectorAll('.chevron').forEach(c => c.classList.add('up'));
  }}

  function collapseAll() {{
    document.querySelectorAll('.host-body').forEach(b => b.classList.remove('open'));
    document.querySelectorAll('.chevron').forEach(c => c.classList.remove('up'));
  }}

  function filterHosts(mode, btn) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    hosts.forEach(card => {{
      if (mode === 'all') {{ card.style.display = ''; return; }}
      const badge = card.querySelector('.vuln-badge-red');
      card.style.display = badge ? '' : 'none';
    }});
  }}

  // Auto-expand hosts that have vulns
  document.querySelectorAll('.host-card').forEach((card, i) => {{
    if (card.querySelector('.vuln-badge-red')) toggleHost(i);
  }});
</script>
</body>
</html>'''

with open(html_file, "w", encoding="utf-8") as f:
    f.write(html)

print(f"HTML report written: {html_file}")
PYEOF

chmod 644 "$HTML_REPORT"

# ── Ensure all scan files are world-readable ──────────────────────────────────
find "$SCAN_DIR" -type f -exec chmod 644 {} \;
find "$SCAN_DIR" -type d -exec chmod 755 {} \;

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"
success "Scan complete in ${DURATION}s"
echo -e "  ${BOLD}Report  :${RESET} ${CYAN}${HTML_REPORT}${RESET}"
echo -e "  ${BOLD}Raw XML :${RESET} ${RAW_XML}"
echo -e "  ${BOLD}Raw TXT :${RESET} ${RAW_TXT}"
echo -e "  ${BOLD}Summary :${RESET} ${SUMMARY_JSON}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"

# Open in default browser if a desktop session is available
if command -v xdg-open &>/dev/null && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  info "Opening report in browser…"
  xdg-open "$HTML_REPORT" &>/dev/null &
else
  info "To view the report, open this file in a browser:"
  echo "  file://${HTML_REPORT}"
fi

exit 0
PYEOF
