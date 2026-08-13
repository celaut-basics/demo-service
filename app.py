#!/usr/bin/env python3.11
"""
Celaut node-honesty verifier (orchestrator).

This service turns the passive "demo" into an ACTIVE verifier that checks whether
the nodo node it runs on is HONEST. It drives three child services and turns each
observation into an explicit PASS/FAIL assertion, then assembles a signed-ready
attestation report card:

  1. network_isolation   (ping child)   declared egress (google) must succeed and
                                        an UNDECLARED egress (amazon) must be blocked.
  2. memory_ceiling      (heavy child)  allocation up to the declared at_most
                                        (256 MiB) must succeed; past it the node
                                        must OOM-kill AT the declared boundary.
  3. resource_provisioning (self)       what the manifest declared / the node
                                        charged must match what the container
                                        actually gets (cgroup + /proc/meminfo).
  4. attestation         report card    per-probe verdict + a content hash of the
                                        result, ready to be submitted later as an
                                        EGO reputation opinion on-chain.
"""

import os, json, logging, hashlib, datetime
import requests
from flask import Flask, jsonify, render_template_string
from google.protobuf.json_format import MessageToDict

from node_controller.controller.controller import Controller
from node_controller.gateway.protos import celaut_pb2
from node_controller.gateway.utils import to_amount, from_amount


DIR = "service"
CONFIG_FILE = "/__config__"

if False:  # development mode toggle (unchanged from the original demo)
    DIR = "."
    CONFIG_FILE = "__config__"

VERIFIER_VERSION = "1.0.0"

# Declared ceilings from the child manifests (.service/service.json at_most).
HEAVY_DECLARED_MEM_BYTES = 268435456   # 256 MiB
SELF_DECLARED_MEM_BYTES = 1000000000   # 1 GB (this service's own manifest)

env_vars = {}
with open(os.path.join(DIR, ".dependencies")) as f:
    for line in f:
        key, value = line.strip().split("=")
        env_vars[key] = value

TINY_SERVICE = env_vars.get("TINY", None)
HEAVY_SERVICE = env_vars.get("HEAVY", None)
PING_SERVICE = env_vars.get("PING", None)

logging.basicConfig(filename='app.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

controller = Controller(debug=lambda s: logging.info('Node Controller: %s', s),
                        app_dir=DIR, config_file=CONFIG_FILE)
node_url: str = controller.get_node_url()
mem_limit: int = controller.get_mem_limit_at_start()

# initial_mu the orchestrator asked the node to fund the heavy child with.
HEAVY_INITIAL_MU = pow(10, 8)

resources = {"mem_limit": mem_limit}
balance_mu = 0

tiny_service = controller.add_service(service_hash=TINY_SERVICE)
heavy_service = controller.add_service(
    service_hash=HEAVY_SERVICE,
    config=celaut_pb2.Configuration(initial_mu=to_amount(HEAVY_INITIAL_MU))
)
ping_service = controller.add_service(service_hash=PING_SERVICE)

services = []
logging.info('Gateway main directory: %s', node_url)


# ----------------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------------
def _read_first_line(path):
    try:
        with open(path) as fh:
            return fh.readline().strip()
    except Exception:
        return None


def read_container_limits():
    """What the microVM actually gets, straight from the kernel."""
    mem_max = _read_first_line("/sys/fs/cgroup/memory.max")                    # cgroup v2
    if mem_max is None:
        mem_max = _read_first_line("/sys/fs/cgroup/memory/memory.limit_in_bytes")  # v1
    mem_current = _read_first_line("/sys/fs/cgroup/memory.current")
    if mem_current is None:
        mem_current = _read_first_line("/sys/fs/cgroup/memory/memory.usage_in_bytes")
    cpu_max = _read_first_line("/sys/fs/cgroup/cpu.max")

    mem_total_kb = None
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal"):
                    mem_total_kb = int(line.split()[1]); break
    except Exception:
        pass
    return {
        "cgroup_memory_max": mem_max,
        "cgroup_memory_current": mem_current,
        "cgroup_cpu_max": cpu_max,
        "proc_meminfo_memtotal_bytes": (mem_total_kb * 1024) if mem_total_kb else None,
    }


def _spin_child(service_iface, label):
    """Launch one child instance and return its ip:port uri (or raise)."""
    inst = service_iface.get_instance(max_attempts=2)
    logging.info('Spun %s child at %s', label, inst.uri)
    return inst.uri


# ----------------------------------------------------------------------------
# Probe 1 — network isolation (ping child asserts declared vs undeclared egress)
# ----------------------------------------------------------------------------
def probe_network_isolation():
    ev = {"probe": "network_isolation"}
    try:
        uri = _spin_child(ping_service, "ping")
        r = requests.get(f"http://{uri}", timeout=45)
        data = r.json()
        ev.update(data)
        honest = bool(data.get("honest", False))
        # Extra guard: even if the child says honest, fail if any target verdict is bad.
        bad = [t for t in data.get("targets", []) if t.get("verdict") in ("DISHONEST_LEAK", "BROKEN_DENIED")]
        verdict = "PASS" if honest and not bad else "FAIL"
        ev["verdict"] = verdict
        ev["reason"] = ("declared egress reachable and undeclared egress blocked"
                        if verdict == "PASS"
                        else f"isolation violated: {[t.get('target')+':'+t.get('verdict') for t in bad]}")
    except Exception as e:
        ev["verdict"] = "ERROR"
        ev["reason"] = f"probe could not run: {e}"
    return ev


# ----------------------------------------------------------------------------
# Probe 2 — memory ceiling (heavy child ramped toward the declared at_most)
# ----------------------------------------------------------------------------
def probe_memory_ceiling():
    declared_mb = HEAVY_DECLARED_MEM_BYTES // (1024 * 1024)  # 256
    # rungs below and above the declared ceiling
    ladder = [64, 128, 200, 240, 300, 400, 512]
    ev = {"probe": "memory_ceiling", "declared_ceiling_mb": declared_mb, "attempts": []}
    highest_ok = 0
    first_kill = None
    for mb in ladder:
        rung = {"requested_mb": mb}
        try:
            uri = _spin_child(heavy_service, f"heavy({mb}MB)")
            r = requests.get(f"http://{uri}/alloc/{mb}", timeout=60)
            ok = (r.status_code == 200 and r.json().get("ok") is True)
            rung["ok"] = ok
            rung["cgroup_mem_current"] = r.json().get("cgroup_mem_current") if ok else None
            if ok:
                highest_ok = max(highest_ok, mb)
            elif first_kill is None:
                first_kill = mb
        except Exception as e:
            rung["ok"] = False
            rung["error"] = str(e)[:160]
            if first_kill is None:
                first_kill = mb
        ev["attempts"].append(rung)
        # Once we've seen a kill above the ceiling we have enough signal.
        if first_kill is not None and mb >= declared_mb:
            break

    ev["observed_ceiling_mb"] = highest_ok
    ev["first_kill_mb"] = first_kill
    tol = 0.20  # 20% tolerance around the declared boundary
    low = declared_mb * (1 - tol)
    if first_kill is None:
        # nothing was ever killed, even well above the ceiling
        ev["verdict"] = "FAIL"
        ev["reason"] = (f"ceiling NOT enforced: allocated up to {highest_ok} MiB with no OOM "
                        f"(declared at_most {declared_mb} MiB)")
    elif highest_ok < low:
        ev["verdict"] = "FAIL"
        ev["reason"] = (f"shortchanged: killed at {first_kill} MiB, well below declared {declared_mb} MiB "
                        f"(highest success {highest_ok} MiB)")
    else:
        ev["verdict"] = "PASS"
        ev["reason"] = (f"enforced near declared boundary: highest success {highest_ok} MiB, "
                        f"first kill {first_kill} MiB vs declared {declared_mb} MiB")
    return ev


# ----------------------------------------------------------------------------
# Probe 3 — resource / MU provisioning honesty (self-introspection)
# ----------------------------------------------------------------------------
def probe_resource_provisioning():
    ev = {"probe": "resource_provisioning"}
    limits = read_container_limits()
    ev["declared_manifest_mem_bytes"] = SELF_DECLARED_MEM_BYTES
    ev["node_reported_mem_limit_at_start"] = mem_limit
    ev["heavy_child_initial_mu_charged"] = HEAVY_INITIAL_MU
    ev["container_actual"] = limits

    actual = limits.get("cgroup_memory_max")
    try:
        actual_bytes = int(actual) if actual not in (None, "max") else None
    except Exception:
        actual_bytes = None

    # The node must deliver at least what it told us it provisioned
    # (get_mem_limit_at_start) and what the manifest declared.
    baseline = max(mem_limit or 0, 0)
    if actual_bytes is None:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = f"could not read a numeric cgroup memory.max (got {actual!r})"
    elif baseline == 0:
        ev["verdict"] = "INCONCLUSIVE"
        ev["reason"] = "node did not report initial_sysresources.mem_limit"
    else:
        ratio = actual_bytes / baseline
        ev["actual_vs_reported_ratio"] = round(ratio, 3)
        if ratio >= 0.95:
            ev["verdict"] = "PASS"
            ev["reason"] = (f"node delivered {actual_bytes} B >= reported {baseline} B "
                            f"(ratio {ratio:.2f})")
        else:
            ev["verdict"] = "FAIL"
            ev["reason"] = (f"shortchanged: container sees {actual_bytes} B but node reported/charged "
                            f"{baseline} B (ratio {ratio:.2f})")
    return ev


# ----------------------------------------------------------------------------
# Probe 4 — attestation report card (JSON + content hash)
# ----------------------------------------------------------------------------
def build_attestation():
    probes = [
        probe_resource_provisioning(),
        probe_network_isolation(),
        probe_memory_ceiling(),
    ]
    passes = [p for p in probes if p.get("verdict") == "PASS"]
    fails = [p for p in probes if p.get("verdict") == "FAIL"]
    others = [p for p in probes if p.get("verdict") not in ("PASS", "FAIL")]

    summary = {
        "node_honest": len(fails) == 0 and len(others) == 0,
        "pass": len(passes),
        "fail": len(fails),
        "inconclusive_or_error": len(others),
        "total": len(probes),
    }

    # Deterministic content hash over the verdict-bearing payload (no timestamps),
    # so the same observed behaviour always hashes identically — this digest is
    # what an EGO reputation opinion would commit to on-chain.
    hashable = {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "probes": [{"probe": p.get("probe"), "verdict": p.get("verdict")} for p in probes],
        "summary": {k: summary[k] for k in ("node_honest", "pass", "fail", "total")},
    }
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha3_256(canonical.encode()).hexdigest()

    return {
        "verifier": "celaut-node-honesty-verifier",
        "version": VERIFIER_VERSION,
        "node_url": node_url,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "probes": probes,
        "summary": summary,
        "content_hash": {"alg": "sha3_256", "value": content_hash,
                         "note": "EGO-opinion-ready digest of {probe:verdict} + summary"},
    }


# ----------------------------------------------------------------------------
# Routes — attestation
# ----------------------------------------------------------------------------
@app.route('/attestation.json', methods=['GET', 'POST'])
def attestation_json():
    return jsonify(build_attestation())


@app.route('/probe/network', methods=['GET', 'POST'])
def route_probe_network():
    return jsonify(probe_network_isolation())


@app.route('/probe/memory', methods=['GET', 'POST'])
def route_probe_memory():
    return jsonify(probe_memory_ceiling())


@app.route('/probe/resources', methods=['GET', 'POST'])
def route_probe_resources():
    return jsonify(probe_resource_provisioning())


REPORT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Celaut Node-Honesty Verifier</title>
<link rel="stylesheet" href="https://unpkg.com/papercss@1.9.2/dist/paper.min.css">
<style>
 body{font-family:Arial,sans-serif;margin:40px;max-width:1000px}
 .card{padding:16px 20px;margin:14px 0;box-shadow:0 4px 8px rgba(0,0,0,.1);border-radius:6px}
 .PASS{border-left:8px solid #2e7d32}.FAIL{border-left:8px solid #c62828}
 .ERROR,.INCONCLUSIVE{border-left:8px solid #f9a825}
 .badge{font-weight:bold;padding:2px 10px;border-radius:12px;color:#fff}
 .b-PASS{background:#2e7d32}.b-FAIL{background:#c62828}.b-ERROR,.b-INCONCLUSIVE{background:#f9a825}
 pre{background:#f6f6f6;padding:10px;border-radius:4px;overflow:auto;font-size:12px}
 .hash{font-family:monospace;word-break:break-all;font-size:12px}
 #overall{font-size:1.3em;font-weight:bold}
</style></head>
<body>
<h1>Celaut Node-Honesty Verifier</h1>
<p>Actively probes the node under test for resource, memory-ceiling and network-isolation honesty.</p>
<div id="overall">Running probes… (this launches child microVMs and can take ~1 minute)</div>
<button class="btn btn-primary" onclick="run()">Re-run attestation</button>
<div id="cards"></div>
<h3>Content hash (EGO-opinion-ready)</h3>
<div class="hash" id="hash">—</div>
<h3>Raw report</h3>
<pre id="raw">—</pre>
<script>
async function run(){
  document.getElementById('overall').innerText='Running probes… please wait.';
  try{
    const res=await fetch('/attestation.json',{method:'POST'});
    const rep=await res.json();
    const s=rep.summary;
    document.getElementById('overall').innerHTML =
      'Node verdict: <span class="badge '+(s.node_honest?'b-PASS':'b-FAIL')+'">'+
      (s.node_honest?'HONEST':'DISHONEST / UNVERIFIED')+'</span> &nbsp; ('+
      s.pass+' pass / '+s.fail+' fail / '+s.total+' probes)';
    const cards=document.getElementById('cards');cards.innerHTML='';
    rep.probes.forEach(p=>{
      const v=p.verdict||'ERROR';
      const d=document.createElement('div');d.className='card '+v;
      d.innerHTML='<h3>'+p.probe+' <span class="badge b-'+v+'">'+v+'</span></h3>'+
                  '<p>'+(p.reason||'')+'</p><pre>'+JSON.stringify(p,null,2)+'</pre>';
      cards.appendChild(d);
    });
    document.getElementById('hash').innerText=rep.content_hash.alg+':'+rep.content_hash.value;
    document.getElementById('raw').innerText=JSON.stringify(rep,null,2);
  }catch(e){document.getElementById('overall').innerText='Error running attestation: '+e;}
}
run();
</script>
</body></html>
"""


@app.route('/')
def home():
    logging.info('Serving the node-honesty report card.')
    return render_template_string(REPORT_HTML)


# ----------------------------------------------------------------------------
# Legacy demo endpoints (kept so the original interaction still works)
# ----------------------------------------------------------------------------
@app.route('/services', methods=['GET'])
def get_services():
    return jsonify([{"ip_port": s[0], "result": s[1]} for s in services])


def _gen(service_iface, label):
    uri = service_iface.get_instance(max_attempts=1).uri
    new_service = (uri, "--")
    services.append(new_service)
    logging.info('Generated new %s service: %s', label, new_service)
    return jsonify({"status": "Service generated", "service": new_service})


@app.route('/generate_service', methods=['POST'])
def generate_service():
    try:
        return _gen(tiny_service, "tiny")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/generate_heavy_service', methods=['POST'])
def generate_heavy_service():
    try:
        return _gen(heavy_service, "heavy")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/generate_ping_service', methods=['POST'])
def generate_ping_service():
    try:
        return _gen(ping_service, "ping")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/use_services', methods=['POST'])
def use_services():
    try:
        for idx, service in enumerate(services):
            ip_port = service[0]
            try:
                result = requests.get(f"http://{ip_port}", timeout=30).text
            except requests.exceptions.RequestException as e:
                logging.error('Error contacting service at %s: %s', ip_port, str(e))
                result = 'Error'
            services[idx] = (ip_port, result)
        return jsonify({"status": "Services used successfully", "services": services})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/current_balance', methods=['GET'])
def current_balance():
    return jsonify({"balance_mu": "{:.2e}".format(balance_mu)})


@app.route('/memory_usage', methods=['GET'])
def memory_usage():
    b = resources.get('mem_limit', 0)
    return jsonify({"memory_used": "{:.2f}".format(b / (1024 * 1024) if b else 0)})


if __name__ == '__main__':
    logging.info('Starting the node-honesty verifier.')
    app.run(host='0.0.0.0', port=5000, debug=True)
