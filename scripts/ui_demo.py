"""
Run the OmniOS UI locally with a ready-made demo customer.      python -m omnios ui-demo      (or double-click ΤΡΕΞΕ-UI.bat)

What you get on http://127.0.0.1:8765/ui :
  * one demo customer ("Demo Acme") with the finance rules template, production profile (2 admins needed for changes)
  * people with their own keys, switchable with one click: the agent, three approvers, three admins, an auditor
  * requests in every state: paid with two approvers, waiting for the second approver, waiting for two, denied by the rules
    (over the ceiling), rejected by a human, allowed at once, and a rule change waiting for a second admin
  * an "Observe" tab with two weeks of reported agent actions judged as a dry run (nothing blocked), plus a downloadable report
  * two witnesses running as separate services on their own ports; the installation pushes its checkpoint to them every
    few seconds, so the "confirmed by witnesses" number on the Overview moves as you work

Everything is local, in a temporary folder that is deleted when you stop it (Ctrl+C). The keys are throw-away demo keys:
the /ui/demo-keys endpoint exists ONLY in this launcher.
"""
import argparse
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn  # noqa: E402

from omnios import witnessd  # noqa: E402
from omnios.api import create_app  # noqa: E402
from omnios.provision import create_tenant  # noqa: E402
from omnios.pusher import start_background  # noqa: E402
from omnios.tenant import TenantRegistry  # noqa: E402
from demo_platform import WitnessServer  # noqa: E402

LABELS = {
    "ap-agent": "agent: ap-agent", "alice": "εγκρίνων: alice", "bob": "εγκρίνων: bob", "eleni": "εγκρίνων: eleni",
    "admin-1": "admin-1", "admin-2": "admin-2", "admin-3": "admin-3", "audit-1": "ελεγκτής",
}


def seed(rt):
    e = rt.engine
    perms = ["finance:pay", "finance:vendor-admin", "finance:books"]
    ag = "ap-agent"
    a = e.propose(ag, "payments.send", {"vendor": "Delta Supplies", "amount_eur": 4000}, permissions=perms)
    e.approve(a["id"], "alice")
    e.approve(a["id"], "bob")
    e.report(a["id"], ag, True, {"bank_ref": "TX-1001"})
    e.propose(ag, "payments.send", {"vendor": "Orion Logistics", "amount_eur": 1250}, permissions=perms)
    pend = e.list(status="PENDING_APPROVAL")[0]
    e.approve(pend["id"], "alice")
    e.propose(ag, "vendors.bank_details.change", {"vendor": "Delta Supplies", "iban": "GR00 0000 0000"}, permissions=perms)
    e.propose(ag, "payments.send", {"vendor": "Delta Supplies", "amount_eur": 25000}, permissions=perms)   # over the ceiling: denied
    r = e.propose(ag, "payments.send", {"vendor": "Unknown Ltd", "amount_eur": 300}, permissions=perms)
    e.reject(r["id"], "bob", "vendor not in our list")
    e.propose(ag, "invoices.mark_paid", {"invoice": "INV-1042"}, permissions=perms)                         # low risk: allowed at once
    pol = json.loads(json.dumps(e.policy()))
    pol["tools"]["payments.send"]["deny"][0]["when"]["value"] = 20000
    pol["tools"]["payments.send"]["deny"][0]["reason"] = "Above the ceiling of 20,000 EUR per payment"
    e.propose_change("policy.replace", {"doc": pol}, "admin-1")


def seed_observed(rt, now=None):
    """Two weeks of what the demo customer's agent 'already does', reported in observe mode (nothing was blocked)."""
    now = now or time.time()
    day = 86400
    perms = ["finance:pay", "finance:vendor-admin", "finance:books"]
    vendors = ["Delta Supplies", "Orion Logistics", "Nova Print", "Atlas Cleaning", "Kappa Software"]
    amounts = [320, 780, 1250, 410, 2900, 560, 7800, 1500, 240, 3100, 980, 12400, 640, 4100, 9200, 880, 5600, 430]
    ev = []
    for i, amt in enumerate(amounts):
        t = now - (14 - i * 0.75) * day + 9 * 3600
        ev.append({"tool": "payments.send", "params": {"vendor": vendors[i % len(vendors)], "amount_eur": amt}, "occurred_at": t, "external_id": f"pay-{i + 1:03d}"})
    for k in range(3):                                         # a busy day: three payments close together, together over the daily limit
        ev.append({"tool": "payments.send", "params": {"vendor": "Delta Supplies", "amount_eur": 6500}, "occurred_at": now - 3 * day + k * 900, "external_id": f"pay-burst-{k}"})
    ev.append({"tool": "payments.send", "params": {"vendor": "Orion Logistics"}, "occurred_at": now - 2 * day, "external_id": "pay-noamount"})
    ev.append({"tool": "payments.send", "params": {"vendor": "Nova Print", "amount_eur": "1 200,50"}, "occurred_at": now - 2 * day + 600, "external_id": "pay-badnumber"})
    for i in range(16):
        ev.append({"tool": "invoices.mark_paid", "params": {"invoice": f"INV-{1000 + i}"}, "occurred_at": now - (13 - i * 0.8) * day + 11 * 3600, "external_id": f"inv-{i + 1:03d}"})
    for i, vendor in enumerate(["Delta Supplies", "Kappa Software"]):
        ev.append({"tool": "vendors.bank_details.change", "params": {"vendor": vendor, "iban": "GR00 0000 0000"}, "occurred_at": now - (9 - 4 * i) * day, "external_id": f"iban-{i + 1}"})
    for i in range(3):
        ev.append({"tool": "contracts.sign", "params": {"counterparty": vendors[i], "value_eur": 15000 * (i + 1)}, "occurred_at": now - (6 - i) * day, "external_id": f"contract-{i + 1}"})
    ev.append({"tool": "email.send", "params": {"to": "supplier@example.com"}, "occurred_at": now - day, "external_id": "mail-1"})
    ev.sort(key=lambda e: e["occurred_at"])
    for i in range(0, len(ev), 100):
        rt.engine.observe("ap-agent", perms, ev[i:i + 100])


def free_port(preferred):
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)
    work = tempfile.mkdtemp(prefix="omnios-ui-demo-")
    ws = []
    try:
        reg = TenantRegistry(os.path.join(work, "data"))
        rt, keys, _ = create_tenant(reg, "demo-acme", "Demo Acme Ltd", template="finance-ap-payments", profile="production",
                                    admins=["admin-1", "admin-2", "admin-3"], approvers=["alice", "bob", "eleni"], auditors=["audit-1"],
                                    agents=[{"name": "ap-agent", "permissions": ["finance:pay", "finance:vendor-admin", "finance:books"]}])
        seed(rt)
        seed_observed(rt)
        for wname in ("auditor-witness", "insurer-witness"):
            wd = os.path.join(work, wname)
            info = witnessd.init_witness(wd, wname)
            cfg = json.load(open(info["config_path"], encoding="utf-8"))
            cfg["logs"] = [{"name": "demo-acme", "origin": "omnios/demo-acme", "log_key": rt.public_info()["log_public_key"]}]
            json.dump(cfg, open(info["config_path"], "w", encoding="utf-8"))
            w = WitnessServer(info["config_path"])
            w.start()
            ws.append(w)
            reg.set_witnesses("demo-acme", {wname: info["public_key"]}, {wname: w.url})
        start_background(reg, 4, log=lambda m: None)
        order = ["ap-agent", "alice", "bob", "eleni", "admin-1", "admin-2", "admin-3", "audit-1"]
        by = {k["name"]: k for k in keys}
        demo_keys = [{"name": n, "role": by[n]["role"], "key": by[n]["key"], "label": LABELS.get(n, n)} for n in order if n in by]
        port = free_port(args.port)
        app = create_app(reg, demo_keys=demo_keys)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        th = threading.Thread(target=server.run, daemon=True)
        th.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        url = f"http://127.0.0.1:{port}/ui"
        print("\nOmniOS UI demo is running:", url)
        print("Pick a role at the top (agent, approvers, admins, auditor). Stop with Ctrl+C.\n")
        if not args.no_browser:
            webbrowser.open(url)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        for w in ws:
            try:
                w.stop()
            except Exception:
                pass
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
