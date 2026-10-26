"""
End-to-end demo of the platform on a throwaway directory.     python -m omnios demo      (or: python scripts/demo_platform.py)

What it shows, in order, with real code paths (a real HTTP server for the witness, real files, real signatures):
  1  two customers on one platform, each with its own rules, keys, log and log signing key
  2  a payment that needs two different people; the agent cannot approve; the same person cannot approve twice
  3  a payment the rules deny outright
  4  customer B cannot see customer A
  5  a change to the rules needs a second admin (four-eyes on the system itself)
  6  the evidence pack, checked offline against the pinned log key
  7  someone edits the pack: the check fails and says where
  8  two witnesses (their own servers and keys) cosign the logs; the auditor demands 'at least 2, recent'; the operator rewrites history and both refuse
  9  the monthly witness report
Nothing here touches the network beyond 127.0.0.1, and nothing is written outside the temp directory.
"""
import argparse
import hashlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import uvicorn  # noqa: E402

from omnios import verifier, witnessd  # noqa: E402
from omnios.api import create_app  # noqa: E402
from omnios.evidence import build_bundle  # noqa: E402
from omnios.errors import OmniError  # noqa: E402
from omnios.ledger import Ledger  # noqa: E402
from omnios.provision import create_tenant  # noqa: E402
from omnios.pusher import push_all  # noqa: E402
from omnios.tenant import TenantRegistry  # noqa: E402

LINE = "-" * 78


def say(msg=""):
    print(msg, flush=True)


def step(n, title):
    say(f"\n{LINE}\n{n}. {title}\n{LINE}")


def expect_refusal(label, fn):
    try:
        fn()
    except OmniError as e:
        say(f"   refused  {label}: {e.code}")
        return e
    raise SystemExit(f"DEMO FAILED: '{label}' should have been refused")


class Server:
    def __init__(self, root):
        self.root, self.reg, self.srv, self.thread = root, None, None, None
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self.reg = TenantRegistry(self.root)
        self.srv = uvicorn.Server(uvicorn.Config(create_app(self.reg), host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.srv.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.srv.started:
                return
            time.sleep(0.05)
        raise SystemExit("server did not start")

    def stop(self):
        self.srv.should_exit = True
        self.thread.join(timeout=10)
        self.reg.close()


class WitnessServer:
    """A witness service on its own port, with its own key and state directory."""
    def __init__(self, config_path):
        self.daemon = witnessd.WitnessDaemon(config_path)
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            self.port = sk.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.public_key = self.daemon.public_key

    def start(self):
        self.srv = uvicorn.Server(uvicorn.Config(self.daemon.app(), host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.srv.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.srv.started:
                return
            time.sleep(0.05)
        raise SystemExit("witness did not start")

    def stop(self):
        self.srv.should_exit = True
        self.thread.join(timeout=10)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the temp directory and print its path")
    args = ap.parse_args(argv)
    work = tempfile.mkdtemp(prefix="omnios-demo-")
    root = os.path.join(work, "data")
    try:
        run(work, root)
    finally:
        if args.keep:
            say(f"\n(kept: {work})")
        else:
            shutil.rmtree(work, ignore_errors=True)


def run(work, root):
    srv = Server(root)
    srv.start()
    reg = srv.reg

    # ------------------------------------------------------------------ 1
    step(1, "Two customers on one platform")
    a, keys_a, _ = create_tenant(reg, "acme-ap", "Acme Accounts Payable", template="finance-ap-payments", profile="production",
                                 approvers=["alice", "bob"], auditors=["auditor"],
                                 agents=[{"name": "ap-agent", "permissions": ["finance:pay", "finance:books", "finance:vendor-admin"]}])
    b, keys_b, _ = create_tenant(reg, "bravo-support", "Bravo Support", template="support-refunds", profile="pilot",
                                 approvers=["bea"], agents=[{"name": "support-bot", "permissions": ["refund:issue"]}])
    ka = {k["name"]: k["key"] for k in keys_a}
    kb = {k["name"]: k["key"] for k in keys_b}
    for rt in (a, b):
        i = rt.public_info()
        say(f"   {i['tenant']:<14} profile {i['profile']:<10} admin quorum {i['admin_quorum']}   log {i['origin']}   key {i['log_public_key'][:16]}...")
    say("   keys are shown once; only their hashes are stored. Each log is signed by its own key.")

    # ------------------------------------------------------------------ 2
    step(2, "A 4,000 EUR payment needs two different people")
    eng = a.engine
    perms = ["finance:pay"]
    act = eng.propose("ap-agent", "payments.send", {"vendor": "Delta Supplies", "amount_eur": 4000}, permissions=perms)
    say(f"   {act['id']}  {act['status']}  needs {act['approvals_required']} approvers  ({'; '.join(act['reasons'][:2])})")
    expect_refusal("the agent approving its own payment", lambda: eng.approve(act["id"], "ap-agent"))
    eng.approve(act["id"], "alice")
    say("   alice approved (1 of 2)")
    expect_refusal("alice approving a second time", lambda: eng.approve(act["id"], "alice"))
    done = eng.approve(act["id"], "bob")
    say(f"   bob approved (2 of 2)  ->  {done['status']}")
    eng.report(act["id"], "ap-agent", True, {"bank_ref": "TX-1001"})
    say("   the agent reported the payment as made (an attestation by the agent; use proxy mode so the platform makes the call itself)")

    # ------------------------------------------------------------------ 3
    step(3, "A 25,000 EUR payment is over the ceiling")
    big = eng.propose("ap-agent", "payments.send", {"vendor": "Delta Supplies", "amount_eur": 25000}, permissions=perms)
    say(f"   {big['id']}  {big['status']}: {big['reasons'][0]}")
    bank = eng.propose("ap-agent", "vendors.bank_details.change", {"vendor": "Delta Supplies", "iban": "GR00 0000"}, permissions=["finance:vendor-admin"])
    say(f"   {bank['id']}  {bank['status']}  needs {bank['approvals_required']} approvers (changing a supplier's bank account is the classic fraud route)")

    # ------------------------------------------------------------------ 4
    step(4, "Customer B cannot see customer A")
    r = b.engine.propose("support-bot", "refunds.issue", {"customer": "C-9", "amount_eur": 40}, permissions=["refund:issue"])
    say(f"   bravo's first action is also called {r['id']}: each customer counts from 1, in its own database")
    say(f"   acme key on bravo: {b.identity.authenticate(ka['alice'])}   bravo key on acme: {a.identity.authenticate(kb['bea'])}")
    say(f"   different log keys: {a.public_info()['log_public_key'][:12]}... vs {b.public_info()['log_public_key'][:12]}...")

    # ------------------------------------------------------------------ 5
    step(5, "Changing the rules needs a second admin")
    new_policy = json.loads(json.dumps(a.engine.policy()))
    new_policy["tools"]["payments.send"]["deny"][0]["when"]["value"] = 50000
    c = eng.propose_change("policy.replace", {"doc": new_policy}, "admin-1")
    say(f"   admin-1 proposes to raise the ceiling to 50,000   ->  {c['id']} {c['status']}; the ceiling is still "
        f"{eng.policy()['tools']['payments.send']['deny'][0]['when']['value']}")
    expect_refusal("admin-1 approving their own change", lambda: eng.approve_change(c["id"], "admin-1"))
    eng.approve_change(c["id"], "admin-2")
    say(f"   admin-2 approves  ->  applied; the ceiling is now {eng.policy()['tools']['payments.send']['deny'][0]['when']['value']}, "
        "and the old and new rules are both in the log")

    # ------------------------------------------------------------------ 6
    step(6, "The evidence pack, checked offline")
    pin = a.public_info()["log_public_key"]
    bundle = build_bundle(a)
    path = os.path.join(work, "acme-evidence.zip")
    open(path, "wb").write(bundle)
    say(f"   {os.path.basename(path)}: {len(bundle):,} bytes, {a.ledger.size()} records. The auditor pins the log key they got from Acme another way:")
    rep = verifier.verify_bundle(path, pin)
    for line in verifier.render(rep).splitlines():
        say("   " + line)
    if not rep["ok"]:
        raise SystemExit("DEMO FAILED: honest bundle did not verify")

    # ------------------------------------------------------------------ 7
    step(7, "Someone edits the pack")
    z = zipfile.ZipFile(io.BytesIO(bundle))
    files = {n: z.read(n) for n in z.namelist()}
    lines = [json.loads(x) for x in files["records.jsonl"].decode().splitlines()]
    i = next(k for k, x in enumerate(lines) if '"bob"' in x["body"])
    lines[i]["body"] = lines[i]["body"].replace('"bob"', '"carol"')
    files["records.jsonl"] = ("\n".join(json.dumps(x) for x in lines) + "\n").encode()
    m = json.loads(files["manifest.json"])
    m["files"] = {n: hashlib.sha256(v).hexdigest() for n, v in files.items() if n != "manifest.json"}   # even with the manifest fixed
    files["manifest.json"] = json.dumps(m).encode()
    bad = os.path.join(work, "acme-edited.zip")
    with zipfile.ZipFile(bad, "w") as out:
        for n, v in files.items():
            out.writestr(n, v)
    say("   a record naming 'bob' now says 'carol' (the manifest was rewritten to match):")
    rep = verifier.verify_bundle(bad, pin)
    for p in rep["problems"][:3]:
        say("   PROBLEM  " + p)
    say("   RESULT: " + ("VERIFIED" if rep["ok"] else "FAILED"))
    if rep["ok"]:
        raise SystemExit("DEMO FAILED: edited bundle verified")

    # ------------------------------------------------------------------ 8
    step(8, "Two witnesses, on their own servers, with their own keys")
    ws = {}
    for wname in ("auditor-witness", "insurer-witness"):
        wd = os.path.join(work, wname)
        info = witnessd.init_witness(wd, wname)
        cfgw = json.load(open(info["config_path"], encoding="utf-8"))
        cfgw["logs"] = [{"name": t, "origin": f"omnios/{t}", "log_key": reg.get(t).public_info()["log_public_key"]} for t in ("acme-ap", "bravo-support")]
        cfgw["max_gap_seconds"] = 86400 * 40
        json.dump(cfgw, open(info["config_path"], "w", encoding="utf-8"))
        ws[wname] = WitnessServer(info["config_path"])
        ws[wname].start()
        for t in ("acme-ap", "bravo-support"):
            reg.set_witnesses(t, {wname: info["public_key"]}, {wname: ws[wname].url})
    say("   each witness holds its OWN key and a list of logs with each log's PINNED public key (given to it by another route).")
    say("   the customer's installation only makes outbound calls: it pushes its signed checkpoint (hashes, no content) to each witness.")
    results = push_all(reg)
    for r in results:
        say(f"   push {r['tenant']:<14} -> {r['witness']:<16} {'cosigned, size ' + str(r['size']) if r['ok'] else r['detail']}")
    if not all(r["ok"] for r in results):
        raise SystemExit("DEMO FAILED: a push was refused")
    wkeys = {n: w.public_key for n, w in ws.items()}
    path2 = os.path.join(work, "acme-evidence-witnessed.zip")
    open(path2, "wb").write(build_bundle(a))
    rep = verifier.verify_bundle(path2, pin, wkeys, min_witnesses=2, max_age=3600)
    say(f"   the auditor asks for 'at least 2 witnesses, each within the last hour': {'VERIFIED' if rep['ok'] else 'FAILED'}"
        f"  ({', '.join(w['witness'] for w in rep['info']['witnesses'])}; records 0..{rep['info']['witnessed_by_required_up_to'] - 1} covered)")
    if not rep["ok"]:
        raise SystemExit("DEMO FAILED: two-witness policy not met")

    step("8b", "The operator rewrites history")
    tdir, key = a.dir, a.log_key
    old_records = a.ledger.records(0, 100000)
    srv.stop()
    alt_path = os.path.join(work, "alt-ledger.db")
    alt = Ledger(alt_path, "acme-ap", key)
    for r in old_records:
        body = json.loads(r["body"])
        data = dict(body["data"])
        if r["seq"] == 3:
            data["by"] = "someone-else"
        alt.append(body["type"], data, at=body["at"])
    for n in range(3):
        alt.append("note", {"id": f"filler-{n}"}, at=time.time())
    alt.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(os.path.join(tdir, "ledger.db" + suffix))
        except FileNotFoundError:
            pass
    shutil.copy(alt_path, os.path.join(tdir, "ledger.db"))
    srv = Server(root)
    srv.start()
    reg = srv.reg
    say("   the operator replaced Acme's ledger file with a rebuilt one: same signing key, one record changed, more records appended.")
    say("   the log is internally consistent and correctly signed. Only the witnesses remember what it used to say:")
    results = push_all(reg, only="acme-ap")
    for r in results:
        say(f"   push {r['tenant']:<14} -> {r['witness']:<16} {r['detail']}")
    if any(r["ok"] for r in results):
        raise SystemExit("DEMO FAILED: a witness accepted a rewritten log")
    path3 = os.path.join(work, "acme-rewritten.zip")
    open(path3, "wb").write(build_bundle(reg.get("acme-ap")))
    rep = verifier.verify_bundle(path3, pin, wkeys, min_witnesses=2, max_age=3600)
    say(f"   the rewritten log cannot produce the witnesses' cosignatures. The auditor's check: {'VERIFIED' if rep['ok'] else 'FAILED'}")
    for p in rep["problems"][:2]:
        say("   PROBLEM  " + p)
    if rep["ok"]:
        raise SystemExit("DEMO FAILED: rewritten log passed the witness policy")
    say("   and bravo-support, untouched, keeps being cosigned:")
    for r in push_all(reg, only="bravo-support"):
        say(f"   push {r['tenant']:<14} -> {r['witness']:<16} {'cosigned, size ' + str(r['size']) if r['ok'] else r['detail']}")

    # ------------------------------------------------------------------ 9
    step(9, "The monthly witness report (from the auditor's witness)")
    month = time.strftime("%Y-%m", time.gmtime())
    rep = ws["auditor-witness"].daemon.monthly_report(month)
    out = witnessd.write_report(rep, os.path.join(work, "reports"))
    for row in rep["logs"]:
        say(f"   {row['log']:<14} checks {row['checks']}  verified {row['verified']}  refusals {row['refusals']}  verdict {row['verdict']}")
    say(f"   written: {os.path.basename(out['html'])} (+ json)")
    srv.stop()
    for w in ws.values():
        w.stop()

    say(f"\n{LINE}\nDemo finished. What it did NOT show: a real agent, a real bank, single sign-on, or an external security review.\n{LINE}")


if __name__ == "__main__":
    main()
