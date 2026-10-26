"""
cli.py — one command line for the four deliverables.   python -m omnios <command> ...
====================================================================================
  assess init|report      1. Agent Control Check            answers.yaml -> report.html + findings + draft rules
  tenant create|list|witness|suspend
                          2. Set a customer up              policy template, keys (shown once), handover folder
  observe import|report   a safe first step: judge what the customer's agent already does against the rules, block nothing
  bundle export           3. Evidence pack                  one zip, checked offline with verify.py
  verify                    (the stand-alone verifier, same code that ships inside every bundle)
  witness init|run|serve|report
                          4. Monthly verification           a witness for many logs (pull, or push via its own server), and the monthly report
  push                      send each tenant's checkpoint out to its witnesses (or serve --push-interval)
  serve                   the HTTP platform
  demo                    an end-to-end run on a throwaway directory
  ui-demo                 the browser UI with a ready-made demo customer
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional


def _split(s: Optional[str]) -> list:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def _tail(argv: Optional[list], cmd: str) -> list:
    """Everything the user typed after the command name, in the order typed (argparse REMAINDER reorders flags)."""
    a = list(sys.argv[1:] if argv is None else argv)
    return a[a.index(cmd) + 1:] if cmd in a else []


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(prog="omnios", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assess").add_subparsers(dest="sub", required=True)
    p = a.add_parser("init"); p.add_argument("--client", required=True); p.add_argument("--out", default="answers.yaml")
    p = a.add_parser("report"); p.add_argument("--answers", required=True); p.add_argument("--out", default="report")

    t = sub.add_parser("tenant").add_subparsers(dest="sub", required=True)
    p = t.add_parser("create")
    p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data")); p.add_argument("--id", required=True)
    p.add_argument("--name", required=True); p.add_argument("--template", default="generic-starter")
    p.add_argument("--profile", default="pilot", choices=["pilot", "production"])
    p.add_argument("--admins"); p.add_argument("--approvers"); p.add_argument("--auditors")
    p.add_argument("--agents", help="name:perm1|perm2,name2:perm")
    p.add_argument("--handover", help="write the handover folder here"); p.add_argument("--write-keys", action="store_true")
    p.add_argument("--public-url", default="https://omnios.example.com")
    p.add_argument("--policy", help="a JSON file with the rules (instead of --template)")
    p = t.add_parser("list"); p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data"))
    p = t.add_parser("witness"); p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data"))
    p.add_argument("--id", required=True); p.add_argument("--name", required=True); p.add_argument("--key", required=True)
    p.add_argument("--url", help="where this witness listens (https://...); enables PUSH from this installation")
    p = t.add_parser("suspend"); p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data"))
    p.add_argument("--id", required=True); p.add_argument("--resume", action="store_true")

    o = sub.add_parser("observe", help="observe mode: dry-run verdicts on what the customer's agent did").add_subparsers(dest="sub", required=True)
    p = o.add_parser("import", help="read a .jsonl or .csv export of agent actions")
    p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data")); p.add_argument("--tenant", required=True)
    p.add_argument("--agent", required=True); p.add_argument("--file", required=True)
    p = o.add_parser("report", help="write the shadow report")
    p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data")); p.add_argument("--tenant", required=True)
    p.add_argument("--out", required=True, help="report.html, or report.json when it ends in .json")
    p.add_argument("--since", type=float); p.add_argument("--until", type=float)

    b = sub.add_parser("bundle").add_subparsers(dest="sub", required=True)
    p = b.add_parser("export"); p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data"))
    p.add_argument("--tenant", required=True); p.add_argument("--scope", default="all", choices=["all", "action", "changes"])
    p.add_argument("--id"); p.add_argument("--out", required=True)

    p = sub.add_parser("verify", add_help=False)
    p.add_argument("rest", nargs=argparse.REMAINDER)

    w = sub.add_parser("witness").add_subparsers(dest="sub", required=True)
    p = w.add_parser("init"); p.add_argument("--out", required=True); p.add_argument("--name", default="witness-1")
    p = w.add_parser("run"); p.add_argument("--config", required=True); p.add_argument("--once", action="store_true")
    p = w.add_parser("report"); p.add_argument("--config", required=True); p.add_argument("--month", required=True)
    p.add_argument("--out", default="reports")
    p = w.add_parser("serve"); p.add_argument("--config", required=True); p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8100)

    p = sub.add_parser("serve")
    p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data")); p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--push-interval", type=float, default=0, help="seconds between pushes of each tenant's checkpoint to its witnesses (0 = off)")
    p = sub.add_parser("push", help="push every tenant's checkpoint to its registered witnesses once")
    p.add_argument("--root", default=os.environ.get("OMNIOS_ROOT", "omnios-data")); p.add_argument("--tenant")

    p = sub.add_parser("demo")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p = sub.add_parser("ui-demo", help="run the browser UI with a ready-made demo customer")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    args, extra = ap.parse_known_args(argv)
    if extra and args.cmd not in ("demo", "ui-demo"):
        ap.error("unrecognized arguments: " + " ".join(extra))

    if args.cmd == "assess":
        from . import assess
        if args.sub == "init":
            print("wrote", assess.init_answers(args.out, args.client))
        else:
            r = assess.run_report(args.answers, args.out)
            print(json.dumps(r["summary"], indent=2)); print("report:", r["report"]); print("draft rules:", r["policy"])
        return 0
    if args.cmd == "tenant":
        from .errors import OmniError
        from .provision import create_tenant, parse_agents
        from .tenant import TenantRegistry
        reg = TenantRegistry(args.root)
        try:
            if args.sub == "create":
                policy = None
                if args.policy:
                    with open(args.policy, encoding="utf-8-sig") as f:
                        policy = json.load(f)
                rt, keys, out = create_tenant(reg, args.id, args.name, template=args.template, profile=args.profile, policy=policy,
                                              admins=_split(args.admins) or None, approvers=_split(args.approvers),
                                              auditors=_split(args.auditors), agents=parse_agents(args.agents or ""),
                                              handover_dir=args.handover, write_keys=args.write_keys, public_url=args.public_url)
                print(f"tenant {rt.id} created ({rt.cfg['profile']}, admin quorum {rt.cfg['admin_quorum']}); log key {rt.public_info()['log_public_key']}")
                print("KEYS (shown once; only hashes are stored):")
                for k in keys:
                    print(f"  {k['name']:<18} {k['role']:<9} {k['key']}")
                if out:
                    print("handover folder:", out)
            elif args.sub == "list":
                for i in reg.public_registry():
                    print(f"{i['tenant']:<20} {i['profile']:<10} quorum {i['admin_quorum']}  {i['origin']}")
            elif args.sub == "witness":
                reg.set_witnesses(args.id, {args.name: args.key}, {args.name: args.url} if args.url else None)
                print("witness registered:", args.name, f"(pushes to {args.url})" if args.url else "(pull only)")
            else:
                reg.suspend(args.id, not args.resume); print("ok")
        except OmniError as e:
            print(f"ERROR {e.code}: {e.detail}", file=sys.stderr)
            return 1
        finally:
            reg.close()
        return 0
    if args.cmd == "observe":
        from . import observe
        from .errors import OmniError
        from .tenant import TenantRegistry
        reg = TenantRegistry(args.root)
        try:
            rt = reg.get(args.tenant)
            if args.sub == "import":
                res = observe.import_events(rt, args.agent, observe.load_events(args.file))
                d = res["decisions"]
                print(f"imported {res['imported']} events: {d['allow']} would pass, {d['pending']} would need approval, {d['deny']} would be refused.")
                print("Nothing was blocked or executed. Next: python -m omnios observe report --tenant", args.tenant, "--out report.html")
            else:
                summary = observe.summarize(rt.engine.observations(limit=5000, since=args.since, until=args.until))
                if args.out.lower().endswith(".json"):
                    text = json.dumps(summary, indent=2, ensure_ascii=False)
                else:
                    text = observe.render_html(summary, rt.cfg.get("name") or rt.id)
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(text)
                print(f"wrote {args.out}  ({summary['total']} events: {summary['allow']} / {summary['pending']} / {summary['deny']})")
        except (OmniError, ValueError, OSError) as e:
            print(f"ERROR {getattr(e, 'code', '')} {getattr(e, 'detail', e)}".strip(), file=sys.stderr)
            return 1
        finally:
            reg.close()
        return 0
    if args.cmd == "bundle":
        from .evidence import build_bundle
        from .tenant import TenantRegistry
        reg = TenantRegistry(args.root)
        try:
            open(args.out, "wb").write(build_bundle(reg.get(args.tenant), scope=args.scope, ref=args.id))
            print("wrote", args.out)
        finally:
            reg.close()
        return 0
    if args.cmd == "verify":
        from .verifier import main as vmain
        return vmain(args.rest)
    if args.cmd == "witness":
        from . import witnessd
        if args.sub == "init":
            r = witnessd.init_witness(args.out, args.name)
            print(f"witness '{r['name']}'  public key: {r['public_key']}\nconfig: {r['config_path']}")
            return 0
        d = witnessd.WitnessDaemon(args.config)
        if args.sub == "serve":
            return d.serve(args.host, args.port)
        if args.sub == "run":
            return d.run(once=args.once)
        rep = d.monthly_report(args.month)
        print(json.dumps(witnessd.write_report(rep, args.out), indent=2))
        return 0
    if args.cmd == "serve":
        import uvicorn
        from .api import create_app
        from .tenant import TenantRegistry
        reg = TenantRegistry(args.root)
        app = create_app(reg, platform_key=os.environ.get("OMNIOS_PLATFORM_KEY") or None)
        if args.push_interval > 0:
            from .pusher import start_background
            start_background(reg, args.push_interval)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    if args.cmd == "push":
        from .pusher import push_all
        from .tenant import TenantRegistry
        reg = TenantRegistry(args.root)
        try:
            res = push_all(reg, only=args.tenant)
        finally:
            reg.close()
        for r in res:
            print(f"{r['tenant']} -> {r['witness']}: {'OK size ' + str(r['size']) if r['ok'] else r['detail']}")
        if not res:
            print("no witness with a URL is registered")
        return 0 if all(r["ok"] for r in res) else 2
    if args.cmd == "ui-demo":
        import runpy
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ns = runpy.run_path(os.path.join(here, "scripts", "ui_demo.py"), run_name="omnios_ui_demo")
        ns["main"](_tail(argv, args.cmd))
        return 0
    if args.cmd == "demo":
        import runpy
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ns = runpy.run_path(os.path.join(here, "scripts", "demo_platform.py"), run_name="omnios_demo")
        ns["main"](_tail(argv, args.cmd))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
