"""Every escalation the predicate reports on the corpus, with its witnesses.

The precision question has to be asked per claim, because the tool makes more
than one. This prints the delegation and takeover findings so each can be given
a verdict by reading the configuration behind it, which is the only way a
precision number for this claim can be honest.
"""
import json, pathlib, subprocess, sys, tempfile
root = pathlib.Path(".")
sys.path.insert(0, str((root / "agentpathtriage").resolve()))
bench = root / "evaluation" / "benchmark"
import extract_graph as X, reach as R, managed_policies as MP

snap = MP.load("agentpathtriage/data/aws_managed_policies.json", required=True)
census = json.loads((bench / "corpus_takeover_census.json").read_text())
want = sorted({e["config"] for mode in ("inline", "expanded")
               for e in census[mode]["escalating_configs"]})
print(f"configurations with an escalation in either mode: {len(want)}\n")

out = []
for rel in want:
    print("=" * 74)
    print(rel)
    with tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "s.json"
        p = subprocess.run([sys.executable, str(bench / "tf_to_state.py"),
                            "--tfdir", str(root / "corpus_tier2" / rel),
                            "--json", str(st)], capture_output=True, text=True)
        if p.returncode != 0:
            print("  did not parse"); continue
        state = json.loads(st.read_text())
    for label, man in (("inline", None), ("expanded", snap.statements)):
        G, ix = X.build(state, man)
        R.enable_delegations(G, ix)
        u = R.build_universe(ix); cache = {}
        for pr in sorted(ix.kind):
            r = R.analyse(G, ix, pr, u, cache)
            if not r["Esc"]:
                continue
            print(f"  [{label}] {pr}  auth={r['n_auth']} eff={r['n_eff']} "
                  f"literal={r['n_gained_literal']} probe={r['n_gained_probe']}")
            print(f"      self_escalation={r.get('self_escalation')} "
                  f"via={r.get('self_escalation_via')}")
            seen = set()
            for w in r["witnesses"]:
                if not w.get("literal"):
                    continue
                key = (w["reaches"], w["action"])
                if key in seen:
                    continue
                seen.add(key)
                ch = " ".join(f"{h['from']} --{h['via']}--> {h['to']}"
                              for h in w["chain"])
                print(f"      LITERAL {w['action']}  ->  {w['reaches']}")
                print(f"              chain: {ch or '(none)'}")
                if len(seen) >= 4:
                    break
            out.append({"config": rel, "mode": label, "principal": pr,
                        "n_auth": r["n_auth"], "n_eff": r["n_eff"],
                        "n_gained_literal": r["n_gained_literal"],
                        "n_gained_probe": r["n_gained_probe"],
                        "gained_literal": r["gained_literal"],
                        "self_escalation": r.get("self_escalation"),
                        "witnesses": [w for w in r["witnesses"] if w.get("literal")][:6]})
(bench / "r2_esc_findings.json").write_text(json.dumps(out, indent=2))
print()
print(f"wrote {bench / 'r2_esc_findings.json'}  ({len(out)} finding rows)")
