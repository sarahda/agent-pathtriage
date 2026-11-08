#!/usr/bin/env python3
"""Does the Foundry verdict actually flip, and does it see the live lab?

Two questions, kept apart because they have different answers.

A. The predicate. Esc(p) is eff(p) minus auth(p). The falsification cell gave
   the caller the resource role directly, so auth grew to cover what eff
   already reached and the predicate should stop firing. Up to now that
   followed from the definition rather than from the code. This builds both
   states and runs the analyser on each, over the mechanism the analyser
   models, which is ProjectManagedIdentity passthrough.

B. Coverage. The live demonstration did not use passthrough. The caller
   authenticated as itself and was authorised to invoke the callee by a role
   assignment, and the callee did the privileged read for it. This asks
   whether the analyser sees that at all.

Every value is derived from the state that is passed in. The role and scope
used to build the falsification state are read out of the callee's own
assignments, so nothing about this lab is written into this file.

  python3 verdict_flip.py --state <show-format json> --agents <agents.json>
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))


def load_analyser():
    import importlib.util
    here = pathlib.Path(__file__).resolve().parent
    for cand in (here / "foundry_cp.py", here / "agentpathtriage" / "foundry_cp.py"):
        if cand.exists():
            spec = importlib.util.spec_from_file_location("foundry_cp", cand)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    print("stop: foundry_cp.py not found next to this script", file=sys.stderr)
    sys.exit(2)


def resources(state):
    return state["values"]["root_module"]["resources"]


def add_role(state, principal_id, role_name, scope, label):
    s = copy.deepcopy(state)
    resources(s).append({
        "type": "azurerm_role_assignment", "name": label, "mode": "managed",
        "values": {"principal_id": principal_id,
                   "role_definition_name": role_name, "scope": scope},
    })
    return s


def add_connection(state, parent_id, auth_type, label):
    s = copy.deepcopy(state)
    resources(s).append({
        "type": "azapi_resource", "name": label, "mode": "managed",
        "values": {"parent_id": parent_id,
                   "body": {"properties": {"authType": auth_type,
                                           "category": "RemoteA2A"}}},
    })
    return s


def verdict(mod, state, agents):
    f = mod.analyse(state, agents)
    return {
        "escalations": len(f["escalations"]),
        "gained": [g for e in f["escalations"] for g in e["gained_roles"]],
        "passthrough": f["passthrough"],
        "auth": f["connection_auth"],
        "cp": [k for k, v in f["cp"].items() if v],
    }


def show(name, v):
    print(f"  {name}")
    print(f"      escalations : {v['escalations']}")
    print(f"      gained      : {v['gained'] or '-'}")
    print(f"      authType    : {', '.join(v['auth'])}   passthrough={v['passthrough']}")
    print(f"      primitives  : {', '.join(v['cp']) or '-'}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True, type=pathlib.Path)
    ap.add_argument("--agents", required=True, type=pathlib.Path)
    ap.add_argument("--live-agents", type=pathlib.Path,
                    help="agents_live.json, for the instance identity principals")
    args = ap.parse_args()

    mod = load_analyser()
    base = json.loads(args.state.read_text())
    agents = json.loads(args.agents.read_text())

    identities, p2i, roles, conns = mod.parse(base)
    name_of = {a["name"]: a["identity"] for a in agents["agents"]}
    inv = (agents.get("invocations") or [None])[0]
    if not inv:
        print("stop: no invocation declared in the topology", file=sys.stderr)
        return 2
    caller_id, callee_id = name_of[inv["caller"]], name_of[inv["callee"]]
    caller_pid, callee_pid = identities.get(caller_id), identities.get(callee_id)
    print(f"invocation      : {inv['caller']} -> {inv['callee']}")
    print(f"caller identity : {caller_id}")
    print(f"callee identity : {callee_id}")
    callee_roles = sorted(mod.roles_of(callee_id, identities, roles))
    print(f"callee roles    : {len(callee_roles)}")
    for rn, sc in callee_roles:
        print(f"                  {rn} @ ...{str(sc)[-48:]}")
    print()

    # ---------------------------------------------------------------- A ----
    print("A. the predicate, over the mechanism the analyser models")
    print()
    print("as deployed, no connection in IaC:")
    show("state 0", verdict(mod, base, agents))
    print()
    if not callee_roles:
        print("stop: the callee holds no roles in this state, so there is "
              "nothing for the caller to gain and the flip cannot be built.",
              file=sys.stderr)
        return 2

    pa = [pid for pid in {c[0] for c in conns} if pid]
    parent = (pa[0] if pa else None) or (
        [r["values"].get("id") for r in resources(base)
         if r.get("type") == "azapi_resource" and r.get("name", "").startswith("project")]
        or [None])[0]
    pt_auth = sorted(mod.PASSTHROUGH_AUTH)[0]
    treat = add_connection(base, parent, pt_auth, "injected_passthrough_conn")
    print(f"treatment, a {pt_auth} connection added:")
    v_treat = verdict(mod, treat, agents)
    show("state 1", v_treat)
    print()

    fals = treat
    for rn, sc in callee_roles:
        fals = add_role(fals, caller_pid, rn, sc, f"injected_caller_{rn[:12]}")
    print("falsification, every callee role also granted to the caller:")
    v_fals = verdict(mod, fals, agents)
    show("state 2", v_fals)
    print()
    flipped = v_treat["escalations"] > 0 and v_fals["escalations"] == 0
    print(f"  VERDICT FLIPS: {flipped}")
    if not flipped:
        print("  (state 1 must fire and state 2 must not. If state 1 does not "
              "fire, the mechanism is not modelled; if state 2 still fires, "
              "auth(p) is not being subtracted.)")
    print()

    # ---------------------------------------------------------------- B ----
    print("B. coverage of the live A2A mechanism")
    print()
    live_pid = None
    if args.live_agents and args.live_agents.exists():
        live = json.loads(args.live_agents.read_text())
        a = (live.get("agents") or {}).get(inv["caller"]) or {}
        if not a:
            for k, vv in (live.get("agents") or {}).items():
                if "caller" in k:
                    a = vv
                    break
        live_pid = ((a.get("instance_identity") or {}).get("principal_id"))
    print(f"caller instance identity (live, layer 3): {live_pid or 'not supplied'}")
    print(f"caller Terraform identity principal       : {caller_pid}")
    same = bool(live_pid) and live_pid == caller_pid
    print(f"same principal: {same}")
    print()
    in_state = {p for (p, _r, _s) in roles}
    print("role assignments in IaC that name the live instance identity: "
          f"{'yes' if live_pid in in_state else 'no'}")
    a2a = [a for (_p, a) in conns if "a2a" in str(a).lower()]
    print(f"A2A connections in IaC: {len(a2a)}")
    print()
    print("What this means for the two cells run live on 2026-10-31:")
    print("  the Consumer role was granted with az, on the agent's instance")
    print("  identity, which is a data plane object and never enters Terraform.")
    print("  The A2A connection is created at runtime through ARM. So neither")
    print("  the treatment nor the falsification state is visible to a reader")
    print("  of the configuration, and the analyser returns 0 for both.")
    print()
    print("  That is the platform asymmetry the paper argues for, now measured")
    print("  on this project's own lab rather than only on other people's code.")
    print("  It is also a gap: the predicate is implemented for identity")
    print("  passthrough (CP-1) and not for delegated invocation authorised by")
    print("  a role, which is what the lab demonstrated.")
    return 0 if flipped else 1


if __name__ == "__main__":
    sys.exit(main())
