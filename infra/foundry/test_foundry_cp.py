#!/usr/bin/env python3
"""
Regression test for foundry_cp determination - synthetic states with known
answers (no Azure needed). Mirrors the AWS falsification controls.

Run:  python3 test_foundry_cp.py        (exit 0 = all pass)
"""
import json, sys, os
# foundry_cp.py lives in agentpathtriage/ (the package dir). Add both the repo
# root and agentpathtriage/ to the path so this runs from anywhere.
_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(os.path.dirname(_here))          # repo root (../../)
for _p in (_root, os.path.join(_root, "agentpathtriage")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from foundry_cp import analyse

AGENTS = {
    "agents": [
        {"name": "agentA", "project": "agentA", "identity": "apt-agentA-thin"},
        {"name": "agentB", "project": "agentB", "identity": "apt-agentB-broad"},
    ],
    "invocations": [{"caller": "agentA", "callee": "agentB", "mediated": False}],
    "shared_memory": [],
}


def state(auth_type, a_has_secret):
    res = [
        {"type": "azurerm_user_assigned_identity", "name": "a",
         "values": {"name": "apt-agentA-thin", "principal_id": "pidA"}},
        {"type": "azurerm_user_assigned_identity", "name": "b",
         "values": {"name": "apt-agentB-broad", "principal_id": "pidB"}},
        {"type": "azurerm_role_assignment", "name": "bsec",
         "values": {"principal_id": "pidB", "role_definition_name": "Key Vault Secrets User", "scope": "/kv"}},
        {"type": "azapi_resource", "name": "conn",
         "values": {"parent_id": "/proj/agentA", "body": {"properties": {"authType": auth_type}}}},
    ]
    if a_has_secret:
        res.append({"type": "azurerm_role_assignment", "name": "asec",
                    "values": {"principal_id": "pidA", "role_definition_name": "Key Vault Secrets User", "scope": "/kv"}})
    return {"values": {"root_module": {"resources": res}}}


def main():
    cases = [
        ("escalation (passthrough, A thin)", state("ProjectManagedIdentity", False),
         {"esc": 1, "CP-1": True, "CP-2": True}),
        ("control OBO (AAD)", state("AAD", False),
         {"esc": 0, "CP-1": False, "CP-2": False}),
        ("falsification (A pre-granted)", state("ProjectManagedIdentity", True),
         {"esc": 0, "CP-1": False, "CP-2": False}),
    ]
    ok = True
    for label, st, want in cases:
        f = analyse(st, AGENTS)
        got = {"esc": len(f["escalations"]), "CP-1": f["cp"]["CP-1"], "CP-2": f["cp"]["CP-2"]}
        passed = got == want
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] {label}: got={got} want={want}")
    # CP-4 should hold in every state (B genuinely has a broad role)
    assert analyse(state("AAD", False), AGENTS)["cp"]["CP-4"], "CP-4 should be present"
    print("CP-4 present regardless of passthrough: PASS")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
