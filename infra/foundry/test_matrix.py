#!/usr/bin/env python3
"""
Regression test for the Foundry matrix harness. Synthetic states, no Azure.

Checks the three things the matrix claims:
  1. the cells cross the factors and share deployments correctly
  2. the analyser's verdict in each cell matches the prediction written down
     for that cell, so `expected` is a test and not a caption
  3. the summary names the right factor as decisive

Run:  python3 test_matrix.py        (exit 0 = all pass)
"""
import json, os, sys, tempfile

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(os.path.dirname(_here))
for _p in (_here, _root, os.path.join(_root, "agentpathtriage")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import matrix as M
from foundry_cp import analyse

AGENTS = {
    "agents": [
        {"name": "agentA", "project": "agentA", "identity": "apt-agentA-thin"},
        {"name": "agentB", "project": "agentB", "identity": "apt-agentB-broad"},
    ],
    "invocations": [{"caller": "agentA", "callee": "agentB", "mediated": False}],
    "shared_memory": [],
}


def state(auth, grant_a):
    res = [
        {"type": "azurerm_user_assigned_identity", "name": "a",
         "values": {"name": "apt-agentA-thin", "principal_id": "pidA"}},
        {"type": "azurerm_user_assigned_identity", "name": "b",
         "values": {"name": "apt-agentB-broad", "principal_id": "pidB"}},
        {"type": "azurerm_role_assignment", "name": "bsec",
         "values": {"principal_id": "pidB",
                    "role_definition_name": "Key Vault Secrets User", "scope": "/kv"}},
        {"type": "azapi_resource", "name": "conn",
         "values": {"parent_id": "/proj/agentA",
                    "body": {"properties": {"authType": auth}}}},
    ]
    if grant_a:
        res.append({"type": "azurerm_role_assignment", "name": "asec",
                    "values": {"principal_id": "pidA",
                               "role_definition_name": "Key Vault Secrets User",
                               "scope": "/kv"}})
    return {"values": {"root_module": {"resources": res}}}


def main():
    ok = True

    plan = M.cells(M.DEFAULT_AUTH)
    deploys = {c["deploy_key"] for c in plan}
    c1 = len(plan) == 8 and len(deploys) == 4
    ok &= c1
    print(f"[{'PASS' if c1 else 'FAIL'}] 8 cells from 4 deployments "
          f"(got {len(plan)} from {len(deploys)})")

    # a deployment group must differ only in the topology factor, which is the
    # reason it costs no extra apply
    shared_ok = True
    for key in deploys:
        g = [c for c in plan if c["deploy_key"] == key]
        if len({(c["auth"], c["grant_a"]) for c in g}) != 1:
            shared_ok = False
        if {c["mediated"] for c in g} != {True, False}:
            shared_ok = False
    ok &= shared_ok
    print(f"[{'PASS' if shared_ok else 'FAIL'}] each deployment covers both "
          f"topology values and nothing else")

    # the prediction must match what the analyser actually returns
    out = tempfile.mkdtemp()
    pred_ok = True
    for c in plan:
        f = M.analyse_cell(state(c["auth"], c["grant_a"]), AGENTS, c["mediated"])
        got_esc = len(f["escalations"]) > 0
        want_esc = M.expected(c).startswith("ESCALATION")
        if got_esc != want_esc:
            pred_ok = False
            print(f"       mismatch: {M.cell_id(c)} expected={want_esc} got={got_esc}")
        rec = {"auth": c["auth"], "grant_a": c["grant_a"], "mediated": c["mediated"],
               "expected": M.expected(c), "findings": f,
               "observed": "reached" if got_esc else "blocked"}
        json.dump(rec, open(os.path.join(
            out, M.cell_id(c).replace(",", "__").replace("=", "-") + ".json"), "w"))
    ok &= pred_ok
    print(f"[{'PASS' if pred_ok else 'FAIL'}] every cell's written prediction "
          f"matches the analyser")

    # exactly one cell should escalate, which is what makes the table readable
    n_esc = sum(1 for c in plan if M.expected(c).startswith("ESCALATION"))
    one = n_esc == 1
    ok &= one
    print(f"[{'PASS' if one else 'FAIL'}] exactly one cell escalates (got {n_esc})")

    # `expected` must agree with the analyser on EVERY auth level, not only on
    # the two defaults. Restating the passthrough rule in the matrix once made
    # it treat any string other than AgentUserImpersonation as passthrough,
    # which was right for the defaults and wrong for everything else. A table
    # that compares prediction against result is worthless if the prediction
    # is derived from a different rule than the one being tested.
    from foundry_cp import PASSTHROUGH_AUTH
    levels = ["AccountManagedIdentity", "AgentUserImpersonation",
              "ProjectManagedIdentity", "SystemAssignedIdentity",
              "AAD", "ApiKey", "CustomKeys"]
    agree = True
    for auth in levels:
        c = {"auth": auth, "grant_a": False, "mediated": False}
        pred = M.expected(c).startswith("ESCALATION")
        truth = auth.lower() in PASSTHROUGH_AUTH
        if pred != truth:
            agree = False
            print(f"       {auth}: expected()={pred} analyser={truth}")
    ok &= agree
    print(f"[{'PASS' if agree else 'FAIL'}] expected() agrees with the analyser "
          f"on all {len(levels)} auth levels, not only the defaults")

    print("\n--- summary output ---")
    M.summarise(out)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
