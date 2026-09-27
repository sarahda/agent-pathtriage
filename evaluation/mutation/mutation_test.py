#!/usr/bin/env python3
"""
AgentPathTriage — mutation testing + fidelity (v3, closes the propagate loop)

Generates IAM-policy mutants with KNOWN ground truth and scores the real
extract + check (single-hop) AND extract + propagate (multi-hop) against them.

v3 changes over v2:
  - The two-hop PassRole mutant now defines BOTH roles in the state, so the
    delegation edge is genuinely present in the graph. The escalation is
    recovered by real graph traversal, not by a hardcoded verdict.
  - Verdicts are scored per principal-under-test (the role an attacker controls),
    not by unioning over every role, so the single-hop false negative is real.
  - Two scorings are reported side by side: single-hop (check only) and
    multi-hop (check + propagate). The delta is the value `propagate` adds.

Mutant classes:
  - "easy" (wildcard vs own ARN): should be perfectly classified by both.
  - "hard" mutants expose declared boundaries:
      * condition-scoped wildcard  -> OVER-approximation (FP) by design, both modes
      * explicit Deny over wildcard-> Deny un-modelled (FP), both modes
      * foreign specific ARN        -> cross-agent but not a wildcard; MISSED (FN)
                                       by BOTH modes -> still future work (ARN reasoning)
      * PassRole to a second role   -> two-hop; MISSED by single-hop (FN),
                                       RECOVERED by propagate -> the loop closes here

Ground truth is the true IAM outcome, derived independently of the tool.
Runs offline; no deployment or cost.
"""
import json, sys
sys.path.insert(0, "../../agentpathtriage")
import extract as EX
import check as CK
import propagate as PR

ACC = "111122223333"
def arn(s): return s.replace("ACC", ACC)

RES = {
    "ECR images":        ("ecr:BatchGetImage",                     "*",
                          arn("arn:aws:ecr:us-east-1:ACC:repository/own")),
    "Agent memory":      ("bedrock-agentcore:*",                   arn("arn:aws:bedrock-agentcore:us-east-1:ACC:memory/*"),
                          arn("arn:aws:bedrock-agentcore:us-east-1:ACC:memory/own")),
    "Code interpreters": ("bedrock-agentcore:InvokeCodeInterpreter","*",
                          arn("arn:aws:bedrock-agentcore:us-east-1:ACC:code-interpreter/own")),
    "Agent runtimes":    ("bedrock-agentcore:InvokeAgentRuntime",  arn("arn:aws:bedrock-agentcore:us-east-1:ACC:runtime/*"),
                          arn("arn:aws:bedrock-agentcore:us-east-1:ACC:runtime/own")),
}
TYPES = list(RES)
SHORT = {"ECR images":"ecr", "Agent memory":"memory",
         "Code interpreters":"codeint", "Agent runtimes":"runtime"}


def role_res(name):
    return {"type": "aws_iam_role", "name": name,
            "values": {"name": name, "arn": f"arn:aws:iam::{ACC}:role/{name}", "id": name}}

def policy_res(name, statements):
    return {"type": "aws_iam_role_policy", "name": name,
            "values": {"role": name, "policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}}

def single_role_state(mid, statements):
    return {"values": {"root_module": {"resources": [
        role_res(mid), policy_res(mid, [s for s in statements if s])]}}}

def passrole_two_role_state(thin, second):
    """thin can only PassRole/AssumeRole `second`; `second` is over-privileged
    on Agent memory. The two-hop is genuinely in the graph."""
    a_mem, wild_mem, _ = RES["Agent memory"]
    thin_stmts = [
        {"Sid": "PassRoleOnly", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": f"arn:aws:iam::{ACC}:role/{second}"},
        {"Sid": "AssumeRoleOnly", "Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": f"arn:aws:iam::{ACC}:role/{second}"},
    ]
    second_stmts = [{"Sid": "MemWild", "Effect": "Allow", "Action": a_mem, "Resource": wild_mem}]
    return {"values": {"root_module": {"resources": [
        role_res(thin), role_res(second),
        policy_res(thin, thin_stmts), policy_res(second, second_stmts)]}}}


def stmt(rtype, mode):
    a, wild, own = RES[rtype]
    if mode == "wild": return {"Sid": rtype.replace(" ", ""), "Effect": "Allow", "Action": a, "Resource": wild}
    if mode == "own":  return {"Sid": rtype.replace(" ", ""), "Effect": "Allow", "Action": a, "Resource": own}
    return None


def gen():
    """Each entry: (id, state, principal_under_test, ground_truth_set, note)."""
    M = []
    # ---- easy: single resource, own vs wild ----
    for rt in TYPES:
        M.append((f"single_{SHORT[rt]}_wild", single_role_state("m", [stmt(rt,"wild")]), "m", {rt}, "easy"))
        M.append((f"single_{SHORT[rt]}_own",  single_role_state("m", [stmt(rt,"own")]),  "m", set(), "easy"))
    M.append(("all_wild", single_role_state("m", [stmt(t,"wild") for t in TYPES]), "m", set(TYPES), "easy"))
    M.append(("all_own",  single_role_state("m", [stmt(t,"own")  for t in TYPES]), "m", set(),      "easy"))

    # ---- hard 1: condition-scoped wildcard (truly safe, tool over-approximates) ----
    a, wild, _ = RES["Agent memory"]
    cond = {"Sid": "CondScoped", "Effect": "Allow", "Action": a, "Resource": wild,
            "Condition": {"StringEquals": {"aws:PrincipalTag/agent": "own"}}}
    M.append(("hard_condition_scoped", single_role_state("m", [cond]), "m", set(),
              "hard: over-approx (FP by design; conditions un-modelled)"))

    # ---- hard 2: explicit Deny over a wildcard Allow (truly safe) ----
    deny = [{"Sid":"WideAllow","Effect":"Allow","Action":a,"Resource":wild},
            {"Sid":"DenyOthers","Effect":"Deny","Action":a,"Resource":wild}]
    M.append(("hard_explicit_deny", single_role_state("m", deny), "m", set(),
              "hard: Deny un-modelled (FP)"))

    # ---- hard 3: foreign specific ARN (not wildcard, but another agent's) ----
    foreign = {"Sid":"Foreign","Effect":"Allow","Action":a,
               "Resource": arn("arn:aws:bedrock-agentcore:us-east-1:ACC:memory/AGENT-B-victim")}
    M.append(("hard_foreign_specific_arn", single_role_state("m", [foreign]), "m", {"Agent memory"},
              "hard: foreign specific ARN is cross-agent; MISSED (FN) by both -> ARN reasoning future work"))

    # ---- hard 4: PassRole to a privileged second role (two-hop, now real) ----
    M.append(("hard_passrole_two_hop", passrole_two_role_state("m_thin", "privileged_second"),
              "m_thin", {"Agent memory"},
              "hard: two-hop via PassRole; MISSED by single-hop (FN), RECOVERED by propagate"))
    return M


def verdict_check(state, principal):
    G = EX.extract(state)
    return {w["reaches"] for w in CK.witnesses_for(G, principal)}

def verdict_propagate(state, principal):
    G = EX.extract(state)
    reached = set()
    if principal in G:
        for w in PR.analyse(G, principal)["witnesses"]:
            reached.add(w["reaches"])
    return reached


def score(M, verdict_fn, label):
    TP=FP=FN=TN=0; rows=[]
    print(f"\n===== {label} =====")
    for mid, state, principal, truth, note in M:
        got = verdict_fn(state, principal)
        tp=len(got&truth); fp=len(got-truth); fn=len(truth-got); tn=len(set(TYPES)-got-truth)
        TP+=tp;FP+=fp;FN+=fn;TN+=tn
        status = "OK" if got==truth else ("FP" if fp and not fn else ("FN" if fn and not fp else "XX"))
        rows.append({"mutant":mid,"principal":principal,"truth":sorted(truth),
                     "tool":sorted(got),"result":status,"note":note})
        print(f"  [{status:2s}] {mid:26s} truth={sorted(truth)} tool={sorted(got)}")
    prec = TP/(TP+FP) if TP+FP else 1.0
    rec  = TP/(TP+FN) if TP+FN else 1.0
    acc  = (TP+TN)/(TP+FP+FN+TN)
    exact = sum(r["result"]=="OK" for r in rows)
    print(f"  -> mutants={len(M)} exact={exact}/{len(M)}  TP={TP} FP={FP} FN={FN} TN={TN}")
    print(f"  -> precision={prec:.3f} recall={rec:.3f} accuracy={acc:.3f}")
    return {"label":label,"mutants":len(M),"exact":exact,"TP":TP,"FP":FP,"FN":FN,"TN":TN,
            "precision":prec,"recall":rec,"accuracy":acc,"detail":rows}


def main():
    M = gen()
    single = score(M, verdict_check, "single-hop (check only)")
    multi  = score(M, verdict_propagate, "multi-hop (check + propagate)")

    print("\n===== delta (what propagate adds) =====")
    print(f"  recall   {single['recall']:.3f} -> {multi['recall']:.3f}  (+{multi['recall']-single['recall']:.3f})")
    print(f"  accuracy {single['accuracy']:.3f} -> {multi['accuracy']:.3f}  (+{multi['accuracy']-single['accuracy']:.3f})")
    closed = [r["mutant"] for r_s,r_m in zip(single["detail"],multi["detail"])
              for r in [r_m] if r_s["result"]=="FN" and r_m["result"]=="OK"]
    print(f"  false negatives closed by propagate: {closed or 'none'}")
    still = [r["mutant"] for r in multi["detail"] if r["result"] in ("FN","FP")]
    print(f"  errors remaining under multi-hop (honest): {still}")

    json.dump({"single_hop":single,"multi_hop":multi,"fn_closed_by_propagate":closed,
               "remaining_errors":still},
              open("mutation_results.json","w"), indent=2)
    print("\nwritten: mutation_results.json")


if __name__ == "__main__":
    main()
