#!/usr/bin/env python3
"""
AgentPathTriage — mutation testing + fidelity (v2, adversarial)

Generates IAM-policy mutants with KNOWN ground truth and scores the real
extract+check against them. v2 adds hard mutants that the current tool can get
wrong, so the numbers are honest and the failures are informative:

  - "easy" mutants (wildcard vs own ARN): should be perfectly classified.
  - "hard" mutants expose the tool's declared boundaries:
      * condition-scoped wildcard  -> tool OVER-approximates (FP) by design
                                       (conditions are un-modelled; see act-scope.md)
      * explicit Deny over wildcard-> tool should suppress (tests Deny handling)
      * foreign specific ARN        -> not a wildcard, but reaches another agent;
                                       tool MISSES it (FN) -> motivates richer ARN reasoning
      * PassRole to a second role   -> a two-hop escalation the single-hop tool
                                       CANNOT see (FN) -> motivates `propagate`

Ground truth is the true IAM outcome of each mutation, derived independently of
the tool. FP/FN are real errors (or declared over-approximations), not hidden.
Runs offline; no deployment or cost.
"""
import json, sys
sys.path.insert(0, "../../agentpathtriage")
import extract as EX
import check as CK

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


def state_from(statements, mid):
    return {"values": {"root_module": {"resources": [
        {"type": "aws_iam_role", "name": mid,
         "values": {"name": mid, "arn": f"arn:aws:iam::{ACC}:role/{mid}", "id": mid}},
        {"type": "aws_iam_role_policy", "name": mid,
         "values": {"role": mid, "policy": json.dumps({"Version": "2012-10-17", "Statement": statements})}},
    ]}}}


def stmt(rtype, mode):
    a, wild, own = RES[rtype]
    if mode == "wild": return {"Sid": rtype.replace(" ", ""), "Effect": "Allow", "Action": a, "Resource": wild}
    if mode == "own":  return {"Sid": rtype.replace(" ", ""), "Effect": "Allow", "Action": a, "Resource": own}
    return None


def gen():
    """Each entry: (id, statements, ground_truth_set, note)."""
    M = []
    # ---- easy: single resource, own vs wild vs absent ----
    for rt in TYPES:
        M.append((f"single_{rt.split()[0]}_wild", [stmt(rt,"wild")], {rt}, "easy"))
        M.append((f"single_{rt.split()[0]}_own",  [stmt(rt,"own")],  set(), "easy"))
    M.append(("all_wild", [stmt(t,"wild") for t in TYPES], set(TYPES), "easy"))
    M.append(("all_own",  [stmt(t,"own")  for t in TYPES], set(),      "easy"))

    # ---- hard 1: condition-scoped wildcard (truly safe, tool over-approximates) ----
    a, wild, _ = RES["Agent memory"]
    cond = {"Sid": "CondScoped", "Effect": "Allow", "Action": a, "Resource": wild,
            "Condition": {"StringEquals": {"aws:PrincipalTag/agent": "own"}}}
    # ground truth: condition restricts to own -> NOT cross-agent
    M.append(("hard_condition_scoped", [cond], set(), "hard: tool should over-approx (FP by design)"))

    # ---- hard 2: explicit Deny over a wildcard Allow (truly safe) ----
    deny = [ {"Sid":"WideAllow","Effect":"Allow","Action":a,"Resource":wild},
             {"Sid":"DenyOthers","Effect":"Deny","Action":a,"Resource":wild} ]
    M.append(("hard_explicit_deny", deny, set(), "hard: Deny should suppress (tests Deny handling)"))

    # ---- hard 3: foreign specific ARN (not wildcard, but another agent's) ----
    foreign = {"Sid":"Foreign","Effect":"Allow","Action":a,
               "Resource": arn("arn:aws:bedrock-agentcore:us-east-1:ACC:memory/AGENT-B-victim")}
    # ground truth: this DOES reach another agent's memory -> cross-agent
    M.append(("hard_foreign_specific_arn", [foreign], {"Agent memory"},
              "hard: foreign specific ARN is cross-agent; tool likely MISSES (FN)"))

    # ---- hard 4: PassRole to a privileged second role (two-hop) ----
    passrole = {"Sid":"PassRole","Effect":"Allow","Action":"iam:PassRole",
                "Resource": arn("arn:aws:iam::ACC:role/privileged-second-role")}
    # ground truth: this is an escalation (obtain a stronger role) -> should be flagged
    M.append(("hard_passrole_two_hop", [passrole], {"(second role via PassRole)"},
              "hard: two-hop via PassRole; single-hop tool CANNOT see it (FN) -> needs propagate"))

    return M


def tool_verdict(state):
    G = EX.extract(state)
    reached = set()
    for r in CK.roles_in(G):
        for w in CK.witnesses_for(G, r):
            reached.add(w["reaches"])
    return reached


def main():
    M = gen()
    TP=FP=FN=TN=0
    rows=[]
    universe = set(TYPES) | {"(second role via PassRole)"}
    for mid, stmts, truth, note in M:
        got = tool_verdict(state_from([s for s in stmts if s], mid))
        tp=len(got&truth); fp=len(got-truth); fn=len(truth-got)
        tn=len(universe-got-truth)
        TP+=tp;FP+=fp;FN+=fn;TN+=tn
        status = "OK " if got==truth else ("FP " if fp and not fn else ("FN " if fn and not fp else "XX"))
        rows.append({"mutant":mid,"class":note.split(":")[0],"truth":sorted(truth),
                     "tool":sorted(got),"result":status.strip(),"note":note})
        print(f"  [{status}] {mid:26s} truth={sorted(truth)} tool={sorted(got)}")
        if status.strip()!="OK": print(f"        -> {note}")

    prec = TP/(TP+FP) if TP+FP else 1.0
    rec  = TP/(TP+FN) if TP+FN else 1.0
    acc  = (TP+TN)/(TP+FP+FN+TN)
    exact = sum(r["result"]=="OK" for r in rows)
    print(f"\nmutants: {len(M)}   exactly-correct: {exact}/{len(M)}")
    print(f"per-edge  TP={TP} FP={FP} FN={FN} TN={TN}")
    print(f"precision={prec:.3f}  recall={rec:.3f}  accuracy={acc:.3f}")
    print("\nInterpretation:")
    print(" - FP on hard_condition_scoped = declared over-approximation (act-scope.md), not a bug")
    print(" - FN on hard_foreign_specific_arn = ARN reasoning gap -> future work")
    print(" - FN on hard_passrole_two_hop = single-hop limit -> motivates `propagate` (the core)")

    json.dump({"mutants":len(M),"exactly_correct":exact,"precision":prec,"recall":rec,
               "accuracy":acc,"TP":TP,"FP":FP,"FN":FN,"TN":TN,"detail":rows},
              open("mutation_results.json","w"), indent=2)
    print("\nwritten: mutation_results.json")


if __name__ == "__main__":
    main()
