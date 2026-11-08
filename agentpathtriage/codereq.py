#!/usr/bin/env python3
"""
AgentPathTriage - required permissions from container code (codereq v0)

The configuration says what an agent MAY do. This says what its code appears to
NEED. The difference is the only honest basis for calling a grant unnecessary,
and calling a grant unnecessary is what gets sent to a repository owner. One
false report and the next one is not read, so the error direction here is chosen
deliberately and is the opposite of the rest of the engine.

Error direction. Everywhere else this project over-approximates REACH: it would
rather report a path that something blocks than miss one. Here it
over-approximates NEED: it would rather call a grant necessary than call a
necessary grant unnecessary. An over-grant claim is only made where the evidence
is strong, because that claim is the one that leaves the building.

Why that matters, measured on a real case. The AgentCore weather-agent sample
calls AWS through SDK wrapper classes, not through boto3:

    client = BrowserClient(AWS_REGION);      client.start(...)
    code_client = CodeInterpreter(AWS_REGION); code_client.invoke(...)
    client = MemoryClient(region_name=...);  client.list_events(...)

An extractor that only looks for boto3 finds nothing, concludes the code needs
no permissions, and reports every grant as unnecessary. Every one of those
reports would be wrong. This module therefore treats an unresolved SDK call as
evidence that the namespace IS needed, and suppresses the over-grant verdict for
that whole namespace rather than guessing which action the wrapper issues.

What it reads:
  - boto3 clients and the methods called on them, which map to actions directly
  - AWS SDK wrapper classes, which map to a namespace and a candidate action
  - a generic escape hatch such as the strands `use_aws` tool, which can call
    anything and therefore voids the over-grant verdict for the whole template

Usage:
  python3 codereq.py --template path/to/template
  python3 codereq.py --corpus corpus_tier2 --json codereq.json [--budget 120]
"""
import argparse, ast, collections, glob, json, os, re, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(os.path.dirname(_HERE), "agentpathtriage"),
           os.path.join(os.path.dirname(_HERE), "evaluation", "benchmark"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

CODE_EXT = (".py",)

# boto3 service name to IAM namespace, where they differ. Anything not listed
# is assumed identical, which is true for most services.
SERVICE_TO_NAMESPACE = {
    "bedrock-agent-runtime": "bedrock",
    "bedrock-runtime": "bedrock",
    "bedrock-agentcore-control": "bedrock-agentcore",
}

# SDK wrapper classes that call AWS on the caller's behalf. The value is the IAM
# namespace the wrapper talks to. The specific action is NOT asserted: see
# `unresolved_namespaces`. Keys are class names as imported.
SDK_WRAPPERS = {
    "MemoryClient": "bedrock-agentcore",
    "CodeInterpreter": "bedrock-agentcore",
    "BrowserClient": "bedrock-agentcore",
    "GatewayClient": "bedrock-agentcore",
    "IdentityClient": "bedrock-agentcore",
    "BedrockAgentCoreApp": "bedrock-agentcore",
}

# Tools that hand the model an arbitrary AWS call. Their presence means no
# over-grant verdict can be made for the template at all, because the set of
# actions the agent may issue is decided by the model at run time, not by the
# source. Saying otherwise would be guessing.
GENERIC_AWS_TOOLS = ("use_aws", "AWSTool", "aws_cli", "boto3_tool")

SNAKE = re.compile(r"_([a-z0-9])")


def to_pascal(method):
    """list_events -> ListEvents. The AWS API name is the Pascal form."""
    return SNAKE.sub(lambda m: m.group(1).upper(), method[:1].upper() + method[1:])


class Visitor(ast.NodeVisitor):
    """Collect boto3 clients, SDK wrapper instances and the methods called."""

    def __init__(self):
        self.client_vars = {}        # var name -> namespace
        self.wrapper_vars = {}       # var name -> namespace
        self.actions = set()         # "svc:Action" we are confident about
        self.unresolved = set()      # namespaces reached through a wrapper
        self.generic = set()         # generic AWS escape hatches seen
        self.imports = set()

    def visit_Import(self, node):
        for a in node.names:
            self.imports.add(a.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for a in node.names:
            self.imports.add(a.name)
            if a.name in GENERIC_AWS_TOOLS:
                self.generic.add(a.name)
        self.generic_visit(node)

    @staticmethod
    def _str_arg(node, idx=0, kw=None):
        if kw:
            for k in node.keywords:
                if k.arg == kw and isinstance(k.value, ast.Constant):
                    return k.value.value
        if len(node.args) > idx and isinstance(node.args[idx], ast.Constant):
            return node.args[idx].value
        return None

    def visit_Assign(self, node):
        tgt = node.targets[0] if node.targets else None
        name = tgt.id if isinstance(tgt, ast.Name) else None
        call = node.value if isinstance(node.value, ast.Call) else None
        if name and call:
            fn = call.func
            # boto3.client("s3") / session.client("s3")
            if isinstance(fn, ast.Attribute) and fn.attr in ("client", "resource"):
                svc = self._str_arg(call, 0, "service_name")
                if isinstance(svc, str):
                    self.client_vars[name] = SERVICE_TO_NAMESPACE.get(svc, svc)
            # MemoryClient(...) etc
            cls = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if cls in SDK_WRAPPERS:
                self.wrapper_vars[name] = SDK_WRAPPERS[cls]
        self.generic_visit(node)

    def visit_Call(self, node):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id in GENERIC_AWS_TOOLS:
            self.generic.add(fn.id)
        if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
            var, meth = fn.value.id, fn.attr
            if var in self.client_vars and not meth.startswith("_"):
                self.actions.add(f"{self.client_vars[var]}:{to_pascal(meth)}")
            elif var in self.wrapper_vars and not meth.startswith("_"):
                # A wrapper method is not an API name. `CodeInterpreter.invoke`
                # issues InvokeCodeInterpreter, not Invoke. The namespace is
                # certain, the action is not, so only the namespace is recorded
                # and the over-grant verdict for it is suppressed.
                self.unresolved.add(self.wrapper_vars[var])
        self.generic_visit(node)


def scan_code(paths):
    v = Visitor()
    parsed, failed = 0, 0
    for p in paths:
        try:
            tree = ast.parse(open(p, encoding="utf-8", errors="ignore").read())
        except Exception:
            failed += 1
            continue
        parsed += 1
        v.visit(tree)
        # a generic tool may be referenced only as a bare name in a tool list
        try:
            text = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            text = ""
        for g in GENERIC_AWS_TOOLS:
            if re.search(rf"\b{re.escape(g)}\b", text):
                v.generic.add(g)
    return v, parsed, failed


def code_files(template_dir):
    out = []
    for ext in CODE_EXT:
        out.extend(glob.glob(os.path.join(template_dir, "**", f"*{ext}"), recursive=True))
    # a test file states what the code may do, not what it does in production
    return sorted(p for p in out
                  if not os.path.basename(p).startswith("test_")
                  and f"{os.sep}tests{os.sep}" not in p)


def granted_actions(template_dir):
    """Agentcore-namespace actions the template's roles grant, and the actions
    the configuration itself shows in use.

    The second return value exists because code is not the only evidence of
    use. When the deployment declares a hand-off, by giving one agent another
    agent's ARN, the invoke action is used by the deployment whether or not
    this analysis can see the call in the container code. Treating it as
    unnecessary because no `invoke_agent_runtime(` appears in a parsed file
    would produce exactly the false over-grant report the disclosure gate
    exists to prevent: in avparkhi/agui-agentcore-demo the configuration wires
    agui to mcp and the code reaches it in a way this pass does not resolve.
    """
    import tf_to_state as T, extract_graph as X
    state, _ = T.to_state(template_dir)
    G, ix = X.build(state)
    out = collections.defaultdict(set)
    for name in list(ix.kind):
        for s in ix.statements(name):
            if not s.is_allow:
                continue
            for a in s.actions:
                if ":" in a:
                    out[name].add(a)

    # a declared hand-off is the configuration saying this agent calls that one
    used = set()
    for a, b, d in G.edges(data=True):
        if d.get("rel") != "handoff":
            continue
        if not str(d.get("evidence", "")).startswith("declared"):
            continue
        meta = getattr(ix, "agent_meta", {}).get(b) or {}
        for act in X.invoke_actions_for(meta.get("type")):
            used.add(act)
    return out, used


def assess(template_dir, code_root=None):
    """Assess one template. Grants always come from the template's own
    Terraform; code is read from code_root, which defaults to the template.

    The default is colocation, and the published prevalence number depends on
    it: a repository that keeps Terraform in terraform/ and agent code in
    agent/ has no colocated code, and saying so is the measurement. A
    disclosure gate wants the other scope, because the maintainer's code is in
    the same repository whatever directory it sits in. code_root lets the gate
    widen without moving the measurement.
    """
    files = code_files(code_root or template_dir)
    v, parsed, failed = scan_code(files)
    try:
        granted, used_by_config = granted_actions(template_dir)
    except Exception as e:
        return {"template": template_dir, "error": f"{type(e).__name__}: {e}"}

    all_granted = set().union(*granted.values()) if granted else set()
    ac_granted = {a for a in all_granted if a.lower().startswith("bedrock-agentcore:")}

    # the configuration's own evidence of use counts the same as the code's
    required = set(v.actions) | set(used_by_config)
    unresolved_ns = set(v.unresolved)
    generic = sorted(v.generic)

    # An action is only called unnecessary when: the code was readable, nothing
    # generic can issue arbitrary calls, and no unresolved wrapper touches its
    # namespace. Anything else leaves the verdict open rather than guessing.
    verdict_possible = bool(files) and parsed > 0 and not generic
    over = set()
    if verdict_possible:
        for a in ac_granted:
            ns = a.split(":", 1)[0].lower()
            if ns in unresolved_ns:
                continue
            if a not in required:
                over.add(a)

    # The other direction, which costs nothing to report and is informative:
    # the code names an action in a namespace the configuration never grants.
    under = {a for a in required
             if a.split(":", 1)[0].lower() == "bedrock-agentcore"
             and a not in ac_granted}

    return {
        "template": template_dir,
        "code_root": os.path.abspath(code_root or template_dir),
        "code_scope": "repository" if code_root else "colocated",
        "code_files": len(files),
        "parsed": parsed,
        "parse_failed": failed,
        "required_actions": sorted(required),
        "required_by_configuration": sorted(used_by_config),
        "unresolved_namespaces": sorted(unresolved_ns),
        "generic_aws_tools": generic,
        "granted_agentcore": sorted(ac_granted),
        "over_granted": sorted(over),
        "under_granted": sorted(under),
        "verdict_possible": verdict_possible,
        "why_no_verdict": (("no code in the repository" if code_root
                            else "no code colocated") if not files else
                           "code did not parse" if parsed == 0 else
                           f"generic AWS tool present: {generic}" if generic else None),
    }


def report_one(r):
    print(f"template: {r['template']}")
    if "error" in r:
        print(f"  ERROR {r['error']}")
        return
    print(f"  code files: {r['code_files']}  parsed: {r['parsed']}  "
          f"failed: {r['parse_failed']}  scope: {r.get('code_scope', 'colocated')}")
    print(f"  required from code      : {r['required_actions'] or '-'}")
    print(f"  namespaces via SDK wrapper, specific action unknown: "
          f"{r['unresolved_namespaces'] or '-'}")
    print(f"  generic AWS escape hatch: {r['generic_aws_tools'] or '-'}")
    print(f"  granted (agentcore)     : {r['granted_agentcore'] or '-'}")
    if r["verdict_possible"]:
        print(f"  OVER-GRANTED (safe to report): {r['over_granted'] or 'none'}")
    else:
        print(f"  OVER-GRANT VERDICT WITHHELD: {r['why_no_verdict']}")
    if r["under_granted"]:
        print(f"  under-granted (code needs, config omits): {r['under_granted']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template")
    ap.add_argument("--code-root", dest="code_root",
                    help="where to look for container code. Defaults to the "
                         "template, which is the colocation measure. Point it "
                         "at the repository for a disclosure gate, where the "
                         "question is what the maintainer's code does rather "
                         "than where they keep it.")
    ap.add_argument("--corpus")
    ap.add_argument("--json")
    ap.add_argument("--cache")
    ap.add_argument("--budget", type=float, default=0)
    a = ap.parse_args()

    if a.template:
        r = assess(a.template, a.code_root)
        report_one(r)
        if a.json:
            json.dump([r], open(a.json, "w"), indent=2)
        return 0

    if not a.corpus:
        ap.error("give --template or --corpus")

    import time
    cache = a.cache or (a.json or "codereq") + ".cache.jsonl"
    deadline = time.time() + a.budget if a.budget else None
    done = set()
    if os.path.exists(cache):
        for ln in open(cache):
            try:
                d = json.loads(ln)
            except Exception:
                continue
            if d.get("_repo_done"):
                done.add(d["_repo_done"])

    repos = sorted(x for x in os.listdir(a.corpus)
                   if os.path.isdir(os.path.join(a.corpus, x)))
    todo = [r for r in repos if r not in done]
    out = open(cache, "a")
    RUNTIME = re.compile(r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"')
    for repo in todo:
        if deadline and time.time() > deadline:
            out.close()
            print(f"budget reached: {len(done)}/{len(repos)} repositories cached, "
                  f"run again to continue", file=sys.stderr)
            print("INCOMPLETE")
            return 1
        root = os.path.join(a.corpus, repo)
        dirs = sorted({os.path.dirname(p)
                       for p in glob.glob(os.path.join(root, "**", "*.tf"), recursive=True)
                       if os.sep + ".terraform" + os.sep not in p})
        for d in dirs:
            try:
                txt = "\n".join(open(f, encoding="utf-8", errors="ignore").read()
                                for f in sorted(glob.glob(os.path.join(d, "*.tf"))))
            except Exception:
                continue
            if not RUNTIME.search(txt):
                continue
            if not code_files(d):
                continue
            r = assess(d)
            r["template"] = os.path.relpath(d, a.corpus)
            out.write(json.dumps(r) + "\n")
        out.write(json.dumps({"_repo_done": repo}) + "\n")
        out.flush()
        done.add(repo)
    out.close()

    rows = []
    for ln in open(cache):
        try:
            d = json.loads(ln)
        except Exception:
            continue
        if not d.get("_repo_done"):
            rows.append(d)

    ok = [r for r in rows if "error" not in r]
    withheld = [r for r in ok if not r["verdict_possible"]]
    reportable = [r for r in ok if r["verdict_possible"] and r["over_granted"]]
    clean = [r for r in ok if r["verdict_possible"] and not r["over_granted"]]
    under = [r for r in ok if r["under_granted"]]

    print(f"templates with colocated code : {len(rows)}  (errors {len(rows) - len(ok)})")
    print(f"over-grant verdict possible   : {len(ok) - len(withheld)}/{len(ok)}")
    print(f"   of those, over-granted     : {len(reportable)}")
    print(f"   of those, nothing to report: {len(clean)}")
    print(f"verdict withheld              : {len(withheld)}")
    why = collections.Counter(r["why_no_verdict"].split(":")[0] for r in withheld)
    for k, n in why.most_common():
        print(f"   {k}: {n}")
    print(f"code needs what config omits  : {len(under)}")
    print("\nsafe to report (over-granted, no escape hatch, no unresolved wrapper):")
    for r in sorted(reportable, key=lambda x: -len(x["over_granted"]))[:20]:
        print(f"   {r['template'][:66]:68s} {len(r['over_granted'])} action(s)")
    if a.json:
        json.dump(rows, open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")
    print("COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
