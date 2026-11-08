#!/usr/bin/env python3
"""C1: does the container code show hand-offs the configuration does not?

The prevalence number so far is configuration-only: a template declares a
hand-off when one agent is given another agent's ARN, and that is 6 of 220.
The honest question a reviewer asks is how much that undercounts, because a
hand-off can also live entirely in the container code.

This produces the two ends of that interval rather than a single number.

  confirmed      the configuration declares the hand-off AND the code reads
                 the variable that carries it. Both layers agree.
  config only    declared in Terraform, nothing in the code reads it. Either
                 the code is not in this repository, or the wiring is unused.
  code only      the code invokes an agent runtime, or reads a variable whose
                 name says it holds an agent ARN, and the configuration
                 declares no hand-off for that agent. This is what a
                 configuration-only count misses.

The link between the two layers is the environment variable name. Terraform
declares it on the runtime resource and extract_graph already records it on
the hand-off edge; the code reads it by that same name. Matching on the name
is exact where it fires, which is why it is preferred over guessing from
directory layout.

Code is searched across the whole repository, not only the Terraform
directory. Measured on the 220-template corpus, 15.0 percent of templates have
Python beside the Terraform and 92.7 percent have it somewhere in the
repository, so searching only the template directory would miss most of the
code that exists.

Withholding, in the same spirit as codereq: a repository with no Python at all
yields no verdict rather than a zero, because absent evidence is not evidence
of absence.

Usage:
    python3 agentpathtriage/handoff_code.py --corpus corpus_tier2 --json c1.json
    python3 agentpathtriage/handoff_code.py --corpus corpus_tier2 --all
"""

import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _p in (HERE, os.path.join(ROOT, "evaluation", "benchmark")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# An env var name that says it carries another agent's address. A name has to
# mention an agent, a runtime or an MCP server AND an address.
#
# ID is not an address. Allowing it swept in CLIENT_ID, SECRET_ID, MEMORY_ID
# and KEY_KID, which are credentials and memory handles rather than hand-off
# targets, and inflated the upper end of the interval. The exclusion list
# below removes the rest of that family, so what remains is a name that says
# it holds the address of another agent.
# The prefix is optional. Requiring at least one character before the keyword
# dropped every name that starts with it, MCP_SERVER_ARN among them, which
# under-counted the upper bound rather than inflating it.
ARN_VAR = re.compile(
    r"\b([A-Z0-9_]*(?:AGENT|RUNTIME|MCP)[A-Z0-9_]*"
    r"(?:ARN|URL|URI|ENDPOINT)[A-Z0-9_]*)\b")
NOT_AN_ADDRESS = re.compile(r"CLIENT|SECRET|KEY|TOKEN|MEMORY|REDIRECT|AUTHORIZATION")

# A role is not an agent. FRONTIER_AGENTS_FEDERATION_ROLE_ARN matched the
# address pattern and is a role, so it is excluded by name.
ROLE_NOT_AGENT = re.compile(r"ROLE_ARN")

# Does the name say WHICH agent, or only that it is an agent runtime?
#
# A variable that names the callee, WEATHER_AGENT_RUNTIME_URL or
# SUPERVISOR_AGENT_ARN, points at another agent. A generic one,
# AGENT_RUNTIME_ARN or AGENTCORE_RUNTIME_URL, is in 184 single-agent
# templates in this corpus and is almost always the template's own address
# exported for whoever calls it. Counting the generic ones as hand-offs put
# the upper bound at 44.6 percent when the evidence does not support it.
GENERIC_ADDRESS = re.compile(
    r"^(?:BEDROCK_)?AGENT(?:CORE)?S?_?(?:RUNTIME_)?"
    r"(?:ARN|URL|URI|ENDPOINT)$")


def names_a_callee(var):
    """True when the variable name identifies a particular agent."""
    if NOT_AN_ADDRESS.search(var) or ROLE_NOT_AGENT.search(var):
        return False
    if not ARN_VAR.fullmatch(var):
        return False
    return not GENERIC_ADDRESS.match(var)

# Reading an environment variable, by any of the usual spellings.
ENV_READ = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\s*\(\s*)["']([A-Za-z_][A-Za-z0-9_]*)["']""")

# Invoking an agent runtime, through boto3 or a thin wrapper over it.
INVOKE_CALL = re.compile(
    r"\b(?:invoke_agent_runtime|invokeAgentRuntime|InvokeAgentRuntime|"
    r"invoke_agent|invokeAgent)\s*\(")

SKIP_DIRS = (os.sep + ".terraform" + os.sep, os.sep + ".git" + os.sep,
             os.sep + "node_modules" + os.sep, os.sep + "tests" + os.sep)


def py_files(root):
    out = []
    for p in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
        if any(s in p for s in SKIP_DIRS):
            continue
        if os.path.basename(p).startswith("test_"):
            continue
        out.append(p)
    return sorted(out)


def read_repo(repo_dir):
    """Env vars the code reads, and whether it invokes an agent runtime."""
    env_read, invokes, n = set(), 0, 0
    for p in py_files(repo_dir):
        try:
            t = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        n += 1
        env_read |= set(ENV_READ.findall(t))
        invokes += len(INVOKE_CALL.findall(t))
    return {"py_files": n, "env_read": env_read, "invoke_calls": invokes}


def declared_handoffs(template_dir):
    """Hand-off edges the configuration declares, with the variable each uses."""
    import tf_to_state as T, extract_graph as X
    state, _ = T.to_state(template_dir)
    G, ix = X.build(state)
    out = []
    agents = set()
    for n, d in G.nodes(data=True):
        if d.get("kind") == "agent" or n in getattr(ix, "agent_meta", {}):
            agents.add(n)
    for a, b, d in G.edges(data=True):
        if d.get("rel") != "handoff":
            continue
        if not str(d.get("evidence", "")).startswith("declared"):
            continue
        # extract_graph records it as via_variable; reading d["var"] silently
        # produced None for every edge and made "confirmed" always zero
        out.append({"from": a, "to": b, "evidence": d.get("evidence"),
                    "var": d.get("via_variable")})
    return out, sorted(agents)


def classify(template_dir, code):
    """code is the repository scan from read_repo, passed in so one
    repository is read once however many templates it holds."""
    try:
        declared, agents = declared_handoffs(template_dir)
    except Exception as e:
        return {"template": template_dir, "error": f"{type(e).__name__}: {e}"}

    if code["py_files"] == 0:
        return {"template": template_dir, "agents": len(agents),
                "declared": len(declared), "py_files": 0,
                "verdict_possible": False,
                "why_no_verdict": "no python in the repository",
                "confirmed": None, "config_only": None, "code_only": None}

    env_read = code["env_read"]
    confirmed, config_only = [], []
    declared_vars = set()
    for h in declared:
        v = h.get("var")
        if v:
            declared_vars.add(v)
        (confirmed if v and v in env_read else config_only).append(h)

    # a variable the code reads whose name says it holds an agent address,
    # and which no declared hand-off accounts for
    code_only = sorted({v for v in env_read
                        if names_a_callee(v) and v not in declared_vars})
    generic_only = sorted({v for v in env_read
                           if ARN_VAR.fullmatch(v)
                           and not NOT_AN_ADDRESS.search(v)
                           and not ROLE_NOT_AGENT.search(v)
                           and GENERIC_ADDRESS.match(v)
                           and v not in declared_vars})

    return {
        "template": template_dir,
        "agents": len(agents),
        "py_files": code["py_files"],
        "invoke_calls": code["invoke_calls"],
        "declared": len(declared),
        "verdict_possible": True,
        "why_no_verdict": None,
        "confirmed": [h["var"] for h in confirmed],
        "config_only": [h["var"] or "<no variable recorded>" for h in config_only],
        "code_only": code_only,
        # kept separately rather than discarded: a generic address is weak
        # evidence, not no evidence, and a reader can see how much was set
        # aside and why
        "generic_address_only": generic_only,
    }


def population(corpus, bench):
    """Templates worth asking about: two or more agents, or a declared
    hand-off. A single-agent template with no declaration has no in-template
    hand-off to find, and counting it would only pad the denominator."""
    topo = json.load(open(os.path.join(bench, "topology_tier2.json")))
    out = []
    for r in topo:
        if "err" in r:
            continue
        if (r.get("n_agents") or 0) >= 2 or r.get("handoffs"):
            out.append(r["t"])
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--json")
    ap.add_argument("--limit", type=int, default=0,
                    help="first N templates of the population, for a pilot")
    ap.add_argument("--all", action="store_true",
                    help="every template, not only multi-agent ones")
    a = ap.parse_args()

    corpus = os.path.abspath(a.corpus)
    bench = os.path.join(ROOT, "evaluation", "benchmark")
    if a.all:
        topo = json.load(open(os.path.join(bench, "topology_tier2.json")))
        pop = sorted(r["t"] for r in topo if "err" not in r)
    else:
        pop = population(corpus, bench)
    if a.limit:
        pop = pop[:a.limit]

    # One repository holds many templates, and reading its Python once per
    # template turns a minutes-long pass into an hours-long one.
    rows, cache = [], {}
    for t in pop:
        repo = t.split("/")[0]
        if repo not in cache:
            cache[repo] = read_repo(os.path.join(corpus, repo))
        r = classify(os.path.join(corpus, t), cache[repo])
        r["template_rel"] = t
        rows.append(r)

    ok = [r for r in rows if r.get("verdict_possible")]
    withheld = [r for r in rows if not r.get("verdict_possible") and "error" not in r]
    errs = [r for r in rows if "error" in r]

    n_conf = sum(len(r["confirmed"]) for r in ok)
    n_cfg = sum(len(r["config_only"]) for r in ok)
    n_code = sum(len(r["code_only"]) for r in ok)
    t_conf = sum(1 for r in ok if r["confirmed"])
    t_cfg = sum(1 for r in ok if r["config_only"])
    t_code = sum(1 for r in ok if r["code_only"])

    print(f"population                      : {len(pop)} templates")
    print(f"  verdict possible              : {len(ok)}")
    print(f"  withheld (no python in repo)  : {len(withheld)}")
    print(f"  errored                       : {len(errs)}")
    print()
    print("hand-off edges, by where the evidence is:")
    print(f"  confirmed in config and code  : {n_conf}   ({t_conf} template(s))")
    print(f"  config only                   : {n_cfg}   ({t_cfg} template(s))")
    print(f"  code only                     : {n_code}   ({t_code} template(s))")
    print()
    print("templates with any hand-off evidence:")
    lo = t_conf + t_cfg
    hi = sum(1 for r in ok if r["confirmed"] or r["config_only"] or r["code_only"])
    print(f"  configuration alone           : {lo}")
    print(f"  configuration or code         : {hi}")
    if len(ok):
        print(f"  interval over the {len(ok)} with a verdict: "
              f"{lo / len(ok) * 100:.1f}% to {hi / len(ok) * 100:.1f}%")
    print()
    for r in ok:
        if r["confirmed"] or r["config_only"] or r["code_only"]:
            print(f"  {r['template_rel'][:66]:<66} "
                  f"conf={r['confirmed']} cfg_only={r['config_only']} "
                  f"code_only={r['code_only']}")

    if a.json:
        json.dump({"population": len(pop), "verdict_possible": len(ok),
                   "withheld": len(withheld), "errored": len(errs),
                   "edges": {"confirmed": n_conf, "config_only": n_cfg,
                             "code_only": n_code},
                   "templates": {"confirmed": t_conf, "config_only": t_cfg,
                                 "code_only": t_code,
                                 "config_alone": lo, "config_or_code": hi},
                   "rows": rows}, open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
