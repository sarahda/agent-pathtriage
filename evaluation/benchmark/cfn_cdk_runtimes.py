#!/usr/bin/env python3
"""How many agent runtimes are declared outside Terraform, and do any share a role?

Why this exists. The shared-role and delegation results are computed over
Terraform only, so the population in which a cross-agent chain is even possible
is 18 projects, and nothing was found in it. Zero out of eighteen bounds the
true rate at 15.3 percent with 95 percent confidence, which is a weak bound. A
reviewer is right to say eighteen is too small to conclude from, and the honest
fix is to enlarge the population rather than to argue about it.

CloudFormation and CDK are where the rest of it is. Both declare the same fact
the Terraform analysis depends on:

  AWS::BedrockAgentCore::Runtime has a RoleArn property
  https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html

  aws_bedrockagentcore.CfnRuntime has roleArn / role_arn
  https://constructs.dev/packages/aws-cdk-lib/v/2.275.0/api/CfnRuntime

So two runtimes carrying the same role is declarable, and detectable, in both.

The two are not equally reliable and are reported separately rather than added
together.

CloudFormation is exact. The resource type is named in the template and the
role is a property of it, so two runtimes sharing a role is a comparison of two
property values. Intrinsic functions are normalised so that the YAML short form
and the JSON long form of the same reference compare equal.

CDK is heuristic. The role is an expression in a program, and this reads the
source rather than synthesising it. Two call sites passing the same expression
text are treated as sharing; two passing different text as not sharing; a call
site whose role argument cannot be located is undecidable and is counted as
such, never as not sharing. A file counts as CDK only if it imports
bedrockagentcore, because CfnRuntime is not a unique name across CDK modules.

The unit differs between the two and the output says so, because the earlier
repository-level analysis was mislabelled once by mixing units. A
CloudFormation stack is one template file. A CDK app is a directory.

  python3 cfn_cdk_runtimes.py --corpus corpus_tier2 \\
      --json evaluation/benchmark/cfn_cdk_tier2.json
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pathlib
import re
import sys

# The spelling shared by every AgentCore resource type and by the CDK module,
# so a file without it cannot declare an agent runtime. Lower case, because the
# check is made against lower-cased bytes.
MARKER = b"bedrockagentcore"

CFN_RUNTIME_TYPE = "aws::bedrockagentcore::runtime"
# Other AgentCore resources, counted so that a zero on runtimes can be told
# apart from a corpus that contains no AgentCore CloudFormation at all.
CFN_OTHER_TYPES = (
    "aws::bedrockagentcore::memory",
    "aws::bedrockagentcore::gateway",
    "aws::bedrockagentcore::browser",
    "aws::bedrockagentcore::codeinterpreter",
    "aws::bedrockagentcore::runtimeendpoint",
)
CDK_MODULE = "bedrockagentcore"
CDK_CALL = re.compile(r"\bCfnRuntime\s*\(")
ROLE_KW = re.compile(r"\brole_arn\s*=|\broleArn\s*:")


# --------------------------------------------------------------- YAML ----
def _yaml_loader():
    """A loader that survives CloudFormation intrinsics.

    `!Ref`, `!GetAtt` and the rest are YAML tags, and a plain safe_load raises
    on every one of them, which would silently reduce the corpus to JSON
    templates only. Each tag becomes a marker so the value is still comparable.

    Built on the C loader when libyaml is present, because the pure-Python one
    runs at a few megabytes a second and the corpus has large YAML in it. The
    fallback keeps the result independent of which is installed.
    """
    import yaml

    base = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

    class Loader(base):
        pass

    def multi(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            val = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            val = loader.construct_sequence(node, deep=True)
        else:
            val = loader.construct_mapping(node, deep=True)
        return {"Fn::" + tag_suffix: val}

    Loader.add_multi_constructor("!", multi)
    return Loader


def canonical_role(value) -> str | None:
    """One spelling for a role expression, whatever form it arrived in.

    `!GetAtt Role.Arn` in YAML is the string "Role.Arn"; the same thing in JSON
    is `{"Fn::GetAtt": ["Role", "Arn"]}`. Without normalising, two runtimes
    sharing a role in different template formats would not compare equal.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key, val in value.items():
            k = key.replace("Fn::", "").strip()
            if k == "GetAtt":
                if isinstance(val, list):
                    return "GetAtt:" + ".".join(str(x) for x in val)
                return "GetAtt:" + str(val).strip()
            if k == "Ref":
                return "Ref:" + str(val).strip()
            if k == "Sub":
                if isinstance(val, list) and val:
                    return "Sub:" + str(val[0]).strip()
                return "Sub:" + str(val).strip()
            if k == "ImportValue":
                return "ImportValue:" + json.dumps(val, sort_keys=True)
            return k + ":" + json.dumps(val, sort_keys=True)
    return json.dumps(value, sort_keys=True)


_LOADER = None


def load_template(path: pathlib.Path, data: bytes | None = None):
    """Parse a template, but only one that could possibly match.

    `data` is the file's bytes when the caller has already read them for the
    marker check, so the file is read once rather than twice.
    """
    global _LOADER
    if data is None:
        data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except Exception:
            return None
    try:
        import yaml
        if _LOADER is None:
            _LOADER = _yaml_loader()
        return yaml.load(text, Loader=_LOADER)
    except Exception:
        return None


def cfn_runtimes(doc):
    """(logical id, canonical role) for every agent runtime in one template."""
    if not isinstance(doc, dict):
        return [], collections.Counter()
    res = doc.get("Resources")
    if not isinstance(res, dict):
        return [], collections.Counter()
    out, others = [], collections.Counter()
    for logical, body in res.items():
        if not isinstance(body, dict):
            continue
        rtype = str(body.get("Type") or "").strip().lower()
        if rtype == CFN_RUNTIME_TYPE:
            props = body.get("Properties")
            role = (props or {}).get("RoleArn") if isinstance(props, dict) else None
            out.append((str(logical), canonical_role(role)))
        elif rtype in CFN_OTHER_TYPES:
            others[rtype] += 1
    return out, others


# ---------------------------------------------------------------- CDK ----
def _arg_expression(text: str, start: int) -> str | None:
    """The role argument of the CfnRuntime call that starts at `start`.

    Walks the call's parentheses so a nested property object does not end the
    search early, and returns the expression text as written. The text, not a
    resolved value: two call sites passing the same expression are treated as
    the same role and two passing different expressions as different ones.
    """
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    call = text[start:i]
    m = ROLE_KW.search(call)
    if not m:
        return None
    j, d2 = m.end(), 0
    buf = []
    while j < len(call):
        c = call[j]
        if c in "([{":
            d2 += 1
        elif c in ")]}":
            if d2 == 0:
                break
            d2 -= 1
        elif c == "," and d2 == 0:
            break
        buf.append(c)
        j += 1
    expr = "".join(buf).strip()
    return expr or None


def cdk_runtimes(path: pathlib.Path, data: bytes | None = None):
    """(call site index, role expression or None) for one CDK source file."""
    if data is None:
        data = path.read_bytes()
    text = data.decode("utf-8", errors="replace")
    if CDK_MODULE not in text:
        return []
    out = []
    for m in CDK_CALL.finditer(text):
        # The call's opening parenthesis, so the walker starts at depth 0.
        open_paren = text.find("(", m.start())
        if open_paren < 0:
            continue
        out.append((open_paren, _arg_expression(text, open_paren)))
    return out


# --------------------------------------------------------------- main ----
# A file can appear many times in a corpus collected by code search without
# being many deployments. Two shapes of that showed up on 2026-11-02, and both
# inflate any denominator built from this scan:
#
#   a copy. Eight of the twenty-six multi-runtime CloudFormation templates were
#   byte identical to one awslabs sample, re-published under other owners. The
#   collector drops forks by GitHub's fork flag and the Terraform topology
#   dedupes by content hash; this scan did neither.
#
#   a file that is not a deployment. A vendored copy of someone else's template
#   inside a benchmark repository, and a snapshot a project's own tests compare
#   against, both exist to be read rather than deployed.
#
# Neither is dropped silently. Each is counted, named and given its reason, so
# the deployable figure and the raw figure are both visible.
NOT_A_DEPLOYMENT = ("/test/fixtures/", "/tests/fixtures/", "/__snapshots__/",
                    "/cdk.out/", "/cfn_benchmark/")


def _not_a_deployment(rel):
    low = "/" + str(rel).replace("\\", "/").lower()
    for marker in NOT_A_DEPLOYMENT:
        if marker in low:
            return marker
    return None


ACCOUNT_ID = __import__("re").compile(r"\b\d{12}\b")
PLACEHOLDER_ACCOUNTS = {"000000000000", "123456789012"}


def redact_account_ids(value):
    """Replace a real AWS account id in recorded text with a placeholder.

    A role expression copied out of a third party's template can carry their
    account id. The id is already public in their repository, but recording it
    here republishes it from this one, and this project already keeps generated
    output that embeds account identifiers out of the tree for that reason.
    Documentation placeholders are left alone so an example still reads as one.
    """
    def sub(m):
        return m.group(0) if m.group(0) in PLACEHOLDER_ACCOUNTS else "000000000000"
    if isinstance(value, str):
        return ACCOUNT_ID.sub(sub, value)
    if isinstance(value, list):
        return [redact_account_ids(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_account_ids(v) for k, v in value.items()}
    return value


def deployable_units(rows, root, key, files_of):
    """Group units by content, and separate the ones that are not deployments.

    `files_of` returns the files whose bytes identify a unit: the template
    itself for CloudFormation, and the files holding the runtime call sites for
    a CDK directory. Units with the same bytes are one unit, and the first by
    name is kept so the choice does not depend on walk order.
    """
    import hashlib
    graded = []
    for r in rows:
        rel = r[key]
        h = hashlib.sha256()
        for f in files_of(r):
            try:
                h.update((root / f).read_bytes())
            except OSError:
                h.update(b"")
        graded.append({"unit": rel, "hash": h.hexdigest()[:12],
                       "not_a_deployment": _not_a_deployment(rel)})
    by_hash = {}
    for g in graded:
        by_hash.setdefault(g["hash"], []).append(g)
    kept, copies, excluded = [], [], []
    for group in by_hash.values():
        group.sort(key=lambda g: g["unit"])
        deployable = [g for g in group if not g["not_a_deployment"]]
        excluded += [g for g in group if g["not_a_deployment"]]
        if not deployable:
            continue
        kept.append(deployable[0])
        copies += [{"unit": g["unit"], "same_bytes_as": deployable[0]["unit"]}
                   for g in deployable[1:]]
    return {
        "reported": len(rows),
        "distinct_contents": len(by_hash),
        "byte_identical_copies": len(copies),
        "not_a_deployment": len(excluded),
        "deployable_distinct_units": len(kept),
        "kept": sorted(g["unit"] for g in kept),
        "copies": copies,
        "excluded": [{"unit": g["unit"], "matched": g["not_a_deployment"]}
                     for g in excluded],
        "how": "units with identical bytes are one unit; a path under a test "
               "fixture, a snapshot directory or a vendored benchmark copy is "
               "not a deployment. Both are reported rather than dropped.",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    ap.add_argument("--progress", type=int, default=2000)
    args = ap.parse_args()

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("stop: pyyaml is needed to read CloudFormation YAML. Install it "
              "with: python3 -m pip install pyyaml", file=sys.stderr)
        return 2

    if not args.corpus.is_dir():
        print(f"stop: no such corpus directory: {args.corpus}", file=sys.stderr)
        return 2

    cfn_files = cfn_with_runtime = 0
    cfn_runtime_total = 0
    cfn_multi = []            # templates with 2+ runtimes
    cfn_shared = []           # of those, with two runtimes on one role
    cfn_undecidable = []      # of those, with a role we could not read
    other_types = collections.Counter()
    cdk_files = cdk_with_runtime = 0
    cdk_runtime_total = 0
    cdk_multi, cdk_shared, cdk_undecidable = [], [], []
    cdk_dirs = collections.defaultdict(list)

    seen = cfn_skipped = cdk_skipped = 0
    root = str(args.corpus)
    for dirpath, dirnames, filenames in os.walk(root):
        # Never descend into .git. A blobless sparse clone still has one, and
        # walking it was most of the walk.
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            path = pathlib.Path(dirpath) / name
            suffix = path.suffix.lower()
            if suffix not in (".yaml", ".yml", ".json", ".ts", ".py"):
                continue
            rel = os.path.relpath(str(path), root)
            seen += 1
            if args.progress and seen % args.progress == 0:
                print(f"  {seen} candidate files examined", flush=True)

            # One read, one exact filter. The resource type and the CDK module
            # both contain the marker, so a file without it cannot match.
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if MARKER not in data.lower():
                if suffix in (".yaml", ".yml", ".json"):
                    cfn_files += 1
                    cfn_skipped += 1
                else:
                    cdk_skipped += 1
                continue

            if suffix in (".yaml", ".yml", ".json"):
                cfn_files += 1
                doc = load_template(path, data)
                runtimes, others = cfn_runtimes(doc)
                other_types.update(others)
                if runtimes:
                    cfn_with_runtime += 1
                    cfn_runtime_total += len(runtimes)
                    if len(runtimes) >= 2:
                        roles = [r for _, r in runtimes]
                        entry = {"template": rel, "runtimes": len(runtimes),
                                 "roles": [{"logical": l, "role": r}
                                           for l, r in runtimes]}
                        cfn_multi.append(entry)
                        if any(r is None for r in roles):
                            cfn_undecidable.append(entry)
                        else:
                            dupes = [r for r, n
                                     in collections.Counter(roles).items()
                                     if n >= 2]
                            if dupes:
                                entry = dict(entry, shared_roles=dupes)
                                cfn_shared.append(entry)

            else:
                calls = cdk_runtimes(path, data)
                if calls:
                    cdk_files += 1
                    cdk_with_runtime += 1
                    cdk_runtime_total += len(calls)
                    key = os.path.relpath(dirpath, root)
                    cdk_dirs[key].extend(
                        [{"file": rel, "role": expr} for _, expr in calls])

    print(f"\n{seen} candidate files read. {cfn_skipped} template files and "
          f"{cdk_skipped} source files do not contain the AgentCore marker "
          f"anywhere, so they cannot declare a runtime and were not parsed.")

    # A CDK app is a directory, not a file: two stacks in one app can share a
    # role across two files. The unit is stated in the output.
    for d, calls in cdk_dirs.items():
        if len(calls) < 2:
            continue
        entry = {"directory": d, "runtimes": len(calls), "calls": calls}
        cdk_multi.append(entry)
        exprs = [c["role"] for c in calls]
        if any(e is None for e in exprs):
            cdk_undecidable.append(entry)
        else:
            dupes = [e for e, n in collections.Counter(exprs).items() if n >= 2]
            if dupes:
                cdk_shared.append(dict(entry, shared_roles=dupes))

    # How many of these are distinct deployments, as against copies of one
    # template and files that exist for a test to read.
    cfn_pop = deployable_units(cfn_multi, args.corpus, "template",
                               lambda r: [r["template"]])
    cdk_pop = deployable_units(cdk_multi, args.corpus, "directory",
                               lambda r: sorted({c["file"]
                                                 for c in r.get("calls", [])}))

    out = {
        "corpus": str(args.corpus),
        "cloudformation": {
            "unit": "one template file is one stack",
            "candidate_files_read": cfn_files,
            "files_declaring_an_agent_runtime": cfn_with_runtime,
            "agent_runtimes": cfn_runtime_total,
            "templates_with_two_or_more": len(cfn_multi),
            "population": cfn_pop,
            "templates_sharing_a_role": len(cfn_shared),
            "templates_undecidable": len(cfn_undecidable),
            # Every multi-runtime template, not only the ones that shared a
            # role. A template with two runtimes on two different roles is
            # exactly where a chain would be, and the chain driver needs the
            # list rather than the count.
            "multi": cfn_multi,
            "shared": cfn_shared,
            "undecidable": cfn_undecidable,
            "other_agentcore_types": dict(other_types),
            "method": "exact: the resource type is named in the template and "
                      "the role is a property of it. Intrinsics are "
                      "normalised so the YAML and JSON forms of one reference "
                      "compare equal.",
        },
        "cdk": {
            "unit": "one directory is one app, because two stacks in one app "
                    "can share a role across two files",
            "population": cdk_pop,
            "files_with_a_runtime_construct": cdk_with_runtime,
            "runtime_constructs": cdk_runtime_total,
            "directories_with_two_or_more": len(cdk_multi),
            "directories_sharing_a_role": len(cdk_shared),
            "directories_undecidable": len(cdk_undecidable),
            "multi": cdk_multi,
            "shared": cdk_shared,
            "undecidable": cdk_undecidable,
            "method": "heuristic: the source is read, not synthesised. Two "
                      "call sites passing the same expression text are "
                      "treated as one role. A call site whose role argument "
                      "cannot be located is undecidable, never 'not sharing'. "
                      "A file counts only if it imports bedrockagentcore, "
                      "because CfnRuntime is not unique across CDK modules.",
        },
        "why": "the Terraform population in which a cross-agent chain is "
               "possible is 18 projects, and 0 of 18 bounds the rate at only "
               "15.3 percent. This measures how much of the population was "
               "outside Terraform.",
        "do_not_add_these_together": "the two units differ and the CDK figure "
                                     "is heuristic while the CloudFormation "
                                     "one is exact. Report them separately.",
    }

    c, k = out["cloudformation"], out["cdk"]
    print()
    print("CloudFormation, exact")
    print(f"  candidate files read                 {c['candidate_files_read']}")
    print(f"  files declaring an agent runtime     {c['files_declaring_an_agent_runtime']}")
    print(f"  agent runtimes                       {c['agent_runtimes']}")
    print(f"  templates with 2 or more             {c['templates_with_two_or_more']}")
    print(f"    sharing a role                     {c['templates_sharing_a_role']}")
    print(f"    undecidable                        {c['templates_undecidable']}")
    if other_types:
        print("  other AgentCore types present:")
        for t, n in other_types.most_common():
            print(f"    {t}  {n}")
    else:
        print("  no other AgentCore CloudFormation type appears either, so a "
              "zero above is a corpus with no AgentCore CloudFormation in it "
              "rather than runtimes being declared some other way")
    print()
    print("CDK, heuristic")
    print(f"  files with a runtime construct       {k['files_with_a_runtime_construct']}")
    print(f"  runtime constructs                   {k['runtime_constructs']}")
    print(f"  directories with 2 or more           {k['directories_with_two_or_more']}")
    print(f"    sharing a role                     {k['directories_sharing_a_role']}")
    print(f"    undecidable                        {k['directories_undecidable']}")

    for label, rows in (("CloudFormation", cfn_shared), ("CDK", cdk_shared)):
        if rows:
            print(f"\n{label} shared-role cases:")
            for r in rows:
                where = r.get("template") or r.get("directory")
                print(f"  {where}")
                print(f"      {r['runtimes']} runtimes, shared: "
                      f"{', '.join(str(x) for x in r['shared_roles'])}")

    # No combined bound is printed here. An earlier version added the two
    # families together and showed the bound that would follow, with a line
    # underneath saying not to quote it as one number. The number is the part
    # a reader copies, so it is gone. The denominator that belongs in a bound
    # is the one the chain analysis actually covered, which chain_cfn.py
    # computes and prints from these populations.
    print()
    for label, pop in (("CloudFormation", c["population"]),
                       ("CDK", k["population"])):
        print(f"{label}: how many of those are distinct deployments")
        print(f"  reported by this scan                {pop['reported']}")
        print(f"  distinct contents                    {pop['distinct_contents']}")
        print(f"  byte identical copies of another     {pop['byte_identical_copies']}")
        print(f"  not a deployment                     {pop['not_a_deployment']}")
        print(f"  deployable distinct units            {pop['deployable_distinct_units']}")
        for x in pop["excluded"]:
            print(f"      [{x['matched']}] {x['unit']}")
        for x in pop["copies"][:4]:
            print(f"      copy of {x['same_bytes_as'].split('/')[0]}: "
                  f"{x['unit']}")
        if len(pop["copies"]) > 4:
            print(f"      ... and {len(pop['copies']) - 4} more copies, all "
                  f"named in the json")
        print()
    print("The two families are different units and the CDK figure is a "
          "heuristic, so they are not added together here.")

    if args.json:
        args.json.write_text(json.dumps(redact_account_ids(out), indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
