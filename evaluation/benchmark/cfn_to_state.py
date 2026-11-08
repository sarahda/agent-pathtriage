#!/usr/bin/env python3
"""Turn a CloudFormation template into the state shape the analyser already reads.

Why an adapter and not a second analyser. `extract_graph.build` consumes a
`terraform show -json` shaped document whose resources carry Terraform type
names, and `reach.py` computes Esc from that graph. Writing a second chain
analysis for CloudFormation would mean two implementations of one predicate and
two sets of bugs, and a reviewer would be right to ask which one the paper's
number came from. Translating instead means the same rule, the same code and
the same tests cover every declaration format, and the only new thing is the
translation.

What it translates:

    AWS::IAM::Role                        aws_iam_role
      Policies                            aws_iam_role_policy, one each
      ManagedPolicyArns                   aws_iam_role_policy_attachment
    AWS::IAM::Policy                      aws_iam_role_policy, one per role
    AWS::IAM::ManagedPolicy               aws_iam_policy + attachments
    AWS::BedrockAgentCore::Runtime        aws_bedrockagentcore_agent_runtime
    AWS::BedrockAgentCore::Memory         aws_bedrockagentcore_memory
    ... and the other AgentCore types

References. A role is named by `!GetAtt Role.Arn` or `!Ref Role`, and the
analyser keys roles by the last segment of an ARN. So each logical id gets one
synthetic ARN, used both where the role is declared and everywhere it is
referenced, and the two sides meet. The real ARN is unknown at template time
and does not matter: what matters is that two runtimes referring to one role
produce one name.

A reference this cannot resolve, to a parameter or to an export from another
stack, is written as `${param.X}` or `${import.X}` rather than dropped. It then
behaves the way an unresolved Terraform local already does in this project: the
role is visibly not resolvable, and the template is reported as undecidable
rather than as having no escalation. `role_arn_resolution.py` made that
distinction for Terraform and the same distinction is kept here.

    python3 cfn_to_state.py --template path/to/stack.yaml --json state.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# One source of truth for the YAML loader and the intrinsic forms.
from cfn_cdk_runtimes import load_template  # noqa: E402

ACCOUNT = "000000000000"
REGION = "us-east-1"

# CloudFormation type -> (terraform type, the arn service and resource path)
AGENT_TYPES = {
    "aws::bedrockagentcore::runtime":
        ("aws_bedrockagentcore_agent_runtime", "bedrock-agentcore", "runtime"),
    "aws::bedrockagentcore::memory":
        ("aws_bedrockagentcore_memory", "bedrock-agentcore", "memory"),
    "aws::bedrockagentcore::gateway":
        ("aws_bedrockagentcore_gateway", "bedrock-agentcore", "gateway"),
    "aws::bedrockagentcore::browser":
        ("aws_bedrockagentcore_browser", "bedrock-agentcore", "browser"),
    "aws::bedrockagentcore::codeinterpreter":
        ("aws_bedrockagentcore_code_interpreter", "bedrock-agentcore",
         "code-interpreter"),
}
# A runtime endpoint carries no role by design, so including it would add a
# resource with no role and make a template look partly unresolved. The same
# type was excluded from the Terraform count for the same reason.
SKIP_TYPES = ("aws::bedrockagentcore::runtimeendpoint",)


def role_arn(logical: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{logical}"


def resource_arn(service: str, path: str, logical: str) -> str:
    return f"arn:aws:{service}:{REGION}:{ACCOUNT}:{path}/{logical}"


class Resolver:
    """Turns a CloudFormation value into something the analyser can compare.

    Every unresolvable reference keeps a distinguishable shape, so a caller can
    tell a role it could not resolve from a role that is not there.
    """

    def __init__(self, resources: dict, parameters: dict):
        self.resources = resources
        self.parameters = parameters or {}
        self.unresolved: list[str] = []

    def _logical_kind(self, logical: str) -> str | None:
        body = self.resources.get(logical)
        if not isinstance(body, dict):
            return None
        return str(body.get("Type") or "").strip().lower()

    def arn_of(self, logical: str) -> str | None:
        kind = self._logical_kind(logical)
        if kind is None:
            return None
        if kind == "aws::iam::role":
            return role_arn(logical)
        if kind in AGENT_TYPES:
            _tf, svc, path = AGENT_TYPES[kind]
            return resource_arn(svc, path, logical)
        if kind == "aws::iam::managedpolicy":
            return f"arn:aws:iam::{ACCOUNT}:policy/{logical}"
        return f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:resource/{logical}"

    def resolve(self, value):
        """A scalar for a reference, the value itself for a literal."""
        if value is None:
            return None
        if isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if not isinstance(value, dict):
            return value

        keys = {k.replace("Fn::", ""): v for k, v in value.items()}

        if "GetAtt" in keys:
            v = keys["GetAtt"]
            parts = v if isinstance(v, list) else str(v).split(".")
            logical = str(parts[0])
            attr = str(parts[1]) if len(parts) > 1 else "Arn"
            arn = self.arn_of(logical)
            if arn is None:
                self.unresolved.append(f"GetAtt {logical}.{attr}")
                return "${import." + logical + "}"
            return arn if attr.lower().endswith("arn") else logical

        if "Ref" in keys:
            logical = str(keys["Ref"])
            if logical.startswith("AWS::"):
                return {"AWS::AccountId": ACCOUNT,
                        "AWS::Region": REGION,
                        "AWS::Partition": "aws"}.get(logical, "${" + logical + "}")
            arn = self.arn_of(logical)
            if arn is not None:
                # Ref on a role yields its name, which is what the analyser
                # keys on, so the name is the honest answer here.
                if self._logical_kind(logical) == "aws::iam::role":
                    return logical
                return arn
            if logical in self.parameters:
                self.unresolved.append(f"Ref {logical} (parameter)")
                return "${param." + logical + "}"
            self.unresolved.append(f"Ref {logical} (unknown)")
            return "${import." + logical + "}"

        if "Sub" in keys:
            v = keys["Sub"]
            text = v[0] if isinstance(v, list) and v else v
            out = str(text)
            out = (out.replace("${AWS::AccountId}", ACCOUNT)
                      .replace("${AWS::Region}", REGION)
                      .replace("${AWS::Partition}", "aws"))
            for logical in list(self.resources):
                arn = self.arn_of(logical)
                if arn:
                    out = out.replace("${" + logical + ".Arn}", arn)
                    out = out.replace("${" + logical + "}", logical)
            if "${" in out:
                self.unresolved.append(f"Sub {out[:60]}")
            return out

        if "Join" in keys:
            # CDK writes almost every ARN as a Join over a partition Ref, so a
            # template it synthesised carries managed policy ARNs and role
            # ARNs in this shape rather than as strings. Leaving the Join as a
            # dict put a dict where the analyser keys on an ARN, which is why
            # CDK output could not be read at all.
            v = keys["Join"]
            if isinstance(v, list) and len(v) == 2:
                sep = v[0] if isinstance(v[0], str) else ""
                parts = [self.resolve(x) for x in (v[1] or [])]
                if all(isinstance(x, str) for x in parts):
                    return sep.join(parts)
                # One unresolved part makes the whole string unknown. Saying so
                # is better than joining around the hole and producing an ARN
                # that looks real.
                self.unresolved.append("Join with an unresolved part")
                return "${join}"
            self.unresolved.append("Join in a shape this does not read")
            return "${join}"

        if "ImportValue" in keys:
            self.unresolved.append("ImportValue")
            return "${import.cross-stack}"

        if "If" in keys:
            # A condition picks one of two branches. Both are kept so neither
            # is silently chosen, and the caller sees a value it cannot
            # compare, which is the truth.
            self.unresolved.append("Fn::If")
            return "${condition}"

        return {k: self.resolve(v) for k, v in value.items()}

    def deep(self, value):
        """Resolve a whole policy document, references and all."""
        if isinstance(value, dict):
            keys = {k.replace("Fn::", "") for k in value}
            if keys & {"GetAtt", "Ref", "Sub", "ImportValue", "If", "Join"}:
                return self.resolve(value)
            return {k: self.deep(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.deep(v) for v in value]
        return value


def convert(doc: dict) -> tuple[list, list]:
    """(resources in the analyser's shape, notes about what did not resolve)."""
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return [], ["the template declares no Resources section"]
    R = Resolver(resources, doc.get("Parameters") or {})
    out = []

    for logical, body in resources.items():
        if not isinstance(body, dict):
            continue
        kind = str(body.get("Type") or "").strip().lower()
        props = body.get("Properties") if isinstance(body.get("Properties"),
                                                     dict) else {}

        if kind == "aws::iam::role":
            trust = R.deep(props.get("AssumeRolePolicyDocument"))
            out.append({"type": "aws_iam_role", "name": logical, "values": {
                "name": logical,
                "arn": role_arn(logical),
                "assume_role_policy": json.dumps(trust) if trust else None,
                "managed_policy_arns": [R.resolve(m) for m
                                        in (props.get("ManagedPolicyArns") or [])],
            }})
            for i, pol in enumerate(props.get("Policies") or []):
                if not isinstance(pol, dict):
                    continue
                pname = R.resolve(pol.get("PolicyName")) or f"{logical}_p{i}"
                out.append({"type": "aws_iam_role_policy",
                            "name": f"{logical}_{pname}", "values": {
                                "role": logical, "name": str(pname),
                                "policy": json.dumps(
                                    R.deep(pol.get("PolicyDocument")))}})

        elif kind == "aws::iam::policy":
            doc_json = json.dumps(R.deep(props.get("PolicyDocument")))
            for ref in (props.get("Roles") or []):
                owner = R.resolve(ref)
                out.append({"type": "aws_iam_role_policy",
                            "name": f"{logical}_{owner}", "values": {
                                "role": owner, "name": logical,
                                "policy": doc_json}})

        elif kind == "aws::iam::managedpolicy":
            arn = f"arn:aws:iam::{ACCOUNT}:policy/{logical}"
            out.append({"type": "aws_iam_policy", "name": logical, "values": {
                "arn": arn, "name": logical,
                "policy": json.dumps(R.deep(props.get("PolicyDocument")))}})
            for ref in (props.get("Roles") or []):
                out.append({"type": "aws_iam_role_policy_attachment",
                            "name": f"{logical}_{R.resolve(ref)}", "values": {
                                "role": R.resolve(ref), "policy_arn": arn}})

        elif kind in AGENT_TYPES:
            tf_type, svc, path = AGENT_TYPES[kind]
            values = {
                "name": R.resolve(props.get("AgentRuntimeName")) or logical,
                "arn": resource_arn(svc, path, logical),
            }
            if kind == "aws::bedrockagentcore::runtime":
                values["agent_runtime_name"] = values["name"]
                values["role_arn"] = R.resolve(props.get("RoleArn"))
                env = R.deep(props.get("EnvironmentVariables"))
                if isinstance(env, dict):
                    values["environment_variables"] = env
            out.append({"type": tf_type, "name": logical, "values": values})

        elif kind in SKIP_TYPES:
            continue

    return out, R.unresolved


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if not a.template.is_file():
        print(f"stop: no such template: {a.template}", file=sys.stderr)
        return 2
    doc = load_template(a.template)
    if doc is None:
        print(f"stop: {a.template} did not parse as a template",
              file=sys.stderr)
        return 2

    rows, unresolved = convert(doc)
    state = {"format_version": "1.0",
             "values": {"root_module": {"resources": rows}}}

    if not a.quiet:
        kinds = {}
        for r in rows:
            kinds[r["type"]] = kinds.get(r["type"], 0) + 1
        for k in sorted(kinds):
            print(f"  {kinds[k]:3d}  {k}")
        runtimes = [r for r in rows
                    if r["type"] == "aws_bedrockagentcore_agent_runtime"]
        bad = [r for r in runtimes
               if not r["values"].get("role_arn")
               or "${" in str(r["values"].get("role_arn"))]
        print(f"agent runtimes: {len(runtimes)}, "
              f"of which the role could not be resolved: {len(bad)}")
        if unresolved:
            print("references that did not resolve, so this template is "
                  "undecidable rather than clean:")
            for u in sorted(set(unresolved))[:10]:
                print(f"    {u}")

    if a.json:
        a.json.write_text(json.dumps(state, indent=2))
        print(f"wrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
