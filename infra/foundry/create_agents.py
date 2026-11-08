#!/usr/bin/env python3
"""FD1: create the caller and callee agents in the Foundry lab.

The lab's Terraform brings up the account, two projects, two user-assigned
identities, a Key Vault with a secret only agentB's identity can read, and the
connection on project A whose authType decides which identity a call runs
under. What Terraform cannot bring up is the agents themselves: an agent is a
data-plane object under a project, and the principal that runs Terraform has
control-plane rights only. That split is why the corpus scan found zero agent
declarations in 16,448 template directories, and it is why this step is a
script rather than another resource block.

Idempotent. An agent that already exists is left alone and reported, so this
can be re-run after a partial failure without making duplicates.

What to read in the output: `instance_identity`. If an agent carries its own
identity, that is the Foundry counterpart of role_arn on an AWS agent runtime,
and the two platforms bind identity at the same layer after all.

Observed 2026-10-25: each agent does carry its own identity, and it is NOT one
of the user-assigned identities Terraform created. The role assignments written
in Terraform therefore do not apply to the running agents. Reading the IaC and
concluding what an agent can reach gives the wrong answer here, which is the
sharpest evidence this project has that source alone has a limit.

  az login
  python3 create_agents.py                 # create, or report what is there
  python3 create_agents.py --show          # report only
"""
import argparse
import json
import os
import subprocess
import sys

CALLER = "apt-caller"
CALLEE = "apt-callee"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents_live.json")


def tf_output(tfdir):
    out = subprocess.check_output(["terraform", f"-chdir={tfdir}", "output", "-json"])
    return {k: v.get("value") for k, v in json.loads(out).items()}


def account_endpoint(foundry_id):
    """The data-plane host, derived from the account name in the resource id."""
    return f"https://{foundry_id.rstrip('/').rsplit('/', 1)[-1]}.services.ai.azure.com"


def client_for(endpoint, project, credential):
    from azure.ai.projects import AIProjectClient
    return AIProjectClient(endpoint=f"{endpoint}/api/projects/{project}",
                           credential=credential)


def describe(agent):
    ident = getattr(agent, "instance_identity", None)
    return {
        "name": getattr(agent, "name", None),
        "id": getattr(agent, "id", None),
        "state": str(getattr(agent, "state", None)),
        "instance_identity": None if ident is None else {
            "client_id": getattr(ident, "client_id", None),
            "principal_id": getattr(ident, "principal_id", None),
            "status": str(getattr(ident, "status", None)),
        },
    }


def ensure(client, name, model, instructions, show_only):
    """Return (record, created). An existing agent is never recreated."""
    try:
        existing = client.agents.get(name)
        return describe(existing), False
    except Exception as e:
        if "404" not in str(e) and "NotFound" not in type(e).__name__:
            raise
    if show_only:
        return {"name": name, "id": None, "state": "absent"}, False

    from azure.ai.projects.models import PromptAgentDefinition
    client.agents.create_version(
        name, definition=PromptAgentDefinition(model=model, instructions=instructions))
    return describe(client.agents.get(name)), True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir", default=".")
    ap.add_argument("--model", default=None,
                    help="deployment name, default: read from terraform")
    ap.add_argument("--show", action="store_true", help="report, create nothing")
    a = ap.parse_args()

    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        raise SystemExit("pip install azure-ai-projects azure-identity")

    tf = tf_output(a.tfdir)
    endpoint = account_endpoint(tf["foundry_id"])
    model = a.model or "gpt-5.4-mini"
    cred = DefaultAzureCredential()

    print(f"account   {endpoint}")
    print(f"model     {model}")
    print(f"auth type {tf.get('connection_auth_type')}   "
          f"(the knob the two observations flip)")
    print()

    out = {"endpoint": endpoint, "model": model,
           "connection_auth_type": tf.get("connection_auth_type"), "agents": {}}

    plan = [
        ("agentA", CALLER,
         "You are the caller. When asked for the secret, use the Key Vault "
         "connection on this project to read it and report exactly what you get "
         "back, including any error."),
        ("agentB", CALLEE,
         "You are the callee. You hold the Key Vault role. Read the secret when "
         "asked and return it."),
    ]

    failed = False
    for project, name, instructions in plan:
        try:
            c = client_for(endpoint, project, cred)
            rec, created = ensure(c, name, model, instructions, a.show)
            rec["project"] = project
            out["agents"][name] = rec
            mark = "created" if created else ("absent" if rec.get("id") is None else "exists")
            print(f"  {name:<12} {mark:<8} id={rec.get('id')}")
            ident = rec.get("instance_identity")
            print(f"  {'':<12} identity: "
                  f"{'none' if not ident else ident}")
        except Exception as e:
            failed = True
            print(f"  {name:<12} FAILED   {type(e).__name__}: {str(e)[:300]}")

    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"\nwritten: {OUT}")

    if not failed:
        idents = [r.get("instance_identity") for r in out["agents"].values()]
        if any(idents):
            print("\nNote: the agents carry their own identity. That is the "
                  "Foundry counterpart of role_arn on an AWS agent runtime, so "
                  "the claim that the two platforms bind identity at different "
                  "layers needs re-checking before it goes in the write-up.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
