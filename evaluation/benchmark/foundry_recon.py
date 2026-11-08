#!/usr/bin/env python3
"""What does Foundry infrastructure as code actually declare?

Before planning a Foundry prevalence study, the question is whether the thing
being measured is expressible in the files at all. On AWS a hand-off is
declared in Terraform, as an environment variable carrying another agent's
ARN, so a corpus can be counted. Foundry agents are often created through the
SDK or the portal rather than through Bicep or Terraform, in which case a
corpus would hold projects and connections and nothing to count.

This answers that by census rather than by assumption: it counts the resource
types and the connection auth types that appear, and reports how many
templates declare more than one agent-like resource. If that last number is
zero across the pilot, the Foundry prevalence study does not have a subject
and should not be planned.
"""

import argparse
import collections
import glob
import os
import re

# Terraform resource declarations and ARM/Bicep resource type strings
TF_RESOURCE = re.compile(r'resource\s+"([a-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"')
ARM_TYPE = re.compile(r"Microsoft\.[A-Za-z]+/[A-Za-z/]+")
AUTH_TYPE = re.compile(r'"?authType"?\s*[:=]\s*["\']([A-Za-z]+)["\']')

# `authType` is not a Foundry word. Microsoft.Logic, Microsoft.AppPlatform and
# Microsoft.ServiceLinker all have a field of that name, and counting those
# puts values like "windows" and "Public" in a denominator that is supposed to
# be Foundry connections. A directory counts only if it declares a connection
# resource of the kind this study is about.
CONNECTION_SCOPE = re.compile(
    r'(CognitiveServices/accounts(/projects)?/connections'
    r'|MachineLearningServices/workspaces/connections'
    r'|azurerm_ai_foundry)', re.I)
EXT = (".tf", ".bicep", ".json")

# resource names that denote an agent rather than the project that holds it.
# A repository can hold blueprints for more than one cloud, so an AWS resource
# can appear in this corpus: AviatrixSystems/aviatrix-blueprints carries both
# and its awscc_bedrockagentcore_runtime matched here. The census separates
# them, because counting an AWS agent as a Foundry one would reverse the
# finding.
AGENTISH = re.compile(r"(agent|assistant)", re.I)
AWS_RESOURCE = re.compile(r"^(aws|awscc)_")

# the strings that would carry an identity decision if Foundry expressed one
MARKERS = {
    "azurerm_ai_foundry": re.compile(r"azurerm_ai_foundry\b"),
    "azurerm_ai_foundry_project": re.compile(r"azurerm_ai_foundry_project\b"),
    "CognitiveServices/accounts/projects": re.compile(r"CognitiveServices/accounts/projects"),
    "MachineLearningServices/workspaces/connections":
        re.compile(r"MachineLearningServices/workspaces/connections"),
    "authType": re.compile(r"authType"),
    "AgentUserImpersonation": re.compile(r"AgentUserImpersonation"),
    "ProjectManagedIdentity": re.compile(r"ProjectManagedIdentity"),
    "connectedAgents": re.compile(r"connected_?[Aa]gents?"),

    # Added 2026-10-26 after reading agents/concepts/agent-identity. Only two
    # tools authenticate with the agent's own identity, and each has its own
    # auth type and connection category:
    #     MCP server   AgenticIdentityToken   RemoteTool
    #     A2A endpoint AgenticIdentity        RemoteA2A
    # Counting authType alone therefore says nothing about whether a
    # connection runs as the agent. These four strings do.
    "AgenticIdentityToken": re.compile(r"AgenticIdentityToken"),
    "AgenticIdentity": re.compile(r"AgenticIdentity\b"),
    "AgenticUser": re.compile(r"AgenticUser"),
    "RemoteA2A": re.compile(r"RemoteA2A"),
    "RemoteTool": re.compile(r"RemoteTool"),
    "AgentOnBehalfOfUser": re.compile(r"AgentOnBehalfOfUser"),
    "UserEntraToken": re.compile(r"UserEntraToken"),
    "AccountManagedIdentity": re.compile(r"AccountManagedIdentity"),

    # Added 2026-10-26, second pass. The markers above came from the
    # connection authType surface, which is how a tool call authenticates at
    # runtime. They do not cover the DECLARATION surface. Microsoft.Cognitive
    # Services/accounts/projects/applications (api versions 2025-10-01-preview
    # through 2026-05-15-preview, Learn "ARM template reference" read
    # 2026-10-26) carries agentIdentityBlueprint and defaultInstanceIdentity,
    # and AssignedIdentity.kind takes AgentBlueprint, AgenticUser, AgentInstance,
    # Managed or None. Agent identity IS declarable in ARM, Bicep and azapi.
    # Without these strings a zero count would only mean the runtime auth
    # surface is undeclared, not that agent identity is.
    "projects/applications": re.compile(r"projects/applications"),
    "AgenticApplicationProperties": re.compile(r"AgenticApplicationProperties"),
    "agentIdentityBlueprint": re.compile(r"agentIdentityBlueprint", re.I),
    "defaultInstanceIdentity": re.compile(r"defaultInstanceIdentity", re.I),
    "AgentInstance": re.compile(r"AgentInstance\b"),
    "AgentBlueprint": re.compile(r"AgentBlueprint\b"),
    "OrganizationScope": re.compile(r"OrganizationScope"),
    "agentDeployments": re.compile(r"agentDeployments"),

    # the A2A tool itself, however it is spelled
    "a2a tool": re.compile(r"A2ATool|\"type\"\s*:\s*\"a2a\"|agent-to-agent", re.I),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_foundry")
    ap.add_argument("--json", help="write the census here so the numbers are "
                                   "re-derivable rather than read off a log")
    a = ap.parse_args()

    repos = sorted(d for d in glob.glob(os.path.join(a.corpus, "*"))
                   if os.path.isdir(d))
    tf_types, arm_types, auth = collections.Counter(), collections.Counter(), collections.Counter()
    auth_scoped = collections.Counter()
    scoped_dirs = 0
    multi, with_any, scanned = [], 0, 0
    foreign, markers = [], collections.Counter()
    n_files = 0

    for r in repos:
        files = [p for ext in EXT
                 for p in glob.glob(os.path.join(r, "**", f"*{ext}"), recursive=True)]
        by_dir = collections.defaultdict(list)
        for p in files:
            by_dir[os.path.dirname(p)].append(p)
        n_files += len(files)
        for d, ps in by_dir.items():
            text = ""
            for p in ps:
                try:
                    text += open(p, encoding="utf-8", errors="ignore").read() + "\n"
                except Exception:
                    pass
            if not text:
                continue
            scanned += 1
            tfs = TF_RESOURCE.findall(text)
            tf_types.update(t for t, _ in tfs)
            arm_types.update(ARM_TYPE.findall(text))
            found_auth = AUTH_TYPE.findall(text)
            auth.update(found_auth)
            if found_auth and CONNECTION_SCOPE.search(text):
                auth_scoped.update(found_auth)
                scoped_dirs += 1
            markers.update({k: len(rx.findall(text)) for k, rx in MARKERS.items()
                            if rx.search(text)})
            agents = {n for t, n in tfs if AGENTISH.search(t) and not AWS_RESOURCE.match(t)}
            aws_agents = {f"{t}.{n}" for t, n in tfs
                          if AGENTISH.search(t) and AWS_RESOURCE.match(t)}
            if aws_agents:
                foreign.append((os.path.relpath(d, a.corpus), sorted(aws_agents)))
            if agents:
                with_any += 1
            if len(agents) >= 2:
                multi.append((os.path.relpath(d, a.corpus), sorted(agents)))

    print(f"files scanned     : {n_files}")
    print(f"repositories      : {len(repos)}")
    print(f"template dirs     : {scanned}")
    print(f"dirs with any agent-like resource : {with_any}")
    print(f"dirs with 2 or more               : {len(multi)}")
    for d, ns in multi[:15]:
        print(f"   {d}  {ns}")
    for label, c in (("terraform resource types", tf_types),
                     ("ARM/Bicep resource types", arm_types),
                     ("connection authType values", auth)):
        print(f"\n{label} (top 20):")
        for k, v in c.most_common(20):
            print(f"   {v:5d}  {k}")
    print("\nmarkers that would carry an identity decision:")
    for k in MARKERS:
        print(f"   {markers[k]:6d}  {k}")
    if foreign:
        print("\nnon-Azure agent resources found in this corpus (counted separately):")
        for d, ns in foreign:
            print(f"   {d}  {ns}")

    if a.json:
        import json as _json
        with open(a.json, "w") as fh:
            # The authType breakdown is the finding, so it goes in the
            # artifact. Until 2026-11-07 it was counted here and then dropped,
            # which left the published numbers resting on a note written by
            # hand against an older corpus rather than on something the
            # verifier could rebuild.
            #
            # These are assigned values, which is a different measurement from
            # the authType marker count: the marker counts how often the word
            # appears, this counts what it was set to.
            _json.dump({"repositories": len(repos), "files_scanned": n_files,
                        "template_dirs": scanned,
                        "dirs_with_an_agent": with_any,
                        "dirs_with_two_or_more_agents": len(multi),
                        "markers": dict(markers),
                        "configured_auth_types": dict(auth_scoped.most_common()),
                        "configured_auth_values": sum(auth_scoped.values()),
                        "configured_auth_scope": (
                            "directories that declare a Foundry or Azure ML "
                            "connection resource. authType is also a field on "
                            "Microsoft.Logic, Microsoft.AppPlatform and "
                            "Microsoft.ServiceLinker, and those are not "
                            "connections of the kind this study is about."),
                        "configured_auth_directories": scoped_dirs,
                        "configured_auth_types_unscoped": dict(auth.most_common()),
                        "configured_auth_values_unscoped": sum(auth.values()),
                        "non_azure_agent_resources": foreign}, fh, indent=2)
        print("\nconnection authType values, scoped to directories that declare a "
          "connection resource:")
    for k, v in auth_scoped.most_common():
        print(f"  {v:7}  {k}")
    print(f"  {sum(auth_scoped.values()):7}  total across {scoped_dirs} directories")
    dropped = sum(auth.values()) - sum(auth_scoped.values())
    print(f"  {dropped:7}  authType values in directories with no connection "
          f"resource, not counted")
    print(f"\nwritten: {a.json}")

    print("\nIf 'dirs with 2 or more' is 0, Foundry hand-off is not declared in "
          "these files and a prevalence study has no subject. Say that and move on.")


if __name__ == "__main__":
    main()
