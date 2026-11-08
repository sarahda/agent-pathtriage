# Rebuilding the Foundry lab

One `terraform apply` and three scripted steps. Everything learned on
2026-10-25 is in the configuration, so the lab's history is this file rather
than a sequence of console fixes.

## Why a rebuild rather than a repair

The first build was changed by hand about ten times while the platform's
behaviour was being established: role assignments granted and revoked at the
console, connections created, replaced and deleted, the account's identity
type changed under a live deployment. After that, a result cannot be
attributed to any one setting, and the reproduction recipe is not something
another person can follow. A lab whose state is one apply can be re-run by a
reviewer; a lab whose state is twenty ad hoc steps cannot.

## What the experiment is

Agent `apt-caller` runs in project A and queries a search index through a
connection on that project. The index holds one document with a canary string.
The agent's answer either contains the canary or it does not.

The variable is the connection's `authType`. Nothing else changes between
cells: same agent, same index, same prompt, same document.

## Who holds what, by default

| Principal | Index read role |
|---|---|
| Project A system-assigned identity | yes |
| Project A user-assigned identity (apt-agentA-thin) | no |
| Project B user-assigned identity (apt-agentB-broad) | no |
| Agent instance identities | no |
| The deployer | no |

Only one principal holds the role. That is deliberate. Three earlier grants
are still in the configuration behind `grant_agentB_uai_search`,
`grant_projectA_uai_search` and `grant_deployer_search_read`, all false. Each
one adds a second explanation for a reached result, so each is a separate
cell to be turned on knowingly, never part of the baseline.

Verify before running any cell:

    az role assignment list --scope "$(terraform output -raw search_id)" \
      --query "[].{role:roleDefinitionName, principal:principalId}" -o table

Exactly one `Search Index Data Reader` row should appear, and its principal
should equal `terraform output projectA_sa_principal_id`.

## The rebuild

    cd infra/foundry
    terraform plan -destroy        # read it; nothing outside this lab
    terraform destroy
    terraform plan                 # read it
    terraform apply

The random suffix is regenerated, so the account, vault and search service all
get new names. That is intended: nothing carries over.

Then the two data-plane steps that Terraform cannot do, because an agent and a
search index are data-plane objects and the Terraform principal has
control-plane rights only:

    sleep 420                      # see below
    python3 create_agents.py       # apt-caller and apt-callee
    python3 lab_search.py seed     # index apt-sensitive, one document

Wait before creating the agents. The deployer's data-plane grant on the
account took about seven minutes to take effect on 2026-10-25; at two minutes
agent creation still failed with

    does not have permissions for
    Microsoft.CognitiveServices/accounts/AIServices/agents/read

which looks like the wrong role and is not. Check the assignment exists before
concluding anything about the role:

    az role assignment list --scope "$(terraform output -raw foundry_id)" \
      --assignee "$(az ad signed-in-user show --query id -o tsv)" \
      --query "[].roleDefinitionName" -o tsv

Confirm the control is valid before measuring anything:

    python3 _probe_search.py

Section 5 must read 403. If the deployer can read the document, the
AgentUserImpersonation cell would come back reached for a reason unrelated to
the mechanism, and the experiment is void until that is fixed.

## The cells, in this order

Run the positive control first. Until one configuration is seen to work, a
refusal cannot be told apart from a path that never worked.

    # 1. positive control. Identity is bypassed with the admin key.
    python3 lab_search.py connect --auth ApiKey
    python3 lab_search.py observe --auth ApiKey
    # expect: reached, and output item types including azure_ai_search_call

    # 2. treatment. The call runs as the project's identity, which holds the role.
    python3 lab_search.py connect --auth ProjectManagedIdentity
    sleep 120
    python3 lab_search.py observe --auth ProjectManagedIdentity
    # expect: reached

    # 3. control. The call runs as the caller, who does not hold the role.
    python3 lab_search.py connect --auth AgentUserImpersonation
    sleep 120
    python3 lab_search.py observe --auth AgentUserImpersonation
    # expect: blocked

    # 4. falsification. Give the caller the role; cell 3 should flip.
    terraform apply -var grant_deployer_search_read=true
    sleep 180
    python3 lab_search.py observe --auth AgentUserImpersonation --label falsification
    # expect: reached
    terraform apply

Cells 2 and 3 together are the claim: one setting decides which identity the
call runs as, and the same request succeeds or fails accordingly. Cell 4 is
what makes it an experiment rather than an anecdote, because without it a
reviewer can say the refusal in cell 3 came from a broken path.

Wait after each `connect`. On 2026-10-25 two cells were run 33 seconds apart
and both returned reached, which connection caching would also explain. That
pair had to be discarded.

## Rules this lab was built from, each after getting it wrong

- Establish the positive control before any treatment cell. A blocked result
  means nothing until something has been seen to work.
- One principal holds the role under test. Any second holder makes a reached
  result unattributable.
- A tool definition echoed in a request is not a tool call. Read the response's
  output item types, not the request body, to tell whether the tool ran.
- A call naming the model deployment reaches the bare model with no tools. It
  is not the agent and its silence is not a refusal.
- Wait for RBAC propagation and for connection changes to take effect. Two
  observations a minute apart do not establish a flip.
- Record every attempt, not the first that returns. The reason a path failed
  is usually the finding.
- Every grant the lab needs belongs in the configuration. The first build was
  given Cognitive Services Data Contributor (Preview) at the console, and the
  rebuild failed at agent creation because that grant existed only in a shell
  history.
- Serialise anything that writes to the same Cognitive Services account. Two
  projects created in parallel fail the second with 409 RequestConflict.
- Do not declare a Key Vault connection. Foundry then stores every connection
  secret in that vault instead of its own, and if its identity cannot write
  there, no connection carrying a secret can be created at all.
