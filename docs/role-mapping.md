# Agent binding to minimal IAM action mapping

Ground truth for the config-to-role gap metric (`gap.py`). For each declared agent
binding, the minimal `bedrock-agentcore` actions that binding actually requires.
`gap(agent) = granted(role) \ required(bindings)`.

All actions are from the AWS Service Authorization Reference for Amazon Bedrock
AgentCore (bedrock-agentcore), retrieved 2026-10-03:
https://docs.aws.amazon.com/service-authorization/latest/reference/list_bedrock-agentcore.html

Actions below are written without the `bedrock-agentcore:` prefix. Resource scope
is the binding's own resource ARN (e.g. a memory binding needs the action only on
its own `memory/<id>`, never `memory/*`).

## Mapping

| Declared binding | Minimal required actions | Resource scope | Access |
|---|---|---|---|
| memory, read | `GetMemoryRecord`, `RetrieveMemoryRecords`, `GetEvent`, `ListMemoryRecords`, `ListEvents` | `memory/<own-id>` | Read/List |
| memory, write | `CreateEvent`, `BatchCreateMemoryRecords`, `BatchUpdateMemoryRecords` | `memory/<own-id>` | Write |
| code interpreter | `StartCodeInterpreterSession`, `InvokeCodeInterpreter`, `StopCodeInterpreterSession` | `code-interpreter/<own-id>` | Write |
| runtime invoke (specific callee) | `InvokeAgentRuntime` | `agent-runtime/<callee-id>` | Write |
| runtime invoke (user context) | `InvokeAgentRuntime`, `InvokeAgentRuntimeForUser` | `agent-runtime/<callee-id>` | Write |
| gateway/tool discovery | `GetGatewayTarget`, `ListGatewayTargets` | `gateway/<own-id>` | Read/List |

ARN formats (same reference):
- `arn:aws:bedrock-agentcore:<region>:<account>:memory/<id>`
- `arn:aws:bedrock-agentcore:<region>:<account>:agent-runtime/<id>`
- `arn:aws:bedrock-agentcore:<region>:<account>:code-interpreter/<id>`
- `arn:aws:bedrock-agentcore:<region>:<account>:gateway/<id>`

## Notes and limitations (state these in the paper)

1. **Gateway tool invocation has no single distinct IAM action in the reference.**
   The gateway actions are management/discovery (Create/Get/List/Update target).
   The actual tool call traverses the gateway data path, not a named
   `bedrock-agentcore` action. So for a gateway binding we count only discovery
   actions as required; this can slightly over-count the gap for gateway-heavy
   agents. Flagged, not hidden.
2. **Upper bound.** `required` is derived from bindings declared in IaC. Tools
   registered at runtime via SDK are not visible statically, so `required` may be
   under-observed and the gap over-stated. The reported quantity is therefore an
   upper bound on unnecessary permission: "role grant vs IaC-declared bindings".
3. **A full `bedrock-agentcore:*` grant** covers all 223 service actions across
   memory, code-interpreter, agent-runtime, and gateway, including every Write,
   Delete, and the one permissions-management action (`SynchronizeGatewayTargets`).
   Against a read-only memory binding (5 actions), that is a gap of the remaining
   actions, i.e. the near-total over-grant this metric is built to quantify.
4. Rows are extended only with actions that appear in the reference. A binding we
   cannot map to referenced actions is excluded from the required set rather than
   guessed.
