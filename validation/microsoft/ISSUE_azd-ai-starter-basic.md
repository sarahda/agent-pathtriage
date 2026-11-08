# Issue draft

**Repository:** `Azure-Samples/azd-ai-starter-basic`
**Channel:** public GitHub issue
**Title:** Every project connection is created with `isSharedToAll: true`, and `sharedUserList` is declared but never used

---

Hello,

I am a masters student at UNSW Sydney measuring how permissions compose across
agents running in the same Foundry project. This template came up while reading
public infrastructure as code. This is a question about the connections it
creates rather than a bug report.

### What I read

`infra/core/ai/connection.bicep` takes `isSharedToAll` as optional and falls
back to true:

```bicep
// line 24
isSharedToAll: bool?

// lines 41 and 42
@description('List of users to share the connection with (optional, alternative to isSharedToAll)')
sharedUserList: string[]?

// line 91
isSharedToAll: connectionConfig.?isSharedToAll ?? true
```

Every connection the template creates also sets it to true explicitly:

| Connection | File and line | `authType` |
|---|---|---|
| Storage blob | `infra/core/storage/storage.bicep:99` | `AAD` |
| AI Search | `infra/core/search/azure_ai_search.bicep:186` | `AAD` |
| Bing grounding | `infra/core/search/bing_grounding.bicep:62` | `ApiKey` |
| Bing custom grounding | `infra/core/search/bing_custom_grounding.bicep:62` | `ApiKey` |
| Container registry | `infra/core/host/acr.bicep:72` | `ManagedIdentity` |
| Application Insights | `infra/core/ai/ai-project.bicep:185` | `ApiKey` |
| Existing container registry | `infra/core/ai/ai-project.bicep:264` | `ManagedIdentity` |

`sharedUserList` is declared in the same file as the alternative, and no call
site uses it.

### Why it matters where a project holds more than one agent

A connection shared to all is reachable by all of them, so the agent with the
smaller job reaches whatever the connection is trusted with. For the three
`ApiKey` connections the credential is stored in the connection, so the target
sees one caller and its logs cannot tell the agents apart.

Setting `isSharedToAll: false` scopes a connection to its creator and would
break the agents this template deploys, so who should see each connection is a
decision about the sample rather than a mechanical change.

### The questions

1. Is `isSharedToAll: true` on every connection a deliberate choice for a
   single project starter, or a default that was never revisited? If it is
   deliberate, a comment saying so would save the next reader the same
   question.

2. `sharedUserList` is declared but unused. Is it there for consumers of the
   module, or is it a leftover?

3. For the Application Insights connection, Microsoft documents an identity
   path: a connection created with **Project Managed Identity** auth, with
   **Monitoring Metrics Publisher** granted to the project managed identity on
   the Application Insights resource, and the same role granted to the Agent
   Identity for hosted agents
   ([docs](https://learn.microsoft.com/en-us/azure/foundry/observability/how-to/trace-ingestion-entra-authentication)).
   That is in preview and documented as not recommended for production, so I
   am not suggesting it as today's default. Is it the intended direction for
   this connection once it leaves preview?

### Scope

`infra/core/ai/connection.bicep` is byte identical in 11 copies across 10
public repositories, including `Azure-Samples/fibey`,
`Azure-Samples/m365-multi-agent-workflow` and
`Azure/microsoft-agent-framework-foundry-starter-pack-net`. I am asking here
rather than in each of them because the answer looks like it belongs to the
template. Happy to move it if this is not the right place.
