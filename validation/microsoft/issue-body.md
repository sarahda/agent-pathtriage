I am a masters student at UNSW Sydney looking at how permissions compose across agents that run in the same Foundry project. Three questions about the connections this template creates.

`infra/core/ai/connection.bicep` defaults `isSharedToAll` to true:

```bicep
line 24   isSharedToAll: bool?
line 42   sharedUserList: string[]?   // "optional, alternative to isSharedToAll"
line 91   isSharedToAll: connectionConfig.?isSharedToAll ?? true
```

Every call site also sets it to true:

| Connection | File and line | `authType` |
|---|---|---|
| Storage blob | `infra/core/storage/storage.bicep:99` | `AAD` |
| AI Search | `infra/core/search/azure_ai_search.bicep:186` | `AAD` |
| Bing grounding | `infra/core/search/bing_grounding.bicep:62` | `ApiKey` |
| Bing custom grounding | `infra/core/search/bing_custom_grounding.bicep:62` | `ApiKey` |
| Container registry | `infra/core/host/acr.bicep:72` | `ManagedIdentity` |
| Application Insights | `infra/core/ai/ai-project.bicep:185` | `ApiKey` |
| Existing container registry | `infra/core/ai/ai-project.bicep:264` | `ManagedIdentity` |

Where a project holds more than one agent, every connection is reachable by all of them. For the three `ApiKey` ones the credential is stored in the connection, so the target sees one caller and its logs cannot tell the agents apart.

1. Is `isSharedToAll: true` on every connection deliberate for a single project starter, or a default that was never revisited?

2. `sharedUserList` is declared in the same file as the alternative, and no call site uses it. Is it for consumers of the module, or a leftover?

3. For Application Insights, Microsoft documents a Project Managed Identity path with Monitoring Metrics Publisher granted on the resource ([docs](https://learn.microsoft.com/en-us/azure/foundry/observability/how-to/trace-ingestion-entra-authentication)), currently in preview and documented as not recommended for production. Is that the intended direction for this connection?

This file is byte identical in 11 copies across 10 public repositories, including `Azure-Samples/fibey` and `Azure-Samples/m365-multi-agent-workflow`, so I am asking here rather than in each of them.
