### Context

An AI Foundry account and each of its projects can hold **connections**, and a
connection's `authType` decides what the account presents when it reaches the
target. Some values are directory identities (`AAD`, `ManagedIdentity`,
`ServicePrincipal`, and the agent identity types). The rest are a credential
stored in the connection (`ApiKey`, `AccountKey`, `AccessKey`, `CustomKeys`,
`PAT`, `SAS`, `UsernamePassword`).

Prowler already checks this at the account level with
`aiservices_account_local_auth_disabled`, which asks whether the account will
accept a key. This check asks the matching question one level down: whether the
account itself is presenting a key to something else.

The difference matters most where several agents share a project. A connection
that holds a key is presented identically by every agent that can use it, so
the target's logs cannot tell them apart, and each agent reaches everything the
connection is trusted with rather than only what its own job needs.

This is not tracked in an open issue. It comes out of a survey of public Azure
Foundry infrastructure as code, described at the end of this description.

### Description

A new Azure check, `aiservices_connection_identity_based_auth`, with one
finding per connection on both account level and project level connections.

| `authType` | Status |
|---|---|
| `AAD`, `ManagedIdentity`, `ServicePrincipal`, `OAuth2`, the agent identity types | PASS |
| `ApiKey`, `AccountKey`, `AccessKey`, `CustomKeys`, `PAT`, `SAS`, `UsernamePassword` | FAIL |
| `None` or empty | FAIL |
| anything else | MANUAL |

MANUAL rather than a guess, for two reasons. The service accepts `authType`
values that `ConnectionAuthType` in `azure-mgmt-cognitiveservices` 14.1.0 does
not list, so an unrecognised value is expected rather than exceptional, and
calling one safe or unsafe without knowing it would be made up. An account
whose connections could not be listed is reported MANUAL too, so an unread
account does not read as an account with no connections.

What the diff contains:

- `aiservices_service.py` gains a `Connection` model and fetches connections
  for each account, from `account_connections.list` and, for each project,
  `project_connections.list`. Both operations exist in the pinned SDK version,
  so nothing in `pyproject.toml` changes.
- The check, its metadata, and its tests.
- A changelog fragment under `prowler/changelog.d/`.

`auth_type` is kept as the string the service returned rather than mapped onto
the SDK enum, so values the enum does not carry are not dropped on the way in.

Listing projects fails on account kinds that do not have them, which is normal
and is logged at warning level rather than treated as a finding.

No dependency change. `account_connections`, `projects` and
`project_connections` all exist in `azure-mgmt-cognitiveservices==14.1.0`,
which is already pinned.

### Steps to review

```bash
pytest tests/providers/azure/services/aiservices/
pytest tests/lib/check
```

On this branch those pass 96 and 4475. The 96 are the 11 new cases plus the 85
that already covered the service. `tests/lib/check` is where the new check's
metadata is validated, so it is the one that catches a malformed addition.

The 11 cases cover no resources, an account with no connections, connections
that could not be listed, each status above, a project level connection naming
its project, and several connections on one account.

Two review points worth a second opinion:

- Whether an empty or absent `authType` should be FAIL, as here, or MANUAL.
  It is FAIL because the deployed default for a connection without an explicit
  `authType` is a stored credential, not an identity.
- Whether project level connections belong in this check or in a separate one.
  They are here because the resource and the field are the same, and the
  finding carries the project name so the two can be told apart in output.

### Checklist

<details>

<summary><b>Community Checklist</b></summary>

- [ ] This feature/issue is listed in the [open issues](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or roadmap.prowler.com
- [ ] Is it assigned to me, if not, request it via the [open issues](https://github.com/prowler-cloud/prowler/issues?q=sort%3Aupdated-desc+is%3Aissue+is%3Aopen) or [Prowler Community Slack](https://goto.prowler.com/slack)
- [x] I have reviewed the [open pull requests](https://github.com/prowler-cloud/prowler/pulls?q=sort%3Aupdated-desc+is%3Apr+is%3Aopen) and confirmed there is no existing PR that implements the same outcome

</details>

The first two are unticked. This check is not in the open issues and is not
assigned, so it arrives unsolicited. Happy to open an issue first and have it
assigned if that is the preferred route.

- [x] Review if the code is being covered by tests.
- [x] Review if code is being documented following this specification https://github.com/google/styleguide/blob/gh-pages/pyguide.md#38-comments-and-docstrings
- [ ] Review if backport is needed.
- [x] Review if is needed to change the [README.md](https://github.com/prowler-cloud/prowler/blob/master/README.md) (no change needed)
- [x] Ensure a changelog fragment is added under [prowler/changelog.d/](https://github.com/prowler-cloud/prowler/tree/master/prowler/changelog.d), if applicable.

#### SDK/CLI
- Are there new checks included in this PR? **Yes**, one: `aiservices_connection_identity_based_auth`.
    - Permissions: no change. The check adds only control plane list calls,
      `account_connections.list` and `project_connections.list` under
      `Microsoft.CognitiveServices/accounts`, which the built-in `Reader` role
      already grants. No secret is read: connection secrets come from a
      separate `listSecrets` operation that this check does not call, so
      nothing here needs `ProwlerRole`.

### License

By submitting this pull request, I confirm that my contribution is made under the terms of the Apache 2.0 license.

---

### Where this came from

A masters research project at UNSW Sydney measuring how IAM permissions
compose across agents that run on the same platform. The survey read 16450
template directories from 360 public repositories and found 516 configured
`authType` values in the 210 directories that declare a Foundry or Azure ML
connection resource: `AAD` 279, `ApiKey` 161, `ManagedIdentity` 44,
`CustomKeys` 13, `ProjectManagedIdentity` 8, `AccessKey` 4, and one each of
`AccountManagedIdentity`, `AccountKey`, `PAT`, `SAS`, `ServicePrincipal`,
`UsernamePassword` and an empty value.

So 183 of 516, about 35 percent, store a credential in the connection, which
is the subset this check reports. `authType` is also a field on
`Microsoft.Logic`, `Microsoft.AppPlatform` and `Microsoft.ServiceLinker`, and
those are counted separately rather than folded in, since they are not
connections of this kind.

The same survey found that the per agent identity types appear in template
parameter lists as allowed values and are never the default. That part is not
expressible as a check against deployed state, so it is not what this check
tests.
