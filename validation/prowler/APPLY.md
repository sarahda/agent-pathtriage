# Prowler contribution: aiservices_connection_identity_based_auth

Status: pull request open at prowler-cloud/prowler#13306, review feedback
addressed, waiting on a maintainer.

| | |
|---|---|
| Fork | `sarahda/prowler` |
| Branch | `aiservices-connection-identity-based-auth` |
| Commits | `c1fd936` feat(azure): add aiservices_connection_identity_based_auth |
| | `1193a1a` fix(azure): report unlisted connection scopes and carry the account location |
| Based on | `9f6ebb0`, the fork's master at first push |

The second commit answers the automated review on the pull request. It reports
a scope whose connections could not be listed as MANUAL instead of leaving it
out, sets each finding's location from the parent account, and documents every
definition the branch adds. `REVIEW_REPLY.md` is the reply posted with it.

The branch was rebased onto current master before pushing, so the PR applies to
the head of the repository rather than to a commit 53 behind it.

## What is left: open the pull request

```bash
pbcopy < validation/prowler/PR_BODY.md
```

Then open this link, paste into the description box, and click Create pull
request. The title is already filled in.

```
https://github.com/prowler-cloud/prowler/compare/master...sarahda:aiservices-connection-identity-based-auth?expand=1&title=feat%28azure%29%3A+add+aiservices_connection_identity_based_auth
```

The body follows the repository's pull request template, so paste over the whole
template including its checklist. Two of the community checklist boxes are left
unticked on purpose, with a line saying why: the check is not in the open issues
and is not assigned, so it arrives unsolicited and the maintainers may want an
issue first.

## Test results

Run on the pushed commit, `poetry install` plus the `dev` dependency group.

| Command | Result |
|---|---|
| `pytest tests/providers/azure/services/aiservices/` | 96 passed |
| `pytest tests/lib/check` | 4475 passed |
| `black --check` on the added and changed files | unchanged |
| `flake8 --ignore=E266,W503,E203,E501,W605` | clean |
| `bandit -q -lll` | clean |
| `vulture --min-confidence 100` | clean |

The 96 are the 11 new cases plus the 85 that already covered the `aiservices`
service.

`tests/lib/check` matters because `CheckMetadata` validates every check's
metadata at load time. The first run failed there: `Description` and `Risk` are
capped at 400 characters and the first draft was 477 and 453. Both are now 395
and 355, with the same content said shorter. This is the only thing the test
run caught, and it would have failed CI on the first push.

Note for reproducing: this repository declares its dev dependencies under
PEP 735 `[dependency-groups]`, so `poetry install --with dev` does not pick them
up. Install that list directly, or use `uv sync --group dev`.

## Files in the commit

| File | Change |
|---|---|
| `prowler/providers/azure/services/aiservices/aiservices_service.py` | `Connection` model, `_to_connection`, `_get_connections`, `connections` on `Account` |
| `.../aiservices_connection_identity_based_auth/__init__.py` | new |
| `.../aiservices_connection_identity_based_auth.py` | the check |
| `.../aiservices_connection_identity_based_auth.metadata.json` | metadata |
| `tests/.../aiservices_connection_identity_based_auth_test.py` | 11 cases |
| `prowler/changelog.d/aiservices-connection-identity-based-auth.added.md` | changelog fragment, required by the pull request template |

No dependency change. `account_connections`, `projects` and
`project_connections` all exist in `azure-mgmt-cognitiveservices==14.1.0`, the
version already pinned in `pyproject.toml`.

No permission change. The check adds only control plane list calls under
`Microsoft.CognitiveServices/accounts`, which the built-in `Reader` role grants.
Connection secrets come from a separate `listSecrets` operation that this check
does not call, so nothing here needs `ProwlerRole`.

## If the push needs redoing

The patch in this directory is kept in sync with the pushed commit.

```bash
git clone https://github.com/sarahda/prowler
cd prowler
git checkout -b aiservices-connection-identity-based-auth
git apply /path/to/aiservices-connection-identity-based-auth.patch
git add -A
git commit -m "feat(azure): add aiservices_connection_identity_based_auth"
git push -u origin aiservices-connection-identity-based-auth
```
