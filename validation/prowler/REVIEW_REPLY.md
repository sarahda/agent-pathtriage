Thanks for the review. Both points are fixed in `1193a1a`.

**Project connections omitted when the list call fails.** Agreed, and the same
gap was one level up: when `account_connections.list` failed while
`projects.list` succeeded, the account's own connections were dropped the same
way. `_get_connections` now returns the scopes whose connections could not be
listed alongside the connections themselves, `""` for the account's own scope
and the project name for a project, and the check reports one MANUAL per scope.
An account kind that has no projects at all still produces no finding, since
that call is expected to fail there and is not evidence of anything unread.

**Finding location.** Fixed. Findings now carry the parent `account.location`,
the same way `storage_smb_protocol_version_is_latest` does, so connection
findings no longer fall back to the global default.

**Docstring coverage.** Every definition this branch adds now has one, 34 of 34.
The pre-existing functions in `aiservices_service_test.py` are left alone so the
diff stays on this change.

Tests go from 96 to 105. The new cases cover a project whose connections could
not be listed, the account scope failing while its projects are read, the
location on both kinds of finding, and the service level branches behind all of
that, which had no direct coverage before. `tests/lib/check` passes 4475.
