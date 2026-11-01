# Typed Desktop capacity request — preparation, not activation

Status: **local candidate; not merged, triggered or operationally validated**.
Base reviewed: `0159cdd9f06e7221bdc0b10acf884a994fbc1e18`.
Rules reviewed: `78e6706bfbf606945543983305480343d04977f8`.
These are preparation evidence, not permanent runtime pins: each request must
contain the exact current main SHA of both repositories and match the event SHA.

## Issue contract

Only after independent review and an explicitly authorized integration into main,
the existing connector create_issue can submit a request without gh or dispatch.
Do not create a triggering issue during preparation. Title exactly:
`Desktop capacity read-only request v1`.

Body is a JSON object, with precisely these six fields (no Markdown fence):
schema integer 1; request_id canonical lowercase UUIDv4; expected_head_sha and
expected_rules_sha lowercase full Git SHAs; scope
`READ_ONLY_CAPACITY_NO_INSTALL`; audit_claim
`RISK2_AUDIT_ONLY_AT_MOST_ONCE`. Duplicate keys, extras, wrong types, invalid
UUID/SHA/scope and bodies larger than 2048 ASCII characters are rejected.

The owner must be ericson-j-santos, numeric GitHub identity 60470500, both sender
and author. Only issues:opened, main, run_attempt 1, open unedited non-PR issues
are eligible. The issue/event/current API snapshot must agree exactly. Freshness
is 300 seconds, checked after network reads and again on the physical host.
The public GitHub read APIs are called without creating or injecting a token.
Rate limits or inability to prove current state fail closed.

## Deliberate scope refinement

The physical measurements remain Gateway **risk 1** and keep the existing
collector unchanged. Issues additionally consent to one **risk 2 audit-only**
write of a durable consumption receipt. It changes neither installation,
configuration, services, SQL, TLS, permissions nor billing. The separate receipt
declares audit_state_changed=true and configuration_changed=false.
This refinement must be reviewed before activation; it is not disguised as a
purely read-only filesystem operation. Existing manual dispatch behavior remains
available; the new issue-request deduplication contract does not retroactively
make separately requested manual dispatches the same request.

## At-most-once, not guaranteed exactly-once

Hosted admission runs before scheduling Desktop. A duplicate can reach the
physical queue, but cannot collect twice: a request UUID is consumed by exclusive
O_CREAT|O_EXCL creation under the existing protected local CommandGateway state
root, before collection. UUID is independent of issue number, run and source SHA;
changing any of them does not free the consumed request.

Concurrency is additional serialization, not the deduplication proof. The fixed
concurrency group is on the admitted capacity job, not the workflow, so rejected
public issues cannot displace legitimate pending physical requests. Both gated
jobs use !cancelled() rather than always(), preserving user/watchdog cancellation. The claim
is flushed, fsynced and independently read back before success. Existing claims,
including empty, malformed and partial files, always block; never delete or
overwrite them automatically. Crash after creation or before/after measurement
leaves CLAIMED_UNCERTAIN. No automatic reclaim/retry. A genuinely new request
requires a new UUID and full owner admission; that is not crash recovery.
Successful collection evidence remains in the existing workflow log/summary.
No artifact upload or new external CAS is introduced.

## Windows trust boundary and physical gates

State root is the **existing** %LOCALAPPDATA%\\ReqSys\\CommandGateway.
No root creation, chmod, icacls, ACL repair, service or policy changes occur.
Require a fixed local NTFS volume; reject UNC/mapped remote/reparse roots, unsafe ownership/DACLs, ambiguous handles, multiple
hardlinks, failures to flush or read back, and unsupported security descriptors.
Directories are pinned without FILE_SHARE_DELETE during the operation. Root and
claim DACLs permit only the current technical SID and trusted OS principals
(LocalSystem, local Administrators and the exact TrustedInstaller SID), with
current SID ownership. No permission is granted or repaired. Ancestors reject mutation grants to untrusted principals.
The existing OS security boundary trusts local administrators and the exact
TrustedInstaller service SID for ancestors; a compromised administrator or
untrusted code sharing the technical identity is outside this boundary and must
prevent activation. Do not infer host ACL readiness from source code or POSIX
tests. Local stable storage and retention of claims for the lifetime of request
identities are required; deleting ledger state invalidates replay protection.
Storage failure/power loss is not an absolute durability guarantee.

Fixed destination: DESKTOP-PDQK954, runner ID 2, dedicated fixed labels/name.
Launcher version preflight, SHA readback and Gateway remain required. No policy
edit or installation fallback. Queue watchdog remains 300s, with actions:write
only in its existing job. Admission/collection have no added GitHub permission.
Standard hosted Ubuntu admission must remain eligible under the current public
repository zero-incremental-cost policy; no larger runner or paid fallback.

## Validation gates

Portable parser and real-filesystem concurrent-claim tests are local evidence,
not Windows ABI/DACL validation or physical E2E. CI already discovers Python
tests on Linux and Windows. Local affected regressions (including the legacy PyYAML workflow tests and draft
gating) pass; decision mocks are tested separately from native execution. The
full repository suite is not approved: its unchanged baseline also lacks legacy
dependencies in this isolated environment. Windows-native security negative
controls, final independent Validator, current-SHA main readback, and controlled
post-integration physical issue-to-receipt E2E remain required.
No claim of operational completion, no merge, issue creation or dispatch follows
from preparation tests. The new trigger cannot operate until the workflow exists
on main.

Native gate: `tests/test_desktop_gitlab_capacity_windows_native.py` is discovered
by the existing Windows CI pytest job. Its five real Win32 tests use disposable
fixtures: positive claim/replay, concurrency, restored NULL/broad DACL negatives,
reparse/hardlink refusal, and directory-handle rename protection. Linux skips
these five tests with an explicit platform reason; that is **not** Windows
validation. The Windows positive baseline must pass before any negative control;
incompatible fixture ownership, privileges, filesystem or ABI fail the Windows
gate rather than silently skipping it. No production host collection is run by
these CI tests, and no production ACL is changed.
