# Reviewed one-file ACL repair

The default execution is read-only. Apply is unavailable without --apply,
--confirm REPAIR-OWNER-RISK3-SINGLE-FILE-ACL and the exact
--reviewed-plan-sha256 from the same existing descriptor.

A human must approve this concrete one-file repair before invocation. The flags
do not independently supply authorization. Target is only the fixed Windows
owner exception file. The existing owner must be the current user or
Administrators; the individual current user must have effective allow access
(inherited access is accepted, inherit-only access is not). No administrator
elevation, privilege adjustment, shell or arbitrary path is available.

Before changing any DACL, the original OWNER+DACL descriptor is protected with
current-user DPAPI and written to the fixed PrivateAclRepair subdirectory.
That new subdirectory and backup have protected owner-only ACLs. The shared
CommandGateway directory and audit ACLs are unchanged. Existing backup bytes
must decrypt to the same descriptor; they are never overwritten.

The target descriptor is compared before backup and again immediately before
SetFileSecurityW. The operation changes only DACL/protection and preserves the
existing owner. Postconditions require exactly current-user and SYSTEM full
control with a protected DACL. Target JSON bytes and grants are never read or
edited. Backup supplies the original descriptor for a separately reviewed
rollback; it is never published or emitted in logs.

A permission denial fails closed. Any failed postcondition requires review of
the preserved backup before another attempt; no automatic broad-reader fallback
or silent rollback is performed.
