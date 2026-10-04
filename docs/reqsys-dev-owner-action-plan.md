# Owner exception for PC24x7 DEV candidate preparation only

Default is a read-only plan. The registry can register only
reqsys.selfhost.publisher.prepare.dev at scope
repo://reqsys/environment/dev/selfhost, for the fixed Windows owner on
DESKTOP-PDQK954 and the reviewed ReqSys source commit.

Receiver/RSA initialization is not part of this registry. Any existing receiver
action and all unrelated configuration fields/actions remain unchanged.
development_mode stays disabled and unchanged. The launcher keeps its two closed
legacy phases for compatibility; the prepare-only registry grants only prepare.
The existing launcher schema marker is retained to avoid changing the pinned
ReqSys source solely for this narrowing.

Provide only --source-sha, --prepare-script-sha256 and
--launcher-script-sha256. The source root is derived as
C:\dev\chatgpt-workers\rs2-{source_sha}; no path, URL, executable, action ID,
scope, recipient digest, or lifetime argument is accepted. The registry validates
Git origin/root/HEAD/clean worktree/index flags and the tracked publisher and
launcher hashes. Git optional writes and global/system configuration are disabled.

The safe plan contains one action ID/scope/script hash, source and launcher hashes,
expiry, hashed diff and plan_sha256. No private configuration values or owner
fingerprint are printed. No file or ACL is changed by planning.

Apply requires the user's explicit approval of the concrete plan, followed by
--apply --reviewed-plan-sha256 <reviewed digest>
--confirm GRANT-REQSYS-DEV-PREPARE-ONE-HOUR using the same three SHA fields.
Nothing invokes this automatically. Expiry is the next start of an hour in UTC,
giving at most one hour. Crossing the hour or changing any reviewed config/input
requires a new plan. Replay does not extend expiry. Expired grants owned by this
helper require --renew-expired plus
--confirm RENEW-REQSYS-DEV-PREPARE-ONE-HOUR and a newly reviewed plan digest.
Collisions and active grants bound to another source fail closed.

The existing owner configuration must already be version 1 and enabled.
Trusted legacy ACLs owned by the current user or Administrators are read internally;
all ACEs must name only the current user, SYSTEM or Administrators, and explicit
current-user access must exist. Unknown/public principals fail before bytes are read.
The read-only plan reports only the owner category; it never changes a file or ACL. Apply creates a private temporary file,
sets current OWNER and protected owner+SYSTEM DACL before writing any bytes,
flushes/fsyncs, confirms the original reviewed bytes, then replaces atomically.
The shared directory and audit files are never re-ACLed.

The workflow invokes the existing OwnerGateway with the prepare action ID, exact
scope, owned source/session cwd, timeout 900, and correlation ID, without an ad-hoc
command after "--". The pinned launcher requires an active private grant and
revalidates owner, expiry, source and hashes at every execution. Its only child is
the fixed publisher prepare operation; it does not restore data or activate a
route. A prepared candidate remains usable=false until its independent restore,
authentication and route checks pass.

Expiration blocks further preparation automatically. It does not remove private
candidate credentials, change the DEV pointer, or remove unrelated exceptions.
Earlier removal must be a separately reviewed operation deleting only the exact
prepare action after verifying this helper's marker; never delete the entire
owner configuration or enable broad development mode.
