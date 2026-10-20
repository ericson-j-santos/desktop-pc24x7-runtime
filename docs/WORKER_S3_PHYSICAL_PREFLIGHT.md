# Worker Pool S3 physical preflight on Desktop

`scripts/desktop_worker_s3_preflight.py` is the bounded bridge between the
Desktop's DPAPI-protected credential and the S3 Git-bundle transport implemented
by `engineering-worker-pool`.

It performs one operation: instantiate the transport from a verified, clean
Worker Pool checkout and call its immutable preflight. The transport performs a
conditional `PutObject` followed by bounded `GetObject` and exact byte
comparison. Repeating the probe is safe: the existing immutable object must
return an explicit precondition failure and the same bytes must still be read.

The script does not start a worker, acquire a lease, execute a task, install a
credential, or assert S4U merely because DPAPI decryption succeeded.

## Preconditions

- Run on `DESKTOP-PDQK954` through a validated session and Command Gateway.
- Install the credential with the procedure in
  `docs/WORKER_S3_CREDENTIAL_BOOTSTRAP.md`.
- Materialize clean runtime and Worker Pool worktrees at their exact published
  commit and tree SHAs.
- Keep the credential limited to `PutObject` and `GetObject` under the approved
  preflight and Git-bundle prefixes. Do not grant bucket administration,
  deletion, or broad listing.
- Place the output outside either Git worktree, preferably in the governed
  runtime evidence directory.

## Invocation contract

Invoke the script via the Command Gateway with these non-secret inputs:

- `--expected-runtime-sha` and `--expected-runtime-tree`;
- `--worker-pool-root`, `--expected-worker-pool-sha`, and
  `--expected-worker-pool-tree`;
- a unique `--correlation-id`;
- approved `--bucket`, `--region`, `--endpoint-url`, and `--key-prefix` route
  values;
- an absolute `--output` path outside the repository.

Credential JSON is never an argument to this command. The protected store is
opened only by the current process identity. Do not place raw route values in a
public workflow artifact or PR comment; successful evidence contains only their
SHA-256 binding.

## Evidence and interpretation

`DESKTOP_WORKER_S3_PREFLIGHT_PASSED` proves, for the recorded SHAs and process:

- the protected credential was decrypted by the current Windows identity;
- an explicit SigV4/path-style client reached the configured private route;
- the Worker Pool conditional-write and exact-readback contract passed;
- runtime and Worker Pool checkouts remained clean and unchanged;
- no task was executed and no `AWS_*` value was mutated by the wrapper.

It does not independently prove that the process was launched as the intended
S4U principal. The physical acceptance workflow must establish that execution
context independently, invoke this script, read back the evidence, and retain
the exact run/job identity. Until that run exists, the Desktop route remains
prepared but not physically homologated.

Any other result is blocked. Failure evidence uses only a closed-set reason and
must never include exception text, raw route values, or credential material.
