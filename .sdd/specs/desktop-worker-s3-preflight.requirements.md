# Desktop Worker S3 physical preflight requirements

## Goal

Prove that the fixed Desktop runtime identity can decrypt its protected
credential and exercise the exact conditional-write/readback contract used by
the Engineering Worker Pool durable artifact transport.

## Functional requirements

1. The entrypoint MUST run only through the existing fixed-host credential
   wrapper for `DESKTOP-PDQK954`.
2. Credential values MUST be loaded from the DPAPI CurrentUser store and passed
   directly to one explicit boto3 client. They MUST NOT be accepted on the
   command line, exported through `AWS_*`, written to evidence, or returned by
   the entrypoint.
3. The runtime and Worker Pool checkouts MUST be absolute, physical directories
   with clean tracked and untracked state, the expected commit SHA, and the
   expected Git tree SHA. The checkouts MUST be revalidated after the network
   effect.
4. The Worker Pool implementation MUST be imported from that verified checkout.
   The runtime MUST instantiate `S3ArtifactConfig` and
   `S3GitBundleArtifactTransport` with the explicit client rather than
   duplicating their S3 protocol.
5. Bucket, region, HTTPS endpoint, and key prefix MUST pass both the runtime
   route validator and the Worker Pool transport validator.
6. Success MUST mean that the transport's immutable preflight object received
   either a confirmed conditional create or explicit precondition failure and
   that an exact, bounded readback matched the expected bytes.
7. Evidence MUST bind correlation ID, host, runtime SHA/tree, Worker Pool
   SHA/tree, and a SHA-256 route binding. It MUST NOT contain the raw route,
   credential values, or task data.
8. The script MUST NOT execute a Worker Pool task or claim that S4U was proven.
   S4U validation remains a physical workflow responsibility that invokes this
   entrypoint under the service identity and independently records that context.
9. All unexpected dependency failures MUST collapse to a closed-set reason;
   exception text MUST NOT reach stdout, stderr, or evidence.

## Negative and regression requirements

- A dirty checkout, wrong commit/tree, symlinked contract file, preloaded
  conflicting `app` package, invalid route, failed preflight, or mutation of the
  process-global `AWS_*` environment MUST fail closed.
- Physical path identity MUST be used where Windows can present the same file
  through long and 8.3 aliases; lexical path inequality alone MUST NOT cause a
  false failure or bypass ACL checks.
- Evidence paths inside either the runtime or Worker Pool checkout MUST be
  rejected.

## Operational acceptance gate

Offline tests and hosted CI validate the wrapper and controls. Operational
acceptance additionally requires a run on `DESKTOP-PDQK954`, under the intended
S4U identity, using a least-privilege credential and the exact published SHAs.
The evidence must be read back independently and the Worker Pool and runtime
checkouts must still be clean at those SHAs.
