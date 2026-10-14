# KB route binding physical read-only

## Goal

Run the existing KB route binding collector once on `DESKTOP-PDQK954` and
publish only its sanitized JSON evidence.

## Requirements

- Trigger only when the unique authorization marker
  `.github/kb-route-binding-authorized-once-20261013` is first published on
  `fix/kb-route-binding-readonly-20261009`. Ordinary later changes must not
  schedule another physical collection. This path filter is a trigger gate, not
  a persistent authorization-consumption ledger; do not treat it as proof that
  an authorization cannot be reused.
- Run positive and negative collector contracts before the physical job.
- Checkout the exact runtime revision at `GITHUB_WORKSPACE` and the pinned
  operational rules as the untracked nested checkout `GITHUB_WORKSPACE/_rules`.
  The Session Launcher must validate the tracked runtime source and materialize
  the isolated execution worktree; Command Gateway must run only in that
  returned `target_path`.
- Require the dedicated Desktop runner, `SESSION_LAUNCH_OK`, exact HEAD,
  runner-version preflight, and Command Gateway risk 1.
- Permit only fixed, bounded, non-redirecting GET probes for the local gateway
  and the already-running KB container. Local HTTP must bypass operating-system
  proxy configuration explicitly and enforce a monotonic five-second total
  deadline, including connect, headers and streamed body. A cancelable watchdog
  must retain the connected socket, interrupt it with `shutdown(SHUT_RDWR)`
  at the absolute deadline, close the response and connection, and be joined on
  every exit, so trickled headers or body bytes cannot extend the budget or
  leave a worker.
- Export status, size, digest and strict OpenAPI contract booleans only; never
  export bodies or free-form headers. Invalid or non-object JSON must fail closed.
  The internal KB probe must call the existing `/openapi.json` endpoint without
  importing or starting the application; a local transport/deadline failure is
  represented by the closed summary sentinel status 599, zero bytes and a false
  contract match.
  A successful association requires valid gateway identity plus identical size
  and SHA-256 for strict direct and routed OpenAPI documents.
- Invoke only `scripts/reqsys_kb_route_binding_probe.py` with the fixed relative
  evidence path `artifacts/kb-route-binding/evidence.json`.
- Do not install software on the Desktop, deploy, restart, mutate Docker, routes,
  services, databases, permissions, or read Config.Env, manifest contents,
  credentials, or secrets.
- A blocked collector must remain a failed physical check while its sanitized
  evidence is still uploaded.
