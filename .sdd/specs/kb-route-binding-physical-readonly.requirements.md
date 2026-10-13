# KB route binding physical read-only

## Goal

Run the existing KB route binding collector once on `DESKTOP-PDQK954` and
publish only its sanitized JSON evidence.

## Requirements

- Trigger only when the unique authorization marker
  `.github/kb-route-binding-authorized-once-20261013` is first published on
  `fix/kb-route-binding-readonly-20261009`. Ordinary later changes must not
  schedule another physical collection.
- Run positive and negative collector contracts before the physical job.
- Keep runtime source and pinned operational rules in sibling checkout trees.
- Require the dedicated Desktop runner, `SESSION_LAUNCH_OK`, exact HEAD,
  runner-version preflight, and Command Gateway risk 1.
- Invoke only `scripts/reqsys_kb_route_binding_probe.py` with the fixed relative
  evidence path `artifacts/kb-route-binding/evidence.json`.
- Do not install software on the Desktop, deploy, restart, mutate Docker, routes,
  services, databases, permissions, or read Config.Env, manifest contents,
  credentials, or secrets.
- A blocked collector must remain a failed physical check while its sanitized
  evidence is still uploaded.
