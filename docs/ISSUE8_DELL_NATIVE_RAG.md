# Issue #8 — Dell native Qwen RAG preflight

This is a **read-only physical qualification** of the existing authorized issue #8. It does not implement or certify an autonomous patch, CAS publication or draft PR. It reuses `engineering-worker-pool@74035488dac6938bfc14957621e86168003cd0c6`, official owner authorization comment #6404265064, and `agent-core@1fc032d4c412bdb4ed202cf1193caf0cb49490ce`.

Noteri's latest physical canary [#40247590037](https://github.com/ericson-j-santos/noteri-runtime/actions/runs/40247590037) was fail-closed with `native_model_ambiguous_or_missing`. Do not install, rename or download a model to bypass attestation. Dell successfully executed native Qwen with the matching GGUF digest in [#40221994125](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40221994125). This experiment qualifies *issue-specific* evidence on that alternative host instead of repeating Noteri's known blocker.

Gate: PR draft, one-shot body marker `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_ONCE` added only **after** Windows/Linux required CI; hosted admission checks current repo main, Worker Pool main SHA, OWNER authorization, exact source blob, canonical rules and four-file scope. Physical runner must be DESKTOP-PDQK954-runtime (ID 2); exact SHA checkouts, Session Launcher `SESSION_LAUNCH_OK`, Command Gateway risk-2 isolated venv and risk-1 issue RAG, real 42-case baseline with failure, local Qwen with pinned GGUF digest, immutable GitHub citation and independent hosted readback. Watchdog blocks without pickup in 300 seconds. All artifact data bounded, no credentials in source/logs. GitHub artifact retention is 2 days.

No Docker on Dell, no cloud inference, no service install, no patch, no CAS write, no model-directed command, no merge/deploy. A failure requires evidence-based repair, not a blind retry. Even full success leaves the next task pending: one real Qwen patch -> CAS git bundle -> independent validator 42/42 + 52/52 -> exactly one agent-generated draft PR -> readback/replay.

SHA rule pin: 92e8b5c87684212964b24ff3597f9f9f8aea49a6. Correlation: `issue8-dell-native-rag-20261026`.

The hosted contract also installs pinned PyYAML. Admission now enforces
exactly five authorized paths including the CI syntax check, and GitHub GET
requests use only the existing bounded token supplied through Actions env.

## Result of first Dell issue-bound probe

Run [#40368039499](https://github.com/ericson-j-santos/desktop-pc24x7-runtime/actions/runs/40368039499) established the authenticated issue #8, physical runner ID 2, Session Launcher and Gateway, and actually invoked Qwen. It then blocked with `issue8_real_rag_not_verified` (the original combined condition did not isolate refusal, head drift, model process, readback or call count). Independent source readback was skipped as required.

This revision **does not relax** the RAG acceptance. It emits one of the finite reason codes under `issue8_rag_*`, including a model decision of insufficient evidence, while keeping the workflow fail-closed. The previous one-shot marker is consumed. Only a separate owner-only body transition to `OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_REASON_V2_ONCE`, after SHA-specific Windows/Linux CI and renewed admission, authorizes another physical diagnostic run. Do not retry if no material change was made.
