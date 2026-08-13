# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-boundary-search-005
STATUS: READY

## Starting point
The previous command `2026-08-13-fzdp-b9-004` completed successfully.

Preserve these VERIFIED facts:
- CXDF B5 has a dynamically satisfiable Download-Mode entry-policy helper (`0xC6ED0`) and a reachable long-press/confirmation route.
- FZDP B9 has helper `0xCABE0`, 100%-normalized to EZB6 `0xCA790`, and returns false unconditionally.
- EZB6 B9 likewise hard-disables the normal Download-Mode long-press route.
- FZDP and EZB6 retain the same persistent transition architecture and privileged EM-token processing, but no authorized consumer-unlock EM-token mode/workflow is established.
- Therefore the hard-disable boundary is earlier than FZDP B9 and later than the known CXDF B5 baseline.

Read only the compact current state plus `codex_context/reports/FZDP_B9_ENTRY_COMPARISON.md` as needed. Do not redo the completed FZDP analysis.

## Primary objective — locate the first hard-disable boundary efficiently
Use a revision-aware historical search, not a broad firmware crawl.

Public SM-S911B/EUX history identifies useful intermediate revisions between CXDF B5 and FZDP B9. Verify build identities independently before using them.

### First probe: earliest public B8
Prioritize:
- `S911BXXU8CYB4` — binary B8, Android 14-era EUX build.
- Expected BL child filename pattern: `BL_S911BXXU8CYB4_S911BXXU8CYB4_*_user_low_ship_MULTI_CERT.tar.md5.zip` or equivalent unmodified BL archive.

1. First inspect the local workspace for this exact build or any already-present B6/B7/B8 SM-S911B BL/ABL input. Do not repeat broad scans if a targeted `find`/`rg` is sufficient.
2. If absent, external retrieval is now justified because missing historical firmware is the explicit blocker. Search reputable/public firmware sources for the exact SM-S911B EUX build and obtain only the BL child archive if a normal direct/public download is available.
3. Do not download the multi-gigabyte AP/full firmware when a ~BL-only package is available.
4. Do not bypass authentication, paywalls, anti-bot controls, access restrictions, or fabricate download URLs. If a normal CLI-accessible BL download is unavailable, stop acquisition cleanly and report the exact build + BL filename the user must supply manually.
5. Before placing any downloaded firmware input, create/use a clearly local-only ignored directory such as `bl_packs/firmware_inputs/` and ensure Git ignores it. Never stage or push firmware binaries, archives, extracted ABLs, PE bodies, or large generated binary artifacts.

## Analysis for each acquired candidate
Reuse the existing CXDF/FZDP/EZB6 extraction and comparison workflow.

For the candidate LinuxLoader:
1. Locate the counterpart of CXDF `0xC6ED0` / FZDP `0xCABE0` / EZB6 `0xCA790`.
2. Recover the two normal Download-Mode event-loop call sites.
3. Determine whether the helper is dynamically satisfiable or unconditional-false.
4. Trace the ~4000 ms Volume-Up path and confirmation handler far enough to classify normal locked→unlocked reachability.
5. Map the persistent transition counterpart and direct/tail caller topology only as far as needed to confirm architectural equivalence.
6. Record OEM/FRP/OEM-LOCK diagnostics only when they materially help date the policy transition.
7. Keep VERIFIED / INFERENCE / UNKNOWN separated.

## Adaptive boundary search
Do not stop after merely classifying the first B8 candidate if another small BL-only probe can materially narrow the boundary.

Use this strategy:
- If earliest B8 (`S911BXXU8CYB4`) is HARD-DISABLED, next test the latest B7 build available near the B7→B8 boundary (prefer `S911BXXS7CXL2` if verified).
- If earliest B8 is DYNAMIC/REACHABLE, the boundary is later; test a late B8 build near B8→B9 (prefer `S911BXXS8EZA1` if verified), then bisect within B8 only if necessary.
- If latest B7 is HARD-DISABLED, step backward to the latest/earliest useful B6 boundary candidate (for example verified B6 builds around `S911BXXS6CXI4` / `S911BXXU6CXH7`) and continue revision-aware narrowing.
- If latest B7 is DYNAMIC, the boundary is localized to B7→B8 and no B6 probe is needed.

Prefer the minimum number of ~BL-only downloads needed to localize the first firmware boundary. Do not collect every historical firmware build.

## Decision goal
Produce the narrowest evidence-supported interval/build where Samsung changed the normal Download-Mode consumer unlock entry from dynamic/reachable to hard-disabled.

The key question is not whether old firmware can be flashed to the current device. This is historical offline analysis only. Never treat an older binary as flash authorization.

## Secondary check
For any candidate already extracted for LinuxLoader, inspect Odin only if it is cheap and only for a material divergence in EM-token mode/command semantics. Do not spend broad effort re-proving the already-known privileged EM-token mechanism unless a candidate reveals a consumer-relevant difference.

## Required outputs
Create/update concise textual evidence, including:
- `codex_context/reports/UNLOCK_ENTRY_BOUNDARY.md` — cumulative compact boundary table and evidence.
- `codex_context/DEVICE_UNLOCK_PLAN.md`
- `PROJECT_STATE.md`
- `CHECKPOINT.md`
- `NEXT_TASK.md`
- `ROADMAP.md`
- `EVIDENCE_LEDGER.csv`
- `REPORT_INDEX.md`
- `CODEX_STATUS.md`

If acquisition is blocked before any new binary can be analyzed, `CODEX_STATUS.md` should use `RESULT: NEEDS_INPUT` and provide the single highest-value exact BL archive/build for the user to supply next. Do not generate a fake analysis result.

## Git / coordination
- Follow the established remote-inbox rule in `AGENTS.md`: fetch `origin/main` and treat the remote inbox as authoritative.
- Preserve unrelated local changes.
- Never commit firmware inputs or extracted binaries.
- Stage only meaningful textual reports/state/checkpoint files and any deliberate `.gitignore` rule needed for the local input directory.
- Commit with a short 3–5-word English message and push automatically.
- Continue autonomously through the adaptive probes while normal BL-only acquisition is available and high-information; stop only at a precise external-input blocker or a well-localized policy boundary.

## Safety
Offline static analysis only. Do not flash, downgrade, patch ABL, modify trusted state, install/generate/replay EM tokens, or perform destructive device operations.
