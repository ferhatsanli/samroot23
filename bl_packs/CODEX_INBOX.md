# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-fzdp-b9-004
STATUS: READY

## Coordination-sync fix — do this first
The previous loop rule was too conservative: a dirty worktree could prevent Codex from seeing a newer GitHub inbox. Fix this permanently.

At the start of this command:
1. Run `git fetch origin main` from anywhere inside this repository.
2. Treat the newest remote inbox as authoritative even if the worktree is dirty. Read it directly with `git show origin/main:bl_packs/CODEX_INBOX.md` when necessary; do not require a clean worktree merely to discover a new command.
3. Add a compact permanent rule to `AGENTS.md` under `GitHub coordination loop`:
   - on every `continue`/`devam`/`updated`, first `git fetch origin main`;
   - inspect the remote inbox with `git show origin/main:bl_packs/CODEX_INBOX.md` and compare its `COMMAND_ID` with `CODEX_STATUS.md`;
   - a dirty worktree must NOT prevent reading/executing a newer remote command;
   - never discard local changes just to sync;
   - before final commit/push, integrate remote history safely, preserving unrelated local changes and stopping on real conflicts instead of guessing.
4. The local uncommitted `.gitignore` and `.DS_Store` changes are expected and must not block command discovery.

## Starting point
The GitHub coordination loop bootstrap completed successfully under `2026-08-13-bootstrap-002`.

Preserve these established facts:
- Device/build: SM-S911B/DS on `S911BXXS9EZB6`, binary B9.
- EZB6 Download-Mode interactive unlock entry is hard-disabled by `0xCA790` returning false unconditionally.
- EZB6 retained interactive confirmation/transition code exists but is skipped by the normal event loop.
- EZB6 LinuxLoader has only two recovered direct/tail callers of `0x26020`: blocked interactive `0xD4BAC` and boot-time EM reconciliation `0x9324`.
- EZB6 Odin has a privileged Samsung EM-token install/verification mechanism, but no consumer-unlock token mode or permitted end-user workflow is established.
- Physical Android-policy evidence is already incorporated into project state.

## New local input available
A same-binary B9 FZDP BL archive is present locally at:

`/Users/ferhatsanli/Desktop/samroot/bl_packs/FZDP/BL_S911BXXU9FZDP_S911BXXU9FZDP_MQB109002558_REV00_user_low_ship_MULTI_CERT.tar.md5`

Repository root:
`/Users/ferhatsanli/Desktop/samroot`

Important Git rules:
- `bl_packs/FZDP/` is intentionally local-only and should be ignored by Git.
- Never add/commit/push the FZDP BL archive, extracted firmware binaries, UEFI bodies, or large generated binary artifacts.
- The local `.gitignore` addition `/bl_packs/FZDP/` is intended and may be committed.
- Existing `.DS_Store` changes are unrelated and may remain unstaged.

## Primary objective — FZDP B9 entry-policy comparison
Use the unmodified local FZDP BL archive for offline static analysis only.

1. Record the exact archive identity and SHA-256 in the textual report.
2. Extract only what is needed. Recover `abl.elf` from `abl.elf.lz4`, then extract the UEFI LinuxLoader PE body. Recover the Odin PE body too if practical with the existing extraction workflow.
3. Reuse existing scripts, UEFI extraction knowledge, reports, and CXDF/EZB6 mappings; do not rebuild the workflow unnecessarily.
4. Locate the FZDP function equivalent to:
   - CXDF LinuxLoader `0xC6ED0` — dynamic Download-Mode entry-policy helper.
   - EZB6 LinuxLoader `0xCA790` — unconditional-false replacement.
5. Recover both FZDP event-loop call sites corresponding to the known CXDF/EZB6 long-press gates and determine whether FZDP:
   - can return true dynamically,
   - is hard-disabled like EZB6,
   - uses a different predicate/authorization mechanism,
   - or removes/rewires the route.
6. Trace FZDP through `LongPressVolUpkeyCheck(~4000 ms)` and its confirmation handler far enough to establish whether the native locked→unlocked transition is legitimately reachable in normal FZDP Download Mode.
7. Map the FZDP counterpart of the persistent transition (`CXDF 0x25EE0`, `EZB6 0x26020`) and compare normalized structure and caller topology. Do not redo VaultKeeper/tz_kg unless FZDP introduces a material contradiction.
8. Produce a concise three-way CXDF B5 vs FZDP B9 vs EZB6 B9 comparison covering:
   - entry-policy helper behavior,
   - event-loop reachability,
   - long-press confirmation reachability,
   - transition caller topology,
   - materially relevant OEM/FRP/OEM-LOCK diagnostics.

## Secondary objective — FZDP Odin / EM channel
If the FZDP Odin PE is available without broad extra work:
1. Compare its EM-token install/verification path with EZB6 Odin.
2. Determine whether FZDP exposes any token mode, command, or authorization path that materially clarifies consumer bootloader unlock.
3. Static analysis only: do not install, generate, request, replay, or fabricate tokens.
4. Keep VERIFIED / INFERENCE / UNKNOWN strictly separated.

## Decision goal
Resolve this question:

**Did FZDP, despite also being binary B9, still retain a legitimately reachable native Download-Mode unlock-entry path that EZB6 later hard-disabled?**

If YES:
- identify the first meaningful FZDP→EZB6 divergence that disables it;
- determine whether it is a code-policy change rather than a KG/FRP runtime prerequisite;
- do not infer flashing safety merely from shared B9 revision.

If NO:
- establish how early the hard-disable already exists in FZDP and update the historical boundary.

If parsing/extraction fails:
- document the exact blocker and cheapest next step rather than broadening analysis.

## Required outputs
Create/update concise textual evidence only, including at minimum:
- `codex_context/reports/FZDP_B9_ENTRY_COMPARISON.md`
- `codex_context/DEVICE_UNLOCK_PLAN.md`
- `PROJECT_STATE.md`
- `CHECKPOINT.md`
- `NEXT_TASK.md`
- `ROADMAP.md`
- `EVIDENCE_LEDGER.csv`
- `CODEX_STATUS.md`
- `AGENTS.md` for the permanent remote-inbox sync fix.

`CODEX_STATUS.md` must use the established fixed handoff format and list all meaningful changed files.

## Git / completion protocol
- Preserve unrelated local modifications.
- Never stage anything under `bl_packs/FZDP/`.
- Stage only meaningful textual project changes plus the intended `.gitignore` and AGENTS sync-rule update.
- Use a short 3-5 word English commit message.
- Push automatically when complete.
- If remote history advanced during the run, integrate safely without discarding local changes.
- Do not stop at an intermediate function/address; continue until FZDP entry-policy/reachability is resolved or reduced to a precise blocker.

## Safety
Offline static analysis only. Do not flash FZDP, downgrade firmware, patch ABL, modify trusted state, install EM tokens, or treat same binary revision as proof of flash compatibility.
