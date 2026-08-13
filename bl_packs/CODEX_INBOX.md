# CODEX_INBOX.md

COMMAND_ID: 2026-08-13-fzdp-b9-003
STATUS: READY

## Starting point
The GitHub coordination loop is already installed and the previous command `2026-08-13-bootstrap-002` completed successfully.

Current verified state to preserve:
- Current device/build: SM-S911B/DS on `S911BXXS9EZB6`, binary B9.
- EZB6 Download-Mode interactive unlock entry is hard-disabled by `0xCA790` returning false unconditionally.
- The retained EZB6 interactive confirmation/transition code exists but is skipped by the normal event loop.
- EZB6 LinuxLoader has only two recovered direct/tail callers of `0x26020`: blocked interactive `0xD4BAC` and boot-time EM reconciliation `0x9324`.
- EZB6 Odin contains a privileged Samsung EM-token install/verification mechanism, but no consumer-unlock token mode or permitted end-user workflow has been established.
- Physical Android policy evidence is already incorporated into project state.

## New local input now available
A same-binary B9 FZDP BL archive is now present locally at:

`/Users/ferhatsanli/Desktop/samroot/bl_packs/FZDP/BL_S911BXXU9FZDP_S911BXXU9FZDP_MQB109002558_REV00_user_low_ship_MULTI_CERT.tar.md5`

Important:
- Repository root is `/Users/ferhatsanli/Desktop/samroot`.
- `bl_packs/FZDP/` is intentionally gitignored locally. Treat the archive and all large/raw extracted FZDP binaries as local analysis inputs only.
- Do NOT add, commit, or push the FZDP archive, extracted firmware binaries, UEFI bodies, or other large generated binary artifacts.
- A local `.gitignore` change adding `/bl_packs/FZDP/` is expected and may be included in this run's commit.
- Existing `.DS_Store` changes are unrelated and need not be staged.

## Primary objective — FZDP B9 entry-policy comparison
Use the unmodified local FZDP BL archive for offline analysis only.

1. Record the exact archive identity and SHA-256 in the textual report.
2. Inspect/extract only what is necessary from the BL archive. Recover `abl.elf` from `abl.elf.lz4`, then extract the UEFI LinuxLoader PE body. Recover the Odin PE body too if practical using the existing extraction workflow/tools.
3. Reuse existing scripts, UEFI extraction knowledge, reports, and CXDF/EZB6 mappings instead of rebuilding the workflow.
4. Locate the FZDP function equivalent to:
   - CXDF LinuxLoader `0xC6ED0` (dynamic Download-Mode entry-policy helper)
   - EZB6 LinuxLoader `0xCA790` (unconditional-false replacement)
5. Recover both FZDP event-loop call sites corresponding to the known CXDF/EZB6 long-press gates and determine whether FZDP:
   - can return true dynamically,
   - is hard-disabled like EZB6,
   - uses a different predicate/authorization mechanism,
   - or removes/rewires the route.
6. Trace the FZDP long-press path through `LongPressVolUpkeyCheck(~4000 ms)` and the confirmation handler far enough to establish whether the native locked→unlocked transition is legitimately reachable in normal FZDP Download Mode.
7. Map the FZDP counterpart of the persistent transition (`CXDF 0x25EE0`, EZB6 `0x26020`) and compare normalized structure/caller topology. Do not re-prove VaultKeeper/tz_kg unless FZDP introduces a material contradiction.
8. Produce a concise three-way comparison table/model for CXDF B5 vs FZDP B9 vs EZB6 B9 showing:
   - entry-policy helper behavior,
   - event-loop reachability,
   - long-press confirmation reachability,
   - transition caller topology,
   - any OEM/FRP/OEM-LOCK diagnostics that materially changed.

## Secondary objective — FZDP Odin / EM channel
If the FZDP Odin PE body is available without broad extra work:

1. Compare its EM-token install/verification path with EZB6 Odin.
2. Determine whether FZDP exposes any token mode, command, or authorization path that materially clarifies consumer bootloader unlock.
3. Do not install, generate, request, replay, or fabricate any token. Static comparison only.
4. Keep VERIFIED / INFERENCE / UNKNOWN strictly separated.

## Decision goal
The most important question is:

**Did FZDP, despite also being binary B9, still retain a legitimately reachable native Download-Mode unlock-entry path that EZB6 later hard-disabled?**

If YES:
- identify the first meaningful FZDP→EZB6 divergence that disables it;
- document whether this is a code-policy change rather than a KG/FRP runtime prerequisite;
- do NOT infer that flashing FZDP is safe or authorized merely because both are B9.

If NO:
- establish how early the hard-disable already exists in FZDP and update the historical boundary accordingly.

If the archive cannot be parsed or the expected component is missing:
- document the exact blocker and cheapest next step rather than broadening analysis.

## Required outputs
Create or update concise textual evidence only, including at minimum:
- `codex_context/reports/FZDP_B9_ENTRY_COMPARISON.md`
- `codex_context/DEVICE_UNLOCK_PLAN.md`
- `PROJECT_STATE.md`
- `CHECKPOINT.md`
- `NEXT_TASK.md`
- `ROADMAP.md`
- `EVIDENCE_LEDGER.csv`
- `CODEX_STATUS.md`

`CODEX_STATUS.md` must use the established fixed handoff format and list all meaningful files changed.

## Git / completion protocol
- First inspect `git status --short`; preserve unrelated local modifications.
- Safely obtain this newest inbox command from the remote without discarding the local `.gitignore` change or unrelated `.DS_Store` changes.
- Stage only meaningful textual project changes from this run plus the intended `.gitignore` rule if appropriate.
- Never stage anything under `bl_packs/FZDP/`.
- Use a short 3-5 word English commit message.
- Push automatically when complete.
- Do not stop at an intermediate address/function identification; continue until the FZDP entry-policy/reachability question is resolved or reduced to a precise blocker.

## Safety
Offline static analysis only. Do not flash FZDP, downgrade firmware, patch ABL, modify trusted state, install EM tokens, or treat same binary revision as proof of flash compatibility.
