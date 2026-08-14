COMMAND_ID: 2026-08-13-bl-files-path-008
RESULT: COMPLETE
VERIFIED:
- CYB4 archive was found in authoritative BL_FILES/CYB4 and validated by SHA-256 7e1231842645dfbf01fe313755bbabbb507c86abae2c458c18b248b877dcc89e.
- CYB4 B8 retains dynamic helper 0xC6ED0; it can return true and its two normal event-loop gates can reach LongPressVolUpkeyCheck(4000).
- CYB4 confirmation 0xCFCC0 calls the retained 0x25EE0 transition; CYB4 0xC6ED0 and 0x25EE0 are each 100.00% normalized to CXDF counterparts.
- FZDP/EZB6 B9 remain unconditional-false; the hard-disable boundary is after CYB4 B8 and no later than B9.
INFERENCE:
- The consumer native unlock-entry removal occurred during late B8 or the B8-to-B9 transition, not before CYB4.
UNKNOWN:
- Whether late B8 S911BXXS8EZA1 is dynamic or hard-disabled, and the exact policy-change commit/build.
FILES_CHANGED:
- CYB4 input/comparison reports, boundary/state/roadmap/ledger/checkpoint/task/status files, and a reusable CYB4 read-only probe script.
NEXT_RECOMMENDED_ACTION:
- Supply unmodified S911BXXS8EZA1 BL tar/archive or archive-identified ABL/LinuxLoader PE in BL_FILES for the next static boundary probe; never flash it.
