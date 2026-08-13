# Install into bl_packs

Copy/extract this bundle so these files land directly under:

`/Users/ferhatsanli/Desktop/samroot/bl_packs`

Expected:
- `AGENTS.md`
- `PROJECT_STATE.md`
- `NEXT_TASK.md`
- `REPORT_INDEX.md`
- `CODEX_START_PROMPT.txt`
- `TOKEN_STRATEGY.md`
- `.codex/config.toml`
- `.agents/skills/s23-firmware-analysis/SKILL.md`
- `codex_context/archive/CODEX_HANDOFF_S23_BOOTLOADER_LONG.md`

Then launch Codex from `bl_packs`, preferably with:

```bash
codex -m gpt-5.6-terra
```

Paste only the contents of `CODEX_START_PROMPT.txt` as the first task.
