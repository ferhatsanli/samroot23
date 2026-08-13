# TOKEN_STRATEGY.md — Human usage guide

This file is for the user, not required reading for Codex.

## Recommended model routing

### Default: Terra
Run the project with:
```bash
codex -m gpt-5.6-terra
```

Use Terra for:
- locating files/reports;
- parsing/disassembling;
- writing or fixing analysis scripts;
- xref/global/caller extraction;
- old/new structural comparisons;
- summarizing evidence.

### Escalate to Sol only for a hard reasoning bottleneck
Inside Codex use `/model`, or start:
```bash
codex -m gpt-5.6-sol
```

Use Sol when:
- Terra has produced evidence but cannot reconcile competing interpretations;
- a difficult indirect/relocation-based call chain needs deep reasoning;
- you want a final synthesis from already-distilled evidence.

Do not make Sol reread every raw report. Give it `PROJECT_STATE.md`, `NEXT_TASK.md`, and the smallest relevant excerpts/results.

### Luna
Use `gpt-5.6-luna` only for very deterministic work:
- renaming/formatting reports;
- extracting addresses into CSV;
- deduplicating string lists;
- simple mechanical transformations.

## Reasoning
Start at medium. Raise reasoning only for a concrete bottleneck. Higher reasoning uses more tokens.

## Avoid
- Ultra unless genuinely necessary: it may use subagents.
- Subagents by default: each does its own model/tool work and consumes additional tokens.
- Fast mode: GPT-5.6 fast mode consumes more credits.
- Unneeded MCP servers.
- Huge initial prompts.
- Repeatedly pasting the long handoff.
- `cat` of multi-megabyte reports into chat.

## Session strategy
Prefer one sustained Codex session for one analysis milestone so existing context can remain useful/cached. When the session becomes noisy, start a fresh one using only:
- `AGENTS.md` (automatic)
- `PROJECT_STATE.md`
- `NEXT_TASK.md`
- relevant report excerpts.

## MCP check
See configured servers:
```bash
codex mcp list
```
Disable/remove anything you do not need for this local firmware project.

## Fast-mode check
Inside Codex:
```text
/fast status
/fast off
```
