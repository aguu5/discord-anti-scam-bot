# AGENTS.md

This file exists so any agent working in this repository — regardless of
which tool spawned it — discovers the same starting point automatically.

## Read this first, every session

Before doing anything else, read `MODEL_DOCUMENT.md` in full. It is the
single source of truth for this project: architecture, non-negotiables,
the detection/scoring model, configuration reference, coding conventions,
the abuse-mitigation checklist, testing requirements, and the full roadmap
with feature-level specs.

Do not treat this file as a substitute for `MODEL_DOCUMENT.md`, and do not
duplicate its content here. If the two ever disagree, `MODEL_DOCUMENT.md`
wins — and the disagreement should be reported, not silently resolved by
guessing which one is right.

## Orchestrator/minion setup

This repository is worked on through an orchestrator/minion pattern
(`antigravity.json`, `prompts/orchestrator.txt`, `prompts/implementer.txt`,
`prompts/researcher.txt`). The `build` agent plans and delegates; it does
not edit files or run commands directly, on purpose. If you are the
orchestrator, delegate per `prompts/orchestrator.txt`. If you are a minion
invoked by the orchestrator, execute the scoped task you were given and
nothing beyond it, per your own prompt file.

## The two rules worth repeating here

Both are covered in full in `MODEL_DOCUMENT.md`, Section 1 — repeated only
because they're the two most likely to be silently violated by an agent
that skims instead of reads:

1. Everything is in English, except the deliberately bilingual scam
   detection patterns in `utils/patterns.py` — that exception is
   intentional, not a bug to fix.
2. Never commit `config.yaml` (only `config.example.yaml` is tracked).
   Never write a real bot token or any other secret into any file in this
   repository.

Everything else — permissions, testing, git conventions, the full roadmap
— is in `MODEL_DOCUMENT.md`. Go read it.
