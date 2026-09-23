# Discord Anti-Scam Bot — Model Document

**Status:** Living spec. Baseline version: v1.0 (initial GitHub release).
**Audience:** Any agent (AI or human) implementing new features, fixing bugs, or reviewing PRs on this project.

Read Section 1 before touching anything. It is not optional context — it encodes decisions that were made deliberately, after finding and fixing real problems, and reversing them silently will reintroduce those problems.

---

## 1. Non-Negotiables

These rules override any convenience, shortcut, or "cleaner" alternative an agent might otherwise reach for.

1. **Everything is in English. No exceptions except one, documented one.**
   Code, comments, docstrings, log messages, embed text, command replies, README, this document, commit messages — all English.
   The **one deliberate exception**: `utils/patterns.py` contains scam-detection regex patterns with Spanish phrases (`bono gratis`, `código promocional`, `tiempo limitado`, `dolares`, etc.) mixed in with English ones. This is intentional and functional — the scam this bot detects circulates in both languages on Discord. **Do not "fix" this into English-only.** Do not add comments apologizing for it. It is correct as-is. If you add a new detection pattern in another language for the same reason, that's fine — just don't silently translate existing ones away.

2. **Least-privilege permissions, always.**
   Every Discord permission the bot requests must map to a line of code that uses it. If you add a feature that needs a new permission, you must also update the permission list in `README.md`'s installation instructions in the same change. Do not request `Administrator`, `Ban Members`, or `Kick Members` — see point 4.

3. **No secrets ever get committed.**
   `config.yaml` (the real one, with a live token) is gitignored and must stay that way. `config.example.yaml` only ever contains placeholder values. Any new secret (an API key for a future integration, etc.) goes through the same pattern: a placeholder in the example file, the real value in the gitignored one, read via `self.cfg.get(...)`.

4. **Timeout, not ban — the flagged account is usually a victim, not the scammer.**
   This bot exists because compromised accounts, not their real owners, send these messages (see Section 2). The default sanction is a timeout (or an optional quarantine role), never a ban or kick. Do not add ban/kick as the default action for any detection signal. If a future feature wants ban as an *option*, it must be opt-in via config, off by default, and documented as such.

5. **Minimize data retention.**
   The bot does not store message content, user IDs, or raw images anywhere persistent. It stores: perceptual hashes (not images) with a moderator-supplied label, a domain blocklist, and (after the SQLite migration in the roadmap) per-guild settings and burst-detection timestamps. Any new feature that wants to persist something new must justify why, and default to the minimum needed.

6. **A flagged message can be a false positive. Design for that, not around it.**
   Existing mitigations exist specifically because early testing found real abuse/false-positive vectors: `exempt_role_ids` (trusted roles skip detection entirely), the `!addhash` audit log (traceability if a mod account is compromised), `max_image_size_mb` (DoS protection), and showing only the image that actually matched a hash in alerts (never an arbitrary attachment). Any new detection signal or new command must be evaluated against the same question: *how could this be turned against an innocent user, or against the bot itself?* Section 7 has the checklist.

7. **Only necessary comments/annotations. Zero unnecessary or meaningless emojis. Both are hard rules, not style preferences.**
   - **Comments:** don't restate what a line of code already says. Don't add a docstring to a trivial, self-explanatory function just to have one — compare `_get_mod_log_channel` (no docstring needed, it's obvious) against `_is_exempt` (has one, because *why* the feature exists isn't recoverable from the code alone). Structural section dividers in longer files (e.g. `# ---------- helpers ----------` in `cogs/scam_detector.py`) are fine — they aid navigation in a file with several distinct responsibilities. Decorative comment banners, placeholder comments, or comments that explain basic language syntax are not.
   - **Emojis:** the only three that exist anywhere in this project (`⚠️` on the alert embed title, `✅` on the `!addhash` confirmation reply) are functional UI signals a moderator scans for at a glance — not decoration. Do not add any more, anywhere: not in code, not in comments, not in commit messages, not in README or other docs, not in this document. Do not remove those two without discussing it first, either — they're load-bearing.

---

## 2. Project Overview

This bot defends Discord servers against a specific, real, ongoing scam: a compromised Discord account (the real owner rarely knows they've been hacked) mass-sends screenshots impersonating a celebrity (MrBeast, Elon Musk, Kai Cenat) announcing a fake crypto casino with a sign-up bonus. Victims who engage are asked to deposit real crypto as "verification" before a payout that never comes.

The bot combines four independent signals into a single risk score per message:

| Signal | Module | What it catches |
|---|---|---|
| Text | `utils/patterns.py` | Celebrity names, "crypto casino"/"promo code" phrasing, fake urgency, large dollar amounts, "you won" phrasing |
| Links | `utils/link_checker.py` | Domains on a manual blocklist, known URL shorteners, suspicious keywords in a domain |
| Images | `utils/image_hash.py` | Perceptual hash (pHash) match against a moderator-curated database of confirmed scam screenshots |
| Behavior | `cogs/scam_detector.py` | Burst of link-containing messages in a short window, recently-created account |

Scores accumulate across all four; if the total crosses `alert_threshold`, moderators are notified; if it crosses `action_threshold`, the bot also deletes the message and times out the author.

---

## 3. Current Architecture (baseline)

```
discord-anti-scam-bot/
├── bot.py                    # Entry point: loads config, sets intents, loads the cog
├── config.example.yaml       # Template config — see Section 5 for the full key reference
├── requirements.txt
├── cogs/
│   └── scam_detector.py      # on_message listener, scoring aggregation, actions, commands
├── utils/
│   ├── patterns.py           # score_text() — regex-based text scoring
│   ├── link_checker.py       # score_links(), extract_urls() — link scoring
│   └── image_hash.py         # score_attachment_urls(), add_known_hash(), download_bytes()
├── data/
│   ├── known_hashes.json     # { "<phash_hex>": "<label>" } — starts empty, grows via !addhash
│   └── blocklist_domains.txt # one domain per line, # for comments
├── README.md                 # Setup instructions, permissions, abuse-mitigation notes
├── LICENSE                   # MIT
└── .gitignore                # Excludes config.yaml, __pycache__, venvs, editor/OS junk
```

**Module responsibilities, precisely:**

- `bot.py` owns process lifecycle only: load YAML config, validate the token is set, configure the `message_content` intent, attach `bot.config`, load `cogs.scam_detector` as an extension, connect. It should never contain detection logic.
- `cogs/scam_detector.py` is the only place that touches the Discord API for moderation actions (delete, timeout, add_roles) and the only place that combines scores from the `utils/` modules into a single decision. It also owns the two moderator commands (`!addhash`, `!scamconfig`).
- `utils/*.py` modules are pure-ish and Discord-agnostic where possible: they take primitive inputs (strings, URL lists) and return `(score, reasons)` tuples (or `(score, reasons, matched_urls)` for images). They should not import `discord` or know about `discord.Message`. This is what makes them unit-testable without a running bot (see Section 8).

---

## 4. Detection & Scoring Model

Current point values (all in `cogs/scam_detector.py` and the `utils/` modules):

| Category | Points | Source |
|---|---|---|
| `celebrity_mentioned` | 2 | `utils/patterns.py` |
| `crypto_casino_offer` | 3 | `utils/patterns.py` |
| `promo_code` | 2 | `utils/patterns.py` |
| `fake_urgency` | 2 | `utils/patterns.py` |
| `large_amount` | 1 | `utils/patterns.py` |
| `you_won_phrase` | 2 | `utils/patterns.py` |
| Domain in blocklist | 6 | `utils/link_checker.py` |
| Known URL shortener | 2 | `utils/link_checker.py` |
| Suspicious keyword in domain | 3 | `utils/link_checker.py` |
| Image matches known hash | 10 | `utils/image_hash.py` |
| Burst of link messages | 4 | `cogs/scam_detector.py` |
| Recently created account | 2 | `cogs/scam_detector.py` |

Default thresholds: `alert_threshold: 3` (notify mods), `action_threshold: 6` (also delete + sanction).

**Rule for adding a new signal:** it must return a `(score: int, reasons: List[str])` tuple (or richer, like image hashing's matched-URL tracking, if the caller needs to act on *which* piece of evidence triggered it — see Section 7's rule about evidence-specific display). Reason strings follow the `"<category>: <human-readable detail>"` convention already used (e.g. `"text: crypto_casino_offer"`, `"link: domain in blocklist (example.com)"`) so the mod-log embed reads consistently regardless of which module produced the signal. New point values should be justified relative to the existing table, not picked arbitrarily — a new signal that's as strong as a hash match should score close to 10; a weak corroborating signal should score 1–2, matching `large_amount`.

---

## 5. Configuration Reference

All config is read via `self.cfg.get(key, default)` — a key missing from an old `config.yaml` must never crash the bot, only fall back to the default. Every new config key added by any feature must follow this pattern and be documented in `config.example.yaml` with a comment explaining it, the same way existing keys are.

| Key | Type | Default | Purpose |
|---|---|---|---|
| `token` | str | — (required) | Bot token. Never has a real default. |
| `prefix` | str | `"!"` | Command prefix. |
| `mod_log_channel_id` | int | — | Channel where alerts and audit-log entries are posted. |
| `quarantine_role_id` | int or `null` | `null` | If set, used instead of timeout for sanctions. |
| `action_threshold` | int | `6` | Score to trigger delete + sanction. |
| `alert_threshold` | int | `3` | Score to trigger a mod-log alert only. |
| `hamming_threshold` | int | `8` | Max Hamming distance for a pHash "match". |
| `new_account_days_threshold` | int | `7` | Accounts younger than this get +2. |
| `burst_message_count` | int | `4` | Messages-with-link count that defines a burst. |
| `burst_window_seconds` | int | `15` | Time window for burst detection. |
| `auto_timeout_minutes` | int | `15` | Timeout duration (ignored if `quarantine_role_id` set). |
| `exempt_role_ids` | list[int] | `[]` | Roles fully skipped by detection. |
| `max_image_size_mb` | number | `8` | Images larger than this are never downloaded. |

---

## 6. Coding Conventions

- **Python 3.10+.** Modern type hints are used throughout (`str | None`, `dict[int, deque]`, `list[str]`) — keep using them, don't downgrade to `Optional[...]`/`Union[...]` for consistency (the one place `Optional`/`List`/`Tuple` from `typing` are used is `utils/*.py`, written that way for broader compatibility in files that might be imported standalone; match whichever style the file you're editing already uses).
- **Async everywhere I/O happens.** Network calls (`aiohttp`) and Discord API calls are always `await`ed inside `async def`. Never block the event loop with synchronous file or network I/O in a hot path (`on_message` runs per message).
- **File placement:** Discord-agnostic scoring/utility logic → `utils/`. Anything that touches `discord.Message`, `discord.Member`, or issues moderation actions → `cogs/`. A new independent feature area (e.g. OCR) gets its own file in `utils/`, imported by the cog — do not add new logic directly into `scam_detector.py`'s `on_message` beyond wiring together calls to `utils/` functions.
- **Comment and emoji discipline: see Section 1, point 7 — it's a non-negotiable, not a style preference.**
- **Config access is always `.get()` with a default**, never `self.cfg["key"]` (except `token` in `bot.py`, which is validated explicitly and should hard-fail if missing — that's the one intentional exception).

---

## 7. Security & Abuse-Mitigation Checklist

Already implemented (do not remove without a documented reason and a replacement):

- [x] `exempt_role_ids` — trusted roles skip detection entirely.
- [x] `!addhash` audit log — every addition is posted to mod-log with who/when.
- [x] `max_image_size_mb` — caps download size before processing, checked via `Content-Length` and again while streaming (in case the header lies).
- [x] Alert embeds show an image only when it's the one that actually matched a known hash — never an arbitrary attachment riding along in the same message.

**Checklist for any new feature** (answer these before considering it done):

1. Could this feature be triggered against an innocent user to get them punished (a "weaponization" vector)? If yes, does an exempt/allowlist mechanism already cover it, or does it need its own?
2. Does this feature request a Discord permission not already justified in Section 6 of `README.md`? If yes, add it there in the same change.
3. Does this feature download, process, or store anything an attacker controls the size or content of (images, files, arbitrary text)? If yes, does it have a size/rate limit, matching the pattern in `download_bytes()`?
4. Does this feature add a new command? If yes, is it gated by the correct `commands.has_permissions(...)` check, matching the sensitivity of what it does (`manage_messages` for moderation-adjacent actions, `manage_guild` for config-reading/writing)?
5. Does this feature persist anything new? If yes, is it the minimum needed (Section 1, point 5), and is it excluded from git if it's runtime/instance-specific state?

---

## 8. Testing & CI Requirements

*(Target state once the "Add tests and CI" roadmap item lands — treat this section as the spec for that feature, and as the bar every subsequent feature must clear afterward.)*

- Framework: `pytest`.
- `utils/*.py` functions are pure enough to unit test directly: feed `score_text()` known scam phrases and known-clean text, assert the score and reason list. Same pattern for `score_links()`. `image_hash.py`'s hash comparison logic should be tested with precomputed hashes (don't require real network downloads in unit tests — mock `download_bytes`).
- One test file per `utils/` module, named `tests/test_<module>.py`.
- `cogs/scam_detector.py`'s Discord-facing methods are harder to unit test directly (they need a `discord.Message`); at minimum, `_is_exempt()`, `_register_burst()`, and `_is_new_account()` should be tested with lightweight mock objects, since they're pure logic wrapped in a method.
- CI: a GitHub Actions workflow (`.github/workflows/test.yml`) that runs `pip install -r requirements.txt` and `pytest` on every push and pull request targeting `main`.
- **Any new feature that adds scoring logic must ship with tests for that logic in the same change.** A PR that adds a signal with no corresponding test is not done.

---

## 9. Git & Commit Conventions

(Recap — see prior discussion for the full walkthrough.)

- Branch per non-trivial feature: `feature/<short-name>` (e.g. `feature/ocr-detection`).
- Commit messages: short imperative summary, optionally typed — `feat: add OCR fallback`, `fix: handle missing Content-Length header`, `test: add pytest suite for score_text`, `docs: update README for slash commands`.
- One feature = one commit or a small related set, not a single commit mixing unrelated changes.
- Tag milestones as releases once a meaningful chunk of the roadmap lands (`git tag -a v1.1.0 -m "..."`).

---

## 10. Roadmap — Feature Specifications

Each spec below is meant to be handed to a single agent as a self-contained brief. Dependencies between items are called out explicitly — respect them (an agent working on 10.4 should not start until 10.3 has landed, for example).

### 10.1 OCR fallback signal

**Goal:** catch scam screenshots the bot has never seen before, without waiting for a moderator to run `!addhash`.
**Why:** the current image signal only fires on an exact-enough pHash match against `known_hashes.json`. A brand-new variant of the scam image slips through until a human catches it once.
**Requirements:**
- New file `utils/ocr.py`, exposing an async `extract_text(image_bytes: bytes) -> str` using `easyocr` or `pytesseract` (pick one; document the choice and the system dependency, if any, in `README.md`).
- Wire it into `cogs/scam_detector.py`: after downloading an attachment for hash comparison, if there's no hash match, run OCR on it and feed the extracted text through the existing `score_text()` from `utils/patterns.py` — reuse the scoring, don't duplicate the pattern list.
- Respect `max_image_size_mb` — OCR runs on the same already-size-checked bytes, don't re-download without the limit.
- New reason string format: `"image (OCR): <matched category>"` so alerts distinguish an OCR-derived text match from a direct hash match.
**Acceptance:** a never-before-seen image containing scam text (test with a synthetic image you generate, not a real screenshot) scores via the text categories in `utils/patterns.py`, without needing `!addhash` first.

### 10.2 Tests and CI

**Goal:** regression safety as the codebase grows via multiple agents.
**Depends on:** nothing — do this early, ideally before or alongside 10.1, since it makes every subsequent item easier to verify.
**Requirements:** see Section 8 in full — that section *is* this spec.

### 10.3 SQLite state migration

**Goal:** persist burst-detection history across restarts, and lay the data layer for per-guild config (10.4).
**Requirements:**
- New file `utils/db.py`, using `aiosqlite`.
- Move `_link_history` (currently an in-memory `defaultdict(deque)` in `cogs/scam_detector.py`) into a table keyed by `(guild_id, user_id, timestamp)`, pruned the same way it's pruned in memory today (drop entries older than `burst_window_seconds`).
- `known_hashes.json` and `blocklist_domains.txt` can stay as flat files for now (they're small, human-editable, and diff nicely in git) — do not migrate them to SQLite in this step. Only burst history and (in 10.4) per-guild settings.
- Add a migration note to `README.md`: the SQLite file's path should be configurable via a new `db_path` config key, defaulting to `data/bot_state.db`, and gitignored (it's runtime state, not source).
**Acceptance:** restart the bot mid-burst-test and confirm the burst counter survives.

### 10.4 Multi-server (per-guild) support

**Depends on:** 10.3.
**Goal:** every setting currently in the single global `config.yaml` (thresholds, `mod_log_channel_id`, `exempt_role_ids`, etc.) becomes per-guild, stored in the SQLite database from 10.3, with `config.yaml` reduced to only what's truly global (`token`, `prefix`, `db_path`).
**Requirements:**
- A `guild_settings` table with one row per guild, columns matching the current per-guild-relevant keys from Section 5.
- A `/config` slash command (see 10.5 — implement this as a slash command directly, don't add a prefix-command version first) letting a moderator view and set their guild's values without editing YAML or restarting the bot.
- On first message from a guild with no settings row, insert one with the current defaults from `config.example.yaml`.
**Acceptance:** run the bot in two test servers simultaneously with different thresholds and confirm they don't affect each other.

### 10.5 Slash commands, `/scan`, `/stats`

**Goal:** modernize the command UX and add operational visibility.
**Requirements:**
- Migrate `!addhash` and `!scamconfig` to slash commands (`/addhash`, `/scamconfig`) using `discord.py`'s `app_commands`. Keep the same permission gates.
- `/scan [limit]`: retroactively runs the existing scoring pipeline against the last `limit` (default 100, cap at 500) messages in the current channel — useful right after installing the bot on a server that already has scam messages sitting in it. Must respect `exempt_role_ids` exactly like live detection does.
- `/stats`: reports counts (messages scored, alerts raised, actions taken) since the bot started or since the last reset — pull these from the SQLite layer (10.3), don't keep a separate in-memory counter that resets independently.
**Acceptance:** `/scan` on a test channel seeded with old scam messages produces the same alerts live detection would have.

### 10.6 One-click undo button

**Goal:** let a moderator reverse a false positive without digging through audit logs.
**Requirements:**
- Attach a `discord.ui.View` with an "Undo" button to every alert embed that resulted in an action (delete + sanction), not to alert-only embeds (nothing to undo there).
- On click: restore the message content as a new message noting it was restored (Discord doesn't allow un-deleting the original), remove the timeout / quarantine role, and edit the original alert embed to show who undid it and when.
- Gate the button interaction with the same `manage_messages` check used elsewhere — verify in the interaction callback, don't rely on Discord UI alone to enforce it.
**Acceptance:** trigger a deliberate false positive, click Undo, confirm the timeout is lifted and the embed reflects the reversal.

### 10.7 DM the flagged account with security steps

**Goal:** help the likely-hijacked real owner, not just punish the symptom.
**Requirements:**
- New config key `dm_on_action: true` (default `true`, but must be toggleable — some servers may prefer not to DM).
- New config key `dm_message` (string, with a sensible default explaining the account may be compromised and pointing to changing the password / reviewing authorized apps / enabling 2FA — reuse the guidance already given earlier in this project's own conversation history as the default copy, translated to a concise DM).
- Send the DM *before* the timeout is applied, wrapped in a try/except (`discord.Forbidden` if the user has DMs closed) — a failed DM must never block the sanction itself.
**Acceptance:** trigger an action in a test server with a test account that has DMs open; confirm the message arrives and the bot doesn't crash for an account with DMs closed.

### 10.8 (Backlog) WHOIS domain-age check

**Goal:** catch brand-new scam domains not yet in any blocklist.
**Requirements:** extend `utils/link_checker.py` with an optional WHOIS lookup (via `python-whois` or similar) for domains not already in the blocklist; domains younger than a new `suspicious_domain_age_days` config key (default 30) add a smaller score bump (suggest +2, weaker than a confirmed blocklist hit) since domain age alone is a weak signal. Cache lookups (in-memory TTL or the SQLite layer from 10.3) — WHOIS servers rate-limit aggressively.

### 10.9 (Backlog) Dockerfile

**Goal:** easier self-hosted deployment.
**Requirements:** a `Dockerfile` (slim Python base image, `pip install -r requirements.txt`, mount `config.yaml` and `data/` as volumes so they persist outside the container) and a short "Running with Docker" section in `README.md`.

---

## 11. Suggested Mini-Agent Breakdown

If splitting this roadmap across separate agents, respect these dependencies:

| Agent | Owns | Depends on |
|---|---|---|
| Agent A | 10.2 (Tests + CI) | Nothing — do first |
| Agent B | 10.1 (OCR) | Nothing (can run parallel to A) |
| Agent C | 10.3 (SQLite) → 10.4 (Multi-guild) | Nothing to start 10.3; needs 10.3 done before 10.4 |
| Agent D | 10.5 (Slash commands, /scan, /stats) | Needs 10.4's `/config` groundwork if it wants per-guild `/stats`; can stub against the current single-config model otherwise and reconcile later |
| Agent E | 10.6 (Undo button) + 10.7 (DM) | Nothing structural — can start immediately, both are additive UX on top of the existing `_act_on_message` flow |

Agents B and E can start immediately alongside A. C should be prioritized early since D and part of the multi-guild story depend on it. Merge order matters more than start order — land A and C's `10.3` half before merging anything that touches `cogs/scam_detector.py` heavily, to minimize merge conflicts in that file.

---

## 12. Definition of Done (per feature)

- [ ] Code and all text (comments, docstrings, logs, UI strings) in English, per Section 1 — except the one documented exception.
- [ ] New/changed permissions reflected in `README.md`.
- [ ] New config keys added to `config.example.yaml` with a comment, read via `.get()` with a default.
- [ ] Passes the Section 7 abuse-mitigation checklist.
- [ ] No unnecessary comments/annotations added, and no new emojis introduced anywhere, per Section 1, point 7.
- [ ] Has tests per Section 8 (once 10.2 has landed — required for everything after).
- [ ] `README.md` updated if the feature is user-facing (new command, new setup step).
- [ ] Committed following Section 9's conventions.

---

## 13. Glossary

- **pHash / perceptual hash:** a fingerprint of an image's visual structure, designed so visually similar images produce similar (low Hamming-distance) hashes even after resizing, recompression, or minor edits — unlike a cryptographic hash, which changes completely for a single-pixel difference.
- **Hamming distance:** the number of differing bits between two hashes; lower means more visually similar.
- **Exempt role:** a role listed in `exempt_role_ids` whose members are fully skipped by detection.
- **Mod-log channel:** the channel configured via `mod_log_channel_id` where alerts and the `!addhash` audit trail are posted.
- **Action vs. alert:** an *alert* (score ≥ `alert_threshold`) only notifies moderators; an *action* (score ≥ `action_threshold`) additionally deletes the message and sanctions the author.
