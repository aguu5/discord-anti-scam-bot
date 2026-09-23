# Discord Anti-Scam Bot (MrBeast / Crypto-Casino and Variants)

A moderation bot built specifically against the "compromised account sending
screenshots of a fake MrBeast/Elon Musk/Kai Cenat crypto casino" scam. It
combines four signals to decide if a message is suspicious:

1. **Text**: phrases typical of the scam (celebrity name + "crypto casino" +
   "promo code" + fake urgency + large dollar amounts).
2. **Links**: domains on your blocklist, URL shorteners, suspicious keywords
   in the domain.
3. **Images**: perceptual hash (pHash) compared against a database of
   already-confirmed scam screenshots. Since these scammers reuse the same
   3-4 images thousands of times, this is the most reliable signal.
4. **Behavior**: recently created account, burst of link messages in a short
   time.

Each signal adds points. If `alert_threshold` is exceeded, moderators get
notified. If `action_threshold` is exceeded, the bot also deletes the
message and applies a timeout (or a quarantine role, if you prefer that).

## ⚠️ Important: what this bot does NOT do

- **It does not automatically report to Discord.** Discord has no public API
  for a bot to file "reports" with their Trust & Safety team — that can only
  be done from the client (right-click the message → Report). What the bot
  does do is get everything ready: it deletes the message, sanctions the
  user in your server, and leaves you an embed with all the evidence so you
  (or any mod) can file the manual report in two clicks.
- **It does not "clean" the malware off the compromised account.** That's on
  the real account owner to fix (change password, review active
  sessions/authorized apps, enable 2FA).
- It doesn't replace having AutoMod and good general practices in your
  server.

## Installation

### 1. Requirements
- Python 3.10 or higher
- A bot application created in the [Discord Developer Portal](https://discord.com/developers/applications)

### 2. Create the bot
1. Go to the Developer Portal → **New Application**.
2. **Bot** tab → **Add Bot**.
3. Under **Privileged Gateway Intents**, enable **Message Content Intent**
   (required for the bot to read message text).
4. Copy the **token** (you'll need it for `config.yaml`).
5. **OAuth2 → URL Generator** tab: check the `bot` scope, and under
   permissions check:
   - View Channels
   - Send Messages
   - Manage Messages (to delete messages)
   - Moderate Members (for timeout)
   - Embed Links
   - **Manage Roles** — only if you're using `quarantine_role_id` instead of
     timeout. Skip it if you're using timeout only (the default).

   Note: `Attach Files` is **not** needed — the bot only links to images by
   URL in its embeds, it never uploads files itself.
6. Open the generated URL and invite the bot to your server.

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure
```bash
cp config.example.yaml config.yaml
```
Edit `config.yaml`:
- `token`: the token from step 2.
- `mod_log_channel_id`: with "Developer Mode" enabled in Discord,
  right-click your mod channel → **Copy ID**.
- Adjust the thresholds if you want to be more or less strict.

### 5. Run the bot
```bash
python bot.py
```

### Running with Docker

Alternatively, you can run the bot using Docker. Make sure to mount your `config.yaml` and the `data/` directory as volumes so your configuration, image hashes, and bot state persist across container restarts.

```bash
# Build the image
docker build -t discord-anti-scam-bot .

# Run the container
docker run -d \
  --name anti-scam-bot \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/data:/app/data \
  discord-anti-scam-bot
```

## How to feed the known-images database

When a new scam screenshot shows up in your server:
1. Reply to that message (before the bot deletes it, or from the log
   channel) with `!addhash whatever_name_you_want`.
2. The bot computes the perceptual hash and stores it in
   `data/known_hashes.json`.
3. From then on, any "similar" image (even if cropped, recompressed, or
   with a different watermark) will match.

You can also share your `known_hashes.json` with other server owners to
build a larger shared database.

## Abuse mitigations

A few things were added specifically so the bot itself can't be turned into
a tool for griefing or wasted resources:

- **`exempt_role_ids`** — members with any of these roles are skipped
  entirely (no scoring, no alert, no action). Use it for a moderator role,
  so quoting scam text to warn others doesn't get a mod auto-timed-out by
  their own bot.
- **Audit log for `!addhash`** — every time someone adds a hash, the bot
  posts an entry to the mod-log channel with who did it and when. If a mod
  account ever gets compromised, there's a trail instead of a silent,
  unattributed change to the scam database.
- **`max_image_size_mb`** — images above this size are skipped before
  they're even downloaded, so a flood of oversized attachments can't be used
  to burn the bot's bandwidth or CPU.
- **Evidence image is match-specific** — the mod-log embed only shows an
  image when it's the one that actually matched a known scam hash, never an
  arbitrary attachment that happened to ride along in the same message.

## Tuning sensitivity

- **Too many false positives** → raise `action_threshold` and
  `alert_threshold`, or lower `hamming_threshold` (stricter for images).
- **Scams are slipping through** → do the opposite, and above all keep
  feeding `data/known_hashes.json` and `data/blocklist_domains.txt` as you
  spot new ones.

## Possible future improvements

- Integrate the [Google Safe Browsing API](https://developers.google.com/safe-browsing)
  (or similar) to check links against an external database, in addition to
  your local blocklist.
- **Migration Note**: The bot now persists burst-detection history using SQLite. The SQLite file's path is configurable via the `db_path` config key, which defaults to `data/bot_state.db`. This file is runtime state and should be gitignored.
- Share `known_hashes.json` across multiple servers via a central service
  (your own API or a community repo).
- Raid detection (many new accounts joining at once) — Discord's native
  AutoMod already covers part of this.

## Project structure

```
discord-anti-scam-bot/
├── bot.py
├── config.example.yaml
├── requirements.txt
├── cogs/
│   └── scam_detector.py
├── utils/
│   ├── patterns.py
│   ├── link_checker.py
│   └── image_hash.py
└── data/
    ├── known_hashes.json
    └── blocklist_domains.txt
```
