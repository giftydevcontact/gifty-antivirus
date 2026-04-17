# Gifty Antivirus — Privacy Notice

**Short version:** Telemetry is **off by default**. We never see your
file names, file paths, hostname, username, or IP address. If you opt
in, we collect anonymous usage events tied to a randomly generated
install ID so we can figure out which features people use and which
ones to improve.

---

## What we collect — only if you opt in

| Field | Example | Why |
|---|---|---|
| `install_id` | `8f3a…b71e` (random UUID) | Lets us count unique installs without identifying you |
| `session_id` | per-launch random ID | Lets us group events from the same launch |
| `version` | `4.0` | Find bugs that only affect certain releases |
| `os` | `windows-11` | Prioritise OS-specific work |
| `event` | `scan_started`, `page_visited`, `protection_toggled` | Understand which features get used |
| Aggregate scan stats | `files_scanned: 3421`, `threats_found: 0`, `duration_sec: 47` | See real-world performance |
| Threat category / severity | `category: "trojan"`, `severity: "High"` | Improve detection coverage |

## What we never collect

- File names, file paths, file hashes, file contents
- Locations of detected threats
- Your name, hostname, username, computer name, domain
- IP address (not stored alongside your install ID)
- MAC address or hardware serial numbers
- Browsing history, documents, emails, photos
- Process names, command lines, registry contents

## Where it's stored

Google Cloud Firestore (project `giftyantivirus`), restricted by the
security rules in `firestore.rules` to **create-only** writes from the
client. The collection is not publicly readable.

## How to control it

- **First-run dialog** — you choose yes or no on first launch.
- **Settings → Privacy → Anonymous Usage Data** — toggle anytime.
- **Turning it off** rotates your install ID, severing the link to
  any data previously sent.
- **Settings → Privacy → "View Exactly What's Collected"** shows
  your current install ID and the full list of fields.

## Deleting your data

Visit <https://github.com/giftydevcontact/gifty-antivirus/issues/new?title=Data+deletion+request> and submit a
request including your install ID (visible in Settings → Privacy).

## Legal basis (GDPR)

Telemetry is processed under Art. 6(1)(a) — your explicit, freely
given consent. Withdrawing consent is as easy as giving it.

## Local data

Independent of telemetry, the app stores in your user profile:

- `~/.gifty_av_data.json` — settings, scan history, quarantine metadata
- `~/.gifty_av_install_id` — your anonymous install ID
- `~/.gifty_av_v4_firstrun` — sentinel file marking the first launch

These never leave your computer unless you explicitly export them.

## Contact

<https://github.com/giftydevcontact/gifty-antivirus/issues>
