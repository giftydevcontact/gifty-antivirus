# Publishing an Update

Gifty Antivirus auto-updates itself by polling GitHub Releases. Here's
how to ship a new version.

## One-time setup

1. Create a public GitHub repository for the project (private repos
   work too, but the API requests would need a token — start public).
2. Open `gifty_av.py` and set:
   ```python
   _GH_REPO = "your-username/gifty-antivirus"
   ```
   This is the only required code change.
3. (Optional) Adjust `_UPDATE_INTERVAL` (default: 86400 seconds /
   24 hours) if you want a different background-check cadence.
4. (Optional) Change `_GH_ASSET_NAME` if you want to ship a
   different file name than `gifty_av.py`.

## Each release

1. Edit `gifty_av.py`, bump the version constant near the top:
   ```python
   _APP_VERSION = "4.1"
   ```
2. Test locally: `python gifty_av.py`.
3. Commit and tag:
   ```
   git commit -am "v4.1: short summary"
   git tag v4.1
   git push && git push --tags
   ```
4. On GitHub:
   - **Releases → Draft a new release**
   - Choose the tag you just pushed (e.g. `v4.1`)
   - **Title:** `v4.1 — short summary`
   - **Description:** the changelog. This is what users see in the
     "Update Available" dialog, so write it for them, not for
     yourself. Bullet points work well. Keep the most important
     line first; the dialog truncates after ~600 characters.
   - **Attach binaries → upload** the new `gifty_av.py`. The asset
     filename **must match `_GH_ASSET_NAME`** (default
     `gifty_av.py`). This is what the client downloads.
   - **Publish release.**
5. Existing installs see the new version on their next launch (or
   within 24 hours for already-running installs).

## Version comparison rules

The client compares versions as numeric tuples. These all work:

| Tag        | Parsed as     |
|------------|---------------|
| `4.1`      | `(4, 1, 0)`   |
| `v4.1`     | `(4, 1, 0)`   |
| `4.1.2`    | `(4, 1, 2)`   |
| `v4.1.0-beta` | `(4, 1, 0)` (suffix dropped for ordering) |

A release is offered to the user only if `_ver_tuple(remote) >
_ver_tuple(local)`. So `4.1` will offer to upgrade `4.0`, but `4.0`
will not offer to "upgrade" to `4.0`.

## What happens on the client

```
launch → wait 8s → check setting → check throttle (24h)
       → GET https://api.github.com/repos/<repo>/releases/latest
       → compare tag to _APP_VERSION
       → newer? → look for "gifty_av.py" asset
              → download to %TEMP%\gifty_av_update.py
              → ast.parse() to verify it's valid Python
              → show confirm dialog with changelog + SHA-256
              → user accepts → write %TEMP%\gifty_av_update.bat
              → ShellExecute "runas" → UAC prompt
              → app exits → batch waits 2s, copies file, relaunches
```

## Rolling back

If a release breaks something, just publish a higher-numbered release
(e.g. `4.2`) that contains the previous good code. The auto-updater
only ever moves forward.

## Things to keep in mind

- The asset is downloaded over HTTPS from GitHub. Anyone who can push
  to the repo can ship code to every installed user — guard your
  GitHub credentials and consider requiring signed commits.
- The client refuses files smaller than 10 KB or that don't parse as
  valid Python. This catches truncated downloads and the obvious
  case of a corrupted release, but it is not a substitute for code
  signing. If you want strong integrity, publish the SHA-256 of each
  release in the changelog and add a verification step to
  `GitHubUpdater.sanity_check`.
- Telemetry events related to updates (`update_check`,
  `update_found`, `update_skipped`, `update_installed`) only fire if
  the user has opted in to telemetry. The update mechanism itself
  works regardless.
- The GitHub API allows 60 unauthenticated requests per hour per IP.
  With one check per 24 hours per install, that's plenty for any
  reasonable user base.
