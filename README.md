# Gifty Antivirus PREMIUM — Installer Builder

Builds a single self-contained `.exe` Windows installer for Gifty
Antivirus. Distribute that one file; users double-click and follow a
standard wizard.

---

## Files in this folder

| File | What it is |
|---|---|
| `gifty_av.py` | The actual antivirus app (Python + Tkinter) |
| `launcher.vbs` | Console-less launcher — starts `gifty_av.py` via `pythonw.exe` |
| `Gifty-Antivirus.iss` | Inno Setup script — defines the installer |
| `build_installer.bat` | Run this to produce the installer `.exe` |
| `License.txt` | EULA + privacy notice (shown during install) |
| `PRIVACY.md` | Standalone privacy policy (shipped to install dir) |
| `firestore.rules` | **Paste into Firebase Console** to lock down telemetry DB |
| `UPDATES.md` | How to ship new versions via GitHub Releases |
| `GiftAntivirusIcon.ico` | Installer + app icon (auto-generated from `.png` if missing) |
| `GiftAntivirusIcon.png` | Source icon |

---

## To build (you, the developer)

**Need:** [Inno Setup 6](https://jrsoftware.org/isdl.php) — free, 5 MB.
The build script will download and silently install it for you if
it's not already present.

1. Keep all files in the same folder.
2. Double-click **`build_installer.bat`**.
3. Output: **`Gifty-Antivirus-PREMIUM-Setup.exe`** in the same folder.

---

## What the end user experiences

1. Double-click `Gifty-Antivirus-PREMIUM-Setup.exe`.
2. Standard install wizard:
   - Welcome → License Agreement → Destination → Ready → Install.
   - If Python isn't installed, the installer downloads and silently
     installs Python 3.12 from python.org.
3. Desktop + Start Menu shortcuts created. App registered in
   Add/Remove Programs.
4. On first launch:
   - Asks if you want to share anonymous usage data (off by default).
   - Asks if you want autostart on Windows boot.

---

## Important — before your first release

Two things outside this folder need doing:

1. **Lock down the Firestore telemetry database.** Open the Firebase
   Console for project `giftyantivirus` → **Firestore Database** →
   **Rules** → paste the contents of `firestore.rules` → **Publish**.
   Without this, the database is publicly readable and writable by
   anyone on the internet.

2. **Set up GitHub Releases for the auto-updater.** Full instructions
   in `UPDATES.md`. Short version: tag a release, attach the new
   `gifty_av.py` as a binary asset, write a changelog. Existing
   installs see the update on next launch.
