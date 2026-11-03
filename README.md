# Rezen Backup

Secure, fully offline backup and restore for **Windows 10/11** and **macOS 13+**.

Rezen Backup copies the folders you choose to an external drive as **encrypted, authenticated, date-marked snapshots**. A stolen backup drive exposes nothing: file contents, file names and folder structure are all encrypted. With your password or recovery key, you can restore everything — even on a brand-new computer.

- **Always encrypted** — AES-256-GCM (segmented STREAM construction, a unique key per object); there is no unencrypted mode.
- **Password protected** — Argon2id (256 MiB, calibrated); the password is never stored.
- **Offline recovery key** — print it or save it to another device; no online reset, no back door.
- **Dated snapshots** — `2026-11-03_20-00-00`, each a complete recovery point; incremental and deduplicated.
- **Verified before it counts** — data is flushed, read back from the device, authenticated and committed with an authenticated record; interrupted backups stay `.incomplete`.
- **100% offline** — no account, cloud, telemetry or update check. A test fails the build if any networking API is referenced.

## Repository layout

| Path | Contents |
|---|---|
| `docs/DESIGN.md` | Technical design: threat model, key hierarchy, format, crash recovery, risk register |
| `docs/FORMAT.md` | On-disk format v1 specification (enough to write an independent restore tool) |
| `src/RezenBackup.Crypto` | STREAM AES-256-GCM, Argon2id (libsodium), HKDF key hierarchy, recovery-key codec |
| `src/RezenBackup.Format` | Key files, encrypted objects, packs, trees, snapshot/commit records, chunk index |
| `src/RezenBackup.BackupEngine` | Keyed FastCDC, dedup, verification, commit protocol, retention |
| `src/RezenBackup.RestoreEngine` | Catalog browsing/search, versions, verified restore, deep verification |
| `src/RezenBackup.Application` | Orchestration shared by the app, agent and CLI |
| `src/RezenBackup.Platform` | Windows (DPAPI, VSS client, NO_BUFFERING) and macOS (Keychain, F_FULLFSYNC) services |
| `src/RezenBackup.UI` | Avalonia desktop app; also the background agent (`--agent`) with tray/menu-bar icon |
| `src/RezenBackup.Cli` | `rezen` command-line tool |
| `src/RezenBackup.Service` | Windows-only VSS helper service (creates/deletes shadow copies only) |
| `tests/RezenBackup.Tests` | Crypto, format, engine, crash-injection, application-flow, policy and offline tests |
| `installer/` | WiX MSI (Windows) and `.app`/`.dmg` packaging (macOS) |

## Building and testing

Requires the .NET 10 SDK (`global.json` pins the version).

```bash
dotnet build RezenBackup.slnx
dotnet test tests/RezenBackup.Tests
```

Run the desktop app or the CLI from source:

```bash
dotnet run --project src/RezenBackup.UI
dotnet run --project src/RezenBackup.Cli -- help
```

### Packaging

- **macOS:** `installer/macos/build-app.sh [arm64|x64]` → `artifacts/macos/<arch>/Rezen Backup.app` and a `.dmg`.
  Set `REZEN_MAC_SIGN_IDENTITY` (and optionally `REZEN_NOTARY_PROFILE`) to sign with the hardened runtime and notarize.
- **Windows:** `installer/windows/build.ps1` (on Windows) → `artifacts/windows/RezenBackup-<version>-x64.msi`.
  Set `REZEN_SIGN_CERT_THUMBPRINT` (and `REZEN_SIGN_TIMESTAMP_URL`) to Authenticode-sign binaries and the MSI.

Signing credentials are never stored in this repository. CI (`.github/workflows/ci.yml`) runs the tests on Windows, macOS and Linux and builds unsigned packages.

### Developer switches

| Variable | Effect |
|---|---|
| `REZEN_DATA_DIR` | Use another local data folder (database, logs, local key copies) |
| `REZEN_DISABLE_OS_CREDENTIALS=1` | Never touch the Keychain / DPAPI ("remember password" becomes unavailable) |
| `REZEN_NO_AUTOSTART=1` | Do not register the background agent to start at sign-in |
| `REZEN_KEYCHAIN_TEST=1` | Enables the test that round-trips (and deletes) one item in the real OS credential store |

## Command line

```text
rezen init                                   create the password and recovery key
rezen job-create --name "Company Documents" --source ~/Documents --dest /Volumes/Backup
rezen backup                                 back up now
rezen snapshots | ls | search --name budget --versions
rezen restore --to ~/Restored [--snapshot 2026-11-03_20-00-00] [--path Invoices]
rezen verify --deep [--repair]
rezen import /Volumes/Backup [--recovery-key]
rezen change-password | recovery-key | remember on|off | history | security-log | status
```

Passwords are read without echo (or from standard input with `--password-stdin`) and are never accepted as command-line arguments.

## How it works, briefly

1. Your password unlocks a random 256-bit **Root Secret** (the recovery key *is* this secret, written for humans).
2. Each backup drive repository derives its own keys from the Root Secret with HKDF.
3. Files are split with keyed content-defined chunking; new chunks are compressed, packed into ~32 MB packs, padded, and encrypted. Names live only inside encrypted directory trees.
4. Every pack is flushed to the device, read back (bypassing the OS cache) and authenticated before it is used. The snapshot is renamed from `….incomplete` to its final name only after verification and an authenticated commit record.
5. Restore authenticates every segment, re-checks every chunk's keyed ID and each file's SHA-256 before moving the file into place.

See `docs/DESIGN.md` for the full design, including what an attacker with the drive can still see (dates, approximate sizes) and the honest limits of the security model (for example, encryption does not stop ransomware from deleting a connected drive's files — disconnect the drive after backing up).
