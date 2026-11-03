# Rezen Backup — Technical Design Document

| | |
|---|---|
| **Status** | Draft for review — implementation has not started |
| **Version** | 0.1 |
| **Date** | 2026-11-03 |
| **Scope** | Rezen Backup v1 for Windows 10 / 11 and macOS 13+ (see §29) |
| **On-disk format** | Rezen Backup Format v1 |

This document is the architecture gate required before implementation (spec §91). Sections 1–25 answer the 25 required topics in order. Section 26 is the risk register: every data-loss and security risk, mapped to the control that handles it. Section 27 is the implementation plan, and Section 28 lists the decisions that need sign-off.

Throughout, **MUST** marks a non-negotiable rule from spec §87.

---

## 0. Design principles

These principles decide trade-offs. When two of them conflict, the one listed first wins (spec §95).

1. **A stolen backup drive exposes nothing.** File contents, file names, folder structure and file sizes are encrypted and authenticated. The only things visible in plaintext are listed in §12.4.
2. **The drive is the source of truth.** Everything needed to restore lives on the backup drive and is readable with only the password or the recovery key. The local database is a cache plus configuration, and can always be rebuilt from the drive (§19).
3. **A backup is complete only when proven complete.** A snapshot counts as successful only after its data has been written, flushed, read back from the device, authenticated, and committed with an authenticated commit record (§15).
4. **Append-only by default.** Normal backups only *create* files on the drive. Existing data is deleted only by an explicit, logged retention run, and only after a newer verified snapshot exists (§20).
5. **No new cryptography.** Rezen uses standard primitives from audited implementations: Windows CNG through .NET, and libsodium. Rezen-specific code is limited to composing them, and that composition is small, isolated, documented and tested against fixed vectors (§4).
6. **Offline, always.** No component opens a network socket. This is enforced by tests and by build-time dependency review (§1.4).
7. **Be honest with the user.** The app never shows "Success" when verification has not completed. Its security claims state their limits (ransomware, SSD erasure, same-user malware).

---

## 1. Overall architecture

### 1.1 Process model

```text
┌──────────────────────────── Interactive user session ───────────────────────────────┐
│                                                                                      │
│  RezenBackup.exe (UI, WPF)                RezenBackup.Agent.exe (per-user, no window)│
│  ─ dashboard, jobs, restore, history      ─ scheduler, drive monitor, job queue      │
│  ─ unlock / restore run in-process        ─ runs ALL backups, verification, prune    │
│  ─ never uses the DPAPI credential        ─ tray icon, toast notifications           │
│              │                              ▲            │                           │
│              └── named pipe (CurrentUserOnly, local only) ┘            │             │
│                                                                        │             │
└────────────────────────────────────────────────────────────────────────┼─────────────┘
                                                                         │ named pipe
                                                       ┌─────────────────▼──────────────┐
                                                       │ RezenBackupService (Windows    │
                                                       │ service, optional component)   │
                                                       │ ─ ONLY creates/deletes VSS     │
                                                       │   shadow copies                │
                                                       │ ─ never sees keys, never reads │
                                                       │   or writes user files         │
                                                       └────────────────────────────────┘
```

**Why the backup engine runs as the user, not as a service.** A service running as SYSTEM could read every file on the machine and would need machine-scope secrets. Spec §51 rules that out. Running as a low-privilege service account would not work either: it cannot read the user's files without extra privileges, and it cannot use the user's DPAPI credentials. A per-user agent:

- reads exactly what the user can read, which is least privilege;
- protects the remembered key with **DPAPI CurrentUser** scope, so other Windows accounts on the PC cannot decrypt it;
- can show tray icons and notifications directly.

**Consequence (accepted trade-off):** scheduled backups run while the user is signed in, including when the screen is locked. If the user is signed out at the scheduled time, the backup counts as *missed* and runs at the next sign-in (setting: "Run missed backups"). A "run while signed out" mode would need the user's Windows password stored in Task Scheduler. S4U tasks are not an alternative, because they cannot decrypt DPAPI user secrets. v1 rejects this mode deliberately.

**Why `RezenBackupService` exists at all.** Volume Shadow Copy (VSS) snapshots need administrator rights. A deliberately tiny privileged service does only that one job (§1.3). If the user deselects it during installation, Rezen still works and reports locked files explicitly instead of reading them from a shadow copy (spec §68).

**Agent lifetime.** The installer registers a per-user Task Scheduler task with a logon trigger and restart-on-failure. The UI starts the agent if it is not running. Closing the UI never stops the agent. Exiting the agent from the tray asks for confirmation and shows the warning "Scheduled protection will stop until you sign in again" (spec §52).

### 1.2 Module layout

```text
RezenBackup.slnx
├── src/
│   ├── RezenBackup.Crypto          AEAD STREAM, Argon2id (libsodium), HKDF key hierarchy, recovery-key codec, SecretBuffer
│   ├── RezenBackup.Core            Domain types, platform interfaces, path policy, schedule & retention math, errors
│   ├── RezenBackup.Format          On-disk format v1: key files, objects, packs, trees, snapshots, commit records, locks
│   ├── RezenBackup.BackupEngine    Scan → chunk → dedup → pack → verify → commit; resume; retention/prune
│   ├── RezenBackup.RestoreEngine   Unlock, catalog session, search, versions, restore, catalog rebuild, deep verify
│   ├── RezenBackup.Database        SQLite schema, migrations, data access, DB backup/recovery
│   ├── RezenBackup.Logging         File logging with redaction, tamper-evident security log
│   ├── RezenBackup.Scheduler       Next-run calculation, missed runs, per-disk job queue
│   ├── RezenBackup.DriveMonitor    Volume arrival/removal, marker detection, volume identity
│   ├── RezenBackup.Security        Password policy, session/auto-lock, unlock service
│   ├── RezenBackup.Platform        Windows + macOS implementations (credential store, durable I/O, keep-awake,
│   │                               notifications, autostart, eject, VSS client) selected at runtime
│   ├── RezenBackup.Application     Orchestration shared by UI, Agent and CLI (jobs, runs, unlock, restore, settings)
│   ├── RezenBackup.Agent           Per-user background host: scheduler, drive monitor, job queue, IPC server
│   ├── RezenBackup.Service         Windows only: privileged VSS helper service (§1.3)
│   ├── RezenBackup.Cli             `rezen` command line (headless operation, scripting, support)
│   └── RezenBackup.UI              Avalonia desktop application (MVVM), Windows + macOS
├── tests/
│   └── RezenBackup.Tests           Crypto KATs/tamper/nonce tests, format golden files, engine round-trips,
│                                   fault injection, crash-kill harness, offline gate, redaction scan
└── installer/
    ├── windows/                    WiX MSI + signing script (no secrets)
    └── macos/                      .app bundle, LaunchAgent plist, dmg + codesign/notarize script (no secrets)
```

This adds projects to the suggested structure in spec §24. **Format** holds the on-disk format layer that the backup and restore engines share, so neither engine owns it. **Platform** keeps OS interop out of the engines. **Application** keeps orchestration out of the UI. **Agent** is the per-user host from §1.1. **Cli** allows headless use and end-to-end testing.

**Platform split.** Every project targets plain `net10.0` and builds on Windows, macOS and Linux. OS-specific behaviour is chosen at runtime (`OperatingSystem.IsWindows()` / `IsMacOS()`) behind interfaces such as `ICredentialStore`, `IDurableFileOps`, `ISourceSnapshotProvider`, `IPowerManager`, `INotifier`, `IAutostart` and `IVolumeInspector`. All cryptography, the format and both engines are platform-neutral, so a backup made on a Mac can be restored on Windows and the reverse (§29).

**Dependency rule.** Crypto depends on nothing in the solution. Format depends on Crypto and Core. Engines depend on Format. The UI depends on engines and services through interfaces, and never calls Crypto directly (spec §90). An architecture test enforces this rule.

### 1.3 Privileged VSS helper (`RezenBackupService`)

- Runs as **LocalSystem**, because creating a VSS snapshot through `Win32_ShadowCopy.Create` needs administrator rights and no smaller built-in identity can do it. This is the only reason, and the service is designed so that being SYSTEM gives it as little reach as possible:
  - It exposes exactly three pipe operations: `CreateShadow(volumeGuid)`, `ReleaseShadow(shadowId)` and `ListMyShadows()`.
  - It impersonates the caller to identify the caller's SID. Shadow copies are tracked per SID, with at most one active set per user. A shadow copy is deleted when the client's pipe disconnects, and in any case after 12 hours.
  - On startup it deletes any shadow copies it created but no longer tracks (crash cleanup).
  - It never opens user files and never receives key material.
  - The user reads files through the shadow device path (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...`) **with their own token**, so normal NTFS permissions still apply and there is no confused-deputy read path.
- Pipe ACL: interactive users get connect access and the NETWORK SID is denied. Remote clients are rejected.
- Spike **S1** must confirm that a standard user can read their own files through a client-accessible shadow device path. If that fails, the fallback is that the service duplicates a read-only handle per file request. That would widen its scope, so it would need a new design review.

### 1.4 Offline enforcement

- No dependency may contain networking code paths that the app reaches. Each package is reviewed and recorded in `docs/DEPENDENCIES.md`.
- `RezenBackup.Offline.Tests` scans the compiled assemblies for references to `System.Net.Http`, `System.Net.Sockets`, `System.Net.WebClient`, `HttpClient` and similar. Any match outside an explicit allow-list (the allow-list starts empty) fails the build.
- No telemetry, crash upload, update check, CDN or online licensing exists anywhere. The Windows Error Reporting opt-out is covered in §22.
- **Cloud placeholder files** (OneDrive "online-only" files, `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`) are **not read**, because reading one makes OneDrive download it from the internet. They are reported as "Online-only file — not backed up", never skipped silently.

---

## 2. Technology stack

| Concern | Choice | Rationale |
|---|---|---|
| Runtime | **.NET 10 (LTS)**, self-contained publish | Current LTS. The installer ships the runtime, so nothing is downloaded (spec §78). |
| UI | **Avalonia** (Fluent theme, light/dark/system) + CommunityToolkit.Mvvm | One native-rendered C# UI for **Windows and macOS** (spec revision: Mac support required). WPF and WinUI 3 are Windows-only; MAUI's Mac Catalyst target is weaker for desktop tools. No browser or Electron (spec §23). |
| Hosting / DI / config | Microsoft.Extensions.Hosting / DependencyInjection / Options | Standard DI, cancellation and lifetime management. |
| Authenticated encryption | **AES-256-GCM** via `System.Security.Cryptography.AesGcm` (Windows CNG / BCrypt) | FIPS-validated OS module with AES-NI. Used inside the STREAM construction in §4. |
| Password KDF | **Argon2id** via **libsodium** (`crypto_pwhash`), through **NSec.Cryptography** or a minimal audited P/Invoke shim | libsodium is widely deployed and has been independently audited. Not available in the .NET BCL. |
| Key derivation / MAC / hash | `HKDF` (SHA-256), `HMACSHA256`, `SHA256` from the BCL | Standard and CNG-backed. |
| Randomness | `RandomNumberGenerator` (BCryptGenRandom) | The only randomness source allowed for security values. `System.Random` is banned by analyzer (§4.6). |
| Serialization (on-disk) | **CBOR** (RFC 8949) via `System.Formats.Cbor` | A standard, compact, self-describing format from a Microsoft-maintained package. Independent readers exist in every language, which matters for long-term recoverability. |
| Compression | **Brotli** (`System.IO.Compression`), per chunk, with an incompressibility check | No third-party dependency. Each chunk records a codec ID so codecs can be added later. |
| Local database | **SQLite** via `Microsoft.Data.Sqlite` | WAL mode, `synchronous=FULL`, transactions. |
| Logging | Microsoft.Extensions.Logging + Serilog rolling-file sink | Structured logs with a redaction policy (§22). |
| Password strength | zxcvbn (.NET port, offline dictionaries) | Encourages passphrases rather than complexity rules. |
| Notifications | Windows: `Shell_NotifyIcon` balloon (shown as a native toast on Windows 10/11). macOS: Notification Center through `osascript` | Local only, and needs no extra runtime or package identity. |
| Tray | Avalonia `TrayIcon` (Windows notification area, macOS menu bar) | One implementation for both. |
| Installer | Windows: **WiX Toolset** MSI, per-machine. macOS: signed and notarized `.app` in a `.dmg`, plus a per-user LaunchAgent | Installs the service (Windows), creates ACL'd directories and shortcuts, and ships the runtime. |
| Tests | xUnit, FsCheck (property tests), Verify (golden files) | |

The exact package versions are chosen and pinned (with lock files) in Phase 0 (§27). Every native binary that ships, such as `libsodium.dll`, has its hash recorded and is code-signed as part of the release.

---

## 3. Threat model

### 3.1 Assets

| ID | Asset | Sensitivity |
|---|---|---|
| D1 | Contents of backed-up files, including old versions of files later deleted from the PC | Critical |
| D2 | File and folder names, folder structure, file sizes, timestamps | High |
| D3 | Backup password, recovery key, Root Secret and derived keys | Critical |
| D4 | Availability and integrity of backups (being able to restore) | Critical |
| D5 | Source files on the PC (must never be modified by backup) | Critical |

### 3.2 Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| A1 | **Thief or finder of the drive** | Unlimited offline time, any hardware, can copy everything and run GPU or ASIC password cracking. |
| A2 | **Tamperer with temporary drive access** | Can modify, delete, replace or roll back files, then return the drive. |
| A3 | **Another Windows user on the same PC** | A standard account with no admin rights. |
| A4 | **Person at an unlocked, signed-in session** | Physical access to the user's desktop for a few minutes. |
| A5 | **Malware running as the user** | Can read anything the user can read, take screenshots and log keystrokes inside the session. |
| A6 | **Malware with admin or kernel rights** | Full control of the PC. |
| A7 | **Ransomware** | A5 or A6, plus mass encryption or deletion of every writable volume it can reach, including attached backup drives. |
| A8 | **Accidents** | Power loss, USB unplugged, crash, disk full, bit rot, failing drive, user mistakes, DST changes, drive-letter changes. |

### 3.3 Security goals and limits

| Goal | Adversaries | Achieved? |
|---|---|---|
| G1. Without the password or recovery key, backup contents and names are computationally inaccessible | A1, A2, A3 | **Yes** — mandatory AEAD encryption, encrypted metadata, Argon2id. |
| G2. Any modification of backup data is detected, and corrupted plaintext is never released | A2, A8 | **Yes** — AEAD everywhere, keyed chunk IDs, file SHA-256, authenticated commit records. |
| G3. Deletion or rollback of snapshots is detected | A2 | **Yes, on the PC that made them** (local catalog plus hash chain, §15.6). On a fresh PC, only gaps in the hash chain are visible, not the deletion of the newest snapshots. |
| G4. Backups survive crashes, power loss and unplugging without silent corruption | A8 | **Yes** — commit protocol (§16). |
| G5. Other Windows users cannot use this user's remembered key | A3 | **Yes** — DPAPI CurrentUser scope plus user-only ACLs. |
| G6. A person at an unlocked PC cannot browse backup history or restore without the password | A4 | **Yes** — the UI always asks for the password and auto-locks. This is a policy control: a determined A4 could install malware, which makes them A5. |
| G7. Same-user malware cannot read backups | A5 | **No, not fully.** If "Remember on this PC" is on, A5 can decrypt the DPAPI blob. A5 can read the source files directly anyway. The real extra exposure is *old versions and deleted files* on a connected drive. Mitigations and the future write-only key design are in §9.5. |
| G8. Admin or kernel malware | A6 | **Out of scope.** It can log the password as it is typed. |
| G9. Ransomware cannot destroy all backups | A7 | **Only with operational help.** Encryption does *not* stop ransomware from deleting or encrypting the backup files. The defences are disconnect-after-backup, multiple drives, anomaly detection and pausing pruning (§21). |

### 3.4 Specific threats (spec §4)

The control for each threat is detailed in the section shown.

| Threat | Primary controls | § |
|---|---|---|
| Stolen or lost drive | Mandatory AES-256-GCM. Names and structure encrypted. Packs padded. Argon2id with high memory cost. Recovery key never written to the drive. | 4, 5, 12 |
| Unauthorized Windows user | DPAPI CurrentUser. App data directories ACL'd to the user. No secrets in SQLite, registry or logs. | 9, 23 |
| Malware reading backups | No plaintext on the drive. The UI never uses the remembered key. Optional "don't remember" mode. Planned write-only scheduled key. | 9 |
| Brute-force password | Argon2id (≥256 MiB, t≥3), minimum length plus zxcvbn score, passphrase guidance. A UI back-off exists but is not relied on. | 5 |
| Backup corruption / bit rot | AEAD per 1 MiB segment. Two copies of metadata and key files. Periodic deep verification. Self-repair from source. Full snapshots that share no data. | 15, 13 |
| Modified backup files | AEAD with the header bound as AAD. Keyed chunk IDs. Authenticated commit record. Hash chain. | 4, 15 |
| Interrupted encryption or writes | Temp-then-rename packs. `.incomplete` snapshot folders. Commit record written last. Journal for resume. | 16 |
| Tampered metadata | All sensitive metadata is AEAD-encrypted. Plaintext metadata is advisory only and never trusted. | 10 |
| Database corruption | SQLite WAL, `synchronous=FULL`, integrity check, rolling DB backups, rebuild from drive. | 23 |
| Application crash | Same as interrupted writes. Nothing is committed until verified. | 16 |
| Password exposure in memory | Pinned buffers zeroed after use. libsodium guarded memory for root keys. Short key lifetime. Auto-lock. WER exclusion. | 22, 9 |
| Accidental deletion | Append-only design. Retention is the only deleter and is logged and conservative. Source files are read-only. | 20 |
| Ransomware on a connected drive | See G9. | 21 |

---

## 4. Encryption algorithm

### 4.1 Primitive

**AES-256-GCM** (NIST SP 800-38D) with 96-bit nonces and 128-bit tags, from Windows CNG. GCM is never used directly with random nonces under a long-lived key. Every encrypted object gets its **own key** (§4.2), so nonces can be simple counters that are guaranteed unique.

### 4.2 Per-object keys

Every encrypted file or object on the drive is called an *object*: packs, snapshot records, commit records, journals and repository config. Each object starts with a 256-bit random `objectSalt`:

```text
K_obj = HKDF-SHA256( IKM  = K_class,                // K_content or K_meta (see §6)
                     salt = objectSalt,              // 32 random bytes, stored in the object header
                     info = "RezenBackup/v1/object" ‖ objectType ‖ repositoryId )
```

Two objects get the same key only if two random 256-bit salts collide, which is negligible. One key therefore never encrypts more than one object, and GCM's usage limits (2³² messages per key with random nonces) cannot be reached.

### 4.3 STREAM construction (segmented AEAD)

Large objects such as packs are split into fixed **1 MiB plaintext segments**. Each segment is encrypted separately, following the STREAM construction (Hoang, Reyhanitabar, Rogaway & Vizár, 2015):

```text
nonce_i (12 bytes) = BE64(i) ‖ 0x00 0x00 0x00 ‖ last_flag     // last_flag = 0x01 only on the final segment
ct_i ‖ tag_i       = AES-256-GCM( K_obj, nonce_i, segment_i, AAD = objectHeaderBytes )
```

This protects against the following:

- **Reordering or duplicating segments**: the segment index is part of the nonce.
- **Truncation**: only the final segment can decrypt with `last_flag = 1`, so removing the tail is detected. An object with no content still has one empty final segment.
- **Header tampering**: the whole plaintext header (format version, type, algorithm ID, segment size, repository ID, salt) is the AAD of every segment.
- **Moving segments between objects**: each object has a different key.
- **Random access**: segment *i* sits at `headerLength + i × (segmentSize + 16)`, so restore can read a single chunk without decrypting the whole pack.

### 4.4 Object header (plaintext, authenticated as AAD)

```text
offset size  field
0      8     magic            "RZNBKOBJ"
8      2     formatVersion    1          (uint16 LE)
10     1     objectType       1=pack-data 2=pack-meta 3=snapshot 4=commit 5=journal 6=repo-config 7=catalog-cache
11     1     algorithmId      1 = AES-256-GCM / STREAM / HKDF-SHA256
12     4     segmentSize      1048576    (uint32 LE)
16     16    repositoryId
32     32    objectSalt
64     8     reserved (zero; MUST be zero in v1)
72     —     segments…
```

### 4.5 Forbidden constructions (spec §5)

There is no unauthenticated mode. CBC, ECB, DES, 3DES, RC4, XOR and ZIP encryption are never used. Nothing is "encrypt then optionally MAC", and plaintext is **never released before its tag verifies**. A segment is decrypted into a buffer, authenticated, and only then handed to the caller.

### 4.6 Randomness (spec §18)

| Value | Size | Source |
|---|---|---|
| Root Secret | 256 bit | `RandomNumberGenerator.Fill` |
| Argon2id salts | 128 bit | same |
| Wrap nonces | 96 bit (random, with a fresh key every time) | same |
| Object salts | 256 bit | same |
| Repository, key-set, snapshot and pack IDs | 128 bit | same |
| Segment nonces | counter — safe because the key is unique per object (§4.2) | — |

A Roslyn analyzer (banned-API list) fails the build on `System.Random`, `Guid.NewGuid()` used as a secret, `DateTime` used as a seed, or `RNGCryptoServiceProvider`.

### 4.7 Algorithm agility

`algorithmId` and `formatVersion` are in every header. A future version could add XChaCha20-Poly1305 (ID 2) without changing how existing objects are read. A reader refuses unknown algorithm IDs with the message "This backup was created by a newer version of Rezen Backup". It never guesses.

---

## 5. Password KDF

### 5.1 Argon2id parameters

| Parameter | v1 default | Accepted range on read | Notes |
|---|---|---|---|
| memory *m* | **256 MiB** | 64 MiB – 4 GiB | |
| iterations *t* | **3**, raised by calibration | 1 – 20 | Calibrated at creation so derivation takes about 1 s on the creating PC, while *m* stays at or below 1 GiB so weaker PCs can still unlock. |
| parallelism *p* | **1** | 1 | libsodium's `crypto_pwhash` supports only p = 1. This is documented, and the larger *m* compensates. |
| salt | 128-bit random per slot | 16 bytes | |
| output | 256-bit KEK | | |

Bounds checking on read stops a tampered key file from forcing a huge allocation, which would be a denial-of-service attack. Lowering the parameters does not help an attacker: a KEK derived with different parameters simply fails to unwrap.

### 5.2 Upgrading parameters later (spec §6)

The parameters are stored per slot. After a successful unlock, if a slot's parameters are below the app's current recommendation, the slot is re-wrapped with the same password and the stronger parameters, using the atomic procedure in §8.

### 5.3 Password handling

- **Policy (spec §7):** minimum 12 characters. Passwords with a zxcvbn score below 3 are blocked with an explanation. A strength meter shows the estimated crack time. The user is encouraged to use 16 or more characters or a 4-word passphrase. Letters, digits, symbols, spaces and any Unicode are allowed, and there is no maximum length. "Show password" (off by default) and "Confirm password" are always present.
- **Normalization:** the password is normalized to **Unicode NFC** and then encoded as UTF-8. Without this, the same passphrase typed through a different keyboard layout or input method on another PC could produce different bytes, and the backup could not be unlocked, which would be a data-loss bug. Leading and trailing spaces are kept, and the UI warns about them.
- **Memory:** the UI reads the WPF `PasswordBox` as a `SecureString` and copies it into an unmanaged buffer. It then converts it into a **pinned** `byte[]` allocated with `GC.AllocateArray(pinned: true)` and passes it to libsodium. Every intermediate buffer is zeroed with `CryptographicOperations.ZeroMemory` straight away. If NFC normalization needs a short-lived managed string because no span-based API is available, that limitation is documented in §22.3.
- **UI back-off:** after 5 failed unlocks there is an exponential delay (1 s, 2 s, 4 s … up to 60 s). This is cosmetic. **The real defence against brute force is Argon2id plus password strength (spec §50).**

---

## 6. Key hierarchy

### 6.1 Overview

```text
                        ┌──────────────────────────────────────────────┐
                        │ Root Secret  RS   (256-bit, CSPRNG)          │◄── Recovery key = human encoding of RS (§7)
                        │ one per Key Set                              │
                        └──────────────────────────────────────────────┘
        password ──Argon2id──► KEK_pw ──wraps──► RS        (key slot, stored in each repository's key files)
        DPAPI (CurrentUser) ─────────────wraps─► RS        (optional, local PC only — §9)

  per repository (one repository = one job on one drive):
        RMK       = HKDF(RS,  salt = repositoryId, info = "RezenBackup/v1/repository-master")
        K_content = HKDF(RMK, info = "RezenBackup/v1/content")     → per-pack keys  (§4.2)
        K_meta    = HKDF(RMK, info = "RezenBackup/v1/metadata")    → snapshot, commit, tree packs, journal, config, catalog cache
        K_chunkid = HKDF(RMK, info = "RezenBackup/v1/chunk-id")    → HMAC-SHA256 chunk identifiers (§13)
        K_cdc     = HKDF(RMK, info = "RezenBackup/v1/cdc-seed")    → keyed chunker gear table (§14)
        K_check   = HKDF(RMK, info = "RezenBackup/v1/key-check")   → quick "is this the right key?" tag in key files
```

### 6.2 Key Sets: the "master password" model (spec §10)

A **Key Set** is one password, one recovery key and one Root Secret. By default an installation has **one Key Set**, which is the Rezen Backup master password, and every job uses it. In Advanced settings a job can get its **own separate Key Set**, with a different password and recovery key, for example to keep finance backups separate from general files.

- Every job and drive pair is its own **repository**, with its own random `repositoryId` and therefore its own RMK and data keys. Each repository's data is encrypted under different keys even when they share a password. Breaking one repository's data keys does not reveal another's.
- The password never encrypts data directly. It only wraps RS, as the spec requires: password → KEK → wrapped key → data keys.
- Changing the password only re-wraps RS. No data is re-encrypted (§8).

### 6.3 Key files on the drive

Each repository stores its key file **in two copies**: `keys\key-a.rzk` and `keys\key-b.rzk` (§10.1). A third copy is kept on the PC in `%LOCALAPPDATA%\Rezen Backup\Keys\`. The file is safe to copy because RS is only stored wrapped. Format (CBOR body after a fixed plaintext header):

```text
magic "RZNBKKEY", formatVersion 1, keySetId (16), repositoryId (16), generation (uint64)
slots: [
  { type: "password", kdf: "argon2id", m, t, p, salt(16),
    nonce(12), wrappedRS(32) ‖ tag(16) }           // AES-256-GCM(KEK_pw, nonce, RS, AAD = keySetId ‖ slot descriptor)
]
keyCheck: HMAC-SHA256(K_check, "key-check" ‖ repositoryId)[0..16)
fileChecksum: SHA-256(all preceding bytes)          // detects accidental damage only; not a security control
```

- Each wrap uses a fresh salt, which gives a fresh KEK, plus a random nonce. No nonce is ever reused.
- `fileChecksum` lets the app tell "this key file copy is damaged" apart from "wrong password". Without it the app could not know when to fall back to the other copy, and the user would never see the "use your recovery key" guidance. It reveals nothing secret.
- **What is never in a key file:** the password, RS in plaintext, the recovery key, or any DPAPI blob (spec §32).

### 6.4 Lifetime of keys in memory

| Key | Where it lives | When it is destroyed |
|---|---|---|
| Password bytes | pinned buffer | right after Argon2id finishes |
| KEK_pw | pinned buffer | right after unwrapping |
| RS, RMK | libsodium `sodium_malloc` guarded, locked pages (`SecretBuffer`) | on lock or auto-lock, at the end of a backup run, or when the process exits |
| K_obj | `AesGcm` instance (CNG key handle) | when the object has been read or written |

---

## 7. Recovery-key architecture

### 7.1 What the recovery key is

The recovery key **is the Root Secret RS**, written so a person can copy it. Recovery therefore does not depend on any key file. If every copy of the key file is lost or damaged, the recovery key still recovers every repository in its Key Set.

```text
RZN1-7KQ4-HX2M-P9TD-…-W3QF-C8      (14 groups of 4 Crockford-Base32 characters)
      └──── 256-bit RS ─────┘ └ 20-bit checksum = SHA-256("RZN-RK" ‖ RS)[0..20 bits)
```

- Crockford Base32 has no ambiguous characters (no I, L, O or U). Input is case-insensitive, and hyphens or spaces are optional.
- The checksum catches typing errors before any decryption is tried. The chance of a random typo passing is about 1 in 10⁶.
- **Key Set fingerprint** (not secret): the first 8 characters of a hash of `keySetId`. It is printed next to the recovery key so the user knows which key belongs to which backups.
- No Argon2 step is needed, because RS has 256 bits of entropy and cannot be guessed.

### 7.2 Lifecycle

1. **Setup step 4:** RS is generated and shown. The user can then:
   - **Print it** through the Windows print dialog, which is local and offline. The app shows a reminder not to use a cloud print service.
   - **Save it to a file** on another removable device. Saving is **blocked** to any volume that holds a Rezen repository for this Key Set, and a warning appears if the target is a cloud-synced folder.
   - **Skip it**, after a strong warning: "If you lose both your password and your recovery key, your encrypted backups cannot be recovered."
2. **Confirmation:** the user re-types two randomly chosen groups. Only then is the Security page set to "Recovery key: Configured".
3. **Viewing it later:** an unlocked user can show the recovery key again after re-entering the password. This helps users who skipped step 1, and it gives an attacker nothing they don't already have with the password.
4. **Rotation:** RS cannot be changed without re-encrypting data. "My recovery key may be exposed" therefore leads to **Re-key** (§8.4), which starts a new repository with a new RS and keeps the old one until the new one is verified.
5. **Never stored by Rezen:** not in the database, the registry, logs, the drive, or DPAPI. Recovery uses no internet and has no back door (spec §12).

---

## 8. Password-change process

### 8.1 Procedure for one repository (spec §11)

1. **Authenticate:** unlock with the current password, or with the recovery key ("forgot password" path), to obtain RS. Confirm it matches the repository's `keyCheck`.
2. Derive `KEK_new` with Argon2id, a fresh salt and the current recommended parameters.
3. Build the new key file: `generation + 1`, one new password slot, and the same `keyCheck`.
4. Write it to `keys\key-a.rzk.new`, flush it with `FlushFileBuffers`, then **read it back from the device** without the system cache (`FILE_FLAG_NO_BUFFERING`), unwrap it with the **new** password, and check that the result equals RS.
5. Atomically replace `key-a.rzk` using `ReplaceFileW` / `MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`, then flush the directory.
6. Repeat steps 4–5 for `key-b.rzk`, and then for the local copy.
7. Re-read both copies on the drive and verify them. Record a security-log event.

**Crash safety:** at every moment, at least one key file copy unlocks with either the old or the new password. When opening a repository, Rezen tries every copy with the password the user entered. Once one works, it repairs the other copies to the highest generation. The recovery key works throughout regardless.

### 8.2 Several repositories and disconnected drives

A Key Set may have repositories on drives that are not currently connected. When the password changes:

- Connected repositories are updated at once.
- Disconnected ones are marked **"Password update pending"** in the local database and on the Security page. The agent applies the update automatically when the drive is next connected, if RS is available (remembered or currently unlocked). Otherwise it applies it at the next unlock.
- Until then, the **old password still opens those drives**. The UI says so clearly: "1 backup drive still uses your previous password. Connect it to finish updating."

### 8.3 What changing the password does *not* do

If an attacker has already copied a key file wrapped with the old password, the old password still opens that copy. Changing the password protects against *future* access. If the password is known to have leaked, the user needs **Re-key**, and the UI recommends it whenever the reason for the change is "my password may be compromised".

### 8.4 Re-key (key compromise)

Re-key creates a new Key Set with a new RS and new repositories, then runs a full backup into them. Only after the new snapshot is verified does the user get the option to delete the old repositories, as an explicit action. This takes as long as a first full backup, and the UI says so.

---

## 9. Secure credential storage for scheduled backups

### 9.1 What is stored

When the user enables **"Remember password on this PC (allows automatic scheduled backups)"**, the agent stores:

```text
%LOCALAPPDATA%\Rezen Backup\Credentials\{keySetId}.dpapi
  = CryptProtectData( RS,
                      optionalEntropy = "RezenBackup/v1/dpapi" ‖ keySetId,
                      flags = CRYPTPROTECT_UI_FORBIDDEN )      // CurrentUser scope (never LOCAL_MACHINE)
```

- The directory is ACL'd to the user, SYSTEM and Administrators, with inheritance turned off.
- Nothing is stored in SQLite, JSON, the registry or plain files (spec §45).
- The DPAPI master key is protected by the user's Windows logon credentials. Another Windows account on the PC cannot decrypt the blob (G5).
- DPAPI is used rather than Credential Manager because Credential Manager is also DPAPI underneath, has blob size limits, and adds roaming behaviour that is not wanted here.

### 9.2 Behaviour

| Remember | Scheduled backup |
|---|---|
| **On** | The agent decrypts RS just before the run and derives the RMK. RS and the RMK are zeroed when the run ends. |
| **Off** | At the scheduled time the agent shows a notification: "Backup is ready — enter your password to start." Clicking it opens the UI unlock prompt. The UI derives RS and passes it to the agent over the local `CurrentUserOnly` pipe, for this run only. If the user ignores it, the job stays *Pending*. |

**If the credential is unavailable** (blob deleted, DPAPI failure after an admin reset the user's Windows password, or a corrupt file), the run fails safely without writing anything. The status becomes "Backup Locked — enter your password", the user gets a notification, and a security-log event is recorded (spec §45).

### 9.3 The UI never uses the remembered credential

Browsing history, restoring, viewing the recovery key and changing security settings **always** need the password or recovery key (spec §9). The remembered key exists only so that unattended backups can run.

### 9.4 Turning it off

Turning the option off overwrites the blob with zeros, deletes it, and records a security-log event. The UI notes that SSDs may keep earlier copies of the file, which are still protected by DPAPI.

### 9.5 Same-user malware: residual risk and mitigations

- **Residual risk:** with "Remember" on, malware running as the user can call DPAPI and obtain RS. This is shown in the Remember toggle's description: "Programs running under your Windows account could use this to read your backups. Recommended only if this PC is well protected."
- **Mitigations in v1:** remember is **off by default**. The drive is connected only during backups (§21). Malware gets nothing extra from the UI process because the UI does not use the blob.
- **Planned after v1 (Format v1 already reserves room for it):** a **write-only scheduled key**. The pack key would be wrapped to an X25519 public key, so the agent could add new backups but could not decrypt existing ones. This needs a locally held chunk-ID index and is a significant design change, so it is planned rather than promised. Optional binding to the TPM through the CNG Platform Crypto Provider is planned as well; it would stop a stolen blob from being used offline.

---

## 10. Backup container format

### 10.1 Directory layout on the drive

```text
X:\Rezen Backup\
│   .rezenbackup                         Drive marker (plaintext JSON, no secrets)            §17
│
└── OFFICE-PC\                            Computer name           (plaintext — can be hidden, §12.4)
    └── Company Documents\                Job display name        (plaintext — can be hidden, §12.4)
        │   repository.rzc               Repository config: plaintext header + encrypted body
        │   repository.lock              Exists only while a job is writing
        ├── keys\
        │       key-a.rzk                Key file, copy A                                      §6.3
        │       key-b.rzk                Key file, copy B
        ├── store\
        │   ├── data\00 … ff\            Encrypted data packs, random 128-bit names (e.g. 9c41e0…d2.rzp)
        │   ├── meta\00 … ff\            Encrypted metadata (tree) packs
        │   ├── meta-copy\00 … ff\       Second copy of every metadata pack (redundancy)
        │   └── tmp\                     Packs being written; never referenced; safe to delete
        ├── 2026-11-03_20-00-00\
        │       snapshot.meta            Plaintext, non-sensitive hint (format id, snapshot id, state)
        │       snapshot.rzb             Encrypted snapshot record (root trees, stats, warnings)
        │       integrity.dat            Encrypted, authenticated commit record (the "complete" proof)
        └── 2026-11-04_20-00-00.incomplete\
                snapshot.meta
                journal.rzj              Encrypted progress journal (for Resume)
```

### 10.2 Files

| File | Encryption | Contents |
|---|---|---|
| `.rezenbackup` | none | `{ "format": "Rezen Backup Drive Marker v1", "driveId": "<uuid>", "createdUtc": "…" }` |
| `repository.rzc` | plaintext header, then STREAM (K_meta, type 6) | **Header:** magic, format version, minimum reader version, repositoryId, keySetId. **Body:** chunker parameters, pack size target, creating app version, job name, source list, creation time. |
| `*.rzk` | slots wrapped (§6.3) | Key slots. |
| `store\data\**.rzp` | STREAM (per-pack key derived from K_content) | Compressed data chunks, padding and an encrypted pack index (§10.3). |
| `store\meta*\**.rzp` | STREAM (per-pack key derived from K_meta) | Tree objects (§10.4). |
| `snapshot.meta` | none | `{ "format": "Rezen Backup Format v1", "formatVersion": 1, "snapshotId": "…", "repositoryId": "…", "state": "incomplete" or "committed" }`. **Advisory only and never trusted.** |
| `snapshot.rzb` | STREAM (K_meta, type 3) | The snapshot record (§10.5). |
| `integrity.dat` | STREAM (K_meta, type 4) | The commit record (§15.3). |
| `journal.rzj` | Separate STREAM objects with a sequence number, written append-only | Packs completed so far and the sources position, for Resume. |

`snapshot.rzb` and `integrity.dat` keep the names used in the spec. `snapshot.rzb` holds the encrypted snapshot record, and the data itself lives in the shared, deduplicated `store\` (spec §35).

### 10.3 Pack file plaintext layout

```text
[blob 0][blob 1]…[blob n-1][zero padding][pack index (CBOR)][uint32 indexLength][uint64 packMagic]
blob      = compressed (or stored) chunk bytes
pack index= [{ id: chunkId(32), kind: data|tree, offset, storedLength, rawLength, codec }]
```

- The padded plaintext length follows the **Padmé** scheme (at most about 12% overhead), so file sizes reveal at most O(log log n) bits about the real size.
- The target size is about 32 MiB, with a minimum of 64 KiB before padding.
- The pack index is inside the encryption, so chunk boundaries and sizes are invisible from outside (§14.3).

### 10.4 Tree objects

One tree object describes one directory and is encoded as canonical CBOR. Each entry holds:

- `name`: the UTF-8 name exactly as stored on NTFS, with no normalization.
- `type`: file, directory or link.
- `size`.
- `ctime`, `mtime`, `atime` and `changeTime`, as 100 ns ticks in UTC.
- `attributes`: hidden, read-only and similar.
- For files: `sha256` of the whole file and the `chunkIds[]` list.
- For directories: `subtreeId`.
- For links: the target, which is recorded and never followed.
- `status`:
  - `ok`
  - `changedDuringBackup`
  - `carriedForward(fromSnapshotId)`: the file could not be read this time, so the previous version is kept and clearly flagged.
  - `unreadable(reason)`

`treeId = HMAC-SHA256(K_chunkid, "tree" ‖ canonicalBytes)`. A directory that has not changed produces an identical tree, so it is deduplicated across snapshots (§13.4).

### 10.5 Snapshot record (`snapshot.rzb`)

The snapshot record contains:

- `snapshotId`, `repositoryId` and `folderName`. The folder name is bound inside the authenticated record, so renaming the folder is detected.
- `startedUtc` and `completedUtc`, plus the UTC offset at the time.
- `hostName`, `appVersion` and `formatVersion`.
- `method`: incremental or full.
- `sources[]`: `{ originalPath, rootTreeId }`.
- Statistics: file and folder counts, bytes scanned, bytes new, bytes stored.
- `warnings[]`: encrypted file-level problems.
- `parentSnapshotId` and `previousCommitHash` (§15.6).
- `encryption`: algorithm and KDF identifiers, which are informational.

### 10.6 Version compatibility (spec §17)

- `formatVersion` must be supported. `minReaderVersion` in `repository.rzc` lets a newer writer tell older readers "you cannot read this" before the user even enters a password.
- A v1 reader rejects anything it does not understand. A newer reader **must** read every older version. A frozen set of **golden v1 repositories** is committed to `tests/` and must restore byte-for-byte in every future build.
- `docs/FORMAT.md`, written in Phase 1, will specify the format completely enough that someone could write an independent restore tool without Rezen's code. This protects recovery over decades.

---

## 11. Date-based snapshot structure

- Folder names use `YYYY-MM-DD_HH-MM-SS` in **local time**, for example `2026-11-03_20-00-00`, matching what the user sees and the spec's examples.
- The authoritative time is the authenticated `startedUtc` in the snapshot record. History is sorted by UTC.
- **Daylight-saving fall-back** can make two local times identical. If a folder with that name already exists, the new snapshot gets a suffix: `2026-11-01_01-30-00_2`. Sorting by name stays correct for every other case.
- **States** (spec §21, §56):
  - `…​.incomplete`: being written, or interrupted.
  - No suffix: committed.
  - `…​.deleting`: being removed by retention (§20).
- A snapshot is treated as **restorable** only if all of the following hold (§15.4):
  1. the folder has no suffix;
  2. `integrity.dat` decrypts and authenticates;
  3. its `snapshotId` and `folderName` match `snapshot.rzb`;
  4. the hash of `snapshot.rzb` matches the value in the commit record.

  A folder renamed by hand from `.incomplete` therefore never passes as complete.

---

## 12. Filename and path encryption

### 12.1 Approach

Rezen does **not** encrypt names one by one. File and folder names exist only **inside encrypted tree objects** (§10.4), and the drive holds only opaque random pack names. Someone browsing the drive sees `store\data\9c\9c41e0…d2.rzp`, never `Payroll.xlsx` or `Customer Contracts` (spec §15).

### 12.2 Why not encrypt each name

Encrypting names individually and keeping the folder tree on disk would reveal the tree's shape, the number of files per folder and every file's size, and it would run into path-length limits. Storing names only in encrypted trees reveals none of this.

### 12.3 Rebuilding names

Real names exist only in memory, inside an unlocked catalog session (§18.2), or are written to the restore destination.

### 12.4 What *is* visible on the drive (complete list)

| Visible | Why | How it can be reduced |
|---|---|---|
| The `Rezen Backup` folder and the drive marker | Needed to recognise the drive | — |
| Computer name and **job display name** (folder names) | The spec's layout (§13), and lets the user see which backup is which | **Setup option "Hide computer and job names on the drive"**, which uses opaque folder names such as `R-7F3A2C`. The job-name field warns: "This name is visible on the backup drive." |
| Snapshot dates and times, and how many snapshots there are | Required by spec §13 | — |
| Total size, approximate new data per snapshot, number of packs | Unavoidable for stored data | Padmé padding, packs combining many files |
| Ratio of metadata to data (`store\meta` vs `store\data`) | Lets metadata get extra redundancy | — (accepted) |
| Format version, Argon2 parameters, key-set ID | Needed to unlock | — |
| Last-modified times of files on the drive | Set by the filesystem | — |

**Not visible:** file names, folder names, folder structure, number of files (roughly correlated with metadata size), individual file sizes, file contents, file types, and whether two files are identical.

---

## 13. Incremental backup design

### 13.1 Pipeline (spec §35, §38)

```text
enumerate (VSS view or live) → filter (exclusions) → change-detect → read → CDC chunk → chunkId = HMAC(K_chunkid, chunk)
    → [known chunk? reference it] / [new chunk? compress → append to pack buffer]
    → pack full → encrypt (STREAM) → write store\tmp\<id>.rzp.tmp → flush → read back (no cache) → verify → rename into store\data\xx\
```

Plaintext exists only in process memory buffers. **No plaintext staging directory ever exists** (spec §38). Buffers are bounded: about 4 packs in flight, roughly 128 MiB. They are pooled and zeroed when returned to the pool.

### 13.2 Change detection (Versioned Incremental, the default)

A file is re-read only if one of `{size, LastWriteTime, ChangeTime, FileId}` differs from the previous snapshot. `ChangeTime` comes from `GetFileInformationByHandleEx(FileBasicInfo)`, which catches metadata-only changes and files whose `mtime` was preserved by a copy or rename.

Otherwise the file entry, with its chunk list and hash, is copied from the previous tree. The previous trees come from a **local encrypted cache** (catalog cache, AEAD under K_meta), so the drive does not have to be re-read. They are re-read from the drive if the cache is missing.

| Source change | Result |
|---|---|
| New file | Read in full. |
| Changed file | Read in full; only new chunks are stored. |
| Renamed or moved file | FileId stays the same, but the path changed, so the file is read again. Its chunk IDs are unchanged, so **nothing new is stored**. |
| Deleted file | Absent from the new snapshot; still in older snapshots until retention removes them. |

### 13.3 Methods (spec §34)

| Method | Behaviour |
|---|---|
| **Versioned Incremental** (default, recommended) | As above. Every run produces a complete, independently restorable logical snapshot. |
| **Full Snapshot** | Re-reads and re-hashes every file and ignores change detection. Data is written into new packs **even if the chunks already exist**, so the snapshot shares no data with others. This guards against one damaged pack affecting many snapshots (§26, R-D3). Suggested pattern: daily incremental plus a monthly full snapshot. |
| **Mirror** | Not a separate engine. It is offered as the retention preset **"Keep latest snapshot only"**, behind a clear warning: "Files you delete or that get damaged on your PC will disappear from the backup after the next run. Not recommended." It is never the default, and no plaintext mirror is ever made. |

### 13.4 Files changing during backup (spec §69)

1. Capture metadata (size, timestamps, FileId).
2. Stream the file through chunking and encryption while computing SHA-256.
3. Capture the metadata again.
4. If it changed, retry up to 3 times with back-off.
5. If it still changes, store the last read **flagged `changedDuringBackup`**. Show it in the run summary, as a badge in the restore browser, and as "Completed with warnings".

When VSS is available (the default), all files are read from **one point-in-time shadow copy**, so this situation hardly ever happens.

### 13.5 Locked files and permission errors (spec §68)

| Situation | Handling |
|---|---|
| VSS on (default when the service is installed) | Locked files are read from the shadow copy. |
| VSS unavailable | The file is retried, then recorded as `carriedForward` (previous version kept, flagged) or `unreadable` if it is new. |
| Permission denied | Same as above. |

The result summary always shows "3 files could not be backed up — View details". Nothing is ever skipped silently.

### 13.6 Special files

| Type | Handling |
|---|---|
| Symbolic links, junctions | Recorded as links; **never followed**. This prevents loops and double counting. |
| Cloud placeholders | Not read (§1.4). |
| Sparse files | Read logically. |
| Alternate data streams and NTFS ACLs | Not backed up in v1. Documented on the job page, and planned for later. |
| Long paths | Handled with `\\?\` paths and a `longPathAware` manifest. |
| Unicode names | Stored byte-exact. |

### 13.7 Exclusions (spec §67)

Exclusions can be a specific file, a folder, an extension or a glob pattern. A new job is created with these **defaults**, shown in the job editor where they can be edited or removed:

```text
$RECYCLE.BIN
System Volume Information
Thumbs.db
~$*            (Office lock files)
*.tmp
pagefile.sys
hiberfil.sys
swapfile.sys
```

Every exclusion is listed in the job summary, and the count of excluded items is shown in each run's report. Nothing is excluded that the user cannot see.

---

## 14. Deduplication design

### 14.1 Scope

Deduplication works **within one repository** (one job on one drive). Different repositories use different keys and are never deduplicated against each other. There is no cross-user or cross-drive deduplication, which rules out attacks that try to confirm whether a known file is present (spec §36).

### 14.2 Chunking

Rezen uses FastCDC content-defined chunking, with a 256 KiB minimum, 1 MiB average and 4 MiB maximum chunk size. The gear table is **seeded from K_cdc**, so chunk boundaries depend on the key. A chunk's ID is `HMAC-SHA256(K_chunkid, chunk)`. It is keyed, so it reveals nothing to anyone without the key. The same chunk ID means the chunk is stored once.

### 14.3 Encryption is never deterministic

Chunks are **not** encrypted deterministically. A chunk is encrypted once, inside a pack, under that pack's random key, and duplicates are found by looking up the ID in the encrypted index, never by comparing ciphertext. An observer cannot tell that two files are identical, because the duplicate is simply not stored a second time.

**Chunk-size fingerprinting:** published attacks on content-defined chunking recover information from the *sizes* of individual chunks. Rezen has three defences against them:

1. Chunks are packed together and encrypted as one STREAM with fixed 1 MiB segments, so individual chunk boundaries and sizes never appear on disk.
2. Pack sizes are padded with Padmé.
3. The chunker is keyed.

What remains visible is roughly how much new data each snapshot added, as noted in §12.4.

### 14.4 Trade-off made for security

Keyed chunking and deduplication only within one repository cost some storage efficiency, which the spec accepts ("Security has priority over storage efficiency").

The bigger trade-off is resilience: with deduplication, **one damaged pack can affect every snapshot that references it**. Section 15.5 and §26 (R-D3) describe the mitigation: duplicated metadata, deep verification, repair from the source, and Full snapshots that share no data.

### 14.5 Local chunk index

The local index maps `chunkId → (packId, offset, length)` and lives in `%LOCALAPPDATA%\Rezen Backup\Cache\{repositoryId}\index.db`. Chunk IDs are keyed hashes, so this file is not sensitive. It can always be rebuilt by reading the pack indexes at the end of each pack on the drive.

---

## 15. Integrity verification

### 15.1 Layers

| Layer | Detects |
|---|---|
| AEAD tag per 1 MiB segment | Any modified bit, truncation, reordering, header tampering |
| Chunk ID check after decryption and decompression (`HMAC(K_chunkid, plaintext) == id`) | Wrong chunk returned, index confusion, decompressor bugs |
| SHA-256 of the whole file (plaintext) | Wrong chunk order or assembly errors on restore |
| Commit record covering snapshot record and packs | Missing or replaced packs; a snapshot rolled back or substituted |
| Hash chain across snapshots | A snapshot deleted from the middle of the history |
| Local catalog compared with the drive | The newest snapshots deleted (on the PC that made them) |

### 15.2 Post-backup verification (spec §20, §57)

Every run verifies before it commits. Reads in this phase bypass the Windows file cache with `FILE_FLAG_NO_BUFFERING`, so they test what is actually on the device rather than what is still in memory.

| Level | Checks |
|---|---|
| **Standard** (default) | Every new pack and metadata object is read back from the device. All AEAD tags are checked. Each pack index is checked against what was written. Every chunk and tree referenced by the snapshot resolves in the index. File and folder counts and the metadata are consistent. |
| **Full** | Everything in Standard, plus: every **new** chunk is decrypted, decompressed and checked against its chunk ID. For every file that was read in this run, the full SHA-256 is rebuilt from the drive copy and compared with the hash computed while reading the source (source-hash verification). This proves that new data can be restored end to end. |
| **Deep verify** (scheduled, default monthly; also available manually) | Everything in Full, applied to the **whole repository**. Finds bit rot in old packs. |

### 15.3 Commit record (`integrity.dat`)

```text
{ snapshotId, folderName, repositoryId,
  snapshotRecordSha256,                  // SHA-256 of snapshot.rzb ciphertext
  packs: [{ packId, sha256OfCiphertext, length }]   // every pack referenced, new and old
  verification: { level, result: "passed", verifiedUtc },
  previousCommitHash,                     // hash chain
  state: "committed" }
```

It is written **only after verification passes**. It is encrypted and authenticated under K_meta, so it cannot be forged without the key. It provides the authenticated "completed" state required by spec §21.

### 15.4 States shown to the user (spec §27)

| Status | Meaning |
|---|---|
| **Encrypted & Verified** | Committed, and the commit record authenticates. |
| **Encrypted — Verification Pending** | Data written but the verify phase has not finished. Never presented as success. |
| **Backup Locked** | Key not available. |
| **Wrong Password** | Unlock failed. |
| **Integrity Failure** | Any authentication or hash failure. The message is "Backup integrity verification failed." It lists the affected snapshots and files, and **no plaintext from a failing segment is ever released** (spec §19). |
| **Recovery Key Required** | No key file copy can be opened. |
| **Backup Drive Disconnected** | The registered drive is not connected. |

### 15.5 Repair

If deep verification finds a damaged pack, Rezen does the following:

1. Lists the chunks in that pack and the snapshots and files affected.
2. Re-reads the current source files. Any chunk whose ID matches a damaged chunk is written to a new pack, so the damage is repaired from the source.
3. Uses the second copy for metadata packs.
4. Rewrites the indexes, and only after the new pack has been verified, moves the damaged pack to `store\quarantine\`. It is never deleted, so data recovery tools can still try to recover it.

Chunks that cannot be repaired are reported for each affected snapshot and file. They are never hidden.

### 15.6 Detecting rollback and deletion

- Each commit record contains `previousCommitHash`. A gap in the chain means a snapshot is missing.
- The local database records every snapshot it committed. When the drive connects, the agent compares the database with the drive, and if snapshots are missing outside a logged retention run, it reports "2 snapshots are missing from the backup drive".
- On a fresh PC with only the drive, deletion of the *latest* snapshots cannot be detected. This is a documented limitation.

---

## 16. Crash recovery

### 16.1 Commit protocol

Each step makes the backup durable before the next step starts.

| # | Step | Durable state if the run stops after this step |
|---|---|---|
| 1 | Create `repository.lock` using `CreateNew` (contains host, PID, start time and run ID) | Lock present. Stale-lock rule: same host, process not alive → safe to break; other host → ask the user. |
| 2 | Create `<ts>.incomplete\` with `snapshot.meta` (state `incomplete`) | Visibly incomplete. |
| 3 | Write each pack to `store\tmp\` → `FlushFileBuffers` → read back without cache and verify → rename into `store\data\xx\` → append a journal record | Finished packs exist but are referenced by nothing committed. |
| 4 | Write metadata packs, twice (`meta\` and `meta-copy\`), using the same procedure | — |
| 5 | Write `snapshot.rzb` → flush | — |
| 6 | Verification phase (§15.2) | — |
| 7 | Write `integrity.dat` (state committed) → flush → read back and verify | Cryptographically committed, folder name still `.incomplete`. |
| 8 | Rewrite `snapshot.meta` (state committed) → flush; rename `<ts>.incomplete` → `<ts>` → flush the parent directory | **Complete.** |
| 9 | Delete the lock; update the local database and catalog cache | — |

### 16.2 Recovery on next start or drive connection

| Found | Action |
|---|---|
| `store\tmp\*` | Deleted. These packs are never referenced. |
| `.incomplete` folder **with** a valid committed `integrity.dat` (crashed between steps 7 and 8) | Re-verify, then complete step 8. |
| `.incomplete` folder **without** a commit record | Offer **Resume Backup**: re-scan the sources, reuse the packs listed in the journal (after re-verifying them), and continue in the same folder. Or offer **Discard Incomplete Snapshot**: delete the folder; orphaned packs are removed by the next retention run. It is never treated as restorable (spec §56). |
| Stale lock | Broken under the rule in §16.1 step 1. |

### 16.3 Specific failures (spec §55)

| Event | Behaviour |
|---|---|
| App, agent or service crash | §16.2. |
| Shutdown or restart | The agent handles `WM_QUERYENDSESSION`. It uses `ShutdownBlockReasonCreate` to get a few seconds to reach a safe stopping point (current pack flushed, journal written), then stops. If interrupted harder, it falls back to §16.2. |
| Power loss | §16.2. NTFS journaling protects the renames. On exFAT, which has no journal, verification on the next start catches damaged packs (§17.4). |
| USB disconnected mid-write | An I/O error such as `ERROR_DEVICE_NOT_CONNECTED` **stops the run immediately** and marks it failed. Resume or discard is offered when the drive is reconnected. |
| Disk full | A safety reserve is kept: 256 MiB plus estimated metadata, so the commit can always finish. If free space runs out, the run stops before the reserve is touched and the incomplete snapshot is kept. The message is: "Backup could not continue because the destination drive is full." **Nothing is deleted to make space** unless retention rules allow it (spec §61). |
| Locked file, permission error, file changing | Per file: continue and finish as "Completed with warnings" (§13.4–13.5). |
| Encryption error, authentication failure on read-back, or the commit cannot be made durable | **Stop immediately.** The snapshot stays `.incomplete` (spec §86). |

### 16.4 Pause, resume and cancel (spec §37)

- **Pause** waits between chunks and keeps the lock and in-memory state. If paused for more than an hour, the agent writes the journal and releases the drive.
- **Cancel** ("Stop safely") finishes the current pack, writes the journal and leaves the snapshot `.incomplete`, which can then be resumed or discarded. Cancelling never leaves a half-written pack under a real name.

---

## 17. Drive identification

### 17.1 Identity

Drive letters are never used as identity (spec §31).

| Layer | Source | Purpose |
|---|---|---|
| **Drive ID** (authoritative, portable) | Random UUID in `X:\Rezen Backup\.rezenbackup` | Recognises the drive on any PC. |
| Volume GUID path | `GetVolumeNameForVolumeMountPointW` | Fast matching on this PC. Specific to this PC. |
| Volume serial number, label, filesystem, size | `GetVolumeInformationW` | Detects marker conflicts and helps the user identify drives. |
| Physical disk number | `IOCTL_STORAGE_GET_DEVICE_NUMBER` | Queues jobs per physical disk (§23.4) and supports eject. |

### 17.2 Detection

The agent watches for volumes arriving and leaving through a hidden message window (`WM_DEVICECHANGE` / `DBT_DEVICEARRIVAL`, plus a polling fallback every 60 seconds). When a volume arrives, the agent looks for `\Rezen Backup\.rezenbackup` on it and matches the drive ID. A drive that comes back as `F:` instead of `E:` is recognised the same way.

### 17.3 Registration (spec §32)

When the user selects a drive:

1. Validate the destination (§17.4).
2. Write `.rezenbackup` (no secrets).
3. Create the repository.
4. Store the drive's identity in the local database.

### 17.4 Destination validation (spec §72)

| Check | Rule |
|---|---|
| Exists | The volume is present. |
| Writable | A write-and-delete test file is created. |
| Registered drive | Drive ID matches. |
| Space | Estimated from the source size, plus the safety reserve. |
| No recursion | The destination must not be inside any source. A source containing the destination root is **blocked** (spec §71). |
| Same physical disk as a source | Allowed, with a clear warning: "This won't protect you if that disk fails." |
| Filesystem | **NTFS** or **ReFS** recommended. **exFAT** allowed, with a warning that it has no journal so the drive should always be ejected safely. **FAT32** rejected because it is unreliable and has size limits. Network paths are not supported in v1 (spec §30). |

### 17.5 Marker spoofing

Someone could copy the marker and the repository onto another drive. Backups would then go to that drive, but they would still be encrypted. Before writing, the agent authenticates `repository.rzc` under the RMK. It also flags a mismatch in volume serial number or size compared with what was registered: "This looks like a different physical drive with the same Rezen Backup ID — continue?"

---

## 18. Restore process

### 18.1 Flow

The restore flow has six steps:

1. **Unlock** (password or recovery key, §6). Nothing protected is shown before unlocking (spec §39, §42).
2. **Open a catalog session** (§18.2).
3. **Browse or search**: by date, job, folder, file name, extension, date range or partial name; or open a file's version history (spec §42–43).
4. **Select**: one file, several files, folders, or a whole snapshot. Pick any version.
5. **Plan**:
   - Destination: the original location or a different one (spec §41).
   - Conflicts: Replace, Keep both (`name (Restored 2026-11-03).ext`), or Skip, with "Apply to all". **Files are never overwritten silently.**
   - Free space on the destination is checked.
6. **Execute.** For each file:
   - a. Read the needed segments. Each is authenticated before use (spec §40).
   - b. Decompress, with output size capped at `rawLength` to block decompression bombs.
   - c. Check the chunk ID.
   - d. Write to `‹dest dir›\.‹name›.rzrestore-tmp`, which is hidden.
   - e. When the file is finished, check its SHA-256. On a match, atomically rename it into place (`ReplaceFileW` if replacing) and restore its timestamps and attributes. On a mismatch, **delete the temporary file** and report "Backup integrity verification failed" for that file.
   - f. Clean up the temporary file in `finally`. At start-up, any leftover `*.rzrestore-tmp` from earlier crashes is removed.

Plaintext is written **only to the destination the user chose**, never to `%TEMP%`. Only data the user selected is decrypted (spec §40).

### 18.2 Catalog session

After unlocking, the snapshot list and trees are loaded from the **local encrypted catalog cache**, or from the drive if the cache is missing or stale. They go into an **in-memory SQLite database** (`Data Source=:memory:`) with full-text search over names. On lock, the in-memory database is disposed. Nothing decrypted is ever written to disk.

### 18.3 Restore without the original PC (spec §63)

Install Rezen on another PC, choose **Import Existing Rezen Backup**, pick the drive, then enter the password or recovery key. This runs a catalog rebuild (§19) and then a normal restore. Optionally, **"Continue backing up this job from this PC"** adopts the repository, and later snapshots record the new host name.

---

## 19. Catalog rebuild

Catalog rebuild is offered as **Rebuild Backup Catalog** (Settings → Advanced) and also runs as part of Import (spec §64). It needs the password or recovery key.

1. Enumerate `\Rezen Backup\*\*\` repositories and read each `repository.rzc` header to get the IDs and the minimum reader version.
2. Unlock. Try every key file copy. If none can be opened, offer the recovery key.
3. For each snapshot folder:
   - Classify it by suffix.
   - Authenticate `integrity.dat` and `snapshot.rzb` and check that they match each other.
   - Check the hash chain.
   - Record the result: valid, incomplete or invalid.
4. Rebuild the chunk index from the pack indexes stored at the end of each pack. Use `meta-copy` if a metadata pack fails.
5. Walk the trees of the valid snapshots to build the encrypted catalog cache.
6. Write jobs, drives and snapshot rows to SQLite in **one transaction**.
7. Report the findings: snapshots, warnings, any integrity failures, and any key file copy that was repaired.

This step is read-only on the drive. The only exception is repairing a damaged key file copy, which the user is asked to confirm.

---

## 20. Retention

### 20.1 Policies (spec §59)

| Kind | Options |
|---|---|
| Count | Last 5, 10 or 30 snapshots |
| Age | 7 days, 30 days, 90 days, 6 months, 1 year |
| Forever | Keep everything |
| **Smart** | All snapshots for 7 days, one per week for 3 months, one per month for 1 year. The thresholds can be edited. |

Individual snapshots can also be **pinned** ("Keep forever").

### 20.2 Safety rules

1. Retention runs **only right after a new snapshot has been committed and verified**. It never runs when backups are failing.
2. The **newest verified snapshot** is always kept, plus a minimum number of the most recent ones (default 3), whatever their age. This means a "7 days" policy cannot delete everything after the PC has been off for two weeks.
3. Retention is **suspended** while the ransomware anomaly guard is triggered (§21.2) or while any integrity failure is unresolved.
4. Snapshots outside the policy are never deleted, and pinned snapshots are never deleted.

### 20.3 Procedure

1. **Plan:** which snapshots to delete, and which packs are no longer referenced. The plan is computed from the local catalog **and confirmed against the decrypted trees on the drive** before anything is deleted.
2. Record the plan in the security log and the run history.
3. Rename each target folder to `<ts>.deleting`.
4. Delete packs with no live chunks.
5. **Repack** packs that are mostly unused (more than 50% dead). Live chunks are copied into a new pack, which is verified and added to the index **before** the old pack is deleted.
6. Delete the `.deleting` folders.
7. Show a notification: "Removed 2 snapshots older than 30 days (retention policy)". Nothing is removed silently (spec §87).

An interrupted deletion leaves `.deleting` folders. These are never offered for restore, and the deletion is completed on the next run.

### 20.4 Deletion and erasure (spec §60)

- Deleting files does **not** guarantee they are forensically erased, especially on SSDs and flash drives (wear-levelling, TRIM). The UI says this. The deleted data was always ciphertext.
- **Cryptographic erasure at the repository level:** "Permanently destroy this backup set" overwrites and deletes every key file copy on the drive and the PC, and deletes the DPAPI blob. **The recovery key would still decrypt any ciphertext left behind**, so the dialog tells the user to destroy the printed or saved recovery key as well. Cryptographic erasure of a *single* snapshot is not possible with deduplication, because its chunks are shared, and this is documented.

---

## 21. Ransomware considerations (spec §53)

### 21.1 What encryption does *not* do

Encryption stops anyone from **reading** the backups. It does **not** stop ransomware that reaches a connected, writable drive from deleting or encrypting the backup files. The UI and documentation never claim otherwise.

### 21.2 Controls

| Control | Detail |
|---|---|
| **Connect only to back up** (recommended workflow) | The job setting "Back up automatically when this drive is connected" (default on) handles this. A backup that is due while the drive is away shows "Backup Pending — Secure Backup Drive Not Connected" (spec §62). |
| **Disconnect prompt** | "Backup complete. You may safely disconnect the backup drive." An option to **eject automatically after the backup** uses `CM_Request_Device_Eject`. |
| **Append-only behaviour** | Normal runs never modify or delete existing files on the drive (§0). |
| **Anomaly guard** | Before committing, the agent compares the share of changed files and the change in compressibility with recent runs. A sharp rise, such as more than 30% of files changed with content that suddenly cannot be compressed, suggests ransomware has encrypted the source files. In that case the agent **commits the snapshot as usual**, **suspends retention**, marks the run "Unusual changes detected", and notifies the user. The good older versions can therefore never be pruned away. |
| **Multiple drives (rotation)** | A job can have several registered drives, each with its own repository under the same Key Set. Backups go to whichever drive is connected. Keeping one drive off-site is recommended. *(This is planned in Phase 6, and Format v1 already supports it.)* |
| **Optional NTFS lockdown** (§21.3) | Off by default. |

### 21.3 NTFS permissions on the drive (spec §54)

**Findings:**

- An ACL that allows only "current user + SYSTEM + Administrators" stops *other users* from deleting files by accident.
- It does **nothing** against ransomware running as the same user.
- ACLs reference SIDs that belong to one PC. On another PC an administrator can still take ownership, so portability survives, but restoring there needs a UAC prompt.
- exFAT has no ACLs at all.

**Decision:** an optional setting, **"Restrict backup folder to my Windows account"**, applied only on NTFS, with these limitations explained. Encryption remains the protection.

---

## 22. Logging security

### 22.1 Technical logs (spec §75)

- Stored at `%LOCALAPPDATA%\Rezen Backup\Logs\`, ACL'd to the user. Files roll daily and are kept for 30 days.
- **Never logged:** passwords, keys, the recovery key, RS, DPAPI blobs or file contents. This is enforced by types: `SecretBuffer.ToString()` returns `"[REDACTED]"`, and a Serilog destructuring policy refuses secret types. A test checks every log line produced by the full test suite for known test secrets.
- **"Hide filenames from logs"** is **on** by default. Paths are wrapped in a `SensitivePath` type that renders as `path#3f9a12c4`, a keyed hash using a per-installation random log salt. Entries about the same file can still be matched up, but the name cannot be recovered.
- Raw exceptions are kept for "View Technical Details" but are never shown by default (spec §85). Exception messages pass through the same path redaction.

### 22.2 Security log (spec §76)

The security log records these events:

- Unlock and failed unlock
- Password changed
- Recovery key used
- Backup created
- Backup verified
- Restore
- Integrity failure
- Import
- Catalog rebuild
- Retention deletion plan
- Remembered credential enabled or disabled

Events are stored in the SQLite table `security_events` and mirrored to a log file. Each record contains `prevHash`, and records are linked by an HMAC chain whose key is a per-installation random key protected by DPAPI. This makes the log **tamper-evident** (an edit or deletion is detected), not tamper-proof. Records hold no secrets and no file names.

### 22.3 Memory and crash data (spec §8)

| Measure | Purpose |
|---|---|
| Pinned buffers, zeroed after use | Stops the garbage collector from making copies of secrets |
| libsodium `sodium_malloc` for RS and the RMK | Locked pages with guard pages; never written to the page file |
| Minimal key lifetime, auto-lock and manual lock (§24) | Secrets spend as little time in memory as possible |
| `WerAddExcludedApplication` | No Windows Error Reporting dumps, which would contain heap memory |
| No dumps written by Rezen itself | Same |

**Documented limits:**

- In a managed runtime, wiping memory is *best-effort*.
- `SecureString` and `PasswordBox` keep their own internal copies.
- NFC normalization may briefly create a managed string.
- A hibernation file contains RAM.

None of this is presented as a guarantee.

---

## 23. Database design

### 23.1 Location and settings

The database is stored at `%LOCALAPPDATA%\Rezen Backup\rezen.db`, one per Windows user, in a directory ACL'd to that user. It is opened with:

```text
PRAGMA journal_mode = WAL;  PRAGMA synchronous = FULL;  PRAGMA foreign_keys = ON;
```

All writes are transactions. Schema changes go through versioned migrations recorded in `schema_version`.

### 23.2 Schema (no secrets anywhere)

```text
settings            (key TEXT PK, value TEXT)
key_sets            (id BLOB PK, display_name, created_utc, password_generation INT, recovery_confirmed INT,
                     remember_on_pc INT)                                  -- flags only; no key material
jobs                (id BLOB PK, key_set_id FK, name, enabled, method, verification_level, retention_json,
                     hide_names_on_drive, auto_run_on_connect, eject_after, created_utc)
job_sources         (id PK, job_id FK, path, added_utc)
job_exclusions      (id PK, job_id FK, kind, pattern, is_default)
schedules           (job_id PK FK, kind, spec_json, run_missed INT, require_ac_power INT)
drives              (id BLOB PK /* drive marker UUID */, label, volume_guid, volume_serial, fs_type,
                     capacity_bytes, last_seen_utc)
repositories        (id BLOB PK, job_id FK, drive_id FK, relative_path, password_generation INT,
                     created_utc)                                         -- password_generation detects pending updates (§8.2)
snapshots           (id BLOB PK, repository_id FK, folder_name, started_utc, completed_utc, state,
                     security_status, verification_level, files INT, bytes_scanned, bytes_new,
                     duration_ms, commit_hash BLOB, pinned INT)
runs                (id PK, job_id FK, snapshot_id FK NULL, trigger, started_utc, ended_utc, result,
                     error_code, files_ok, files_warned, files_failed)
run_issues          (id PK, run_id FK, kind, reason_code, path_enc BLOB)  -- path AEAD-encrypted under K_meta
security_events     (id PK, utc, type, job_id NULL, detail_json, prev_hash BLOB, mac BLOB)
pending_actions     (id PK, kind, repository_id, created_utc)            -- e.g. password slot update
```

- **Sensitive data:** file-level information, whether catalog or issue paths, is either AEAD-encrypted (`run_issues.path_enc`) or kept only in the encrypted catalog cache files in `Cache\{repositoryId}\`. Source paths in `job_sources` are configuration describing the PC's own folders and are stored in plaintext, as stated in the privacy notes.
- **History** (spec §58) shows only snapshot and run statistics.

### 23.3 Corruption recovery

- `PRAGMA quick_check` runs at start-up.
- A daily online backup copy is made with the SQLite backup API (`rezen.db.bak1`, `.bak2`).
- If the database is corrupt, Rezen restores the newest backup copy that passes the check, then reconciles it with the drive (§19).
- **No backup data is lost if the database is lost**, because the drive is the source of truth.

### 23.4 Job queue (spec §73)

The agent keeps one queue per physical disk. Jobs on the same disk run one at a time ("Waiting for another Rezen Backup job"). Jobs on different disks may run in parallel; the default limit is 2.

### 23.5 Configuration export (spec §66)

`RezenBackupConfig.json` contains jobs, sources, exclusions, schedules, retention and non-security settings. It **never** contains passwords, keys, the recovery key, DPAPI data or catalog contents. Importing it validates paths and asks the user to re-attach drives.

---

## 24. Remaining application behaviour

These are covered briefly because they follow directly from the architecture above.

- **Scheduling (spec §44):**
  - Schedule types: daily, weekly (chosen days), monthly, interval (1, 2, 6 or 12 hours) and manual.
  - The scheduler computes the next run time in local time, handling DST.
  - When the agent starts, the PC resumes from sleep, or the drive is connected, it checks for missed runs.
  - It does not wake the PC from sleep in v1.
- **Power (spec §74):** `SetThreadExecutionState(ES_SYSTEM_REQUIRED | ES_CONTINUOUS)` keeps the PC awake during a run (default on). "Do not start backup while on battery" is optional.
- **Auto-lock (spec §46–48):**
  - Options: on minimize, or after 5, 15 (default) or 30 minutes idle, or "never during this Windows session".
  - The PC is locked when Windows locks (`WTSRegisterSessionNotification`), on by default.
  - **Lock Rezen Backup** (manual) closes unlocked views, disposes the catalog session and zeroes RS and the RMK.
  - A restore in progress delays auto-lock until it finishes. A manual lock asks before cancelling it.
- **Notifications (spec §77):** local Windows toasts, configured per category (success, failure, waiting for drive, integrity problems, low space).
- **Storage (spec §61):** shows capacity, used and free space, and how much the backups use. Warns at less than 10% free, or when free space is below the estimated size of the next backup.
- **Overlapping sources (spec §29):** adding a source inside another source, or containing one, prompts the user to merge them or keep only the parent.
- **Errors (spec §85):** each error code maps to a plain-language message. "View Technical Details" reveals the redacted technical text.
- **UI (spec §83–84):** a WPF Fluent theme with a Rezen blue accent. The dashboard answers six questions at a glance: protected? encrypted? last backup verified? when was it? when is the next one? is the drive connected?
- **Installer, signing and updates (spec §78–80):**
  - WiX MSI with a self-contained runtime. It installs the service, registers the toast AUMID and creates the per-user logon task at first run.
  - Signing uses `signtool` on a release machine with the certificate on a hardware token. No certificate or secret is ever in the repository.
  - Updates are installed manually by running a newer signed MSI. Backups made by older versions remain readable (§10.6).

---

## 25. Major risk summary

The full register follows in §26. These are the risks that most affect the design:

1. **Loss of both the password and the recovery key** means total, permanent data loss. This is unavoidable by design. Mitigation: the recovery-key flow, confirmation of the recorded key, and repeated warnings.
2. **Deduplication makes data shared between snapshots**, so one damaged pack can affect many snapshots. Mitigation: two copies of metadata, deep verification, repair from source, Full snapshots that share no data, and drive rotation.
3. **Ransomware against a connected drive.** Encryption cannot stop it. Mitigation: operational controls (§21).
4. **"Remember on this PC" combined with same-user malware.** Mitigation: off by default, an honest description, and the planned write-only key.
5. **A bug in Rezen's own STREAM, key-hierarchy or format code** could make data undecryptable or insecure. Mitigation: small isolated code, known-answer and property tests, golden repositories, fuzzing, and an external review before 1.0.

---

## 26. Risk register

Format: **Risk → how the architecture handles it**. R-D numbers are data-loss risks. R-S numbers are security risks.

### 26.1 Data-loss risks

| ID | Risk | Mitigation |
|---|---|---|
| R-D1 | Password forgotten | Recovery key = RS (§7). Key files are not needed to recover. Warnings at setup. |
| R-D2 | Every copy of the key file damaged or deleted | Two copies on the drive plus a local copy. Damage is detected by checksum and the copy is repaired automatically. The recovery key works without any key file (§7.1). |
| R-D3 | A pack is damaged (bit rot, bad sectors) and affects deduplicated snapshots | AEAD detects it. Metadata has two copies. Monthly deep verification. Repair from source. Damaged packs are quarantined, never deleted. Full snapshots share no data. Drive rotation (§15.5, §13.3). |
| R-D4 | Interrupted backup taken for a complete one | `.incomplete` naming plus an authenticated commit record (§11, §15.3, §16). |
| R-D5 | Crash in the middle of a write produces a torn pack | Written to temp, flushed, read back, verified, then renamed. Temp packs are never referenced (§16.1). |
| R-D6 | Write cache lies ("written" but not on the device) | `FlushFileBuffers` plus reading back with `FILE_FLAG_NO_BUFFERING` before the commit (§15.2). |
| R-D7 | Retention deletes good data | Runs only after a new verified snapshot. Keeps a minimum and the newest. Suspended on anomalies or integrity problems. Plan checked against the drive. Two-phase `.deleting`. Repacking verifies before deleting (§20). |
| R-D8 | Password change bricks access | Write-verify-replace for each copy. The old copy works until the new one is verified. Generation numbers. The recovery key still works (§8.1). |
| R-D9 | Unicode password differs between PCs | NFC normalization before UTF-8 encoding (§5.3). |
| R-D10 | A newer app version cannot read old backups | `formatVersion` and `minReaderVersion`, golden repositories in CI, `FORMAT.md` (§10.6). |
| R-D11 | Local database corrupted | WAL, `synchronous=FULL`, rolling backup copies, rebuild from the drive (§23.3). |
| R-D12 | Drive letter changes and the backup goes to the wrong drive | The drive ID in the marker is authoritative (§17). |
| R-D13 | Restore overwrites newer files | Explicit conflict choice; never silent (§18.1). |
| R-D14 | Restore writes corrupted data | Each segment authenticated, chunk ID and whole-file hash checked before the atomic rename. Temp file deleted on failure (§18.1). |
| R-D15 | Source files modified by Rezen | The engine opens sources only with `FileAccess.Read`, `FileShare.ReadWrite \| Delete`. Restore is the only code path that writes. A test checks every source for byte equality and unchanged timestamps (spec §70). |
| R-D16 | Backup loops or a recursive destination | Blocked during validation (§17.4). Links are never followed (§13.6). |
| R-D17 | Disk full during the commit | Space reserve. Run stops before the reserve is touched. Nothing is auto-deleted (§16.3). |
| R-D18 | Locked or unreadable files missing without anyone knowing | VSS. Explicit `carriedForward` / `unreadable` status. Warnings in the run summary (§13.5). |
| R-D19 | Online-only cloud files stored as empty placeholders | Detected and reported, never read (§1.4). |
| R-D20 | exFAT damaged after an unsafe removal | Warning at selection. Verification on reconnect. NTFS recommended (§17.4). |
| R-D21 | A snapshot is silently missing | Hash chain plus comparison with the local catalog (§15.6). |
| R-D22 | Inconsistent copy of a file that was changing | VSS point-in-time snapshot. Recheck and retry. Explicit `changedDuringBackup` flag (§13.4). |

### 26.2 Security risks

| ID | Risk | Mitigation |
|---|---|---|
| R-S1 | Offline brute force of the password | Argon2id with at least 256 MiB, calibrated *t*, minimum length and zxcvbn score. Parameters can be raised later (§5). |
| R-S2 | Weak or misused cryptography | Standard AES-GCM, HKDF and HMAC from CNG, Argon2id from libsodium. No custom primitives. Banned-API analyzer (§4). |
| R-S3 | GCM nonce reused | A unique key per object plus counter nonces. Every wrap uses a fresh KEK. Tests check nonce uniqueness (§4.2–4.6). |
| R-S4 | Ciphertext modified, truncated or reordered | STREAM with index and last-flag in the nonce and the header bound as AAD (§4.3). |
| R-S5 | Plaintext released before authentication | Decrypt into a buffer, check the tag, then release. Restore writes to a temp file and renames only after the full-file hash matches (§4.5, §18.1). |
| R-S6 | File names or structure visible on the drive | Names exist only inside encrypted trees. Pack names are random. The plaintext list in §12.4 is complete. Names can be hidden. |
| R-S7 | Inferring content from chunk sizes, or confirming that a known file is present | Keyed chunking, keyed chunk IDs, chunks hidden inside packs, Padmé padding, deduplication only within a repository (§14). |
| R-S8 | Secrets stored at rest | Only RS wrapped by Argon2id-KEK (drive) and RS wrapped by DPAPI CurrentUser (opt-in). Never in the database, registry, logs or configuration (§6, §9). |
| R-S9 | Secrets in memory, the page file or crash dumps | §22.3. Limits documented. |
| R-S10 | Another Windows user steals the remembered key | DPAPI CurrentUser plus directory ACLs (§9.1). |
| R-S11 | Same-user malware | Remember off by default. The UI never uses the blob. Disconnected-drive workflow. Planned write-only key (§9.5). The remaining risk is stated honestly. |
| R-S12 | Person at an unlocked PC | Password needed to browse or restore. Auto-lock. Lock when Windows locks (§24). |
| R-S13 | Recovery key exposed | Never stored by Rezen. Saving to the backup drive is blocked. Print-only flow. Re-key if exposed (§7, §8.4). |
| R-S14 | Error messages reveal information | A generic "Unable to unlock backup. Check your password or recovery key." The only distinction made is damaged key file versus wrong password, which reveals nothing secret (§6.3, spec §49). |
| R-S15 | Tampered Argon2 parameters cause denial of service | Bounds checked on read (§5.1). |
| R-S16 | Malicious input in parsers (CBOR, Brotli) | Parsers only see data **after** it has been authenticated. Plaintext headers are bounds-checked and fuzzed. Decompression is capped at `rawLength` (§10, §18.1). |
| R-S17 | Fake drive or cloned marker | The repository must authenticate under the RMK. A mismatch in volume serial or size is flagged. Any data written is ciphertext (§17.5). |
| R-S18 | Privileged service abused | Three operations only, never reads files, no keys, caller identified by impersonation, rate and lifetime limits, no network access (§1.3). |
| R-S19 | Another process injects commands over IPC | `PipeOptions.CurrentUserOnly`, network denied, versioned schema. RS hand-off is accepted only from the installed UI binary, which is best-effort because same-user code is not a security boundary (§9.2). |
| R-S20 | Tampered or substituted binaries | Authenticode-signed EXE, DLL and MSI. Native dependency hashes pinned. No executables are ever run from the backup drive. |
| R-S21 | Data leaves the PC (telemetry, cloud) | No networking code. Offline test gate (§1.4). |
| R-S22 | Secrets in logs | Type-level redaction plus a log scan in the test suite (§22.1). |
| R-S23 | Older password still opens a drive that was disconnected during the change | Pending-update tracking, applied automatically on connection, user warned (§8.2). |
| R-S24 | Forensic recovery of deleted ciphertext | It is ciphertext. Cryptographic erasure for whole backup sets, and the user is told to destroy the recovery key too (§20.4). |

---

## 27. Implementation plan

Each phase ends with passing tests. No phase leaves UI placeholders for features that are already part of the plan (spec §92).

| Phase | Deliverable | Exit criteria |
|---|---|---|
| **0 — Foundations** | Solution skeleton; pinned dependencies with lock files; analyzers (banned APIs, nullable, warnings as errors); CI on Windows and Linux; offline test gate; `DEPENDENCIES.md` | CI green; architecture tests enforce the dependency rule. |
| **1 — Crypto + Format** | `RezenBackup.Crypto` (STREAM, HKDF hierarchy, Argon2id, recovery-key codec, `SecretBuffer`); `RezenBackup.Format` (key files, objects, packs, trees, snapshots, commit records); `docs/FORMAT.md` | Known-answer tests; tamper, truncation and reorder tests; property tests; first **golden v1 repository** frozen. |
| **2 — Backup engine** | Scan, CDC, deduplication, packs, verification levels, commit protocol, journal and resume, exclusions, change detection; `IDurableFileSystem` with fault injection | Crash-kill harness: thousands of random kill points, with the invariant that every committed snapshot restores exactly and no incomplete snapshot is ever accepted. |
| **3 — Restore engine + catalog** | Unlock, catalog session, search, version history, restore planning and conflicts, catalog rebuild and import | Round-trip tests including Unicode, long paths, large and empty files, more than 1M files (synthetic); tests on a corrupted repository. |
| **4 — Windows platform + Agent + Service** | DPAPI store, drive monitor, VSS helper service, scheduler, per-disk queue, power handling, IPC, notifications, retention and prune, anomaly guard | Windows integration tests: drive-letter change, unplug mid-write (simulated), DPAPI unavailable, session lock, missed schedules. |
| **5 — WPF UI** | Setup wizard, Dashboard, Jobs, Restore, History, Security, Settings, Logs; light and dark themes | Every action in spec §92 works end to end on a real external drive. |
| **6 — Installer & hardening** | WiX MSI, signing scripts, WER exclusion, ACLs, drive rotation, NTFS lockdown option; external crypto and format review | Clean-VM install and uninstall; restore on a second clean VM from the drive alone. |

### Spikes to run early

| ID | Question |
|---|---|
| S1 | Can a standard user read their own files through a client-accessible VSS shadow device path? This determines the scope of the service (§1.3). |
| S2 | Argon2id performance and memory use on a low-end PC. This sets the calibration (§5.1). |
| S3 | `FILE_FLAG_NO_BUFFERING` read-back on USB and exFAT volumes, and how alignment is handled. |
| S4 | `CM_Request_Device_Eject` running as a standard user, for auto-eject. |
| S5 | Throughput of AES-GCM plus Brotli plus FastCDC in .NET, to confirm the pipeline can saturate a USB 3 SSD. |

---

## 28. Decisions needing sign-off

1. **Per-user agent instead of a SYSTEM service for backups.** Scheduled backups run only while the user is signed in; runs missed while signed out happen at the next sign-in (§1.1).
2. **The recovery key is the Root Secret.** This maximises recoverability, because no key file is needed. It also means rotating the recovery key requires a Re-key (§7).
3. **One Key Set (master password) by default**, with a separate Key Set per job available in Advanced settings (§6.2).
4. **Job and computer names are visible on the drive by default**, as in the spec's layout, with an option to hide them (§12.4). *Alternative: hide them by default.*
5. **Mirror is offered only as the "Keep latest snapshot only" retention preset**, not as a plaintext mirror (§13.3).
6. **v1 does not back up NTFS ACLs or alternate data streams** (§13.6).
7. **Drive rotation (several drives per job) is scheduled for Phase 6.** The v1 format already supports it (§21.2).
8. **macOS support uses Avalonia and per-OS platform services** (§29). The on-disk format is identical on both systems.

---

## 29. macOS support

The product requirement now includes macOS. Everything in Sections 4–20 (cryptography, format, engines, verification, retention) is platform-neutral and unchanged. Only the platform services in this section differ.

| Concern | Windows | macOS |
|---|---|---|
| UI | Avalonia | Avalonia (native menu bar, Dock icon) |
| Background agent | Per-user Task Scheduler logon task | Per-user **LaunchAgent** (`~/Library/LaunchAgents/com.rezen.backup.agent.plist`, `KeepAlive`, `RunAtLoad`) |
| Remembered key (§9) | DPAPI CurrentUser | **macOS Keychain** generic-password item in the user's login keychain, service `com.rezen.backup`, account = key-set ID. Protected by the user's login password. Other macOS users cannot read it. Limitation: same-user processes the user approves can read it (same as §9.5). |
| Point-in-time source snapshots | VSS via the helper service (§1.3) | Not available to unprivileged apps (APFS snapshot mounting needs root and entitlements). Files are read live, using the change-recheck-retry procedure (§13.4), and are flagged if inconsistent. |
| Durable writes | `FlushFileBuffers` | `fcntl(F_FULLFSYNC)`. Plain `fsync` on macOS does not flush the drive's write cache. |
| Uncached read-back (§15.2) | `FILE_FLAG_NO_BUFFERING` | `fcntl(F_NOCACHE)` |
| Keep awake (§24) | `SetThreadExecutionState` | `caffeinate -i -w <pid>` for the duration of the run |
| Eject after backup | `CM_Request_Device_Eject` | `diskutil eject` |
| Drive detection (§17) | Volume polling plus `.rezenbackup` marker | Same, over `/Volumes/*` |
| Cloud placeholders (§1.4) | `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` / `OFFLINE` | iCloud "dataless" files (`SF_DATALESS` flag), which are not read because reading would trigger a download |
| Session lock (§24) | `WTSRegisterSessionNotification` | Screen-lock distributed notification (`com.apple.screenIsLocked`); idle auto-lock everywhere |
| Privacy permission | — | **Full Disk Access** is needed to back up protected folders such as Mail and Desktop. Missing access is reported as "Permission denied" per file (never silent), and the UI explains how to grant it. |
| Filesystems | NTFS, ReFS recommended; exFAT warned; FAT32 rejected | APFS, HFS+ recommended; exFAT warned; FAT32 rejected; NTFS read-only on macOS (rejected as a destination) |

**Moving backups between operating systems.**

- File names are stored byte-exact (UTF-8). On macOS, names may be in decomposed (NFD) form, which the backup preserves.
- When restoring onto Windows, characters that Windows does not allow (`< > : " | ? *`, trailing dots and spaces, reserved names such as `CON`) are replaced with visible substitutes. Each renamed file is listed in the restore report, so nothing is renamed silently.
- Windows attributes are restored only on Windows. POSIX permission bits are restored only on macOS.
- The password is NFC-normalized (§5.3), so the same passphrase works on both systems.

---

## 30. Implementation notes (v1 as built)

Where the implementation differs from the plan above, this section takes precedence.

| Topic | As built | Reason |
|---|---|---|
| Background agent (§1.1) | The desktop executable itself in `--agent` mode, with a tray / menu-bar icon. Starts at sign-in via a LaunchAgent (macOS), the MSI's machine `Run` key, or the user's `Run` key (Windows). | One executable keeps macOS Keychain access rules simple, because the item creator and reader are the same binary. Creating a logon task through Task Scheduler needs admin rights; the `Run` key does not. |
| Catalog session (§18.2) | Trees are decrypted on demand into an in-memory tree cache, searched with LINQ, and dropped on lock. | Simpler than an in-memory SQLite database, with the same security property: decrypted names never touch disk. |
| Previous-snapshot trees for change detection (§13.2) | Read from the drive's metadata packs, which are connected during a backup. No local encrypted tree cache. | Less code; the encrypted chunk-index cache gives most of the speed-up. |
| Local database (§23.2) | Jobs are stored as a JSON `definition_json` column rather than separate source and exclusion tables. | Same information, simpler migrations. |
| Argon2 read bounds (§5.1) | Readers accept *m* ≥ 8 MiB. New slots require *m* ≥ 256 MiB and *t* ≥ 3 outside the test suite. | Lowering the parameters in a stored slot cannot help an attacker (unwrapping fails), so the read floor only needs to block DoS. |
| Windows notifications | `Shell_NotifyIcon` balloon. | No package identity or WinRT dependency. |
| macOS notifications | `osascript display notification`. | Works without an app-bundle notification entitlement. |
| Run-issue paths (spec §68) | Sealed with the repository key (AES-256-GCM, per-value HKDF key) in `run_issues.path_sealed`. Shown only after unlocking. | File names never sit in the local database in plaintext. |

**Deferred (not in v1, format already allows them):**

- Write-only scheduled key and TPM binding (§9.5).
- Drive rotation with several drives per job (§21.2).
- Optional NTFS ACL lockdown of the backup folder (§21.3).
- Automatic "full snapshot every N days" (the field exists; the method is selected per job).

**Verification status of platform code:**

| Area | Status |
|---|---|
| Crypto, format, engines, application layer, CLI and UI | Tested on macOS (arm64). |
| macOS Keychain, `F_FULLFSYNC` / `F_NOCACHE`, `lstat` metadata | Exercised by tests on macOS. |
| Windows-specific code (DPAPI, `FILE_FLAG_NO_BUFFERING`, `MoveFileEx`, VSS helper service, notifications, eject, MSI) | Compiles and cross-publishes for `win-x64`, but has not yet been run on Windows. CI runs the suite on `windows-latest`. Spike S1 (shadow-copy access as a standard user) is still open. |
