# Rezen Backup Format v1 — Specification

This document specifies the on-disk format of Rezen Backup repositories completely enough to implement an independent restore tool. It is normative for format version 1. Readers **must** reject unknown versions, algorithms, object types and non-zero reserved bytes rather than guess.

## 1. Conventions

- Integers in fixed headers are **little-endian** unless stated otherwise.
- **UUIDs** (`repositoryId`, `keySetId`, `snapshotId`, `packId`, `driveId`) are 16 bytes in **.NET `Guid` byte order**: the first three fields (4, 2, 2 bytes) are little-endian and the last 8 bytes are as written. Their textual form appears only in the plaintext drive marker and `snapshot.meta`.
- **Timestamps** in encrypted records are .NET ticks: 100-nanosecond intervals since 0001-01-01T00:00:00Z (UTC).
- Structured data uses **CBOR** (RFC 8949) as positional arrays, written in canonical mode. A name is a CBOR text string. If a name is not valid UTF-16 (for example, it has unpaired surrogates from Windows), it is written as tag `0x525A4E31` followed by a byte string of its UTF-16LE code units.
- `HKDF` is HKDF-SHA256 (RFC 5869). `HMAC` is HMAC-SHA256. `‖` means concatenation.

## 2. Directory layout

```text
<volume>/Rezen Backup/.rezenbackup                 drive marker (JSON)
<volume>/Rezen Backup/<computer>/<job>/            repository root
    repository.rzc                                 preamble + encrypted configuration (type 6)
    repository.lock                                present only while writing
    keys/key-a.rzk, keys/key-b.rzk                 identical key file copies
    store/data/<xx>/<packhex>.rzp                  data packs (type 1)
    store/meta/<xx>/<packhex>.rzp                  metadata packs (type 2)
    store/meta-copy/<xx>/<packhex>.rzp             second copy of each metadata pack (byte-identical)
    store/tmp/                                     in-flight writes; never referenced
    store/quarantine/                              damaged packs set aside by repair; never referenced
    YYYY-MM-DD_HH-MM-SS[_N][.incomplete|.deleting]/
        snapshot.meta                              plaintext JSON, advisory only
        snapshot.rzb                               snapshot record (type 3)
        integrity.dat                              commit record (type 4)
        journal.rzj                                progress journal (type 5), only while incomplete
```

- `<packhex>` is the 32-character lowercase hex of the pack UUID bytes. `<xx>` is its first two characters.
- `<computer>` and `<job>` are either readable names or opaque names such as `R-1A2B3C` / `J-4D5E6F`.
- The snapshot folder name is the **local** start time. `_N` (N ≥ 2) breaks ties.

### 2.1 Drive marker (`.rezenbackup`)

```json
{ "format": "Rezen Backup Drive Marker v1", "formatVersion": 1, "driveId": "<uuid>", "createdUtc": "<ISO-8601>", "label": "<string|null>" }
```

The marker holds no secrets. It only identifies the drive.

## 3. Keys

### 3.1 Root Secret and recovery key

The Key Set's **Root Secret (RS)** is 32 random bytes.

The **recovery key** is a human encoding of RS:

1. Build a 280-bit payload: `RS (256 bits) ‖ C (20 bits) ‖ 0000 (4 bits)`, where `C` is the first 20 bits of `SHA-256("RZN-RK" ‖ RS)`.
2. Encode the payload most-significant bit first, 5 bits per character, as 56 Crockford Base32 characters (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`).
3. Display it as `RZN1-` followed by 14 groups of 4 characters separated by `-`.

On input, ignore case, spaces and hyphens. Map `O`→`0` and `I`/`L`→`1`. Reject the key if the padding bits are non-zero or the checksum does not match.

### 3.2 Repository keys

```text
RMK        = HKDF(IKM = RS,  salt = repositoryId (16 bytes), info = "RezenBackup/v1/repository-master", L = 32)
K_content  = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/content",   L = 32)
K_metadata = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/metadata",  L = 32)
K_chunkid  = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/chunk-id",  L = 32)
K_treeid   = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/tree-id",   L = 32)
K_cdc      = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/cdc-seed",  L = 32)
K_check    = HKDF-Expand(PRK = RMK, info = "RezenBackup/v1/key-check", L = 32)
```

| Value | Definition |
|---|---|
| Data chunk ID | `HMAC(K_chunkid, chunkPlaintext)` |
| Tree ID | `HMAC(K_treeid, treeCborBytes)` — a separate key, so file content can never collide with a tree |
| Key check | `HMAC(K_check, "key-check" ‖ repositoryId)`, first 16 bytes |

### 3.3 Key files (`*.rzk`)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `RZNBKKEY` |
| 8 | 2 | version = 1 |
| 10 | 16 | keySetId |
| 26 | 16 | repositoryId (the local per-computer copy uses keySetId here) |
| 42 | 8 | generation (uint64) |
| 50 | n | CBOR body `[ [slot…], keyCheck(bstr16) / null ]` |
| 50+n | 32 | SHA-256 of all preceding bytes (detects corruption only) |

A slot is a 9-element array:

```text
["password", "argon2id", memoryKiB, iterations, parallelism, salt(16), nonce(12), ciphertext(32), tag(16)]
```

To unwrap a slot:

```text
pw   = UTF-8( Unicode NFC (typed password) )
KEK  = Argon2id v1.3 (password = pw, salt, t = iterations, m = memoryKiB, p = parallelism (1), outLen = 32)
AAD  = "RZN-SLOT-v1" ‖ LE32(memoryKiB) ‖ LE32(iterations) ‖ LE32(parallelism) ‖ salt ‖ "keyset:" ‖ keySetId
RS   = AES-256-GCM-Decrypt(KEK, nonce, ciphertext, tag, AAD)
```

The result must satisfy the key check, if present.

If both key file copies are lost or damaged, the recovery key alone is sufficient: RS is the recovery key.

## 4. Encrypted objects

Every encrypted file or object starts with a 72-byte plaintext header:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `RZNBKOBJ` |
| 8 | 2 | formatVersion = 1 |
| 10 | 1 | objectType: 1 data pack, 2 metadata pack, 3 snapshot, 4 commit, 5 journal, 6 repository config, 7 local catalog cache |
| 11 | 1 | algorithmId = 1 (AES-256-GCM STREAM, HKDF-SHA256) |
| 12 | 4 | segmentSize (1 048 576; readers accept 4 KiB – 16 MiB) |
| 16 | 16 | repositoryId |
| 32 | 32 | objectSalt (random) |
| 64 | 8 | reserved, must be zero |

**Object key:**

```text
K_class = K_content   for object type 1
          K_metadata  for every other object type
K_obj   = HKDF(IKM = K_class, salt = objectSalt, info = "RezenBackup/v1/object" ‖ objectType(1 byte) ‖ repositoryId, L = 32)
```

**Segments:** the plaintext is split into segments of `segmentSize` bytes. The last segment may be shorter, and an empty object has exactly one empty segment. Segment *i* is stored as `ciphertext_i ‖ tag_i (16 bytes)`:

```text
nonce_i = BE64(i) ‖ 00 00 00 ‖ last      (last = 01 for the final segment, else 00)
AAD     = the 72 header bytes
```

The final segment is the one that ends the file. Its `last` flag must be `01`, and every other segment's must be `00`. Plaintext from a segment must not be used before its tag verifies.

## 5. Repository configuration (`repository.rzc`)

The file starts with a 44-byte preamble, followed by an encrypted object of type 6:

```text
"RZNBKREP"(8) ‖ formatVersion(2) ‖ minReaderVersion(2) ‖ repositoryId(16) ‖ keySetId(16)
```

The decrypted body is CBOR:

```text
[1, jobName, hostName, createdTicks, appVersion, chunkMin, chunkAvg, chunkMax, packTargetSize, [sourcePath…]]
```

## 6. Packs

The plaintext of a pack is:

```text
blob_0 ‖ … ‖ blob_n-1 ‖ zero padding ‖ index ‖ LE32(indexLength) ‖ "RZNPACK1"
```

**Padding:** the total plaintext length is Padmé(L), where L is the length without padding. For L ≥ 2:

```text
E  = floor(log2 L)
S  = floor(log2 E) + 1
lb = E − S
Padmé(L) = (L + 2^lb − 1) rounded down to a multiple of 2^lb
```

**Index:** a CBOR array. Each entry is:

```text
[id(bstr32), kind(1 = data, 2 = tree), offset, storedLength, rawLength, codec(0 = none, 1 = Brotli)]
```

`offset` is measured from the start of the plaintext.

**Reading a blob:**

1. Decrypt and authenticate the segments covering `[offset, offset + storedLength)`.
2. Decompress into exactly `rawLength` bytes, rejecting any other length.
3. Recompute the ID (chunk ID for data, tree ID for trees) and require it to match.

Metadata packs (type 2) contain trees. The copy in `meta-copy/` may be used whenever the primary fails.

## 7. Trees

A tree is CBOR `[1, [entry…]]`, with entries sorted by ordinal (UTF-16 code unit) name order. Each entry has 17 elements:

```text
[ name, kind(0 file, 1 directory, 2 link), size, modifiedTicks, createdTicks, changeTicks|null,
  attributes(Windows FileAttributes), unixMode|null, status(0 ok, 1 changedDuringBackup, 2 carriedForward, 3 unreadable),
  statusDetail|null, carriedFromSnapshotId|null, sha256(bstr32)|null, [chunkId…], subtreeId|null, linkTarget|null,
  fileId|null, reserved(null) ]
```

- A file's content is the concatenation of its chunks in order. Its SHA-256 must equal `sha256`.
- Readers must reject a name that is empty, `.`, `..`, or contains `/`. On Windows they must also reject names containing `\`.

## 8. Snapshot record (`snapshot.rzb`, type 3)

The record is a 19-element CBOR array:

```text
[1, snapshotId, repositoryId, folderBaseName, startedTicks, completedTicks, utcOffsetMinutes, hostName, appVersion,
 platform, method(0 incremental, 1 full), [[originalPath, rootTreeId, isFile]…],
 [files, directories, bytesScanned, bytesNew, bytesStored, filesNew, filesChanged, filesUnchanged, filesWithWarnings],
 [[path, issueKind, detail|null]…], parentSnapshotId|null, previousCommitHash|null, verification(0 standard, 1 full),
 anomalyDetected(bool), reserved(null)]
```

- For a folder source, `rootTreeId` is the tree of the folder's contents.
- For a single-file source (`isFile = true`), `rootTreeId` is a tree with exactly that one file.

## 9. Commit record (`integrity.dat`, type 4)

The record is an 11-element CBOR array:

```text
[1, snapshotId, repositoryId, folderBaseName, sha256(snapshot.rzb file bytes),
 [[packId, packKind(1 data, 2 meta), length, sha256(pack file bytes)]…],
 verification, verificationResult("passed"), verifiedTicks, previousCommitHash|null, "committed"]
```

- `previousCommitHash` is the SHA-256 of the previous snapshot's `integrity.dat` file bytes. The chain reveals snapshots missing from the middle of the history.

## 10. Snapshot validity

A snapshot is **restorable** only if all of the following hold:

1. Its folder name has no suffix.
2. `snapshot.rzb` and `integrity.dat` both decrypt and authenticate.
3. `commit.state == "committed"`.
4. The snapshot IDs and repository IDs match between the two records.
5. Both `folderBaseName` fields equal the folder name.
6. `commit.snapshotRecordSha256` equals the SHA-256 of the `snapshot.rzb` file.

| Folder state | Meaning |
|---|---|
| `.incomplete` with a valid commit record | Interrupted between commit and rename. It may be finalized by renaming it. |
| `.incomplete` without a commit record | Never restorable. |
| `.deleting` | Being removed by retention. Never restorable. |

`snapshot.meta` (plaintext JSON) is a hint only and must never be trusted:

```json
{ "format": "Rezen Backup Format v1", "formatVersion": 1, "snapshotId": "…", "repositoryId": "…", "state": "incomplete|committed" }
```

## 11. Journal (`journal.rzj`, type 5)

The journal is CBOR:

```text
[1, snapshotId, folderBaseName, startedTicks, [[packId, kind, length, sha256]…]]
```

It lists packs already written by an interrupted run so a resume can reuse them.

## 12. Content-defined chunking (writers only)

Readers do not need chunking. Writers use FastCDC with normalized chunking level 2:

- **Gear table:** 256 little-endian uint64 values from `HKDF-Expand(K_cdc, "RezenBackup/v1/gear-table", 2048)`.
- **Masks:** with `bits = round(log2(avg))`:
  - `maskS` = top `bits + 2` bits set.
  - `maskL` = top `bits − 2` bits set.
- **Scanning:** start at `min` and compute `fp = (fp << 1) + gear[byte]`.
  - Cut after the current byte when `fp & maskS == 0`, for positions below `avg`.
  - Cut after the current byte when `fp & maskL == 0`, for later positions.
  - Always cut at `max`.
