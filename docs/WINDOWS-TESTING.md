# Testing Rezen Backup on Windows

The Windows-specific code compiles and cross-publishes, but it has not yet run on a Windows PC. This guide walks you through the checks, from quickest to most thorough. Tick each box as you go.

You need:

- A Windows 10 or 11 PC where you are an administrator, because installing the shadow-copy service needs admin rights.
- An empty USB drive. Format it as **NTFS**, or **exFAT** if you also want to test moving backups between Windows and Mac.
- About an hour.

## 1. Run the automated tests (10 minutes)

1. Install the **.NET 10 SDK** for x64 from Microsoft's .NET download page.
2. Copy this repository to the PC (USB stick, or `git clone` from wherever you keep it), then open **PowerShell** in the repository folder.
3. Run the tests. The second command also checks DPAPI (the Windows store for the remembered password); its test item is deleted again afterwards.

   ```powershell
   dotnet test RezenBackup.slnx
   $env:REZEN_KEYCHAIN_TEST = "1"; dotnet test tests\RezenBackup.Tests --filter Platform; Remove-Item Env:REZEN_KEYCHAIN_TEST
   ```

- [ ] All tests pass. If any fail, save the full output.

## 2. Build and install the MSI (10 minutes)

```powershell
.\installer\windows\build.ps1
```

The script needs nothing extra: the WiX installer tools download automatically during the build. It produces `artifacts\windows\RezenBackup-1.0.0-x64.msi`. The MSI is unsigned, so Windows SmartScreen will warn you; choose **More info → Run anyway**.

- [ ] The installer runs and offers two features: **Rezen Backup** and **Back up open and locked files (Volume Shadow Copy)**. Keep both.
- [ ] **Rezen Backup** appears in the Start menu.
- [ ] In `services.msc`, **Rezen Backup Shadow Copy Helper** is **Running**.

## 3. First backup (15 minutes)

1. Create a test folder, for example `C:\RezenTest`, with a few files and a subfolder. Include one file with a long name and one with non-English characters, such as `Résumé 日本語.txt`.
2. Start Rezen Backup. In the setup wizard, choose `C:\RezenTest` and your USB drive. Create a password, then **print or save** the recovery key (saving to Documents on this PC is allowed) and tick **I have saved my recovery key**. Choose **Daily** and **Full verification**.
3. Click **Back Up Now** when asked.

- [ ] The Dashboard shows progress, then **Your files are protected** with the status **Encrypted & Verified**.
- [ ] A Windows notification appears saying the backup is complete and you may disconnect the drive.
- [ ] On the USB drive, open `Rezen Backup\<PC name>\<job name>`. You see a dated folder and an encrypted `store` folder. **None of your file names appear anywhere.**
- [ ] The system tray shows the Rezen Backup icon.
- [ ] Close the window. The tray icon stays, because background protection keeps running.

## 4. Locked files and shadow copies (10 minutes)

This is design spike S1: can a standard user read files through a shadow copy?

1. Open a file in `C:\RezenTest` in a program that locks it. For example, open a `.docx` in Word, or run this in PowerShell to hold a file open:

   ```powershell
   $f = [System.IO.File]::Open("C:\RezenTest\locked.txt", "OpenOrCreate", "ReadWrite", "None")
   ```

2. In Rezen Backup, click **Back Up Now**.

- [ ] **Best result:** the backup is **Success** with no warnings, so the locked file was read from the shadow copy.
- [ ] **Acceptable result:** **Completed with warnings — 1 file could not be backed up**. Open **History → details**: the path is shown after you enter your password. If you see this, the shadow-copy path is not working. Send me the logs from step 9.

When you're done, close the file (`$f.Close()` in PowerShell).

## 5. Drive letter change, unplugging and resuming (10 minutes)

1. In **Disk Management**, change the USB drive's letter (for example from `E:` to `R:`), then click **Back Up Now**.
   - [ ] The backup works. The drive is recognised under its new letter.
2. Start a backup with a large file in `C:\RezenTest` (a few GB copied in), then **pull the USB drive out mid-backup**.
   - [ ] The backup stops with "Backup stopped because the backup drive was disconnected."
   - [ ] After reconnecting, **Backup Jobs → Edit** shows an interrupted backup with **Resume Backup** and **Discard Incomplete Snapshot**. Resume completes it.
   - [ ] The interrupted attempt never appears as a restorable date in **Restore**.

## 6. Restore (10 minutes)

1. Delete a file from `C:\RezenTest` and edit another.
2. Open **Restore** and unlock.
   - [ ] Your dates appear. Browsing, search and the **Versions** panel all work.
3. Restore the deleted file to its original location.
   - [ ] It comes back with its original date.
4. Restore the edited file to its original location.
   - [ ] You are asked **Replace / Keep both / Skip**. Nothing is overwritten without asking.
5. Restore the whole snapshot to another folder.
   - [ ] The files match the originals.

## 7. Reinstall or new-PC recovery (10 minutes)

1. Uninstall Rezen Backup from **Settings → Apps**.
   - [ ] The backups on the USB drive are untouched.
2. Delete `%LOCALAPPDATA%\Rezen Backup` to simulate a new PC. **Only do this on a test PC.**
3. Reinstall. In the wizard, choose **Import an existing backup**, select the drive, and use the **recovery key**.
   - [ ] The import succeeds. All dates are listed and restoring works.

## 8. Mac ↔ Windows (optional, needs an exFAT drive)

- [ ] Back up on the Mac to an exFAT drive. On Windows, use **Import Existing Rezen Backup** and restore to another folder. Files with characters Windows does not allow, such as `:`, are restored under a visibly renamed name, and the restore report lists every rename.

## 9. What to send back

Send me:

- Which boxes failed, with what you saw.
- The logs from `%LOCALAPPDATA%\Rezen Backup\Logs`. File names in them are already hidden.
- If the service misbehaved, the **Application** log entries in Event Viewer for **RezenBackupService**.
