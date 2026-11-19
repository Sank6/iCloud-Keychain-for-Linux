# iCloud for Windows: static analysis (iCloud Passwords)

Interoperability and security research on the author's own Apple account and own copy of the
app. **Static and read-only**: nothing from the package was executed, patched, repackaged or
redistributed, and no Apple binaries are in this repository. No keys, certificates, tokens or
secrets were extracted or used. Apple's servers were not contacted. Tags: **VERIFIED** (seen in
the files), **INFERRED** (reasoned from verified facts), **UNVERIFIED** (not checked).

## Summary

- The Windows app is not a thin client. It ships a port of Apple's own stack (CoreFoundation,
  Foundation, objc, `secd.exe`, `iCloudCKKS.exe`, `AOSKit.dll`, `CoreADI64.dll`, `APSDaemon.exe`).
  The password sync is done by Apple's real keychain code, not by a re-implementation. (VERIFIED
  files; INFERRED that `secd`/CKKS is the Security-framework daemon.)
- The browser extension talks to `iCloudPasswordsExtensionHelper.exe` over native messaging
  (`com.apple.passwordmanager`), which asks `secd` for credentials. The helper's command set
  matches the extension's 1:1. (VERIFIED)
- The real Windows client identifies itself as `<PC> <...> <com.apple.AuthKitWin/major.minor
  (bundle/version)>`. Our client (and upstream's fix) sends `com.apple.AuthKit/1
  (com.apple.akd/1.0)`, which is different. (VERIFIED strings; INFERRED that it matters.)
- Anisette comes from Apple's own `CoreADI64.dll` running locally. (INFERRED from name, strings
  and the provisioning blob name `Global\adi-pb-un`.)
- For the Linux backend, the most promising directions are: (a) match the real client identity
  format, (b) a VM or Wine only if we want Apple's code to do the sync, (c) keep the Apple-device
  export path as the safe default. See "Recommendation".

## Method

1. Resolved the package through Microsoft's public delivery service (the generator site was
   behind a bot check, which was not bypassed). TLS was verified against Microsoft Root
   Certificate Authority 2011 (fetched from the AIA URL in the server's own certificate; SHA-1
   fingerprint 8F:43:28:8A:D2:72:F3:10:3B:6F:B1:42:84:85:EA:30:14:C0:BC:FE matched Microsoft's
   published value).
2. Downloaded only from `tlu.dl.delivery.mp.microsoft.com` into a new empty scratchpad folder.
3. Verified size and SHA-256 against the delivery service's listing, then the package signature.
4. Unpacked as a zip (Python `zipfile`), read the manifest, then used `objdump -p` and `strings`.
   No disassembly or debugging was done.

## Package (VERIFIED)

| Item | Value |
| --- | --- |
| Identity | `AppleInc.iCloud` 15.10.39.0, x64 (`AppleInc.iCloud_15.10.39.0_x64__nzyj5cx40ttqa`) |
| File | `82b96add-40e1-4acf-abb3-cc66c4f4f61e.appx` (saved as `iCloud_15.10.39.0_x64.appx`) |
| Size | 352,738,089 bytes (723 MiB unpacked, 1233 entries) |
| SHA-256 | `bdca7b5b8b2819d758cd7ba4ea25bd87b7cca1ae7dc25627e6cd02248d8d38ca` (matches the service listing) |
| Signer | `CN=5BD5593D-A41B-4F89-884E-B4F3E0FBAA75` (manifest Publisher), issued by Microsoft Marketplace CA G 027 -> Microsoft MarketPlace PCA 2011 -> Microsoft Root Certificate Authority 2011 |
| Signature checks | chain validates to the 2011 root at the certificate's validity window (Sep 18-21 2026; the leaf is short-lived and now expired, which is normal for Store re-signing; one Microsoft-specific critical extension had to be ignored by OpenSSL); RSA signature over signed attributes valid; messageDigest matches the signed content; the signed content contains the SHA-256 of `AppxBlockMap.xml` |
| Not checked | per-file block hashes against `AppxBlockMap.xml`; the Apple-side signing (the Store re-signs the package) |
| Target | Windows.Desktop min 10.0.19041.0; capabilities `runFullTrust`, `unvirtualizedResources`, `internetClient` |
| Apps | `iCloudHome.exe`, `iCloudPhotoViewer.exe`, `iCloudPasswords.exe`, `iCloudChrome.exe` (all full trust) |

Other versions seen in the catalog: x86 13.4.101.x and x64 15.8.x. The delivery service also
listed x64 15.10.39.0 as newest.

## Browser host (VERIFIED)

`ChromePwdMgrHostApp_manifest.json`: name `com.apple.passwordmanager`, path
`iCloudPasswordsExtensionHelper.exe`, type `stdio`, allowed origins
`chrome-extension://pejdijmoenmkgeppbflobdenhhabjlaj/` (the extension in the user's Helium) and
`chrome-extension://mfbcdcnpokpoajjciilocoachedjkima/`. Firefox:
`password-manager-firefox-extension@apple.com`. Bookmarks use a separate host
`com.apple.bookmarks` (`iCloudChrome.exe`, `iCloudFirefox.exe`).

The helper contains: the `Cmd*` names matching the extension (`CmdChallengePIN`,
`CmdGetLoginNames4URL`, `CmdGetPassword4LoginName`, `CmdSetPassword4LoginName_URL`,
`CmdNewAccount4URL`, `CmdGetOneTimeCodes`, `CmdSetUpTOTPGenerator`, ...), a `SecretSession`
class (source path `...PasswordManager-410.4\srcroot\pwdutilslib\SecretSession.cpp`), a
`PINDialog` ATL dialog with `ShowPIN`, the check `strPIN must be not null and length == 6`, and a
`KeyChainChangesMonitor` (registry change monitoring). It reports `secd returned STATUS (%d)`,
so credential lookups are delegated to `secd`.

Compared with the extension we analysed (host name, SRP + AES-GCM, six-digit PIN, command ids):
consistent. The Linux host in `icp/applehost.py` implements the same wire protocol and passes
tests against Apple's own client code (`tests/test_applehost.py`).

## Binaries and endpoints (VERIFIED strings; behaviour INFERRED)

- Ported platform: `CoreFoundation.dll`, `Foundation.dll`, `objc.dll`, `libdispatch.dll`,
  `CFNetwork.dll`, `SQLite3.dll`, `ASL.dll`.
- Keychain stack: `secd.exe` (strings: `ks_encrypt_data`, ECIES/AES-GCM algids, CKKS, SOS
  circle messages), `iCloudCKKS.exe`, `kccadp.dll`.
- Auth: `AOSKit.dll`, `iCloudAuthKitWin.resources`, `CoreADI64.dll` / `CoreADI32.dll`.
- Push: `ApplePushService.dll`, `APSDaemon.exe` (`push.apple.com`).
- Endpoints seen: `gsa.apple.com/grandslam/GsService2/lookup` (also `grandslam-it`, `-it3`,
  `-uat` variants), `setup.icloud.com` (`/configurations/init`),
  `gateway.icloud.com/configuration/configurations/internetservices/cloudkit/cloudkit-1.0.plist`,
  `contactsws.icloud.com`, `ocsp.apple.com/ocsp-wwdr01`.
- Auth headers: `X-Apple-I-MD`, `X-Apple-I-MD-DATA`, `X-Apple-I-MD-LU`, `X-Apple-I-MD-M`,
  `X-Apple-I-MD-RINFO`, `X-Apple-I-Client-Time`, `X-Mme-Device-Id`.
- Client info format: `<PC> <%@> <com.apple.AuthKitWin/%d.%d (%@/%@)>`.
- `CoreADI.dll` (path shows an Apple build tree) uses a shared provisioning blob named
  `Global\adi-pb-un`.
- Local key wrapping: `CWrapKeyWithNCryptKeyStorage` with `NCrypt*` and `BCrypt*` imports
  (`ncrypt.dll`, `bcrypt.dll`, `CRYPT32.dll`).
- Also shipped: `WebsiteNamesForPasswordManager.sqlite` (site-name data).

## Comparison with our Linux client

| | Windows app | Our client |
| --- | --- | --- |
| Sign-in | Apple's AuthKit/AOSKit code | Re-implemented GrandSlam |
| Client info | `<PC> <...> <com.apple.AuthKitWin/x.y (bundle/ver)>` | `<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.akd/1.0)>` |
| Anisette | local `CoreADI64.dll` | third-party server in Docker |
| Keychain sync | `secd` + `iCloudCKKS` (Apple code) | own CKKS/Octagon decryption |
| Local store | secd database, key wrapped via NCrypt | libsodium vault, key in Secret Service |
| Browser channel | helper, SRP PIN pairing | our host, same protocol (tests pass) |

## Security observations (evidence only)

- The browser channel uses a six-digit PIN as the SRP password (extension code; helper enforces
  length 6). The number of wrong-PIN attempts the helper allows was **not found** (UNVERIFIED).
- Secrets at rest appear to be protected by NCrypt-wrapped keys (INFERRED); whether that key is
  TPM-backed or a software KSP is **UNVERIFIED**.
- The expired short-lived signing certificate is expected for Store packages, not a finding.
- **Possible security issues**: none established. Anything further needs disassembly (not done).

## Recommendation

1. Our 403 at the first GrandSlam call is plausibly related to the client-info string and the
   anisette identity. The real format is `com.apple.AuthKitWin/<major>.<minor>
   (<bundle>/<version>)`; trying that shape (with a realistic version) is a cheap, low-risk
   experiment, but only after the account is out of its back-off, and once. (INFERRED.)
2. If we want Apple's code to do the sync, run the real app in a Windows VM (KVM) instead of
   Wine: it needs Windows services, the Store packaging and `runFullTrust`. Then relay the
   extension to the VM's helper. Heavy but the most faithful. Wine is UNVERIFIED and likely
   fragile.
3. Keep the Apple-device export (CSV / Credential Exchange) as the safe default.
4. Our native host for the official extension is feasible today (done in the repo).

## Limitations / open questions

- No disassembly, dynamic analysis, or network capture was done; behaviour is inferred from
  names and strings.
- PIN attempt limit, local DB location and exact key protection are unknown.
- Whether `com.apple.AuthKitWin` is what makes Apple accept requests (vs anisette alone) is
  untested and would require contacting Apple.
- Next: with approval to install a disassembler (e.g. Ghidra or radare2) inspect
  `SecretSession` and the PIN counters; consider reporting anything weak via Apple Security
  Bounty first.
