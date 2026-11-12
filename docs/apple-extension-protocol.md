# Apple "iCloud Passwords" extension: native protocol

Source: the installed extension v3.4.0 (ID `pejdijmoenmkgeppbflobdenhhabjlaj`), read-only, plus
`tests/ext/apple_client.js`, which runs the extension's own `SecretSession` as a test client.
**Verified** = exercised against that real code or the real extension in a headless Helium.

## Transport
- `chrome.runtime.connectNative("com.apple.passwordmanager")`; standard 4-byte LE framing. Verified.
- OS gate: the extension only starts if `navigator.platform == "MacIntel"` or the UA says Windows
  >= 6.1. On Linux its state is `IncompatibleOS` and it never connects. Verified. Our fix is a local
  patched copy (`python -m icp.applehost_install patch-extension`).

## Commands (`cmd`)
2 ChallengePIN, 3 SetIconNTitle, 4 GetLoginNames4URL, 5 GetPassword4LoginName, 6 SetPassword,
7 NewAccount, 8 TabEvent, 9 PasswordsDisabled, 10 ReloginNeeded, 14 Hello, 16 GetOneTimeCodes,
17 DidFillOneTimeCode, 19 CancelPINPairing. Ext -> host messages carry `payload`/`msg` as JSON
*strings*; host -> ext `payload` is an object (cmd 3: a string).

## Pairing (cmd 2). SRP-6a, RFC 5054 3072-bit group (g=5), SHA-256. Verified.
- Hello: ext sends `{cmd:14}`; host answers `{cmd:14, capabilities:{...}}`.
- m0 (ext): `{cmd:2, msg: '{"QID":"m0","PAKE":b64(JSON{TID,A,MSG:0,VER:"1.0",PROTO:[0,1]}),"HSTBRSR":..}'}`
  `TID` = `"0x"+hex` of a random 128-bit id; `A` hex.
- msg1 (host): `{cmd:2, payload:{QID:"m0", PAKE:b64(JSON{TID,MSG:1,s,B,VER,PROTO:0})}}`.
  x = SHA256(salt || SHA256(TID ":" PIN)) (TID string verbatim, with 0x); v = g^x; k = SHA256(N||pad(g));
  B = k*v + g^b; u = SHA256(pad(A)||pad(B)); S = (A*v^u)^b; key = SHA256(minimal big-endian S)[:16].
- m2 (ext): `PAKE:b64(JSON{TID,MSG:2,v})`; for PROTO 0, `v` = hex of AES-GCM(key, utf8(hex of v)) in
  the extension's own layout (below). A wrong PIN fails the GCM tag. Host answers m2 with
  `{TID,MSG:3,ErrCode:0|1}`. PROTO 1 (RFC M/HAMK proofs) is **not implemented**; we answer PROTO 0.

## Encrypted messages (SMSG). Verified.
`{"TID":..,"SDATA":hex}`. AES-128-GCM, 16-byte IV, 128-bit tag. Ext -> host: `ct||tag||iv`.
Host -> ext: `iv||ct||tag` (the two directions differ in the extension's code).

## Queries
- cmd 4 (list): body `{ACT:5, URL:<hostname>}`; reply body `{STATUS:0|3, Entries:[{USR, PWD:"Not Included",
  sites:[domain], highLevelDomain, customTitle?}], RequiresUserAuthenticationToFill:false}`. Verified
  (popup received the list). Dates (`CDate`/`ModDate`) are omitted: format UNVERIFIED.
- cmd 5 (password): body `{ACT:2, URL, USR}`; the reply echoes `url`; the extension picks the entry whose
  `sites` contains it and fills `USR`/`PWD`. Verified (fill callback got user + a 20-char password).
- cmd 6/7 (save/update): ignored; this host is read-only.
- cmd 16/17 (TOTP codes): **UNVERIFIED and not offered** (`canFillOneTimeCodes:false`).
- cmd 10 is sent when a request arrives with no valid session; cmd 9 while PIN pairing is locked out.

## Verified end to end on Linux (extension 3.4.0, Chromium 157)
Both ways past the OS gate work with this host: (a) the unmodified Web Store extension in a browser
started with `--user-agent` set to a Windows UA (`checkForValidOS` matches `\(Windows\s*\w*\s*(\d*)\.(\d*)`,
state goes `NotInSession` -> `MSG1Set` -> `SessionKeySet` after the PIN), and (b) a copy with the gate
short-circuited. A `CmdGetLoginNames4URL` lookup returned `STATUS 0` and the matching entry.

## UNVERIFIED
Behaviour in a long-lived real profile; Apple's real-host message for non-zero `STATUS` values other than
0/3; TOTP; `operatingSystem` capability values (we send `{name:"Linux"}`); whether Apple's real host keeps
sessions across browser restarts (ours does not: every browser start pairs again).
