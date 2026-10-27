# iCloud Keychain on Linux

Notes on the Apple APIs: how a non-Apple-hardware client authenticates as
a device, joins the account's Octagon trust, and decrypts the iCloud Keychain - including the
Passwords-app web logins - and how `icp edit` writes a changed login back (last section).

Primary reference throughout is [OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush)
(`src/icloud/*.rs`), cross-checked against
[apple-oss-distributions/Security](https://github.com/apple-oss-distributions/Security) - the
open-source keychain / TrustedPeersHelper (Octagon) code Mac clients run (and its unit tests), for the byte-exact format pins and test vectors.

## Why the native GSA path

Two ways to reach iCloud exist; only one can decrypt the keychain:

- Web/appleauth (idmsa -> 30-day trust token -> `accountLogin`, what pyicloud/rclone use):
  reaches CloudKit/Drive - but a web session cannot join the keychain SOS/Octagon circle, so
  it dead-ends before decryption.
- Native GSA device (this project): GrandSlam SRP-6a login -> device trust -> CloudKit ->
  Octagon join. The only path that can reach the keychain. Subsequent logins don't re-prompt 2FA
  because Apple sees a stable, trusted device.

## Stage 1 - Auth & tokens (GSA -> mmeAuthToken -> CloudKit)

GrandSlam SRP-6a login (`gsa.apple.com`) yields a decrypted `spd` containing the SRP session key
`sk`, `GsIdmsToken`, `adsid` (GUID) + numeric `DsPrsId`, and a dict `t` of ~15 app tokens. The
SRP implementation is adapted from
[JJTech0130's GrandSlam gist](https://gist.github.com/JJTech0130/049716196f5f1751b8944d93e73d3452).

- `com.apple.gs.idms.pet` is a short-lived, password-equivalent token: it is fed back into
  the SRP flow as the password, not used as a service bearer token. Sending the PET to
  `setup.icloud.com` as `Basic dsid:PET` returns the generic `status 1`. The longer-lived GS
  `com.apple.gs.icloud.auth` settings token only authorizes Apple-ID settings/terms, not
  CloudKit.
- Token lifetimes (all Apple-side, adjustable without notice): the PET is single-use (spent
  once for `mmeAuthToken`), so its own TTL never gates a login. `mmeAuthToken` is the
  persistent credential - Apple caps sync-scoped tokens at ~2 months, so the password is re-entered that often, never re-2FA: the stable `X-Mme-Device-Id` keeps the device
  trusted months-to-indefinitely. Refresh can even be silent - rustpush re-mints every 7 days
  from a stored password.
  - [pyicloud](https://github.com/picklepete/pyicloud/blob/master/README.rst) /
  [icloudpd](https://icloud-photos-downloader.github.io/icloud_photos_downloader/authentication.html)
  (~2-month cap)
  - [ElcomSoft](https://blog.elcomsoft.com/2017/11/icloud-authentication-tokens-inside-out/)
  (sync tokens don't expire)
  - [Apple](https://support.apple.com/en-us/122621) (device trust),
  - [rustpush](https://github.com/OpenBubbles/rustpush/blob/master/src/auth.rs) (7-day silent refresh).
- Reaching CloudKit is a multi-hop chain, each hop with a specific auth scheme:

```
GSA SRP login --(PET, fresh)--> loginDelegates --> mmeAuthToken (+ 9 service tokens)
mmeAuthToken --> get_account_settings --> webservices URL map + cloudKitToken
cloudKitToken --> ckAppInit --> cloudKitUserId --> CloudKit / CKCode
```

### Hop 1 - loginDelegates

While the PET is fresh ([malmeloo/FindMy.py](https://github.com/malmeloo/FindMy.py)).

```
POST     setup.icloud.com/setup/iosbuddy/loginDelegates
auth     Basic base64(apple-id : PET)   # not dsid:PET
headers  X-Apple-ADSID, iCloudHelper UA, AOSKit X-Mme-Client-Info, device, anisette
body     {
           apple-id,
           delegates: { com.apple.mobileme: {} },
           password:  PET,
           client-id: <uuid>,
         }
```

Returns numeric `dsid` + `service-data.tokens.{mmeAuthToken, cloudKitToken, mmeFMIPToken,
searchPartyToken, keyTransparencyToken, ...}`. `mmeAuthToken` is persistent (survives reboot, no
re-2FA).

### Hop 2 - get_account_settings

```
POST     setup.icloud.com/setup/get_account_settings
auth     Basic base64(dsid : mmeAuthToken)
body     (empty)
```

Empty body ([dinosec/iphone-dataprotection](https://github.com/dinosec/iphone-dataprotection)).
Returns a ~28 KB plist webservices map. Key URLs (partitionId 183 example):

- `CKDatabaseService.url` = `https://p183-ckdatabase.icloud.com:443`
- `CKCodeService` -> `https://p183-ckcoderouter.icloud.com:443`
- `KeyValue.url` = `https://p183-keyvalueservice.icloud.com:443`
- `KeychainSync.escrowProxyUrl` = `https://p183-escrowproxy.icloud.com:443`
- `appleAccountInfo.iCDPEnabled = false` -> standard-protection account (no Advanced Data
  Protection); relevant to which Octagon fields are set below.

### Hop 3 - ckAppInit

```
POST     gateway.icloud.com/setup/setup/ck/v1/ckAppInit?container=...
auth     Basic base64(dsid : mmeAuthToken)
```

CloudKit's `x-cloudkit-userid` is the per-container `cloudKitUserId` this call returns (not the dsid).

## Stage 2 - Transport (CloudKit CKCode + CKKS records)

All Cuttlefish (Octagon) RPCs ride CloudKit CKCode function invocations, not raw REST.
`apple-oss-distributions/Security` `ContainerMap.swift` invokes each op as a CloudKit function
`com.apple.security.<op>` (establish, joinWithVoucher, fetchChanges, fetchViableBottles,
fetchRecoverableTlkshares, updateTrust, ...) on the private DB. There is no SEP/hardware
attestation in the request path - the join is gated on the IDMS trusted-device list (we passed
GSA+2FA -> trusted) plus a voucher, not on attestation.

`transport/cloudkit.py` (ported from rustpush `cloudkit.rs`):

```
POST     gateway.icloud.com/ckcoderouter/api/client/code/invoke
auth     Header.userToken = cloudKitToken
headers  x-cloudkit-{bundleid, containerid, databasescope=PRIVATE, environment=Production,
                     userid, authtoken}
         x-cloudkit-functionroutinghint = Cuttlefish/<op>
         accept: application/x-protobuf, content-type ... CloudDBClient.desc
         x-apple-operation-{group-}id = hex(rand[8]).upper()
         anisette
body     gzip( uleb128(len) ++ RequestOperation )
         RequestOperation.functionInvokeRequest = { service: "Cuttlefish", name: <op>,
                                                     parameters: <request> }
```

- container `com.apple.security.keychain`, bundle `com.apple.security.cuttlefish`.
- the shared header block (`accept`, `content-type`, `x-apple-operation-{group-}id`) must be on
  every ckAppInit / CKCode / record op.
- gzip gotcha: `requests`/urllib3 already gunzips a `Content-Encoding: gzip` body, so the
  manual gunzip must key on the gzip magic bytes, not the header, or it double-decompresses.

`transport/ckks.py` - keychain items are CloudKit records in per-view private-DB zones
("Passwords", "Manatee", ...), fetched with a RecordRetrieveChanges op (type 213) per zone:

```
POST     {partition}-ckdatabase.icloud.com/ckdatabase/api/client/record/sync
```

Same transport, securityd bundle id. Record types: `tlkshare` (ECIES blob), `synckey` (class key
wrapped by TLK), `item` (wrappedkey + data), `currentitem` (pointer).

## Stage 3 - Octagon self-peer identity (offline crypto)

`octagon/keys.py` builds the complete self-peer the way Cuttlefish/the sponsoring iPhone would.
Recipe reconstructed from the open-source `apple-oss-distributions/Security` TrustedPeersHelper
([`OctagonPeerKeys.swift`](https://github.com/apple-oss-distributions/Security/blob/main/keychain/TrustedPeersHelper/OctagonPeerKeys.swift),
[`TPHObjcTranslation.m`](https://github.com/apple-oss-distributions/Security/blob/main/keychain/TrustedPeersHelper/TPHObjcTranslation.m),
`Container.swift`, and the `TPPBPeer*Info` protobufs) and verified against Apple's own public
unit-test vector (the peerID hash below, from
[`TrustedPeersHelperUnitTests.swift`](https://github.com/apple-oss-distributions/Security/blob/main/keychain/TrustedPeersHelperUnitTests/TrustedPeersHelperUnitTests.swift)):

- Two NIST P-384 key pairs (signing + encryption). Curve pinned from `TPHObjcTranslation.m`
  (`ccec_cp_384()` + `ccsha384`); `OctagonPeerKeys.swift` holds `_SFECKeyPair`.
- Private serialization = X9.63 `0x04||X||Y||D` (97-byte point + 48-byte scalar = 145 B) -
  what `SecKeyCopyExternalRepresentation` / `OTPrivateKey.keyData` emit; re-import round-trips
  with a scalar/point consistency check. Public encodings: X9.63 point (97 B) and SPKI DER.
- `permanentInfo.data` = `TPPBPeerPermanentInfo` protobuf:
  ```
  1  epoch             uint64
  2  signingPubKey     SPKI
  3  encryptionPubKey  SPKI
  4  machineId         string
  5  modelId           string
  6  creationTime      uint64
  ```
- `permanentInfo.sig` = ECDSA-P384-SHA384 over `UTF8("TPPB.PeerPermanentInfo") ++ data` (the
  `typesafeSignature` domain-separation wrapper) - not a bare ECDSA over data.
- `peerID` = `"SHA256:" + base64(SHA256(data ++ sig))` (standard padded base64). The hash format
  is unit-tested against Apple's `TPPolicyVersion` vector ->
  `SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs=`. The randomized sig makes peerID
  generate-once; the verifier only re-checks the sig + `peerID == hash(data||sig)`.
- `stableInfo` = `TPTypedSignedData(TPPBPeerStableInfo, sig="TPPB.PeerStableInfo")`. Field map
  (from `TPPBPeerStableInfoReadFrom`):
  ```
  1   clock
  2   frozenPolicyVersion
  3   frozenPolicyHash
  4   policySecrets
  5   osVersion
  6   deviceName
  7/8 recovery{Signing,Encryption}PubKey
  9   serialNumber
  10  flexiblePolicyVersion
  11  flexiblePolicyHash
  12  userControllableViewStatus
  13  custodianRecoveryKeys
  14  secureElementIdentity
  15  walrus
  16  webAccess
  18  isInheritedAccount
  19  supportsRepudiation
  ```
  A standard-protection account leaves recovery/secureElement/walrus/webAccess/custodian unset;
  the frozen/flexible policy version+hash are the current builtin Octagon policy (a constant from
  `fetchPolicyDocuments`).
- `dynamicInfo` = `TPPBPeerDynamicInfo` (the mutable trust graph):
  ```
  1  clock
  2  included       (trusted peerIDs)
  3  excluded
  5  preapprovals
  ```
  A joining peer lists itself + the sponsor's trusted peers in `included`.

Residual unknowns, both inside data we sign and confirmable on a live join: `mungeModelID` body
(pass-through on production builds), and whether SecurityFoundation's ECDSA encoding is DER/X9.62.

## Stage 4 - Joining the trust (escrow recovery -> voucher)

Two voucher sources exist (rustpush `join_clique`):

1. Sponsored proximity - iPhone taps "Allow" over an OTPairing/Bluetooth channel. Needs a
   pairing radio transport rustpush doesn't implement; not used here.
2. Escrow recovery (`join_clique_from_escrow`, what this project uses) - the "enter the
   passcode of another device / iCloud Security Code" flow. Recover the escrowed old peer
   identity and have it self-vouch for our new peer. No proximity channel needed.

> **IRREVERSIBLE.** `escrowproxy` allows only 10 authentication attempts per escrow record,
> enforced in HSM firmware (the admin cards to reflash it were destroyed). After several
> failures the record locks and only Apple Support can grant more attempts; the 10th
> failed attempt makes the HSM cluster destroy the record and the keychain is lost forever.
> One correct passcode entry is safe (not brute-forcing), but a wrong passcode or a
> bug burns an irreversible attempt.
> [Apple Platform Security, "Escrow security for iCloud Keychain"](https://support.apple.com/guide/security/sec3e341e75d).

Flow:

1. `fetchViableBottles` (CKCode) returns the account's escrow bottles - non-destructive, spends
   no attempt. With **multiple bottles** (one per device that ever enabled Keychain) the bottle
   carries no human label, so to know *which device's passcode* unlocks each one we also call the
   escrowproxy **`GETRECORDS`** command (`escrow/srp.py list_records`, also non-destructive, no
   passcode) and correlate by bottle id. Its per-record metadata (`serial`, `build`,
   `com.apple.securebackup.timestamp`, `passcode_generation`, `ClientMetadata`) names the device.
   `octagon/client.py list_recoverable_bottles` unions the two; the CLI shows the list and lets
   the user pick before any attempt is spent (`cli/app.py _select_bottle`). Mirrors rustpush,
   which pairs `fetchViableBottles` with `getrecords` metadata and passes a caller-chosen bottle
   into `join_clique_from_escrow` (keychain.rs:1661-1680).
2. escrowproxy SRP-6a (`escrow/srp.py`, RFC-5054 2048-bit group, SHA-256).
   - `command` body value is SCREAMING_SNAKE_CASE (`SRP_INIT` / `RECOVER` / `GETRECORDS` /
     `GETCLUB` / `ENROLL` / `DELETE`), the URL slug is the lowercase form. PascalCase (`"SrpInit"`)
     -> `-5001 "Wrong command sent"`, rejected before SRP so no attempt is spent. Content-Type
     `application/x-apple-plst`; auth `Basic(GSA email, fresh PET)`.
   - SRP uses the vendored [rustcrypto-srp](https://github.com/RustCrypto/PAKEs) fork variant:
     A and B are trimmed
     (`to_bytes_be()`, no left-zero pad) in `u`, `M1`, `M2`, `K`; only `g` is padded to len(N);
     username = the dsid the server returns, not the email.
   - `x = H(salt | H(dsid ":" passcode))`; verify M2; AES-256-CBC/GCM(K) -> inner;
     PBKDF2-SHA256(passcode, salt, rounds, 16) -> AES-128-CBC -> EscrowBottle plist ->
     `bottled_peer_entropy`.
3. Bottle decryption (`escrow/bottle.py`, all local). Everything derives from the same
   `bottled_peer_entropy (72 B)` via HKDF-SHA384 salted with `adsid`, keyed by an `info` label:
   - `info="Escrow Symmetric Key"` -> 32 B AES key.
   - `info="Escrow Signing Private Key"` / `"Escrow Encryption Private Key"` -> 56 B ->
     FIPS 186-4 B.5.1 (mod n-1, +1) -> a P-384 private each. These are a *check*: their public
     keys must equal the bottle's escrowed SPKI keys, or wrong entropy/adsid aborts before decrypt.
   Then `OTBottle.ciphertext --AES-256-GCM(32 B IV)--> OTInternalBottle`, whose
   `{signing,encryption}Key.keyData (X9.63)` are the recovered old P-384 peer keys.
4. The recovered peer signs `Voucher{beneficiary=new peer, sponsor=old peer}`; `joinWithVoucher`
   registers us as a trusted peer.

## Stage 5 - Decryption chain (TLKShare -> ... -> password)

The unwrap chain (Apple Platform Security + rustpush `keychain.rs`, ported to `keychain/crypto.py`
+ `keychain/pipeline.py`):

```
TLKShare.wrappedkey  --SF-ECIES(our peer enc key)-->  CuttlefishSerializedKey{uuid,key}  (the TLK)
synckey.wrappedkey   --AES-SIV(parent TLK)-->         class key
item.wrappedkey      --AES-SIV(parent class key)-->   item key
item.data            --AES-SIV(item key, AAD)-->      plist -> credential
```

- ECIES = ECDH(P-384) -> ANSI-X9.63 KDF(SHA-256, sharedInfo = ephemeral sender pubkey) ->
  AES-256-GCM, 16-byte IV. Layout: ephemeralSenderPubKey(97 B) + ciphertext + 16 B GCM tag.
  (Apple appends 97+16 B of junk to stored ciphertext; ignored.)
- Key wrap + item encryption = AES-256-SIV (RFC 5297, CMAC), 64-byte keys. Item record
  `data = randomIV(16) || SIV(tag||ciphertext)`, random IV is the first associated-data element;
  plaintext padding 0x80||0x00* (ISO 7816-4), to a 20-byte block (min 2 blocks).

Discovered format corrections:

1. A TLKShare `wrappedkey` decrypts to a `CuttlefishSerializedKey` protobuf
   (`uuid=1, zoneName=2, keyclass=3, key=4`), not raw TLK bytes - the TLK is field 4, and its
   uuid is field 1 (NOT the share's record_name).
2. `parentkeyref` is a CloudKit `Reference`, not a string - `ckks._parse_value` must resolve
   `referenceValue(9) -> recordIdentifier -> value -> name`, or synckey->TLK and item->classkey links
   break.
3. The decrypted `inet` item plist uses `srvr` (domain), `acct` (username), `v_Data`
   (password) - reading `server` leaves every domain blank.
4. **`v_Data` is not always a password, and `agrp` says which is which.** The keychain zones
   carry many record types through the same item schema, all with a `srvr`/`acct`. Every item
   also carries **`agrp`**, the access group of the subsystem that wrote it, which identifies
   the record type. (`desc` states the same in words - "Web form password", "Website Metadata",
   "AirPort network password" - but it is a display string, so `agrp` is the better key.)

   | `agrp` | what it is |
   |---|---|
   | `com.apple.cfnetwork` | Safari web-form logins - **the credentials** |
   | `apple` | generic passwords, incl. AirPort/wi-fi |
   | `com.apple.password-manager` | per-login metadata sidecar (below) |
   | `com.apple.password-manager.website-metadata` | per-**site** record, a different payload entirely (below) |
   | `com.apple.password-manager.generated-passwords` | a generated password in `pwd` - not metadata |
   | `com.apple.safari.credit-cards` | payment cards - full PAN, CVV, expiry, FPAN hash |
   | `com.apple.webkit.webauthn` | passkeys - `v_Data` is 97 raw bytes |
   | `com.apple.ProtectedCloudStorage` (+ variants) | PCS blobs |
   | `hap.pairing`, `rapport`, `sbd`, `security.sos`, `bluetooth`, `photos`, `FinanceKit`, ... | subsystem key material and state |

   `vault/host.py classify_item` keys on `agrp`: the `password-manager*` prefix is a sidecar,
   `safari.credit-cards` a card, `webkit.webauthn` a passkey, `cfnetwork`/`apple` a login, any
   other `com.apple.*` a subsystem record, and an unrecognised group falls back to
   `classify_payload` (plist shape, then UTF-8, then C0 control bytes). The payload alone is not
   a sufficient signal: some card and HomeKit-pairing records carry plain text in `v_Data`.

   A non-text payload must not be forced through `.decode("utf-8", "replace")` - that yields
   mojibake and destroys the bytes.

### The "Password Manager Metadata" sidecar

The `password-manager*` prefix covers **three unrelated record types**, which `classify_item`
lumps together as one "sidecar" kind:

| `agrp` | scope | joins onto a login? |
|---|---|---|
| `com.apple.password-manager` | one per login | yes, on `(srvr, acct)` |
| `...password-manager.website-metadata` | one per site, `acct` always blank | effectively never |
| `...password-manager.generated-passwords` | one per generated password, payload `{pwd}` | no |

Only the first is the metadata sidecar, and it is **not** written for every login - a minority of
logins have one. Its label is exactly `Password Manager Metadata: <srvr> (<acct>)`, byte-exact
against the record's own `srvr`/`acct` (the join key), though some carry a bare URL instead. An
emptied sidecar decrypts to `{}` and is left behind rather than deleted, its login still live.

Its `v_Data` is a binary plist:

```
notes  BYTES, not str - the Notes field       s_hi  password history - list of
title  BYTES - user-set custom title                {d: date, p: a CLEARTEXT
ctxt   {<profile>: {lUsed: <float>}}                PASSWORD (str), id: uuid,
       the real last-used time lives HERE,          t: "pwcr" or "pwch", op}
       nested - never at top level           s_as  list of {s: ...}
       Apple absolute time (secs since 2001)  totp  the 2FA enrolment (below)
       `<profile>` is usually the EMPTY
       STRING, occasionally
       "SafariProfile-<name>", which also
       carries an `slUsed` DICT (not a
       timestamp)
```

`icp` merges `notes`, `title`, `totp`, `s_as` and the nested `lUsed` (as `Credential.last_used`,
which drives recency ordering - `mdat` is only the record's *write* time). `s_as` holds the
login's extra websites as `[{"s": "<host>"}]` (bare hosts, no scheme); the autofill match tries
them after the primary `srvr`. Everything else is dropped; `s_hi` deliberately so, since it
would put cleartext passwords in the vault.

**The per-site `website-metadata` record is a separate payload** and shares none of the keys
above - breach-notification and passkey-endpoint state, keyed by site with no `acct`:

```
wn                                 STR, not a date
wn_dm / wn_dr                      datetime
passkeyEndpointsDateLastRefreshed  datetime
supportsPasskey / enrollPasskeyURL / managePasskeyURL
```

Its `acct` is always blank, so it joins only a login that itself has no username and is otherwise
inert in the merge; the `_is_credential` title filter drops it from the vault anyway.

**Verification codes.** Setting up an authenticator code in the Passwords app writes it into the
per-login sidecar's payload as `totp`; the login item and the sidecar's own record fields are
untouched. The value is a sub-dict:

```
secret       RAW BYTES - not the base32 the QR shows (b32encode it to recover the setup key)
algorithm    0 = SHA1 (the only value seen; this block rests on a single enrolment)
digits       6        period  30
issuer / accountName   from the otpauth label, with `+` left undecoded by Apple
originalURL  the scanned otpauth:// URI kept verbatim (absent for a typed-in setup key)
_initialDate unset (1970)
```

`icp/totp.py` rebuilds a canonical `otpauth://` URI from the structured fields rather than
trusting `originalURL`, and generates RFC 6238 codes from it. The secret is stored in the vault
but never crosses the native-messaging protocol: `match` carries a code generated at request
time, and a `totp` command re-generates one when the browser's copy has rolled over.

**Passkeys.** They sync as `com.apple.webkit.webauthn` items, all with a blank `acct` and a
`v_Data` of 97 raw bytes rather than a fillable secret, so they are dropped. Surfacing them
would need the extension to speak WebAuthn.

Unlocking Passwords (fetch on the sponsor's behalf). The Passwords-app web logins
(`com.apple.cfnetwork` items) live in the `Passwords` CKKS view, a user-controllable view
(likewise `Manatee`). Their plain CKKS `tlkshare` records are addressed to other devices, not a
freshly-joined peer, so scraping zone records yields only the always-on views.

`fetchRecoverableTLKShares(forPeer = X)` returns the TLKShares recoverable by peer X, each
bundled with its `viewkeys` (class keys). A freshly-joined peer is only entitled to the always-on views (WiFi, Home, Contacts, ...), so `forPeer = us` never returns the
user-controllable views - asking for our own peer silently omits Passwords/Manatee. The
escrow-recovered sponsor identity IS entitled to every view, so we call
`forPeer = sponsor` and ECIES-unwrap those shares with the sponsor's encryption key (recovered
from the bottle). We persist that sponsor key at join (`octagon['sponsor']`) and, on every sync,
UNION the sponsor fetch with our own - see `octagon/client.py fetch_recoverable_tlks`. Mirrors
rustpush `join_clique_from_escrow` -> `fetch_shares_for(other_identity)`.

## Hide My Email (web-SRP)

iCloud+ Hide My Email aliases are not Keychain items - a full CKKS sync across every zone
decrypts cleanly with zero alias data. They live behind the `premiummailsettings` webservice,
which never appears in the device path's `get_account_settings` map - only in a web session's
`accountLogin` response. That web session is the "Web/appleauth" path above (unable to join
Octagon); `icp` runs it as a second, parallel auth surface.

idmsa web-session login is SRP-6a. The older pyicloud `{accountName, password}` one-shot POST
to `/signin` no longer works: a live attempt returns a generic HTTP 503 regardless of
credentials/headers/UA/IP version, and bare `curl` reproduces it, ruling out a client bug.
Fetching the sign-in widget page (`idmsa.apple.com/appleauth/auth/signin?widgetKey=...`) shows why:
its config carries `"enableSRPAuth": true` and `"isPasswordSecondStep": true`. Real flow:

```
GET      authorize/signin     (loads widget, sets the `aasp` session cookie the rest needs)
POST     federate             (account name only, no password)
POST     signin/init          (sends SRP public A; server returns {salt, b, iteration, protocol, c})
POST     signin/complete      (sends proofs m1/m2 + echoed c; 200 = signed in, 409 = HSA2 pending)
```

The password KDF (SHA256 -> s2k/s2k_fo -> PBKDF2-SHA256) and SRP math (RFC5054 2048-bit group,
no-username-in-x) are the same variant `gsa.py` uses. Session state threads across calls via
response headers (`X-Apple-ID-Session-Id`, `scnt`, `X-Apple-Session-Token`,
`X-Apple-TwoSV-Trust-Token`) plus cookies; `frame_tag` is a random `auth-<uuid>` threaded through
`X-Apple-OAuth-State`/`X-Apple-Frame-Id`; `WIDGET_KEY` is a fixed public constant.

The 409 no longer auto-sends the 2FA push. Apple's backend used to auto-trigger the push on
the `409` from `signin/complete`; a recent change ([rclone](https://github.com/rclone/rclone)'s
`iclouddrive` backend dates it to
"iOS 26.4+") means the client must now explicitly request it via
`PUT verify/trusteddevice/securitycode` before prompting for the code.

The alias API (`hme/client.py`, ported from
[dedoussis/icloud-hide-my-email-browser-extension](https://github.com/dedoussis/icloud-hide-my-email-browser-extension))
is JSON REST:

```
GET      {premiummailsettings_url}/v2/hme/list
auth     web-session cookies (no bearer token)
```

It also documents `v1/hme/{generate, reserve, updateMetaData, deactivate, reactivate, delete,
updateForwardTo}`, which mutate real account state and are deliberately not implemented here.

## Shared password groups (KCSharing, read-only)

Groups from the Passwords app ("Shared Groups") are not CKKS items. They live in their own
CloudKit container, `com.apple.security.shared.keychain` (bundle `com.apple.security.kcsharing`),
one zone per group named `group-<UUID>`: in the owner's **private** DB for groups you created, in
the **shared** DB for groups shared with you (the participant path - share info + invited
protection - is not implemented; `icp diag sharing` shows whether such zones exist).

Fetch (all read-only): `zone/sync` (RetrieveZoneChanges, op 203) lists the zones;
`zone/retrieve` (op 201, `ZoneRetrieveRequest{zoneIdentifier=1}`) returns the zone with
`protectionInfo(3)` and `recordProtectionInfo(6)`, each `ProtectionInfo{protectionInfo=1 bytes}`;
`record/sync` (op 213) returns `item` records and one `cloudkit.share` record. Never call the
zone/record save ops - a client that "creates the zone if missing" would mutate the account.

Decryption chain (`icp/sharing/pcs.py`, `groups.py`):

1. Zone `protectionInfo` is a DER `PCSShareProtection` ([APPLICATION 1] SEQUENCE: keyset
   `{INTEGER, SET OF {{keytype, OCTET pubX}, OCTET wrapped, INTEGER flags OPTIONAL}}`, [0] meta,
   [1] `{version, OCTET signature data}`, OCTET hmac, [2] truncated key id, ...).
2. The private key for one keyset entry is a keychain item in the Manatee view, access group
   `com.apple.ProtectedCloudStorage`, `acct` = base64(pubX); `v_Data` = DER `PCSPrivateKey`
   (V1 `SEQUENCE{OCTET X||d}` or V2 `[APPLICATION 5]{OCTET protobuf{1:{1: X||d}, 2: signing}}`).
3. `wrapped` = `u16 bits || ephemeral X || u8 len || AES-KW blob`; ECDH (P-256, X only) + RFC 6637
   KDF (`sha256(00000001 || Z || curve OID || 12 03 01 08 07 || "Anonymous Sender    " ||
   "fingerprint" padded to 20)`, first 16 bytes) -> AES key unwrap -> `01 || key || sum16 || pad`.
4. Unless `signature version == 5` or the share is read-only (`flags & 1`), the working master key
   is `KDF(master, "MsaeEooevaX fooo 012")`. KDF = SP 800-108 counter mode, HMAC-SHA256,
   output length = key length. Checks: key id prefix == truncated key id;
   `HMAC(KDF(k, "hmackey-of-masterkey"), keyset DER || meta || signature data) == hmac`.
5. PCS ciphertext v3: `03 || id[0:2] || n || id[2:2+n] || iv(12) || tag(12) || data`, AES-128-GCM
   with key `KDF(k, "encryption key key m")` and AAD = header || caller AAD. Key id =
   `HMAC(KDF(k, "master key id labell"), "M key input data 2 u")`.
6. `meta` (AAD empty) -> `{[0] SET OF OCTET symmetric keys, [1] ..., [2] SET OF {INTEGER, OCTET
   [APPLICATION 2]{name, SET OF PCSPrivateKey, ...}}}` - the zone identity keys.
7. `recordProtectionInfo` opens with those identity keys -> the default record keys (a record with
   its own `protectionInfo(13)` opens the same way).
8. Encrypted fields (`Value.type = 20`, bytes in `bytesValue`): AAD = `"<zone>-<record>-<field>"`.
   `item.payload` is a `SharingItem` protobuf (3 = internet password: 1 accessGroup, 2 mdat,
   3 cdat, 4 account, 6 server, 9 data, 12 label, ...; 2 = private key/passkey, skipped).
   `cloudkit.share.displayName` decrypts to `EncryptedValue{stringValue=6}` - the group name.

The items carry the same access groups as the private keychain (`com.apple.cfnetwork` logins,
`com.apple.password-manager` sidecars), so they go through `CredentialStore.from_items` unchanged
and are tagged with the group name (`Credential.group`).

Provenance: container/zone names, op numbers and the PCS layout were learned from the public
OpenBubbles `rustpush` sources (SSPL). Only facts about Apple's format were taken; the Python
here is an independent implementation - no rustpush code was copied.

## Writing (RecordSave / RecordDelete)

`icp edit` (`icp/keychain/write.py`, transport in `transport/ckks.py` + `cloudkit.py`) changes an
existing login in the `Passwords`/`Manatee` CKKS zones. Same CKDatabase endpoint family and
`com.apple.securityd` bundle as the record fetch:

- **Save**: `POST /ckdatabase/api/client/record/save`, operation type **210**, request in
  `RequestOperation` field 210: `RecordSaveRequest{record=1, etag=4, saveSemantics=6}`.
  `saveSemantics` **2 = insert** (no etag; fails if the name exists), **3 = update** (etag
  required - a stale etag fails instead of overwriting another device's newer version). The
  response carries the new etag (`serverFields(4) = Record{etag=1}`; appleservices reads a bare
  string at 2 - both are accepted).
- **Delete**: `POST /ckdatabase/api/client/record/delete`, operation type **214**,
  `RecordDeleteRequest{recordIdentifier=1, etag=2}`. `icp` never deletes without an etag.
- **Errors**: `Result{code=1, error=2}`, `Error{client=1 {code=1}, errorDescription=4}`. The client
  code is the useful part (e.g. 9 = exists, 15 = oplock / etag mismatch); it is kept on
  `CloudKitError.client_code`.
- The record is re-sent **byte for byte as fetched** (`Record{etag=1, recordIdentifier=2,
  type=3, fields=7}`), with only `data` and `wrappedkey` swapped in; zone identifier, `parentkeyref`,
  `gen`, `encver`, `uploadver` etc. go back unchanged. An insert copies a sibling record's
  layout under a new name with the `server_*` fields set to 0.

Item encryption is the inverse of Stage 5:

- A **fresh 64-byte item key per upload**, AES-SIV-wrapped with the record's class key ->
  `wrappedkey` (base64). Only the class key that `currentkey` points to is used; an item under a
  rotated (older) class key is refused.
- `data = randomIV(16) || SIV(item key, padded plist)` with the **same AAD** as for decryption
  (record name, `encver`, `gen`, parent key and the other authenticated fields) - an update does
  not change any of them, so a backed-up old ciphertext stays valid and can be put back.
- Padding: `0x80` then zeros up to a multiple of **20 bytes, at least two blocks**
  (`CKKSItemEncrypter`).
- The item's `sha1` attribute is dropped (receivers recompute it; a stale one would mismatch) and
  `mdat` is set to now.
- For a new record the item's **`UUID` attribute equals the record name** (true for every login
  and sidecar seen); an insert sets both to the same fresh uppercase UUID.
- Metadata sidecar payload: `s_as` = `[{"s": "<host>"}]`; `notes`/`title` keep their stored type
  (bytes). A written `totp` block uses `algorithm 0` (SHA1, the only value observed) and
  `_initialDate` 1970 as the Passwords app leaves it.

**Primary-key reconcile.** Website (`srvr`) and username (`acct`) are part of an `inet` item's
primary key. A device applies an incoming modify by primary key only
(`CKKSIncomingQueueOperation` -> `SecDbItemInsertOrReplace`): it does not look the old row up by
UUID. Observed on iOS 27 (2026-10-20): an in-place update that changed `srvr` left a stale row
for the old website on the iPhone next to the new one. A **rekey** fixed it: insert login and
sidecar under new UUIDs, read both back from the server and compare, then delete the old
records (with their etags) - the delete removed both stale rows with that UUID on the iPhone.
`icp` refuses a rekey onto a website/username that another login already uses, since a device
would keep only one of the two items.

Provenance: the save/delete request layout, the item encoding and the Passwords-metadata
format were learned from [Laky-64/appleservices](https://github.com/Laky-64/appleservices) (MIT:
`cloudkit/recordsave.go`, `ckks/encode.go`, `keychain/webpassword*.go`); the proto field numbers
were cross-checked against the OpenBubbles `rustpush` sources (SSPL, facts only). The Python here
is an independent implementation - no code was copied from either.
