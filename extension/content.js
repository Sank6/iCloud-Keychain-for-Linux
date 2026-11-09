(function () {
  "use strict";

  const PASSWORD_SEL = 'input[type="password"]';
  // Username-ish inputs. Excludes password (handled separately) and obvious non-login types.
  const USERNAME_SEL =
    'input[type="text"], input[type="email"], input[type="tel"], input[type="username"], input:not([type])';
  const OTP_SEL = 'input[type="text"], input[type="tel"], input[type="number"], input:not([type])';
  const SEGMENT_SEL = 'input[maxlength="1"]';
  const FIELD_SEL = `${PASSWORD_SEL}, ${USERNAME_SEL}, input[type="number"]`;

  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
    if (el.checkVisibility && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) {
      return false;
    }
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  const observedRoots = new WeakSet();
  function observeRoot(root) {
    if (observedRoots.has(root)) return;
    observedRoots.add(root);
    observer.observe(root, { childList: true, subtree: true });
  }

  function deepQueryAll(selector, root) {
    root = root || document;
    const out = [];
    const walk = (node) => {
      node.querySelectorAll(selector).forEach((el) => out.push(el));
      node.querySelectorAll("*").forEach((el) => {
        if (el.shadowRoot) { observeRoot(el.shadowRoot); walk(el.shadowRoot); }
      });
    };
    walk(root);
    return out;
  }

  function deepQuery(selector) {
    return deepQueryAll(selector)[0] || null;
  }

  function looksLikeUsername(el) {
    const hay = `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""
      }`.toLowerCase();
    return /user|email|e-mail|login|account|identif|phone|tel\b/.test(hay)
      || el.type === "email" || el.type === "username";
  }

  const OTP_KEYWORDS = [
    "2facode", "approvalscode", "authcode", "authentication", "mfacode", "onetimecode",
    "onetimepassword", "otccode", "otcconfirmation", "otpcode", "secondfactor", "securitycode",
    "smscode", "totp", "totpcode", "twofa", "twofactor", "twofactorcode", "verificationcode",
    "verifycode",
  ];
  const OTP_NEVER = ["recovery", "backup"];
  const OTP_AMBIGUOUS = ["code", "otc", "otp", "2fa", "mfa", "pin", "token", "challenge"];
  const OTP_EXCLUDE = [
    "zip", "postal", "postcode", "coupon", "promo", "discount", "referral",
    "invite", "area", "country", "currency", "barcode", "encode", "decode", "search", "captcha",
    "user", "email", "phone", "address",
  ];
  const OTP_TYPES = new Set(["text", "tel", "number"]);

  function fieldWords(el) {
    return `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder || ""} ${
      el.getAttribute("aria-label") || ""} ${el.className}`.toLowerCase().replace(/[\s_-]/g, "");
  }

  function namedLikeOtp(el) {
    const words = fieldWords(el);
    if (OTP_NEVER.some((w) => words.includes(w))) return false;
    if ((el.autocomplete || "").toLowerCase().includes("one-time-code")) return true;
    if (!OTP_TYPES.has(el.type)) return false;
    if (OTP_EXCLUDE.some((w) => words.includes(w))) return false;
    if (OTP_KEYWORDS.some((w) => words.includes(w))) return true;
    if (!OTP_AMBIGUOUS.some((w) => words.includes(w))) return false;
    return (el.maxLength >= 4 && el.maxLength <= 10) || el.inputMode === "numeric"
      || /0-9|\d/.test(el.pattern || "");
  }

  function segmentGroup(el) {
    if (el.maxLength !== 1) return null;
    const group = deepQueryAll(SEGMENT_SEL, el.form || el.getRootNode())
      .filter((f) => visible(f) && f.maxLength === 1 && OTP_TYPES.has(f.type));
    return group.length >= 4 && group.length <= 10 && group.includes(el) ? group : null;
  }

  function isOtpField(el) {
    return namedLikeOtp(el) || !!segmentGroup(el);
  }

  // Sites do render the password box as type="text" with the real one hidden (LinkedIn).
  function looksLikePassword(el) {
    if (el.type === "password") return true;
    if (!OTP_TYPES.has(el.type)) return false;
    const words = fieldWords(el);
    return words.includes("password")
      && !/passwordless|passwordhint|forgotpassword|resetpassword/.test(words);
  }

  // A page can carry several copies of the same sign-in form
  function within(el, selector) {
    const scoped = el && el.form ? deepQueryAll(selector, el.form).filter(visible) : [];
    return scoped.length ? scoped : deepQueryAll(selector).filter(visible);
  }

  function passwordField(anchor) {
    return within(anchor, FIELD_SEL).find(looksLikePassword) || deepQuery(PASSWORD_SEL);
  }

  function findUsernameField(pwField) {
    const all = within(pwField, USERNAME_SEL).filter((el) => !looksLikePassword(el));
    // Prefer a field that precedes the password field in document order. Across shadow-root
    // boundaries compareDocumentPosition can't establish order, so fall back to any candidate.
    const before = all
      .filter((inp) => pwField.compareDocumentPosition(inp) & Node.DOCUMENT_POSITION_PRECEDING)
      .reverse();
    return before.find(looksLikeUsername) || before[0]
      || all.find(looksLikeUsername) || all[0] || null;
  }

  function setValue(el, value) {
    if (!el) return;
    const proto = el.tagName === "TEXTAREA"
      ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fill(cred, anchor) {
    const pw = passwordField(anchor);
    let userField = null;
    if (anchor && !looksLikePassword(anchor)) userField = anchor;
    else if (pw) userField = findUsernameField(pw);
    // Mark these as programmatically filled so the 'input' they emit doesn't re-open the menu.
    if (userField && cred.username) { userField.__applepwFilled = true; setValue(userField, cred.username); }
    if (pw && cred.password) { pw.__applepwFilled = true; setValue(pw, cred.password); }
    if (cred.totp) {
      const otp = within(anchor || pw, OTP_SEL).find(isOtpField);
      if (otp) fillCode(cred, otp);
    }
  }

  function currentCode(cred) {
    if (!cred.totp) return Promise.resolve("");
    if (Date.now() / 1000 < cred.totp.expires - 1) return Promise.resolve(cred.totp.code);
    return send({ cmd: "totp", domain: location.hostname, username: cred.username }).then((r) => {
      if (r && r.ok && r.totp) cred.totp = r.totp;
      return cred.totp.code;
    });
  }

  function fillCode(cred, anchor) {
    return currentCode(cred).then((code) => {
      if (!code) return;
      const group = segmentGroup(anchor);
      if (group && code.length >= group.length) {
        group.forEach((el, i) => { el.__applepwFilled = true; setValue(el, code[i]); });
        group[group.length - 1].focus();
        return;
      }
      anchor.__applepwFilled = true;
      setValue(anchor, code);
    });
  }

  // Hide My Email aliases carry no password - always fill the username/email field, never
  // the password field, even when that's the anchor that was clicked/focused.
  function fillAlias(alias, anchor) {
    const pw = passwordField(anchor);
    const userField = anchor && !looksLikePassword(anchor) ? anchor : (pw ? findUsernameField(pw) : null);
    if (userField) { userField.__applepwFilled = true; setValue(userField, alias.address); }
  }

  // Unix epoch seconds (0 = unknown). Render as a coarse "N days/months/years ago" string;
  // "" when unknown so the line is omitted.
  function relTime(when) {
    if (!when) return "";
    const days = Math.floor(Date.now() / 1000 / 86400 - when / 86400);
    if (days < 0) return "";
    if (days < 1) return "today";
    if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? "" : "s"} ago`;
  }

  let tickers = [];
  let ticker = null;
  let pickIndex = -1;

  function removeMenu() {
    if (ticker) { clearInterval(ticker); ticker = null; }
    tickers = [];
    pickIndex = -1;
    const m = document.getElementById("__applepw_menu");
    if (m) m.remove();
  }

  function refreshCode(cred) {
    if (cred.__refreshing) return;
    cred.__refreshing = true;
    send({ cmd: "totp", domain: location.hostname, username: cred.username }).then((r) => {
      cred.__refreshing = false;
      if (r && r.ok && r.totp) cred.totp = r.totp;
    });
  }

  // ---- Strong password (Apple's xxxxxx-xxxxxx-xxxxxx shape) ---------------------------------
  function randomInt(n) {  // unbiased: reject values that would skew the modulo
    const buf = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / n) * n;
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % n;
  }

  function strongPassword(maxLength) {
    const lower = "abcdefghijkmnopqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digit = "0123456789";
    const compact = maxLength > 0 && maxLength < 20;
    const groups = compact ? 1 : 3, size = compact ? Math.max(8, maxLength) : 6;
    const chars = [];
    for (let i = 0; i < groups * size; i++) chars.push(lower[randomInt(lower.length)]);
    chars[randomInt(chars.length)] = upper[randomInt(upper.length)];
    let d;
    do { d = randomInt(chars.length); } while (/[A-Z]/.test(chars[d]));
    chars[d] = digit[randomInt(digit.length)];
    let out = "";
    for (let g = 0; g < groups; g++) out += (g ? "-" : "") + chars.slice(g * size, (g + 1) * size).join("");
    return out;
  }

  function isNewPasswordField(el) {
    if (!looksLikePassword(el)) return false;
    if ((el.autocomplete || "").toLowerCase() === "new-password") return true;
    return within(el, FIELD_SEL).filter(looksLikePassword).length >= 2;
  }

  function useStrongPassword(anchor) {
    const pw = strongPassword(anchor.maxLength);
    within(anchor, FIELD_SEL).filter(looksLikePassword).forEach((f) => {
      f.__applepwFilled = true;
      setValue(f, pw);
    });
    try { navigator.clipboard.writeText(pw).catch(() => {}); } catch (_) { /* best effort */ }
    return pw;
  }

  // ---- Popover (closed shadow root so page CSS/JS can't touch it) ------------------------------
  const POPOVER_CSS = `
    :host { all: initial; }
    .menu {
      --bg: #fff; --fg: #1d1d1f; --muted: #86868b; --line: #e8e8ed; --hover: #f2f2f7; --accent: #0071e3;
      box-sizing: border-box; background: var(--bg); color: var(--fg); border-radius: 12px;
      border: .5px solid rgba(0,0,0,.14); box-shadow: 0 10px 34px rgba(0,0,0,.22);
      font: 13px/1.3 -apple-system, system-ui, "Segoe UI", Ubuntu, sans-serif; padding: 6px;
      overflow-y: auto; text-align: left;
    }
    @media (prefers-color-scheme: dark) {
      .menu { --bg: #2c2c2e; --fg: #f5f5f7; --muted: #98989d; --line: #3a3a3c; --hover: #3a3a3c;
              --accent: #0a84ff; border-color: rgba(255,255,255,.14); }
    }
    .head { display: flex; align-items: center; gap: 6px; padding: 4px 8px 6px; color: var(--muted);
            font-size: 11px; font-weight: 600; letter-spacing: .02em; }
    .head svg { width: 13px; height: 13px; flex: none; }
    .warn { margin: 2px 4px 6px; padding: 6px 8px; border-radius: 8px; background: #fff4e5;
            color: #8a4b00; font-size: 11px; }
    .row { display: flex; align-items: center; gap: 10px; padding: 7px 8px; border-radius: 8px;
           cursor: pointer; }
    .row.sel, .row:hover { background: var(--accent); color: #fff; }
    .row.sel .sub, .row:hover .sub, .row.sel .code, .row:hover .code { color: rgba(255,255,255,.85); }
    .ava { width: 26px; height: 26px; flex: none; border-radius: 7px; background: var(--hover);
           display: grid; place-items: center; font-weight: 600; color: var(--muted); text-transform: uppercase; }
    .row.sel .ava, .row:hover .ava { background: rgba(255,255,255,.22); color: #fff; }
    .meta { min-width: 0; flex: 1; }
    .t { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; }
    .sub { color: var(--muted); font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .code { color: var(--accent); font-variant-numeric: tabular-nums; letter-spacing: .08em; font-size: 11px; }
    .big { font-size: 18px; letter-spacing: .14em; font-weight: 500; color: inherit; }
    .sep { height: 1px; background: var(--line); margin: 4px 2px; }
    .act { color: var(--accent); }
    .row.sel .act, .row:hover .act { color: #fff; }
  `;
  const KEY_SVG = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M10.5 1a4.5 4.5 0 0 0-4.2 6.1L1 12.4V15h3v-1.5h1.5V12H7l1.1-1.1A4.5 4.5 0 1 0 10.5 1Zm1.2 3.2a1.2 1.2 0 1 1 0 2.4 1.2 1.2 0 0 1 0-2.4Z"/></svg>';

  function relRow(row, cls, text) {
    const el = document.createElement("div");
    el.className = cls;
    el.textContent = text;
    row.appendChild(el);
    return el;
  }

  function showMenu(anchor, creds, aliases, codes) {
    removeMenu();
    aliases = aliases || [];
    const strong = !codes && isNewPasswordField(anchor);
    if (!creds.length && !aliases.length && !strong) return;

    const rect = anchor.getBoundingClientRect();
    const host = document.createElement("div");
    host.id = "__applepw_menu";
    Object.assign(host.style, {
      position: "fixed", zIndex: 2147483647, top: `${rect.bottom + 4}px`, left: `${rect.left}px`,
      width: `${Math.max(rect.width, 260)}px`,
    });
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = POPOVER_CSS;
    const menu = document.createElement("div");
    menu.className = "menu";
    menu.style.maxHeight = `${Math.max(160, window.innerHeight - rect.bottom - 16)}px`;
    root.append(style, menu);

    const rows = [];  // pickable rows, for keyboard navigation
    function addRow(row, onPick) {
      row.classList.add("row");
      row.addEventListener("mousedown", (e) => { e.preventDefault(); onPick(); removeMenu(); });
      row.__pick = onPick;
      rows.push(row);
      menu.appendChild(row);
    }

    const head = document.createElement("div");
    head.className = "head";
    head.innerHTML = KEY_SVG;
    head.appendChild(document.createTextNode(codes ? "Verification Code" : "Passwords"));
    menu.appendChild(head);
    if (location.protocol === "http:") {
      const w = document.createElement("div");
      w.className = "warn";
      w.textContent = "This page is not secure. Your password could be seen by others.";
      menu.appendChild(w);
    }

    for (const cred of creds) {
      const row = document.createElement("div");
      const website = cred.title || cred.domain || "";
      const ava = document.createElement("div");
      ava.className = "ava";
      ava.textContent = (cred.username || website || "?").charAt(0);
      const meta = document.createElement("div");
      meta.className = "meta";
      row.append(ava, meta);
      if (codes) {
        const c = relRow(meta, "code big", "");
        const paint = () => {
          const left = Math.max(0, Math.round(cred.totp.expires - Date.now() / 1000));
          c.textContent = `${cred.totp.code} \u00b7 ${left}s`;
          if (!left) refreshCode(cred);
        };
        paint(); tickers.push(paint);
        relRow(meta, "sub", cred.username ? `${cred.username} \u00b7 ${website}` : website);
        addRow(row, () => fillCode(cred, anchor));
        continue;
      }
      relRow(meta, "t", cred.username || website || "(no title)");
      relRow(meta, "sub", cred.username ? website : "");
      if (cred.totp) {
        const c = relRow(meta, "code", "");
        const paint = () => {
          const left = Math.max(0, Math.round(cred.totp.expires - Date.now() / 1000));
          c.textContent = `Code ${cred.totp.code} \u00b7 ${left}s`;
          if (!left) refreshCode(cred);
        };
        paint(); tickers.push(paint);
      }
      addRow(row, () => { send({ cmd: "chose", domain: location.hostname, username: cred.username }); fill(cred, anchor); });
    }

    if (aliases.length) {
      const h = document.createElement("div");
      h.className = "head";
      h.textContent = "Hide My Email";
      menu.appendChild(h);
      for (const alias of aliases) {
        const row = document.createElement("div");
        const meta = document.createElement("div");
        meta.className = "meta";
        relRow(meta, "t", alias.address);
        if (alias.label) relRow(meta, "sub", alias.label);
        row.appendChild(meta);
        addRow(row, () => fillAlias(alias, anchor));
      }
    }

    if (!codes) {
      menu.appendChild(Object.assign(document.createElement("div"), { className: "sep" }));
      if (strong) {
        const row = document.createElement("div");
        relRow(row, "act", "Use Strong Password");
        addRow(row, () => useStrongPassword(anchor));
      }
      const open = document.createElement("div");
      relRow(open, "act", "Passwords\u2026");
      addRow(open, () => send({ cmd: "open_app" }));
    }

    document.body.appendChild(host);
    host.__rows = rows;
    if (tickers.length) ticker = setInterval(() => tickers.forEach((paint) => paint()), 1000);
  }

  function showLocked(anchor, onUnlocked) {
    removeMenu();
    const rect = anchor.getBoundingClientRect();
    const host = document.createElement("div");
    host.id = "__applepw_menu";
    Object.assign(host.style, { position: "fixed", zIndex: 2147483647, top: `${rect.bottom + 4}px`,
                                left: `${rect.left}px`, width: `${Math.max(rect.width, 260)}px` });
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = POPOVER_CSS;
    const menu = document.createElement("div");
    menu.className = "menu";
    const head = document.createElement("div");
    head.className = "head";
    head.innerHTML = KEY_SVG;
    head.appendChild(document.createTextNode("Passwords Locked"));
    const row = document.createElement("div");
    row.className = "row";
    relRow(row, "act", "Unlock Passwords\u2026");
    row.addEventListener("mousedown", (e) => {
      e.preventDefault();
      send({ cmd: "unlock" }).then((r) => { if (r && r.ok) { cache = null; onUnlocked(); } });
      removeMenu();
    });
    row.__pick = () => row.dispatchEvent(new MouseEvent("mousedown"));
    menu.append(head, row);
    root.append(style, menu);
    host.__rows = [row];
    document.body.appendChild(host);
  }

  // Arrow keys / Enter / Escape drive the popover while it is open (capture: before the page).
  document.addEventListener("keydown", (e) => {
    const host = document.getElementById("__applepw_menu");
    if (!host || !host.__rows || !host.__rows.length) return;
    const rows = host.__rows;
    const paintSel = () => rows.forEach((r, i) => r.classList.toggle("sel", i === pickIndex));
    if (e.key === "ArrowDown") { pickIndex = (pickIndex + 1) % rows.length; paintSel(); }
    else if (e.key === "ArrowUp") { pickIndex = (pickIndex - 1 + rows.length) % rows.length; paintSel(); }
    else if (e.key === "Enter" && pickIndex >= 0) { rows[pickIndex].__pick(); removeMenu(); }
    else if (e.key === "Escape") { removeMenu(); return; }
    else return;
    e.preventDefault(); e.stopPropagation();
  }, true);

  // A username field's typed value narrows the list; a password field (or empty value)
  // never filters.
  function fieldQuery(field) {
    if (!field || field.type === "password") return "";
    return (field.value || "").trim().toLowerCase();
  }

  function filterCreds(creds, field) {
    const q = fieldQuery(field);
    if (!q) return creds;
    return creds.filter(
      (c) =>
        (c.username || "").toLowerCase().includes(q) ||
        (c.title || c.domain || "").toLowerCase().includes(q));
  }

  function filterAliases(aliases, field) {
    const q = fieldQuery(field);
    if (!q) return aliases;
    return aliases.filter(
      (a) =>
        (a.address || "").toLowerCase().includes(q) ||
        (a.label || "").toLowerCase().includes(q));
  }

  const EMPTY_MATCHES = { credentials: [], aliases: [] };

  function send(msg) {
    return new Promise((resolve) => {
      if (!chrome.runtime || !chrome.runtime.id) return resolve(null);
      chrome.runtime.sendMessage(msg, (resp) => resolve(chrome.runtime.lastError ? null : resp));
    });
  }

  let cache = null;
  function getMatches() {
    if (cache) return Promise.resolve(cache);
    return send({ cmd: "match", domain: location.hostname }).then((resp) => {
      if (resp && resp.locked) return { locked: true, credentials: [], aliases: [] };
      cache = resp && resp.ok
        ? { credentials: resp.credentials || [], aliases: resp.aliases || [] }
        : EMPTY_MATCHES;
      return cache;
    });
  }

  function attach(field) {
    if (field.__applepw) return;
    field.__applepw = true;
    const open = (e) => { if (e && e.isTrusted === false) return; return getMatches().then(({ locked, credentials, aliases }) => {
      if (locked) return showLocked(field, () => open());
      if (isOtpField(field)) return showMenu(field, credentials.filter((c) => c.totp), [], true);
      showMenu(field, filterCreds(credentials, field), filterAliases(aliases, field));
    }); };
    field.addEventListener("focus", open);
    field.addEventListener("click", open);
    field.addEventListener("input", () => {
      if (field.__applepwFilled) { field.__applepwFilled = false; return; }
      open();
    });
  }

  function scan() {
    const fields = deepQueryAll(FIELD_SEL).filter(visible);
    const passwords = fields.filter(looksLikePassword);
    passwords.forEach(attach);
    // A text field is only a sign-in field if it is a code box, is named like a username, or sits
    // in the same form as a password field. (A search box next to a login form is neither.)
    const NOT_LOGIN = /search|query|zip|postal|coupon|promo|captcha|newsletter|subscribe|\bq\b/;
    const sameScope = (el) => passwords.some((p) => (p.form || null) === (el.form || null)
      && (p.form || p.getRootNode() === el.getRootNode()));
    fields.forEach((el) => {
      if (looksLikePassword(el)) return;
      if (isOtpField(el)) return attach(el);
      const words = fieldWords(el);
      if (el.type === "search" || NOT_LOGIN.test(words)) return;
      if (looksLikeUsername(el) || sameScope(el)) attach(el);
    });
  }

  // deepQueryAll walks the whole tree (incl. shadow roots), so coalesce the many mutations a
  // page emits into one scan per frame instead of scanning per record.
  let scanScheduled = false;
  function scheduleScan() {
    if (scanScheduled) return;
    scanScheduled = true;
    requestAnimationFrame(() => { scanScheduled = false; scan(); });
  }

  const observer = new MutationObserver(scheduleScan);

  document.addEventListener("click", (e) => {
    // composedPath crosses shadow boundaries; e.target is retargeted to the shadow host, which
    // would make clicks on shadow-DOM fields (Reddit) look like outside-clicks and close the menu.
    const path = e.composedPath ? e.composedPath() : [e.target];
    for (const t of path) {
      if (t && t.id === "__applepw_menu") return;
      if (t && t.__applepw) return;
    }
    removeMenu();
  });

  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg && msg.cmd === "fill") {
      removeMenu();
      fill(msg.credential, null);
      respond({ ok: true });
    }
    return false;
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });
  scan();
})();
