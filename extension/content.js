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

  function removeMenu() {
    if (ticker) { clearInterval(ticker); ticker = null; }
    tickers = [];
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

  function codeLine(cred, style) {
    const el = document.createElement("div");
    Object.assign(el.style, style);
    const paint = () => {
      const left = Math.max(0, Math.round(cred.totp.expires - Date.now() / 1000));
      el.textContent = `${cred.totp.code}  ${left}s`;
      if (!left) refreshCode(cred);
    };
    paint();
    tickers.push(paint);
    return el;
  }

  function subLine(text) {
    const el = document.createElement("div");
    el.textContent = text;
    Object.assign(el.style, { fontSize: "11px", color: "#888" });
    return el;
  }

  function menuRow(onPick) {
    const row = document.createElement("div");
    Object.assign(row.style, { padding: "8px 10px", cursor: "pointer", textAlign: "left" });
    row.addEventListener("mouseenter", () => (row.style.background = "#f1f5ff"));
    row.addEventListener("mouseleave", () => (row.style.background = "#fff"));
    row.addEventListener("mousedown", (e) => {
      e.preventDefault();
      // Only a real click fills the credential: a page script can dispatch a synthetic
      // mousedown, and that must not be able to make us hand a password to the page.
      if (!e.isTrusted) return;
      onPick();
      removeMenu();
    });
    return row;
  }

  function showMenu(anchor, creds, aliases, codes) {
    removeMenu();
    aliases = aliases || [];
    if (!creds.length && !aliases.length) return;
    const rect = anchor.getBoundingClientRect();
    const menu = document.createElement("div");
    menu.id = "__applepw_menu";
    Object.assign(menu.style, {
      position: "fixed", zIndex: 2147483647,
      top: `${rect.bottom + 2}px`, left: `${rect.left}px`,
      minWidth: `${Math.max(rect.width, 220)}px`,
      maxHeight: `${Math.max(160, window.innerHeight - rect.bottom - 12)}px`,
      overflowY: "auto",
      background: "#fff", color: "#111", textAlign: "left",
      border: "1px solid #c7c7c7", borderRadius: "8px",
      boxShadow: "0 6px 24px rgba(0,0,0,.18)", font: "13px -apple-system,system-ui,sans-serif",
    });
    function sectionHeader(text, extraStyle) {
      const el = document.createElement("div");
      el.textContent = text;
      Object.assign(el.style, { padding: "6px 10px", color: "#666", fontSize: "11px" }, extraStyle);
      menu.appendChild(el);
    }

    if (creds.length) {
      sectionHeader(codes ? "Verification code" : "iCloud Passwords",
                    { borderBottom: "1px solid #eee" });
    }
    for (const cred of creds) {
      const row = menuRow(() => (codes ? fillCode(cred, anchor) : fill(cred, anchor)));
      if (codes) {
        row.appendChild(codeLine(cred, {
          fontSize: "17px", letterSpacing: ".12em", fontVariantNumeric: "tabular-nums",
        }));
      }
      const website = cred.domain || cred.title || "";
      const name = document.createElement("div");
      if (cred.username && website) {
        const user = document.createElement("span");
        user.textContent = cred.username;
        const site = document.createElement("span");
        site.textContent = ` (${website})`;
        Object.assign(site.style, { fontSize: "11px", color: "#999" });
        name.appendChild(user);
        name.appendChild(site);
      } else {
        name.textContent = cred.username || website || "(no title)";
      }
      row.appendChild(name);
      if (codes) {
        menu.appendChild(row);
        continue;
      }
      if (cred.totp) {
        row.appendChild(codeLine(cred, { fontSize: "11px", color: "#0071e3" }));
      }
      // last_used is a real use time; mdat is only the record's write time.
      const rel = relTime(cred.last_used || cred.mdat);
      if (rel) row.appendChild(subLine(`Last used ${rel}`));
      menu.appendChild(row);
    }

    if (aliases.length) {
      sectionHeader("Hide My Email", { borderTop: creds.length ? "1px solid #eee" : "" });
      for (const alias of aliases) {
        const row = menuRow(() => fillAlias(alias, anchor));
        const name = document.createElement("div");
        name.textContent = alias.address;
        row.appendChild(name);
        if (alias.label) row.appendChild(subLine(alias.label));
        menu.appendChild(row);
      }
    }
    document.body.appendChild(menu);
    if (tickers.length) ticker = setInterval(() => tickers.forEach((paint) => paint()), 1000);
  }

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
      cache = resp && resp.ok
        ? { credentials: resp.credentials || [], aliases: resp.aliases || [] }
        : EMPTY_MATCHES;
      return cache;
    });
  }

  function attach(field) {
    if (field.__applepw) return;
    field.__applepw = true;
    const open = () => getMatches().then(({ credentials, aliases }) => {
      if (isOtpField(field)) return showMenu(field, credentials.filter((c) => c.totp), [], true);
      showMenu(field, filterCreds(credentials, field), filterAliases(aliases, field));
    });
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
    fields.forEach((el) => {
      if (looksLikePassword(el)) return;
      if (isOtpField(el) || passwords.length || looksLikeUsername(el)) attach(el);
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
