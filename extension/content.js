(function () {
  "use strict";

  const PASSWORD_SEL = 'input[type="password"]';
  const OTP_SEL = 'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[type="number"], input[type="tel"], input[type="text"], input:not([type])';
  // Username-ish inputs. Excludes password (handled separately) and obvious non-login types.
  const USERNAME_SEL =
    'input[type="text"], input[type="email"], input[type="tel"], input[type="username"], input:not([type])';

  function visible(el) {
    if (!el || el.disabled || el.readOnly) return false;
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

  function findUsernameField(pwField) {
    const all = deepQueryAll(USERNAME_SEL).filter(visible);
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
    // Preserve the original extension's known-working username/password fill path exactly.
    const pw = deepQuery(PASSWORD_SEL);
    let userField = null;
    if (anchor && anchor.type !== "password" && !looksLikeOtp(anchor)) userField = anchor;
    else if (pw) userField = findUsernameField(pw);

    if (userField && cred.username) {
      userField.__applepwFilled = true;
      setValue(userField, cred.username);
    }
    if (pw && cred.password) {
      pw.__applepwFilled = true;
      setValue(pw, cred.password);
    }

    // OTP is additive: fill the selected OTP field, or the first recognised OTP field.
    if (cred.totp && cred.totp.code) {
      const otp = anchor && looksLikeOtp(anchor)
        ? anchor
        : deepQueryAll(OTP_SEL).find((el) => visible(el) && looksLikeOtp(el));
      if (otp) {
        otp.__applepwFilled = true;
        setValue(otp, cred.totp.code);
      }
    }
  }

  // Hide My Email aliases carry no password - always fill the username/email field, never
  // the password field, even when that's the anchor that was clicked/focused.
  function fillAlias(alias, anchor) {
    const pw = deepQuery(PASSWORD_SEL);
    const userField = anchor && anchor.type !== "password" ? anchor : (pw ? findUsernameField(pw) : null);
    if (userField) { userField.__applepwFilled = true; setValue(userField, alias.address); }
  }

  // mdat is unix epoch seconds of the item's last change (0 = unknown). Render as a coarse
  // "N days/months/years ago" string; "" when unknown so the line is omitted.
  function relTime(mdat) {
    if (!mdat) return "";
    const days = Math.floor(Date.now() / 1000 / 86400 - mdat / 86400);
    if (days < 0) return "";
    if (days < 1) return "today";
    if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? "" : "s"} ago`;
  }

  function removeMenu() {
    const m = document.getElementById("__applepw_menu");
    if (m) m.remove();
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
      onPick();
      removeMenu();
    });
    return row;
  }

  function showMenu(anchor, creds, aliases) {
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

    if (creds.length) sectionHeader("iCloud Passwords", { borderBottom: "1px solid #eee" });
    for (const cred of creds) {
      const row = menuRow(() => fill(cred, anchor));
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
      if (cred.totp && cred.totp.code) row.appendChild(subLine(`Verification code: ${cred.totp.code}`));
      const rel = relTime(cred.mdat);
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

  let cache = null;
  function getMatches() {
    if (cache) return Promise.resolve(cache);
    return new Promise((resolve) => {
      if (!chrome.runtime || !chrome.runtime.id) return resolve(EMPTY_MATCHES);
      chrome.runtime.sendMessage({ cmd: "match", domain: location.hostname }, (resp) => {
        if (chrome.runtime.lastError) return resolve(EMPTY_MATCHES);
        cache = resp && resp.ok
          ? { credentials: resp.credentials || [], aliases: resp.aliases || [] }
          : EMPTY_MATCHES;
        resolve(cache);
      });
    });
  }

  function attach(field) {
    if (field.__applepw) return;
    field.__applepw = true;
    const open = () => getMatches().then(({ credentials, aliases }) =>
      showMenu(field, filterCreds(credentials, field), filterAliases(aliases, field)));
    field.addEventListener("focus", open);
    field.addEventListener("click", open);
    field.addEventListener("input", () => {
      if (field.__applepwFilled) { field.__applepwFilled = false; return; }
      open();
    });
  }

  function scan() {
    const pwFields = deepQueryAll(PASSWORD_SEL).filter(visible);
    pwFields.forEach(attach);
    deepQueryAll(OTP_SEL).filter((el) => visible(el) && looksLikeOtp(el)).forEach(attach);
    const hasPassword = pwFields.length > 0;
    deepQueryAll(USERNAME_SEL).forEach((el) => {
      if (!visible(el) || el.type === "password") return;
      if (hasPassword || looksLikeUsername(el)) attach(el);
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

  observer.observe(document.documentElement, { childList: true, subtree: true });
  scan();
})();
