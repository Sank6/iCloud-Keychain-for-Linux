const statusEl = document.getElementById("status");
const listEl = document.getElementById("list");
const subEl = document.getElementById("subcount");

function activeDomain() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      try {
        resolve(tabs[0] ? new URL(tabs[0].url).hostname : "");
      } catch (_) {
        resolve("");
      }
    });
  });
}

function send(msg) {
  return new Promise((resolve) =>
    chrome.runtime.sendMessage(msg, (r) => resolve(r || { ok: false, error: "no response" })));
}

function activeTabId() {
  return new Promise((resolve) =>
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(tabs[0] && tabs[0].id)));
}

// Frame 0 only; the content script owns field detection.
async function fillOnPage(cred) {
  const tabId = await activeTabId();
  if (tabId != null) chrome.tabs.sendMessage(tabId, { cmd: "fill", credential: cred }, { frameId: 0 });
}

async function copyCode(cred) {
  const fresh = await send({ cmd: "totp", domain: await activeDomain(), username: cred.username });
  if (fresh.ok) cred.totp = fresh.totp;
  await navigator.clipboard.writeText(cred.totp.code);
}

const tickers = [];
setInterval(() => tickers.forEach((paint) => paint()), 1000);

function codeChip(cred) {
  const el = document.createElement("div");
  el.className = "codebox";
  el.title = "Click to copy verification code";
  const R = 9, C = 2 * Math.PI * R;
  el.innerHTML =
    `<div class="code"></div><div class="ring"><svg width="24" height="24" viewBox="0 0 24 24">` +
    `<circle class="bg" cx="12" cy="12" r="${R}"/><circle class="fg" cx="12" cy="12" r="${R}" ` +
    `stroke-dasharray="${C}" stroke-dashoffset="0"/></svg></div>`;
  const code = el.querySelector(".code");
  const fg = el.querySelector(".fg");
  let copied = 0;
  const paint = () => {
    const left = Math.max(0, cred.totp.expires - Date.now() / 1000);
    fg.style.strokeDashoffset = String(C * (1 - Math.min(1, left / 30)));
    fg.style.stroke = left < 6 ? "var(--bad)" : "";
    if (Date.now() < copied) return;
    const c = cred.totp.code;
    code.textContent = c.length === 6 ? `${c.slice(0, 3)} ${c.slice(3)}` : c;
  };
  paint();
  tickers.push(paint);
  el.addEventListener("click", (e) => {
    e.stopPropagation();
    copyCode(cred).then(() => { copied = Date.now() + 1500; code.textContent = "Copied"; });
  });
  return el;
}

function avatarText(c) {
  const s = (c.username || c.title || c.domain || "?").trim();
  return s.charAt(0) || "?";
}

function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

// One line under the header: when the vault last synced, or what is wrong and how to fix it.
// "Sign-in needed" (no session, or Apple rejected it) gets a button that opens the sign-in window.
function renderSync(resp) {
  const el = document.getElementById("sync");
  const sync = (resp && resp.ok && resp.sync) || {};
  const signedOut = resp && resp.ok && resp.signed_in === false;
  el.className = "";
  el.textContent = "";
  if (signedOut || sync.needs_login) {
    el.className = "bad";
    el.append(signedOut ? "Not signed in to iCloud. " : "Sign-in needed. ");
    const b = document.createElement("button");
    b.textContent = "Sign in\u2026";
    b.style.cssText = "border:0;border-radius:6px;padding:3px 8px;background:var(--accent);color:#fff;font:inherit;cursor:pointer";
    b.onclick = () => { send({ cmd: "login" }); window.close(); };
    el.appendChild(b);
    el.title = sync.last_error || "";
  } else if (sync.failures) {
    el.className = "bad";
    el.textContent = `Sync failing${sync.hint ? ": " + sync.hint : ""}`;
    el.title = sync.last_error || "";
  } else if (sync.last_success) {
    const stale = Date.now() / 1000 - sync.last_success > 3 * 86400;
    el.className = stale ? "bad" : "";
    el.textContent = `Synced ${ago(sync.last_success)}${stale ? " - run icp sync" : ""}`;
  } else {
    el.textContent = "Not synced yet - run icp sync";
  }
}

async function main() {
  const ping = await send({ cmd: "ping" });
  if (!ping.ok) {
    subEl.textContent = "Not connected";
    statusEl.innerHTML = `<span class="err">Host unavailable: ${ping.error || "?"}</span>`;
    return;
  }
  if (ping.locked) {
    subEl.textContent = "Locked";
    statusEl.innerHTML = "";
    const b = document.createElement("button");
    b.textContent = "Unlock Passwords\u2026";
    b.style.cssText = "border:0;border-radius:8px;padding:8px 12px;background:var(--accent);color:#fff;font:inherit;cursor:pointer";
    b.onclick = async () => { b.disabled = true; await send({ cmd: "unlock" }); location.reload(); };
    statusEl.appendChild(b);
    renderSync(await send({ cmd: "status" }));
    return;
  }
  const domain = await activeDomain();
  const resp = await send({ cmd: "match", domain });
  const creds = resp.ok ? resp.credentials : [];

  subEl.textContent = `${ping.count.toLocaleString()} saved logins`;
  const n = creds.length;
  statusEl.textContent = domain
    ? `${n} ${n === 1 ? "login" : "logins"} for ${domain}`
    : `${ping.count} saved | open a site to autofill`;

  renderSync(await send({ cmd: "status" }));

  render(creds);
  const q = document.getElementById("q");
  let timer = 0;
  q.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const text = q.value.trim();
      if (text.length < 2) { statusEl.textContent = n ? `${n} for ${domain}` : ""; return render(creds); }
      const r = await send({ cmd: "search", query: text });
      const found = r.ok ? r.credentials : [];
      statusEl.textContent = `${found.length} result${found.length === 1 ? "" : "s"}`;
      render(found);
    }, 120);
  });
  document.getElementById("openapp").addEventListener("click", () => {
    send({ cmd: "open_app" }); window.close();
  });
  document.getElementById("resync").addEventListener("click", () => {
    statusEl.textContent = "Run `icp sync` (or `icp doctor`) in a terminal";
  });
  q.focus();
}

function render(creds) {
  tickers.length = 0;
  listEl.innerHTML = "";
  for (const c of creds) {
    const div = document.createElement("div");
    div.className = "cred";
    div.innerHTML =
      `<div class="avatar"></div>` +
      `<div class="meta"><div class="u"></div><div class="d"></div></div>` +
      `<div class="fill"></div>`;
    div.querySelector(".avatar").textContent = avatarText(c);
    div.querySelector(".u").textContent = c.username || "(no username)";
    div.querySelector(".d").textContent = c.title || c.domain;
    if (c.totp) div.insertBefore(codeChip(c), div.querySelector(".fill"));
    const icons = document.createElement("div");
    icons.className = "icons";
    for (const [label, field] of [["User", "username"], ["Pass", "password"]]) {
      if (!c[field]) continue;
      const b = document.createElement("button");
      b.textContent = label;
      b.title = `Copy ${field}`;
      b.addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(c[field]);
        b.textContent = "\u2713";
        // like the Apple app: don't leave a password on the clipboard
        setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
      });
      icons.appendChild(b);
    }
    div.insertBefore(icons, div.querySelector(".fill"));
    div.addEventListener("click", () => { fillOnPage(c); window.close(); });
    listEl.appendChild(div);
  }
}

main();
