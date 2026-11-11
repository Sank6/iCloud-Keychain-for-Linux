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
  el.className = "code";
  el.title = "Copy verification code";
  let copied = 0;
  const paint = () => {
    if (Date.now() < copied) return;
    const left = Math.max(0, Math.round(cred.totp.expires - Date.now() / 1000));
    el.textContent = `${cred.totp.code} ${left}s`;
  };
  paint();
  tickers.push(paint);
  el.addEventListener("click", (e) => {
    e.stopPropagation();
    copyCode(cred).then(() => { copied = Date.now() + 1500; el.textContent = "Copied"; });
  });
  return el;
}

function avatarText(c) {
  const s = (c.username || c.title || c.domain || "?").trim();
  return s.charAt(0) || "?";
}

async function main() {
  const ping = await send({ cmd: "ping" });
  if (!ping.ok) {
    subEl.textContent = "Not connected";
    // Built with textContent, not innerHTML: the message can come from the native host.
    statusEl.textContent = "";
    const err = document.createElement("span");
    err.className = "err";
    err.textContent = `Host unavailable: ${ping.error || "?"}`;
    statusEl.appendChild(err);
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

  listEl.innerHTML = "";
  for (const c of creds) {
    const div = document.createElement("div");
    div.className = "cred";
    div.innerHTML =
      `<div class="avatar"></div>` +
      `<div class="meta"><div class="u"></div><div class="d"></div></div>` +
      `<div class="fill">Fill -></div>`;
    div.querySelector(".avatar").textContent = avatarText(c);
    div.querySelector(".u").textContent = c.username || "(no username)";
    div.querySelector(".d").textContent = c.title || c.domain;
    if (c.totp) div.insertBefore(codeChip(c), div.querySelector(".fill"));
    div.addEventListener("click", () => { fillOnPage(c); window.close(); });
    listEl.appendChild(div);
  }
}

main();
