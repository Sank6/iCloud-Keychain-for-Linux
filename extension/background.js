const HOST = "org.icp.native";

function nativeRequest(payload) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(HOST, payload, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response || { ok: false, error: "no response" });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

const FORWARDED = new Set(["ping", "match", "totp", "status", "open_app", "search", "lock", "unlock", "chose"]);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message && FORWARDED.has(message.cmd)) {
    nativeRequest(message).then(sendResponse);
    return true; // async
  }
  sendResponse({ ok: false, error: "unknown message" });
  return false;
});
