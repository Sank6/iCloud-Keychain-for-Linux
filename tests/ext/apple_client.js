// Test harness: runs Apple's own extension code (SecretSession + sjcl, from the installed
// extension's background.js) as the *client* so our host implementation is checked against the
// real thing. Read-only: the extension file is only read and evaluated in a vm sandbox.
// Protocol: one JSON object per stdin line -> one JSON line on stdout.
//   {"op":"init","caps":{...}}                    -> {"pake": <m0 PAKE>}
//   {"op":"pin","pin":"123456","pake":<msg1>}      -> {"pake": <m2 PAKE>}
//   {"op":"msg3","pake":<msg3>}                   -> {"ok":true} | {"error":..}
//   {"op":"smsg","obj":{...}}                     -> {"smsg": "<json string>"}
//   {"op":"parse","smsg":"<json or object>"}      -> {"obj": {...}}
const fs = require("fs"), vm = require("vm"), readline = require("readline");
const src = fs.readFileSync(process.argv[2], "utf8");
const end = src.indexOf("const ContextState");
const sandbox = { self: { crypto: require("crypto").webcrypto }, console };
vm.createContext(sandbox);
vm.runInContext(src.slice(0, end) + "\n;globalThis.__SS = SecretSession; globalThis.__sjcl = sjcl;", sandbox);
let ss = null;
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  let m, out;
  try {
    m = JSON.parse(line);
    switch (m.op) {
      case "init":
        ss = new sandbox.__SS(m.caps || {});
        out = { pake: ss.initialMessage() };
        break;
      case "pin":
        ss.setPin(m.pin);
        out = { pake: ss.processMessage(m.pake) };
        break;
      case "msg3":
        out = { ok: ss.processMessage(m.pake) === true };
        break;
      case "smsg":
        out = { smsg: ss.createSMSG(JSON.stringify(m.obj)) };
        break;
      case "parse":
        out = { obj: JSON.parse(ss.parseSMSG(m.smsg)) };
        break;
      case "dump":   // group modulus, for the host constant (public RFC 5054 value)
        out = { N: sandbox.__sjcl.keyexchange.srp.knownGroup(3072).N.toString() };
        break;
      default: out = { error: "unknown op" };
    }
  } catch (e) { out = { error: String(e && e.message || e), code: e && e.code }; }
  process.stdout.write(JSON.stringify(out) + "\n");
});
