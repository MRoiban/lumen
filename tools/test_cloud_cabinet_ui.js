// Run: node tools/test_cloud_cabinet_ui.js
// Cabinet pairing in the Cloud Saves tab: provider order, forgiving code entry,
// local validation before the RPC, the staged "Connected to … as …" state, the
// revoked-token path, the Advanced server / connect-link field and Disconnect.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const menuDir = path.join(__dirname, "..", "lua", "menu");
const read = (name) => fs.readFileSync(path.join(menuDir, name), "utf8");
const source = [read("01-core.js"), read("02-i18n.js"), read("12-cloud-tab.js")].join("\n") +
  "\nwindow.__testRenderCloud = renderCloud;" +
  "\nwindow.__testNormalize = cloudCabinetNormalizeCode;" +
  "\nwindow.__testFormat = cloudCabinetFormatInput;\n})();";

let fails = 0;
function check(cond, message) {
  if (cond) console.log("ok   " + message);
  else { console.error("FAIL: " + message); fails++; }
}

// ── minimal DOM ──────────────────────────────────────────────────────────────
class El {
  constructor(tag) {
    this.tagName = String(tag || "div").toUpperCase();
    this.children = []; this.parentNode = null; this.style = {};
    this.attributes = {}; this.listeners = {}; this._text = "";
    this.className = ""; this.value = ""; this.placeholder = ""; this.id = "";
    const self = this;
    this.classList = {
      add(c) { if (!this.contains(c)) self.className = (self.className + " " + c).trim(); },
      remove(c) { self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(" "); },
      contains(c) { return self.className.split(/\s+/).indexOf(c) !== -1; },
      toggle() {},
    };
  }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  remove() {
    if (!this.parentNode) return;
    const k = this.parentNode.children; k.splice(k.indexOf(this), 1); this.parentNode = null;
  }
  set textContent(v) { this.children = []; this._text = v == null ? "" : String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set innerHTML(v) { this.children = []; this._text = ""; }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k]; }
  addEventListener(t, fn) { (this.listeners[t] = this.listeners[t] || []).push(fn); }
  removeEventListener() {}
  fire(t) { (this.listeners[t] || []).forEach((fn) => fn({ target: this, stopPropagation() {} })); }
  click() { this.fire("click"); }
  all(pred, out = []) {
    for (const c of this.children) { if (pred(c)) out.push(c); c.all(pred, out); }
    return out;
  }
  find(pred) { return this.all(pred)[0] || null; }
}
const byClass = (root, c) => root.all((e) => e.classList.contains(c));
const byText = (root, t) => root.find((e) => e._text === t);

function setup(status, handlers) {
  const calls = [];
  const win = {
    Millennium: {
      callServerMethod(_plugin, fn, args) {
        calls.push({ fn, args });
        const h = handlers[fn];
        const value = typeof h === "function" ? h(args) : h;
        return Promise.resolve(JSON.stringify(value || { success: true }));
      },
    },
  };
  const ctx = {
    window: win,
    document: { createElement: (t) => new El(t), getElementById: () => null,
      querySelectorAll: () => [], head: new El("head"), body: new El("body"),
      documentElement: new El("html"), addEventListener() {} },
    navigator: { language: "en-US" },
    location: { hostname: "steamloopback.host" },
    console: { log() {} },
    setTimeout: () => 0, clearTimeout() {},
  };
  handlers.LumenCloudStatus = handlers.LumenCloudStatus || status;
  handlers.LumenCloudApps = handlers.LumenCloudApps || { success: true, apps: [], accounts: [] };
  vm.createContext(ctx);
  vm.runInContext(source, ctx, { filename: "cloud_cabinet_ui_bundle.js" });
  const body = new El("div");
  return { win, body, calls, S: win.__lumenI18n ? win.__lumenI18n.en.cloud : null };
}
const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const providersLocal = {
  local: { authenticated: false }, cabinet: { authenticated: false, settings: {} },
};

(async () => {
  // ── pure helpers ───────────────────────────────────────────────────────────
  {
    const { win } = setup({ success: true, provider: "local", providers: providersLocal }, {});
    check(win.__testNormalize(" abcd efgh jkmn ") === "ABCD-EFGH-JKMN", "code: case and spaces ignored");
    check(win.__testNormalize("O0IL-1234-5678") === "0011-1234-5678", "code: O->0, I/L->1");
    check(win.__testNormalize("ABCD-EFGH-JKMU") === null, "code: U rejected");
    check(win.__testNormalize("ABCD-EFGH-JKM") === null, "code: wrong length rejected");
    check(win.__testFormat("abcdefgh") === "ABCD-EFGH", "typing groups the code as XXXX-XXXX");
    check(win.__testFormat("abcd-efgh-jkmnzz") === "ABCD-EFGH-JKMN", "typing stops at 12 characters");
    const link = "https://cabinet.mc2.onl/connect#cab_abc";
    check(win.__testFormat(link) === link, "a pasted connect link is left untouched");
  }

  // ── fresh connect: Cabinet first, validation, staged connected state ──────
  {
    const account = { server: "https://cabinet.mc2.onl", host: "cabinet.mc2.onl",
      user: { id: "u1", name: "Mihai" } };
    const { win, body, calls } = setup(
      { success: true, provider: "local", providers: providersLocal },
      { LumenCloudCabinetConnect: { success: true, pending: true, account } });
    const S = win.__lumenI18n.en.cloud;
    await win.__testRenderCloud(body); await flush();
    const sel = body.find((e) => e.tagName === "SELECT");
    check(sel && sel.children[0].value === "cabinet", "Cabinet is first in the provider list");
    check(sel.children[0].textContent === S.providerCabinet, "Cabinet option is labelled");
    sel.value = "cabinet"; sel.fire("change"); await flush();
    check(byText(body, S.cabinetNotConnected) !== null, "not connected status is shown");
    const input = body.find((e) => e.tagName === "INPUT" && e.classList.contains("lumen-cabinet-code"));
    check(input && input.placeholder === "XXXX-XXXX-XXXX", "code field has the XXXX-XXXX-XXXX placeholder");
    const connect = byText(body, S.cabinetConnect);
    check(connect && connect.getAttribute("role") === "button", "Connect is gamepad-focusable");

    input.value = "abcd efgh jkm"; input.fire("input");
    check(input.value === "ABCD-EFGH-JKM", "input is grouped while typing");
    connect.click(); await flush();
    check(!calls.some((c) => c.fn === "LumenCloudCabinetConnect"),
      "an incomplete code never reaches the backend");
    check(byText(body, S.cabinetCodeInvalid) !== null, "an incomplete code explains the format");

    input.value = "abcdefghjkmn"; input.fire("input");
    connect.click(); await flush();
    const sent = calls.find((c) => c.fn === "LumenCloudCabinetConnect");
    const payload = sent && JSON.parse(sent.args.json);
    check(payload && payload.code === "ABCD-EFGH-JKMN" && payload.server === "",
      "Connect sends the normalized code and the default server");
    check(byText(body, "Connected to cabinet.mc2.onl as Mihai") !== null,
      "status reads Connected to <host> as <name>");
    const actions = byClass(body, "lumen-cloud-actions")[0];
    check(actions && actions.style.display === "flex", "the pairing is a pending draft change");
    check(byText(body, S.cabinetDisconnect) !== null, "a staged pairing can be disconnected");

    const save = byText(body, S.saveRestart);
    save.click(); await flush();
    const apply = calls.find((c) => c.fn === "LumenCloudApplyAndRestart");
    check(apply && JSON.parse(apply.args.json).provider === "cabinet",
      "Save and restart applies the cabinet provider");
  }

  // ── Advanced: custom server and full connect link ──────────────────────────
  {
    const { win, body, calls } = setup(
      { success: true, provider: "local", providers: providersLocal },
      { LumenCloudCabinetConnect: { success: false, reason: "code_rejected" } });
    const S = win.__lumenI18n.en.cloud;
    await win.__testRenderCloud(body); await flush();
    const sel = body.find((e) => e.tagName === "SELECT");
    sel.value = "cabinet"; sel.fire("change"); await flush();
    const adv = byClass(body, "lumen-cabinet-adv")[0];
    check(adv && adv.getAttribute("role") === "button", "Advanced disclosure is present");
    check(!body.find((e) => e.placeholder === "https://cabinet.mc2.onl"), "server field starts hidden");
    adv.click();
    const server = body.find((e) => e.tagName === "INPUT" && e.placeholder === "https://cabinet.mc2.onl");
    check(server !== null, "Advanced reveals the server field defaulting to cabinet.mc2.onl");
    const link = "https://cab.example.org/connect#cab_" + "x".repeat(43);
    server.value = link; server.fire("input");
    byText(body, S.cabinetConnect).click(); await flush();
    const sent = JSON.parse(calls.find((c) => c.fn === "LumenCloudCabinetConnect").args.json);
    check(sent.server === link && sent.code === "", "a connect link in Server needs no code");
    check(byText(body, S.cabinetCodeRejected) !== null, "a rejected code is explained");
  }

  // ── a connect link pasted straight into the code field ─────────────────────
  {
    const { win, body, calls } = setup(
      { success: true, provider: "cabinet", providers: providersLocal }, {});
    const S = win.__lumenI18n.en.cloud;
    await win.__testRenderCloud(body); await flush();
    const input = body.find((e) => e.classList.contains("lumen-cabinet-code"));
    const link = "https://cabinet.mc2.onl/connect#cab_" + "y".repeat(43);
    input.value = link; input.fire("input");
    byText(body, S.cabinetConnect).click(); await flush();
    const sent = JSON.parse(calls.find((c) => c.fn === "LumenCloudCabinetConnect").args.json);
    check(sent.server === link && sent.code === "", "a link in the code field is sent as the link");
  }

  // ── stored token: account lookup, revoked, disconnect ──────────────────────
  {
    const stored = { success: true, provider: "cabinet", authenticated: true, providers: {
      local: { authenticated: false },
      cabinet: { authenticated: true, settings: { server: "https://cabinet.mc2.onl", host: "cabinet.mc2.onl" } },
    } };
    const ok = setup(stored, { LumenCloudCabinetAccount:
      { success: true, host: "cabinet.mc2.onl", user: { id: "u1", name: "Mihai" } } });
    await ok.win.__testRenderCloud(ok.body); await flush();
    check(byText(ok.body, "Connected to cabinet.mc2.onl as Mihai") !== null,
      "a stored token shows the account from /api/me");
    const S = ok.win.__lumenI18n.en.cloud;
    byText(ok.body, S.cabinetDisconnect).click(); await flush();
    const sel = ok.body.find((e) => e.tagName === "SELECT");
    const chosen = sel.children.find((o) => o.selected);
    check(chosen && chosen.value === "local", "Disconnect returns the draft to local");
    byText(ok.body, S.saveRestart).click(); await flush();
    const req = JSON.parse(ok.calls.find((c) => c.fn === "LumenCloudApplyAndRestart").args.json);
    check(req.provider === "local" && req.sign_out_provider === "cabinet",
      "Disconnect applies as a cabinet sign-out to local");
    check(ok.calls.filter((c) => c.fn === "LumenCloudCabinetAccount").length === 1,
      "the account is looked up once per tab load");

    const revoked = setup(stored, { LumenCloudCabinetAccount:
      { success: false, reason: "revoked", host: "cabinet.mc2.onl" } });
    await revoked.win.__testRenderCloud(revoked.body); await flush();
    check(byText(revoked.body, S.cabinetRevoked.replace("{host}", "cabinet.mc2.onl")) !== null,
      "a revoked token is explained");
    check(revoked.body.find((e) => e.classList.contains("lumen-cabinet-code")) !== null,
      "a revoked token offers a new pairing code");
  }

  if (fails) { console.error(`\n${fails} check(s) failed`); process.exit(1); }
  console.log("test_cloud_cabinet_ui: ALL PASS");
})().catch((e) => { console.error("FAIL: " + (e && e.stack || e)); process.exit(1); });
