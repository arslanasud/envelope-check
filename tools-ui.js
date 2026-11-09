/* Envelope Check - UI for the tabs and the extra tools. */
(function () {
  "use strict";
  const T = window.EnvelopeTools;

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => { if (k === "class") node.className = v; else node.setAttribute(k, v); });
    children.flat().forEach((c) => { if (c !== null && c !== undefined && c !== false) node.append(c); });
    return node;
  }

  // ---- Tabs ---------------------------------------------------------------
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  const panels = new Map(tabs.map((t) => [t.getAttribute("aria-controls"), document.getElementById(t.getAttribute("aria-controls"))]));
  const RESERVED = new Set(["settings", "sidebar", "customize", "upgrade", "downloads"]);

  function show(id, focus) {
    if (!panels.has(id)) id = tabs[0].getAttribute("aria-controls");
    tabs.forEach((tab) => {
      const on = tab.getAttribute("aria-controls") === id;
      tab.setAttribute("aria-selected", on ? "true" : "false");
      tab.tabIndex = on ? 0 : -1;
      panels.get(tab.getAttribute("aria-controls")).hidden = !on;
    });
    const name = id.replace(/^tab-/, "");
    if (!RESERVED.has(name)) { try { history.replaceState(null, "", "#" + name); } catch (_) {} }
    if (focus) panels.get(id).scrollIntoView({ block: "nearest" });
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => show(tab.getAttribute("aria-controls"), true));
    tab.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      e.preventDefault();
      const next = (i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length;
      tabs[next].focus();
      show(tabs[next].getAttribute("aria-controls"), true);
    });
  });
  const fromHash = "tab-" + (location.hash.replace(/^#/, "") || "email");
  show(panels.has(fromHash) ? fromHash : tabs[0].getAttribute("aria-controls"));

  // ---- Link checker -------------------------------------------------------
  (function linkTool() {
    const input = document.getElementById("link-input");
    const button = document.getElementById("link-button");
    const output = document.getElementById("link-output");
    if (!input) return;
    const run = () => {
      const result = T.analyzeLink(input.value);
      if (!result.ok) { output.replaceChildren(el("p", { class: "inline-error" }, result.message)); return; }
      const repLinks = T.reputationLinks(result.href);
      output.replaceChildren(
        el("article", { class: "check", "data-status": result.level },
          el("header", {},
            el("div", {}, el("p", { class: "summary-domain" }, "Goes to: " + result.host)),
            el("span", { class: "pill" }, el("span", { class: "dot", "aria-hidden": "true" }), result.level === "fail" ? "Unsafe signs" : result.level === "warn" ? "Be careful" : "Looks ordinary")),
          el("p", { class: "headline" }, result.verdict.headline),
          el("p", {}, result.verdict.text),
          el("p", { class: "plan-note" }, "The part that matters most is the main domain: " + result.mainDomain + ". Everything else can be made to say anything."),
          result.flags.length ? el("div", { class: "fix" }, el("h4", {}, "What we noticed"),
            el("ul", { class: "flag-list" }, result.flags.map((f) =>
              el("li", { "data-status": f.level }, el("strong", {}, f.title + ": "), f.detail)))) : null,
          el("div", { class: "fix" },
            el("h4", {}, "Check its reputation"),
            el("p", { class: "plan-note" }, "Look this link up against databases of known-bad sites. Opens the service in a new tab. A clean result isn't proof it's safe - brand-new scam sites may not be listed yet."),
            el("p", { class: "links" }, repLinks.map((l) => el("a", { href: l.href, target: "_blank", rel: "noopener noreferrer" }, l.label))))));
    };
    button.addEventListener("click", run);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } });
  })();

  // ---- Password tools -----------------------------------------------------
  (function passwordTools() {
    const genOut = document.getElementById("gen-output");
    if (!genOut) return;
    const lengthInput = document.getElementById("gen-length");
    const lengthLabel = document.getElementById("gen-length-label");
    const modeInputs = Array.from(document.querySelectorAll('input[name="gen-mode"]'));
    const symbols = document.getElementById("gen-symbols");

    function randomInts(count) {
      const arr = new Uint32Array(count);
      (window.crypto || window.msCrypto).getRandomValues(arr);
      return arr;
    }
    function generate() {
      const mode = (modeInputs.find((m) => m.checked) || {}).value || "words";
      let value;
      if (mode === "words") {
        const count = Math.max(4, Math.min(8, Number(lengthInput.value) || 6));
        const r = randomInts(count + 1);
        value = T.makePassphrase(Array.from(r.slice(0, count)), r[count], "-");
      } else {
        const count = Math.max(8, Math.min(40, Number(lengthInput.value) || 20));
        value = T.makePassword(randomInts(count), count, { symbols: symbols.checked });
      }
      genOut.replaceChildren(
        el("div", { class: "pw-result" }, el("code", { id: "gen-value" }, value), copyButton(value, "password", () => document.getElementById("gen-value"))),
        el("p", { class: "plan-note" }, "Generated on your device. It is never sent anywhere. Store it in your password manager."));
    }
    function syncLabel() {
      const mode = (modeInputs.find((m) => m.checked) || {}).value || "words";
      if (mode === "words") { lengthInput.min = 4; lengthInput.max = 8; if (lengthInput.value > 8) lengthInput.value = 6; lengthLabel.textContent = lengthInput.value + " words"; symbols.parentElement.hidden = true; }
      else { lengthInput.min = 8; lengthInput.max = 40; if (lengthInput.value < 8) lengthInput.value = 20; lengthLabel.textContent = lengthInput.value + " characters"; symbols.parentElement.hidden = false; }
    }
    lengthInput.addEventListener("input", () => { syncLabel(); generate(); });
    modeInputs.forEach((m) => m.addEventListener("change", () => { syncLabel(); generate(); }));
    symbols.addEventListener("change", generate);
    document.getElementById("gen-button").addEventListener("click", generate);
    syncLabel();
    generate();

    // Breach + strength check
    const pwInput = document.getElementById("pw-input");
    const pwOut = document.getElementById("pw-output");
    const showToggle = document.getElementById("pw-show");
    showToggle.addEventListener("change", () => { pwInput.type = showToggle.checked ? "text" : "password"; });
    document.getElementById("pw-check").addEventListener("click", checkPassword);
    pwInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); checkPassword(); } });

    async function sha1Hex(str) {
      const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    }
    async function checkPassword() {
      const value = pwInput.value;
      if (!value) { pwOut.replaceChildren(el("p", { class: "inline-error" }, "Type a password to check.")); return; }
      const strength = T.assessPassword(value);
      const meter = el("div", { class: "meter", "data-score": String(strength.score) }, el("span", {}));
      const block = el("div", { class: "pw-assess" },
        el("p", {}, el("strong", {}, "Strength: " + strength.label)), meter,
        strength.suggestions.length ? el("ul", { class: "flag-list" }, strength.suggestions.map((s) => el("li", {}, s))) : null,
        el("p", { class: "breach-status" }, "Checking known breaches…"));
      pwOut.replaceChildren(block);
      const status = block.querySelector(".breach-status");
      try {
        const hash = await sha1Hex(value);
        const res = await fetch("https://api.pwnedpasswords.com/range/" + hash.slice(0, 5), { headers: { "Add-Padding": "true" } });
        if (!res.ok) throw new Error("bad response");
        const count = T.parseBreachResponse(await res.text(), hash.slice(5));
        if (count > 0) {
          status.className = "breach-status breach-bad";
          status.textContent = "Found in known breaches " + count.toLocaleString() + " times. Don't use this password anywhere - change it if you do.";
        } else {
          status.className = "breach-status breach-ok";
          status.textContent = "Not found in the known-breach database. That's good, but it doesn't prove the password is strong.";
        }
      } catch (_) {
        status.textContent = "Couldn't reach the breach database from here. This check works on the live site; it's blocked in this preview.";
      }
    }
  })();

  function copyButton(text, label, selectFrom) {
    const copy = el("button", { type: "button", class: "copy", "aria-label": "Copy " + label }, "Copy");
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; }
      catch (_) {
        const target = selectFrom ? selectFrom() : copy.parentElement.querySelector("code");
        const sel = window.getSelection(); const range = document.createRange();
        range.selectNodeContents(target); sel.removeAllRanges(); sel.addRange(range); copy.textContent = "Press Ctrl+C";
      }
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    });
    return copy;
  }

  // ---- File fingerprint + VirusTotal lookup -------------------------------
  (function fileTool() {
    const fileInput = document.getElementById("file-input");
    const output = document.getElementById("file-output");
    if (!fileInput) return;
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      output.replaceChildren(el("p", { class: "plan-note" }, "Fingerprinting “" + file.name + "”…"));
      try {
        if (file.size > 150 * 1024 * 1024) { output.replaceChildren(el("p", { class: "inline-error" }, "That file is very large. Try one under 150 MB.")); return; }
        const buffer = await file.arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", buffer);
        const hash = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
        const kb = file.size < 1024 * 1024 ? (file.size / 1024).toFixed(0) + " KB" : (file.size / 1024 / 1024).toFixed(1) + " MB";
        output.replaceChildren(
          el("div", { class: "tool-card", style: "padding:1rem;background:var(--code-bg);border:0" },
            el("p", {}, el("strong", {}, file.name), " · " + kb),
            el("div", { class: "pw-result" }, el("code", { id: "file-hash" }, hash), copyButton(hash, "fingerprint", () => document.getElementById("file-hash")))),
          el("p", {}, el("a", { class: "lookup-btn", href: T.virusTotalFileUrl(hash), target: "_blank", rel: "noopener noreferrer" }, "Look up this file on VirusTotal")),
          el("p", { class: "plan-note" }, "This opens VirusTotal and searches for the file's fingerprint. If the file is known malware, around 70 security engines will flag it. If VirusTotal hasn't seen it, you'll get “not found” - which is not proof it's safe, just that it isn't in the database yet. Your file was not uploaded."));
      } catch (_) {
        output.replaceChildren(el("p", { class: "inline-error" }, "Couldn't read that file. Try another one."));
      }
    });
  })();

  // ---- Security basics checklist -----------------------------------------
  (function checklist() {
    const list = document.getElementById("basics-list");
    if (!list) return;
    const counter = document.getElementById("basics-count");
    const KEY = "envelope-check:basics";
    let done = {};
    try { done = JSON.parse(localStorage.getItem(KEY)) || {}; } catch (_) { done = {}; }
    function update() {
      const total = T.CHECKLIST.length;
      const ticked = T.CHECKLIST.filter((i) => done[i.id]).length;
      counter.textContent = ticked + " of " + total + " done";
    }
    list.replaceChildren(...T.CHECKLIST.map((item) => {
      const box = el("input", { type: "checkbox", id: "basics-" + item.id });
      box.checked = Boolean(done[item.id]);
      box.addEventListener("change", () => {
        done[item.id] = box.checked;
        try { localStorage.setItem(KEY, JSON.stringify(done)); } catch (_) {}
        update();
      });
      return el("li", { class: "basics-item" },
        box,
        el("div", {},
          el("label", { for: "basics-" + item.id }, el("strong", {}, item.title)),
          el("p", { class: "plain" }, el("em", {}, "Why: "), item.why),
          el("p", { class: "plain" }, el("em", {}, "How: "), item.how)));
    }));
    update();
  })();
})();
