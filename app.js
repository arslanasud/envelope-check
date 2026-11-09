/* Envelope Check: connects the form to the checks and draws the results. */
(function () {
  "use strict";
  const Checks = window.EnvelopeChecks;
  const { normalizeDomain, buildReport, summarise, compareSummaries, buildHandover } = Checks;
  const { gather, findLookalikes, probeHttps, gatherSpoofability } = window.EnvelopeDns;

  const form = document.getElementById("check-form");
  const input = document.getElementById("domain");
  const button = document.getElementById("check-button");
  const message = document.getElementById("form-message");
  const results = document.getElementById("results");

  // Example data for a reserved test domain, shown until someone runs a check.
  const none = { ok: true, records: [] };
  const exampleReport = buildReport("example.org", {
    mx: { ok: true, records: ["0 example-org.mail.protection.outlook.com."] },
    spf: { ok: true, records: ["v=spf1 include:spf.protection.outlook.com ~all"] },
    dmarc: [{ name: "example.org", ok: true, records: ["v=DMARC1; p=none"] }],
    dkim: Checks.DKIM_SELECTORS.map((selector) => ({ selector, ...none })),
    mtaSts: none,
    tlsRpt: none,
    caa: [{ name: "example.org", ...none }],
    spfTree: { lookups: 1, broken: [], includes: ["spf.protection.outlook.com"], incomplete: false },
  });

  // Browser storage can be unavailable, so nothing may depend on it working.
  function load(key, fallback) {
    try {
      const raw = localStorage.getItem("envelope-check:" + key);
      return raw ? JSON.parse(raw) : fallback;
    } catch (_) {
      return fallback;
    }
  }
  function save(key, value) {
    try {
      localStorage.setItem("envelope-check:" + key, JSON.stringify(value));
    } catch (_) {
      // The page still works without saved progress.
    }
  }

  // Builds elements using text only. DNS records can contain anything, so they
  // must never be inserted as HTML.
  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    Object.entries(props || {}).forEach(([key, value]) => {
      if (key === "class") node.className = value;
      else node.setAttribute(key, value);
    });
    children.flat().forEach((child) => {
      if (child !== null && child !== undefined && child !== false) node.append(child);
    });
    return node;
  }

  const STATUS = { pass: "Looks good", warn: "Improve", fail: "Fix this", unknown: "Check manually", optional: "Optional" };

  function copyButton(text, label, selectFrom) {
    const copy = el("button", { type: "button", class: "copy", "aria-label": "Copy " + label }, "Copy");
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        copy.textContent = "Copied";
      } catch (_) {
        const target = selectFrom ? selectFrom() : copy.parentElement.querySelector("code");
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(target);
        selection.removeAllRanges();
        selection.addRange(range);
        copy.textContent = "Press Ctrl+C";
      }
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    });
    return copy;
  }

  function envelopeIcon() {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 48 34");
    svg.setAttribute("class", "traveller");
    svg.setAttribute("aria-hidden", "true");
    const shape = (name, attrs) => {
      const node = document.createElementNS(svg.namespaceURI, name);
      Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, v));
      svg.append(node);
    };
    shape("rect", { x: "1", y: "1", width: "46", height: "32", rx: "2.5", class: "env-body" });
    shape("path", { d: "M2 3 L24 20 L46 3", class: "env-flap" });
    return svg;
  }

  function replayJourney(journey) {
    if (!journey) return;
    journey.classList.remove("play");
    void journey.offsetWidth; // force a reflow so the animation restarts
    journey.classList.add("play");
    const score = results.querySelector(".score");
    if (score) {
      const fg = score.querySelector(".ring-fg");
      if (fg) fg.style.strokeDashoffset = fg.getAttribute("data-full");
      animateScore(score);
    }
  }

  function renderJourney(report) {
    const sim = report.simulation;
    const replay = el("button", { type: "button", class: "replay" }, "▶ Replay animation");
    replay.addEventListener("click", () => replayJourney(replay.closest(".journey")));
    return el("section", { class: "journey", "data-outcome": sim.outcome.level, "aria-label": "Fake email simulation" },
      el("p", { class: "eyebrow" }, "Simulation. No email was sent"),
      el("h2", { tabindex: "-1", id: "verdict" }, sim.outcome.title),
      el("p", { class: "journey-text" }, sim.outcome.text),
      el("div", { class: "route" },
        el("div", { class: "line", "aria-hidden": "true" }, envelopeIcon()),
        el("ol", { class: "gates" },
          el("li", { class: "gate gate-start" },
            el("span", { class: "gate-mark", "aria-hidden": "true" }),
            el("strong", {}, "Fake email"),
            el("span", { class: "gate-text" }, "Claims to be from " + report.domain)),
          sim.gates.map((gate) => el("li", { class: "gate", "data-state": gate.state },
            el("span", { class: "gate-mark", "aria-hidden": "true" }),
            el("strong", {}, gate.name),
            el("span", { class: "gate-label" }, gate.label),
            el("span", { class: "gate-text" }, gate.text))),
          el("li", { class: "gate gate-end" },
            el("span", { class: "postmark" }, sim.outcome.stamp)))),
      replay,
      el("p", { class: "caveat" }, "Each mail system makes its own final decision. This doesn't cover lookalike domains, hacked mailboxes or fake display names."));
  }

  // An animated ring summarising how many clear-cut checks are passing.
  function renderScore(report) {
    const all = report.checks.concat(report.extras);
    const scored = all.filter((c) => c.status === "pass" || c.status === "warn" || c.status === "fail");
    const pass = scored.filter((c) => c.status === "pass").length;
    const total = scored.length;
    if (!total) return null;
    const R = 54;
    const circumference = 2 * Math.PI * R;
    const ns = "http://www.w3.org/2000/svg";
    const mk = (tag, attrs) => {
      const node = document.createElementNS(ns, tag);
      Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, v));
      return node;
    };
    const svg = mk("svg", { viewBox: "0 0 120 120", class: "score-ring", "aria-hidden": "true" });
    svg.append(mk("circle", { cx: 60, cy: 60, r: R, class: "ring-bg" }));
    const fg = mk("circle", { cx: 60, cy: 60, r: R, class: "ring-fg", "data-target": String(circumference * (1 - pass / total)), "data-full": String(circumference) });
    fg.style.strokeDasharray = String(circumference);
    fg.style.strokeDashoffset = String(circumference);
    svg.append(fg);
    const num = el("span", { class: "score-num", "data-to": String(pass) }, "0");
    return el("div", { class: "score", "data-status": report.verdict.level, role: "img", "aria-label": `${pass} of ${total} clear-cut checks passing` },
      el("div", { class: "score-ring-wrap" }, svg, el("div", { class: "score-center" }, num, el("span", { class: "score-of" }, "of " + total))),
      el("div", { class: "score-text" },
        el("h2", {}, "Checks passing"),
        el("p", {}, "How many of the clear-cut public checks on this page are passing right now. It's a quick summary, not a full security rating.")));
  }

  function animateScore(score) {
    if (!score) return;
    const reduce = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
    const fg = score.querySelector(".ring-fg");
    if (fg) {
      const target = fg.getAttribute("data-target");
      if (reduce) fg.style.strokeDashoffset = target;
      else requestAnimationFrame(() => { fg.style.strokeDashoffset = target; });
    }
    const num = score.querySelector(".score-num");
    if (num) {
      const to = Number(num.getAttribute("data-to"));
      if (reduce || to === 0) { num.textContent = String(to); return; }
      let current = 0;
      const step = () => { current += 1; num.textContent = String(current); if (current < to) setTimeout(step, 170); };
      setTimeout(step, 300);
    }
  }

  function renderHistory(report, previous) {
    if (!previous) return null;
    const { improved, worse } = compareSummaries(previous, summarise(report));
    const date = new Date(previous.when).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
    const parts = [];
    if (improved.length) parts.push("Improved: " + improved.join(", ") + ".");
    if (worse.length) parts.push("Now needs attention: " + worse.join(", ") + ".");
    if (!parts.length) parts.push("The main settings haven't changed.");
    return el("p", { class: "history" }, el("strong", {}, "Since your last check on " + date + ": "), parts.join(" "));
  }

  function renderPlan(report, isExample) {
    if (!report.plan.length) return null;
    const storeKey = "plan:" + report.domain;
    const done = isExample ? {} : load(storeKey, {});
    const counter = el("p", { class: "plan-count" });
    const update = () => {
      const total = report.plan.length;
      const ticked = report.plan.filter((job) => done[job.key]).length;
      counter.textContent = `${ticked} of ${total} done`;
    };
    update();
    const list = el("ol", { class: "plan-list" }, report.plan.map((job, i) => {
      const id = "plan-" + i;
      const box = el("input", { type: "checkbox", id });
      box.checked = Boolean(done[job.key]);
      box.addEventListener("change", () => {
        done[job.key] = box.checked;
        if (!isExample) save(storeKey, done);
        update();
      });
      return el("li", { "data-status": job.status },
        box,
        el("label", { for: id }, el("strong", {}, job.title + ": "), job.headline),
        el("a", { href: "#check-" + job.id }, "How to fix"));
    }));
    const handover = buildHandover(report);
    const pre = el("pre", { class: "handover-text", tabindex: "0" }, handover);
    return el("section", { class: "plan", "aria-label": "Your fix plan" },
      el("div", { class: "plan-head" }, el("h2", {}, "Your fix plan"), counter),
      list,
      el("details", { class: "handover" },
        el("summary", {}, "Get a message for your IT provider"),
        pre,
        copyButton(handover, "message", () => pre)),
      isExample ? null : el("p", { class: "plan-note" }, "Your ticks stay in this browser. After you make changes, check the domain again to see what has improved. DNS changes can take a while to appear."));
  }

  function renderLookalikes(report) {
    const output = el("div", { class: "lookalike-output", "aria-live": "polite" });
    const start = el("button", { type: "button", class: "secondary", id: "lookalike-button" }, "Look for lookalike domains");
    start.addEventListener("click", async () => {
      start.disabled = true;
      output.replaceChildren(el("p", {}, "Looking up similar names…"));
      const outcome = await findLookalikes(report.domain, undefined, (done, total) => {
        start.textContent = `Checked ${done} of ${total}`;
      });
      start.hidden = true;
      if (outcome.failed === outcome.checked) {
        start.hidden = false;
        start.disabled = false;
        start.textContent = "Try again";
        output.replaceChildren(el("p", {}, "We couldn't reach the DNS services, so we can't say whether any of these names exist."));
        return;
      }
      const mail = outcome.found.filter((f) => f.canMail).length;
      output.replaceChildren(...[
        el("p", { class: "headline" }, outcome.found.length
          ? `${outcome.found.length} similar ${outcome.found.length === 1 ? "name exists" : "names exist"}, and ${mail} can receive email`
          : `None of the ${outcome.checked} names we tried appear to exist`),
        outcome.found.length ? el("ul", { class: "lookalike-list" }, outcome.found.map((f) =>
          el("li", {}, el("code", {}, f.name), el("span", { class: "tag" }, f.canMail ? "Email set up" : "Registered")))) : null,
        outcome.failed ? el("p", {}, `${outcome.failed} lookups failed, so this list may be incomplete.`) : null,
        outcome.found.length ? el("p", {}, "This doesn't mean they're malicious. They may belong to you or to an unrelated organisation, so check before you act or accuse anyone. In the UK, you can forward suspicious emails to report@phishing.gov.uk.") : null,
        el("p", { class: "plan-note" }, "We tried common misspellings and other endings, so this isn't a complete list."),
      ].filter(Boolean));
    });
    return el("section", { class: "lookalikes", "aria-label": "Lookalike domains" },
      el("h2", {}, "Who could be using a name like yours?"),
      el("p", {}, "Attackers often register a name that looks almost like yours, which your own settings can't stop. We'll look up up to 40 similar names using public DNS and won't contact those domains."),
      start,
      output);
  }

  function renderFix(fix) {
    return el("div", { class: "fix" },
      el("h4", {}, "How to fix it"),
      fix.intro ? el("p", {}, fix.intro) : null,
      el("ol", {}, fix.steps.map((step) => el("li", {}, step))),
      fix.record ? el("div", { class: "recipe" },
        el("dl", {},
          el("dt", {}, "Type"), el("dd", {}, fix.record.type),
          el("dt", {}, "Name"), el("dd", {}, fix.record.host)),
        el("div", { class: "recipe-value" }, el("code", {}, fix.record.value), copyButton(fix.record.value, "record"))) : null,
      fix.links && fix.links.length ? el("p", { class: "links" },
        fix.links.map((link) => el("a", { href: link.href, target: "_blank", rel: "noopener noreferrer" }, link.label))) : null);
  }

  function renderCheck(check) {
    return el("article", { class: "check", "data-status": check.status, id: "check-" + check.id },
      el("header", {},
        el("div", {},
          el("h3", {}, check.title),
          el("p", { class: "plain" }, check.plain)),
        el("span", { class: "pill" }, el("span", { class: "dot", "aria-hidden": "true" }), STATUS[check.status])),
      el("p", { class: "headline" }, check.headline),
      el("p", {}, check.detail),
      check.records && check.records.length ? el("details", {},
        el("summary", {}, "See what we found"),
        el("div", { class: "found" }, check.records.map((record) => el("code", {}, record)))) : null,
      check.fix ? renderFix(check.fix) : null,
      !check.fix && check.links && check.links.length ? el("p", { class: "links" },
        el("strong", {}, "Full reports: "),
        check.links.map((link) => el("a", { href: link.href, target: "_blank", rel: "noopener noreferrer" }, link.label))) : null);
  }

  function renderWebsite(report) {
    const output = el("div", { class: "website-output", "aria-live": "polite" });
    const start = el("button", { type: "button", class: "secondary", id: "website-button" }, "Check my website's HTTPS");
    start.addEventListener("click", async () => {
      start.disabled = true;
      start.textContent = "Checking…";
      const check = Checks.checkWebsite(await probeHttps(report.domain));
      start.hidden = true;
      output.replaceChildren(renderCheck(check));
    });
    return el("section", { class: "website", "aria-label": "Website check" },
      el("h2", {}, "Is your website secure?"),
      el("p", {}, "A basic, optional check of whether your website answers over an encrypted HTTPS connection. Your browser's security rules stop it reading the finer details, so it also links you to full reports."),
      start,
      output);
  }

  function renderSupplier() {
    const field = el("input", { type: "text", id: "supplier-domain", inputmode: "url", autocomplete: "off", autocapitalize: "none", spellcheck: "false", placeholder: "theircompany.com", "aria-describedby": "supplier-hint" });
    const go = el("button", { type: "button", class: "secondary" }, "Check this sender");
    const output = el("div", { class: "supplier-output", "aria-live": "polite" });
    const run = async () => {
      const domain = normalizeDomain(field.value);
      if (!domain) {
        output.replaceChildren(el("p", { class: "inline-error" }, "Enter a domain, such as theircompany.com."));
        field.focus();
        return;
      }
      go.disabled = true;
      go.textContent = "Checking…";
      try {
        const data = await gatherSpoofability(domain);
        if (!data.spf.ok && data.dmarc.every((l) => !l.ok)) {
          output.replaceChildren(el("p", { class: "inline-error" }, "We couldn't reach the DNS services. Try again in a minute."));
          return;
        }
        const verdict = Checks.checkSupplier(Checks.simulateForgery(domain, data));
        output.replaceChildren(el("article", { class: "check supplier-result", "data-status": verdict.level },
          el("header", {},
            el("div", {}, el("p", { class: "summary-domain" }, domain), el("p", { class: "headline" }, verdict.headline)),
            el("span", { class: "pill" }, el("span", { class: "dot", "aria-hidden": "true" }), STATUS[verdict.level])),
          el("p", {}, verdict.detail),
          el("div", { class: "fix" },
            el("h4", {}, "Protect yourself"),
            el("ul", {}, verdict.advice.map((a) => el("li", {}, a))))));
      } finally {
        go.disabled = false;
        go.textContent = "Check this sender";
      }
    };
    go.addEventListener("click", run);
    field.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); run(); } });
    return el("section", { class: "supplier", "aria-label": "Check a sender" },
      el("h2", {}, "Got an email asking about money?"),
      el("p", {}, "If an organisation emails you about an invoice, a payment or a change of bank details, check whether their domain can be easily faked before you act. We only read their public records and never contact them."),
      el("div", { class: "field" }, field, go),
      el("p", { id: "supplier-hint", class: "hint" }, "Enter the part after the @ in their email address."),
      output);
  }

  function renderLoading(domain) {
    results.replaceChildren(el("div", { class: "loading", role: "status" },
      el("div", { class: "loading-env", "aria-hidden": "true" }, envelopeIcon()),
      el("p", { class: "loading-text" }, "Checking " + domain + "…"),
      el("p", { class: "plan-note" }, "Reading public DNS records. This usually takes a few seconds.")));
  }

  function render(report, isExample, previous) {
    const providerName = { microsoft: "Microsoft 365", google: "Google Workspace" }[report.provider];
    let context = null;
    if (providerName) context = "This domain appears to use " + providerName + ", so the fixes are tailored to it.";
    if (report.noMail) context = "This domain doesn't appear to receive email, so the fixes are for a domain that sends no email.";

    if (!report.simulation) {
      results.replaceChildren(el("div", { class: "summary", "data-status": report.verdict.level },
        el("p", { class: "summary-domain" }, report.domain),
        el("h2", { tabindex: "-1", id: "verdict" }, report.verdict.title),
        el("p", {}, report.verdict.text)));
      return;
    }
    results.replaceChildren(...[
      el("div", { class: "summary", "data-status": report.verdict.level },
        isExample ? el("p", { class: "example-tag" }, "Example result for a test domain") : null,
        el("p", { class: "summary-domain" }, report.domain),
        el("p", { class: "summary-verdict" }, el("strong", {}, report.verdict.title + ". "), report.verdict.text),
        context ? el("p", { class: "context" }, context) : null,
        renderHistory(report, previous)),
      renderScore(report),
      renderJourney(report),
      renderPlan(report, isExample),
      isExample ? null : renderLookalikes(report),
      isExample ? null : renderWebsite(report),
      isExample ? null : renderSupplier(),
      el("h2", { class: "section-title" }, "The details"),
      ...report.checks.map(renderCheck),
      report.extras.length ? el("div", { class: "extras-heading" },
        el("h2", {}, "Extra protections"),
        el("p", {}, "These don't affect the overall result above. Fix the main settings first.")) : null,
      ...report.extras.map(renderCheck),
    ].filter(Boolean));

    // A gentle staggered entrance, only for real results (not the resting example).
    if (!isExample) {
      Array.from(results.children).forEach((child, i) => {
        child.classList.add("reveal");
        child.style.animationDelay = Math.min(i * 70, 560) + "ms";
      });
    }
    // Play the journey animation and fill the score ring (for the example too, so
    // the preview shows the motion when the page opens).
    requestAnimationFrame(() => {
      const journey = results.querySelector(".journey");
      if (journey) journey.classList.add("play");
      animateScore(results.querySelector(".score"));
    });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.textContent = "";
    const domain = normalizeDomain(input.value);
    if (!domain) {
      message.textContent = "Enter a domain name, such as yourcharity.org.uk.";
      input.focus();
      return;
    }
    button.disabled = true;
    button.textContent = "Checking…";
    results.setAttribute("aria-busy", "true");
    renderLoading(domain);
    try {
      const data = await gather(domain);
      const allFailed = !data.mx.ok && !data.spf.ok && data.dmarc.every((l) => !l.ok) && data.dkim.every((l) => !l.ok);
      if (allFailed) {
        results.replaceChildren();
        message.textContent = "We couldn't reach the DNS services, so no results are shown. Check your connection or try again. Browser content blockers and restricted previews can also stop these lookups.";
        return;
      }
      const report = buildReport(domain, data);
      const historyKey = "last:" + domain;
      render(report, false, load(historyKey, null));
      if (report.simulation && !report.checks.some((c) => c.headline === "We couldn't complete this check")) {
        save(historyKey, summarise(report, new Date().toISOString()));
      }
      document.getElementById("verdict").focus();
    } finally {
      button.disabled = false;
      button.textContent = "Follow the fake email";
      results.removeAttribute("aria-busy");
    }
  });

  render(exampleReport, true);
})();
