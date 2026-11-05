/* Envelope Check: connects the form to the checks and draws the results. */
(function () {
  "use strict";
  const { normalizeDomain, buildReport } = window.EnvelopeChecks;
  const { gather } = window.EnvelopeDns;

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
    dkim: window.EnvelopeChecks.DKIM_SELECTORS.map((selector) => ({ selector, ...none })),
    mtaSts: none,
    tlsRpt: none,
    caa: [{ name: "example.org", ...none }],
    spfTree: { lookups: 1, broken: [], includes: ["spf.protection.outlook.com"], incomplete: false },
  });

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

  const STATUS = {
    pass: "Looks good",
    warn: "Improve",
    fail: "Fix this",
    unknown: "Check manually",
    optional: "Optional",
  };

  function copyButton(text, label) {
    const button = el("button", { type: "button", class: "copy", "aria-label": "Copy " + label }, "Copy");
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
      } catch (_) {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(button.parentElement.querySelector("code"));
        selection.removeAllRanges();
        selection.addRange(range);
        button.textContent = "Press Ctrl+C";
      }
      setTimeout(() => { button.textContent = "Copy"; }, 2000);
    });
    return button;
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
    return el("article", { class: "check", "data-status": check.status },
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
      check.fix ? renderFix(check.fix) : null);
  }

  function render(report, isExample) {
    const providerName = { microsoft: "Microsoft 365", google: "Google Workspace" }[report.provider];
    let context = null;
    if (providerName) context = "Your email appears to use " + providerName + ", so the fixes are tailored to it.";
    if (report.noMail) context = "This domain doesn't appear to receive email, so the fixes are for a domain that sends no email.";
    results.replaceChildren(...[
      el("div", { class: "summary", "data-status": report.verdict.level },
        isExample ? el("p", { class: "example-tag" }, "Example result for a test domain") : null,
        el("p", { class: "summary-domain" }, report.domain),
        el("h2", { tabindex: "-1", id: "verdict" }, report.verdict.title),
        el("p", {}, report.verdict.text),
        context ? el("p", { class: "context" }, context) : null),
      ...report.checks.map(renderCheck),
      report.extras.length ? el("div", { class: "extras-heading" },
        el("h2", {}, "Extra protections"),
        el("p", {}, "These don't affect the overall result above. Fix the main settings first.")) : null,
      ...report.extras.map(renderCheck)].filter(Boolean));
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
    try {
      const data = await gather(domain);
      const allFailed = !data.mx.ok && !data.spf.ok && data.dmarc.every((l) => !l.ok) && data.dkim.every((l) => !l.ok);
      if (allFailed) {
        results.replaceChildren();
        message.textContent = "We couldn't reach the DNS services, so no results are shown. Check your connection or try again. Browser content blockers and restricted previews can also stop these lookups.";
        return;
      }
      render(buildReport(domain, data), false);
      document.getElementById("verdict").focus();
    } finally {
      button.disabled = false;
      button.textContent = "Check my email security";
      results.removeAttribute("aria-busy");
    }
  });

  render(exampleReport, true);
})();
