/*
 * Envelope Check: the rules that turn DNS records into plain-English results.
 *
 * This file makes no network requests and does not touch the page, which keeps
 * it easy to test. See docs/HOW-IT-WORKS.md for a walkthrough.
 *
 * Security note: DNS records are written by whoever controls a domain, so treat
 * them as untrusted. app.js only ever shows them as text, never as HTML.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.EnvelopeChecks = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // These are common names only. DKIM selectors can't be listed from DNS, so
  // not finding one here doesn't prove that DKIM is off.
  const DKIM_SELECTORS = [
    "selector1", "selector2", "google", "default", "k1", "k2",
    "s1", "s2", "dkim", "mail", "smtp",
  ];

  const LINKS = {
    microsoft: {
      spf: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure",
      dkim: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure",
      dmarc: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about",
    },
    google: {
      spf: "https://support.google.com/a/answer/33786?hl=en",
      dkim: "https://support.google.com/a/answer/174124?hl=en",
      dmarc: "https://support.google.com/a/answer/2466580?hl=en",
    },
  };

  /** Turns "https://www.Example.org/page" or "me@example.org" into a hostname. Returns null if invalid. */
  function normalizeDomain(input) {
    let value = String(input == null ? "" : input).trim();
    if (!value) return null;
    if (value.includes("@") && !value.includes("/")) value = value.split("@").pop();
    let host;
    try {
      host = new URL(value.includes("://") ? value : "https://" + value).hostname;
    } catch (_) {
      return null;
    }
    host = host.toLowerCase().replace(/\.$/, "");
    if (host.startsWith("www.")) host = host.slice(4);
    const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
    const parts = host.split(".");
    if (parts.length < 2 || host.length > 253 || !parts.every((p) => label.test(p))) return null;
    if (/^[0-9]+$/.test(parts[parts.length - 1])) return null; // an IP address
    return host;
  }

  /** Where to look for a DMARC record: the domain first, then each parent. */
  function dmarcCandidates(domain) {
    const parts = domain.split(".");
    const names = [];
    for (let i = 0; i < parts.length - 1; i++) names.push(parts.slice(i).join("."));
    return names;
  }

  function detectProvider(mxRecords) {
    const hosts = (mxRecords || []).join(" ").toLowerCase();
    if (/\.mail\.protection\.outlook\.com|\.protection\.outlook\.com|\.mx\.microsoft/.test(hosts)) return "microsoft";
    if (/(^|[\s.])(google|googlemail)\.com/.test(hosts)) return "google";
    return "other";
  }

  function isNullMx(mxRecords) {
    return (mxRecords || []).length === 1 && /^0\s+\.?$/.test(mxRecords[0].trim());
  }

  function spfRecipe(provider, noMail) {
    if (noMail) return "v=spf1 -all";
    if (provider === "microsoft") return "v=spf1 include:spf.protection.outlook.com -all";
    if (provider === "google") return "v=spf1 include:_spf.google.com ~all";
    return "v=spf1 include:YOUR-EMAIL-PROVIDER ~all";
  }

  const providerLink = (provider, check) =>
    LINKS[provider] ? [{ label: (provider === "microsoft" ? "Microsoft" : "Google") + " setup guide", href: LINKS[provider][check] }] : [];

  function couldNotCheck(id, title) {
    return {
      id, title, status: "unknown",
      headline: "We couldn't complete this check",
      detail: "The DNS lookup failed, so this result says nothing about your domain. Try again in a minute.",
      records: [],
    };
  }

  function checkSpf(lookup, domain, provider, noMail) {
    const base = { id: "spf", title: "SPF", plain: "Lists the services allowed to send email for your domain." };
    if (!lookup.ok) return { ...couldNotCheck("spf", "SPF"), plain: base.plain };
    const records = lookup.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
    const fix = (steps) => ({
      steps,
      record: { host: domain, type: "TXT", value: spfRecipe(provider, noMail) },
      links: providerLink(provider, "spf"),
    });
    const edit = "List every service that sends email for you, such as your newsletter or invoicing tool, before you save this record.";

    if (records.length === 0) {
      return {
        ...base, status: noMail ? "warn" : "fail", records,
        headline: "No SPF record found",
        detail: noMail
          ? "This domain doesn't appear to receive email. Publishing this record says it sends none either, which makes it harder to impersonate."
          : "Receiving mail systems can't tell which services are allowed to send email for your domain.",
        fix: fix(noMail
          ? ["Check that nothing sends email from this domain.", "Add the TXT record below at your DNS provider."]
          : [edit, "Add the TXT record below at your DNS provider."]),
      };
    }
    if (records.length > 1) {
      return {
        ...base, status: "fail", records,
        headline: "More than one SPF record found",
        detail: "A domain can only have one SPF record. With two or more, SPF checks return an error.",
        fix: { steps: ["Combine the allowed senders into one record.", "Delete the extra records."], links: providerLink(provider, "spf") },
      };
    }

    const terms = records[0].trim().toLowerCase().split(/\s+/).slice(1);
    const lookups = terms.filter((t) => /^[+\-~?]?(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:|redirect=)/.test(t)).length;
    const all = terms.find((t) => /^[+\-~?]?all$/.test(t));
    const hasRedirect = terms.some((t) => t.startsWith("redirect="));
    const manualFix = (steps) => ({ steps, links: providerLink(provider, "spf") });

    if (all === "all" || all === "+all") {
      return {
        ...base, status: "fail", records,
        headline: "Your SPF record allows anyone to send",
        detail: `The "${all}" ending tells mail systems to accept email for your domain from any server.`,
        fix: manualFix(["Change the end of the record to ~all, or to -all once you've listed all your senders."]),
      };
    }
    if (lookups > 10) {
      return {
        ...base, status: "fail", records,
        headline: "Your SPF record needs too many lookups",
        detail: `We counted ${lookups} DNS lookups in the main record. SPF allows 10, and going over makes the check fail.`,
        fix: manualFix(["Remove services you no longer use.", "Ask your email provider how to reduce the number of lookups."]),
      };
    }
    if (!all && !hasRedirect) {
      return {
        ...base, status: "warn", records,
        headline: "Your SPF record doesn't say how to treat other senders",
        detail: "Without an ending such as ~all or -all, the record gives no instruction about servers it doesn't list.",
        fix: manualFix(["Add ~all to the end of the record."]),
      };
    }
    if (all === "?all") {
      return {
        ...base, status: "warn", records,
        headline: "Your SPF record is neutral about other senders",
        detail: "The ?all ending gives mail systems no instruction about servers the record doesn't list.",
        fix: manualFix(["Change ?all to ~all, or to -all once you've listed all your senders."]),
      };
    }
    const notes = [];
    if (terms.some((t) => /^[+\-~?]?ptr/.test(t))) notes.push('It uses the "ptr" method, which the SPF standard advises against.');
    return {
      ...base, status: notes.length ? "warn" : "pass", records,
      headline: notes.length ? "SPF is set up, with one thing to tidy" : "SPF is set up",
      detail: [hasRedirect && !all
        ? "This record points to another domain's SPF policy. We didn't check that policy."
        : "The record gives a clear instruction about servers it doesn't list.",
        `It uses ${lookups} of 10 lookups in the main record. Nested lookups aren't counted in this version.`,
        ...notes].join(" "),
    };
  }

  function parseTags(record) {
    const tags = {};
    record.split(";").forEach((part) => {
      const i = part.indexOf("=");
      if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
    });
    return tags;
  }

  /** `lookups` is a list of { name, ok, records }, nearest domain first. */
  function checkDmarc(lookups, domain, provider, noMail) {
    const base = { id: "dmarc", title: "DMARC", plain: "Tells mail systems what to do with email that fails these checks." };
    const recipe = {
      host: "_dmarc." + domain, type: "TXT",
      value: noMail ? "v=DMARC1; p=reject;" : "v=DMARC1; p=none; rua=mailto:YOUR-REPORTS-ADDRESS",
    };
    const stages = ["Start with p=none, then read the reports to confirm your real email passes.", "Move to p=quarantine, then to p=reject when you're confident."];

    let found = null;
    let failed = false;
    for (const l of lookups) {
      if (!l.ok) { failed = true; break; }
      const hits = l.records.filter((r) => /^v=dmarc1\s*(;|$)/i.test(r.trim()));
      if (hits.length) { found = { name: l.name, hits }; break; }
    }
    if (!found) {
      if (failed) return { ...couldNotCheck("dmarc", "DMARC"), plain: base.plain };
      return {
        ...base, status: "fail", records: [],
        headline: "No DMARC record found",
        detail: noMail
          ? "This record tells mail systems to reject email that claims to come from this domain."
          : "Your domain gives mail systems no instruction about email that fails these checks, and you get no reports about misuse.",
        fix: {
          steps: noMail ? ["Add the TXT record below at your DNS provider."]
            : ["Choose a mailbox that can receive reports, then replace YOUR-REPORTS-ADDRESS.", "Add the TXT record below at your DNS provider.", ...stages],
          record: recipe, links: providerLink(provider, "dmarc"),
        },
      };
    }

    const records = found.hits;
    if (records.length > 1) {
      return {
        ...base, status: "fail", records,
        headline: "More than one DMARC record found",
        detail: "With more than one record, mail systems ignore DMARC for your domain.",
        fix: { steps: ["Keep one record and delete the others."], links: providerLink(provider, "dmarc") },
      };
    }
    const inherited = found.name !== domain;
    const tags = parseTags(records[0]);
    const policy = ((inherited && tags.sp) || tags.p || "").toLowerCase();
    const source = inherited ? ` This policy comes from the parent domain, ${found.name}.` : "";

    if (!["none", "quarantine", "reject"].includes(policy)) {
      return {
        ...base, status: "fail", records,
        headline: "Your DMARC record has no valid policy",
        detail: "The p= setting must be none, quarantine or reject." + source,
        fix: { steps: ["Correct the record."], record: recipe, links: providerLink(provider, "dmarc") },
      };
    }
    const notes = [];
    if (!tags.rua) notes.push("You aren't asking for summary reports, so you may not see who is sending as your domain. Add rua=mailto: with a mailbox you monitor.");
    const pct = tags.pct === undefined ? 100 : Number(tags.pct);
    if (pct < 100) notes.push(`The policy applies to only ${pct}% of failing email.`);

    if (policy === "none") {
      return {
        ...base, status: "warn", records,
        headline: "DMARC is only monitoring",
        detail: "With p=none, email that fails the checks gets no DMARC enforcement, so your domain has less protection against impersonation." + source + (notes.length ? " " + notes.join(" ") : ""),
        fix: { steps: ["Read your reports and confirm your real email passes.", "Move to p=quarantine, then to p=reject when you're confident."], links: providerLink(provider, "dmarc") },
      };
    }
    return {
      ...base, status: notes.length ? "warn" : "pass", records,
      headline: `DMARC is enforcing p=${policy}`,
      detail: `Mail systems are asked to ${policy === "reject" ? "reject" : "treat as suspicious"} email that fails the checks.` + source + (notes.length ? " " + notes.join(" ") : ""),
    };
  }

  /** `lookups` is a list of { selector, ok, records }. */
  function checkDkim(lookups, domain, provider, noMail) {
    const base = { id: "dkim", title: "DKIM", plain: "Adds a digital signature that shows an email is genuine and unchanged." };
    const failedCount = lookups.filter((l) => !l.ok).length;
    const isKey = (r) => /(^|;)\s*(v=dkim1|k=|p=)/i.test(r);
    const hits = lookups.filter((l) => l.ok && l.records.some(isKey));
    const live = hits.filter((l) => l.records.some((r) => /(^|;)\s*p=[^;\s]+/i.test(r)));
    const shown = hits.flatMap((l) => l.records.filter(isKey).map((r) => l.selector + ": " + r));

    if (live.length) {
      return {
        ...base, status: "pass", records: shown,
        headline: "A DKIM key was found",
        detail: `Selector found: ${live.map((l) => l.selector).join(", ")}. This shows a key is published. To confirm it's being used, check the headers of an email you've sent.`,
      };
    }
    if (hits.length) {
      return {
        ...base, status: "warn", records: shown,
        headline: "A DKIM key has been revoked",
        detail: `The key at ${hits.map((l) => l.selector).join(", ")} is empty, which means it has been withdrawn. This is only a problem if nothing else signs your email.`,
        fix: { steps: ["Check whether your email provider signs with a different selector.", "If not, turn DKIM on again."], links: providerLink(provider, "dkim") },
      };
    }
    if (failedCount === lookups.length) return { ...couldNotCheck("dkim", "DKIM"), plain: base.plain };
    if (noMail) {
      return { ...base, status: "unknown", records: [], headline: "Probably not needed", detail: "We found no DKIM key at the common names, which is normal if this domain sends no email." };
    }
    const steps = {
      microsoft: ["In the Microsoft Defender portal, open your email authentication settings.", "Select your domain, add the two CNAME records it shows you, then turn on DKIM signing."],
      google: ["In the Google Admin console, go to Apps > Google Workspace > Gmail > Authenticate email.", "Generate a key, add the TXT record at your DNS provider, then select Start authentication."],
      other: ["Ask your email provider how to turn on DKIM signing for your domain.", "Add the DNS record it gives you."],
    }[provider];
    return {
      ...base, status: "unknown", records: [],
      headline: "No DKIM key found at the common names",
      detail: `We tried ${lookups.length} common names. DNS has no way to list them all, so your domain may still use DKIM under a different name.`,
      fix: {
        intro: "To confirm, look for dkim=pass in the headers of an email you've sent. If it's missing:",
        steps, links: providerLink(provider, "dkim"),
      },
    };
  }

  /**
   * Builds the full report.
   * data = { mx, spf: lookup, dmarc: [lookups], dkim: [lookups] }
   * where a lookup is { ok, records, nx } and failed lookups have ok: false.
   */
  function buildReport(domain, data) {
    const provider = data.mx.ok ? detectProvider(data.mx.records) : "other";
    if (data.mx.ok && data.mx.nx && data.spf.ok && data.spf.nx) {
      return { domain, provider, noMail: false, checks: [], verdict: { level: "unknown", title: "This domain doesn't exist", text: `DNS has no record of ${domain}. Check the spelling and try again.` } };
    }
    const noMail = data.mx.ok && (data.mx.records.length === 0 || isNullMx(data.mx.records));
    const checks = [
      checkSpf(data.spf, domain, provider, noMail),
      checkDkim(data.dkim, domain, provider, noMail),
      checkDmarc(data.dmarc, domain, provider, noMail),
    ];
    const count = (s) => checks.filter((c) => c.status === s).length;
    const lookupFailed = !data.mx.ok || checks.some((c) => c.headline === "We couldn't complete this check");
    let verdict;
    if (count("fail")) {
      verdict = { level: "fail", title: `${count("fail")} ${count("fail") === 1 ? "problem" : "problems"} to fix first`, text: "Your domain is easier to impersonate until these are fixed." };
    } else if (count("warn")) {
      verdict = { level: "warn", title: `${count("warn")} ${count("warn") === 1 ? "improvement" : "improvements"} to make`, text: "The basics are in place, and there's more you can do." };
    } else if (lookupFailed) {
      verdict = { level: "unknown", title: "This check is incomplete", text: "Some lookups failed, so try again in a minute." };
    } else {
      verdict = { level: "pass", title: "No problems found", text: count("unknown") ? "Everything we could confirm looks good. One item needs a manual check." : "These three public settings look good. This doesn't test every part of your email security." };
    }
    return { domain, provider, noMail, checks, verdict };
  }

  return { DKIM_SELECTORS, normalizeDomain, dmarcCandidates, detectProvider, isNullMx, checkSpf, checkDmarc, checkDkim, buildReport };
});
