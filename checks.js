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

  /** Reads an SPF record into the parts the deeper checks need. */
  function spfTerms(record) {
    const terms = String(record).trim().split(/\s+/).slice(1);
    const targets = [];
    let lookups = 0;
    terms.forEach((term) => {
      const t = term.replace(/^[+\-~?]/, "");
      const lower = t.toLowerCase();
      if (/^(a|mx|ptr)([:/]|$)/.test(lower) || lower.startsWith("exists:")) lookups++;
      const m = t.match(/^(?:include:|redirect=)(.+)$/i);
      if (m) {
        lookups++;
        targets.push(m[1].toLowerCase().replace(/\.$/, ""));
      }
    });
    return { lookups, targets };
  }

  /** Finds IP ranges so large that many unrelated servers could pass SPF. */
  function wideSpfRanges(terms) {
    return terms.filter((t) => {
      const v4 = t.match(/^[+?~]?ip4:[^/]+\/(\d+)$/);
      const v6 = t.match(/^[+?~]?ip6:[^/]+\/(\d+)$/);
      return (v4 && Number(v4[1]) < 16) || (v6 && Number(v6[1]) < 32);
    });
  }

  function checkSpf(lookup, domain, provider, noMail, tree) {
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
    const treeUsable = tree && !tree.incomplete;
    const lookups = treeUsable ? tree.lookups : spfTerms(records[0]).lookups;
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
    if (tree && tree.broken.length) {
      return {
        ...base, status: "fail", records,
        headline: "Your SPF record points to something broken",
        detail: `We couldn't find a valid SPF record at: ${tree.broken.join(", ")}. This can make SPF checks return an error for your real email.`,
        fix: manualFix(["Remove the old entry, or ask that service for its current SPF address."]),
      };
    }
    if (lookups > 10) {
      return {
        ...base, status: "fail", records,
        headline: "Your SPF record needs too many lookups",
        detail: `We counted ${lookups} DNS lookups${treeUsable ? ", including nested ones" : " in the main record"}. SPF allows 10, and going over makes the check fail.`,
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
    const wide = wideSpfRanges(terms);
    if (wide.length) notes.push(`It allows a very large IP range (${wide.join(", ")}), so servers you don't control could pass SPF. Replace it with your exact sending addresses.`);
    const included = (tree ? tree.includes : spfTerms(records[0]).targets).join(" ");
    const expected = { microsoft: ["spf.protection.outlook.com", "Microsoft 365"], google: ["_spf.google.com", "Google Workspace"] }[provider];
    if (expected && !included.includes(expected[0])) notes.push(`Your email appears to use ${expected[1]}, but this record doesn't include ${expected[0]}. If you send through ${expected[1]}, your real email may fail SPF.`);
    return {
      ...base, status: notes.length ? "warn" : "pass", records,
      headline: notes.length ? "SPF is set up, with something to review" : "SPF is set up",
      detail: [hasRedirect && !all
        ? "This record points to another domain's SPF policy. We didn't check that policy."
        : "The record gives a clear instruction about servers it doesn't list.",
        treeUsable
          ? `It uses ${lookups} of 10 allowed lookups, including nested ones.`
          : `It uses ${lookups} of 10 lookups in the main record. We couldn't finish counting nested lookups.`,
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
    if (!inherited && policy !== "none" && (tags.sp || "").toLowerCase() === "none") notes.push("Subdomains are set to sp=none, so someone could impersonate an address like mail.yourdomain without DMARC enforcement. Remove sp=none or make it stricter.");
    if (tags.rua && !/mailto:/i.test(tags.rua)) notes.push("The rua setting should start with mailto:, or you may not receive reports.");

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

  /** Works out a DKIM key's type and size. Returns null if it can't be read. */
  function dkimKeyInfo(record) {
    const tags = parseTags(record);
    if ((tags.k || "rsa").toLowerCase() === "ed25519") return { type: "ed25519" };
    if (!tags.p) return null;
    let bytes;
    try {
      const raw = atob(tags.p.replace(/\s+/g, ""));
      bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    } catch (_) {
      return null;
    }
    let i = 0;
    const readHeader = () => {
      const tag = bytes[i++];
      let length = bytes[i++];
      if (length & 0x80) {
        const count = length & 0x7f;
        length = 0;
        for (let n = 0; n < count; n++) length = length * 256 + bytes[i++];
      }
      return { tag, length };
    };
    const skipOuter = (expected) => readHeader().tag === expected;
    if (!skipOuter(0x30)) return null; // SubjectPublicKeyInfo
    const algorithm = readHeader();
    if (algorithm.tag !== 0x30) return null;
    i += algorithm.length;
    if (!skipOuter(0x03)) return null; // the key, held as a bit string
    i++; // unused-bits byte
    if (!skipOuter(0x30)) return null;
    const modulus = readHeader();
    if (modulus.tag !== 0x02 || i + modulus.length > bytes.length) return null;
    while (modulus.length > 0 && bytes[i] === 0) { i++; modulus.length--; }
    if (!modulus.length) return null;
    return { type: "rsa", bits: (modulus.length - 1) * 8 + (32 - Math.clz32(bytes[i])) };
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
      const sizes = live.map((l) => {
        const record = l.records.find((r) => /(^|;)\s*p=[^;\s]+/i.test(r));
        return { selector: l.selector, info: dkimKeyInfo(record) };
      }).filter((k) => k.info && k.info.type === "rsa");
      const weakest = sizes.reduce((low, k) => (!low || k.info.bits < low.info.bits ? k : low), null);
      if (weakest && weakest.info.bits < 2048) {
        const veryWeak = weakest.info.bits < 1024;
        return {
          ...base, status: veryWeak ? "fail" : "warn", records: shown,
          headline: veryWeak ? "Your DKIM key is too weak" : "Your DKIM key could be stronger",
          detail: `The key at ${weakest.selector} is about ${weakest.info.bits} bits. ${veryWeak ? "Keys this short can be cracked, and some mail systems reject them." : "A 2048-bit key gives more protection."}`,
          fix: { steps: ["Create a new 2048-bit key with your email provider.", "Publish it, confirm your email passes DKIM, then remove the old key."], links: providerLink(provider, "dkim") },
        };
      }
      return {
        ...base, status: "pass", records: shown,
        headline: "A DKIM key was found",
        detail: `Selector found: ${live.map((l) => l.selector).join(", ")}.${weakest ? ` Its key is about ${weakest.info.bits} bits.` : ""} This shows a key is published. To confirm it's being used, check the headers of an email you've sent.`,
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

  const RFC = (number) => [{ label: "Technical standard", href: "https://www.rfc-editor.org/rfc/rfc" + number }];

  function checkMtaSts(lookup, domain) {
    const base = { id: "mta-sts", title: "MTA-STS", plain: "Asks other mail systems to use encrypted connections when delivering to you." };
    if (!lookup.ok) return { ...couldNotCheck("mta-sts", "MTA-STS"), plain: base.plain };
    const records = lookup.records.filter((r) => /^v=stsv1\s*;/i.test(r.trim()));
    if (!records.length) {
      return {
        ...base, status: "optional", records,
        headline: "Not set up",
        detail: "Without it, an attacker in the network path may be able to force email delivery to you over an unencrypted connection.",
        fix: { intro: "This takes more work than SPF and DMARC, so fix those first.", steps: [`Publish a policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt.`, `Add a TXT record at _mta-sts.${domain}.`], links: RFC(8461) },
      };
    }
    return { ...base, status: "pass", records, headline: "The MTA-STS record is present", detail: "We read the DNS record only. Browsers can't reliably read the policy file, so check it with a dedicated MTA-STS tool." };
  }

  function checkTlsRpt(lookup, domain) {
    const base = { id: "tls-rpt", title: "TLS reporting", plain: "Sends you reports when encrypted email delivery fails." };
    if (!lookup.ok) return { ...couldNotCheck("tls-rpt", "TLS reporting"), plain: base.plain };
    const records = lookup.records.filter((r) => /^v=tlsrptv1\s*;/i.test(r.trim()));
    if (!records.length) {
      return {
        ...base, status: "optional", records,
        headline: "Not set up",
        detail: "You won't get these reports, so delivery encryption problems may go unnoticed.",
        fix: { steps: ["Choose a mailbox for reports, then replace YOUR-REPORTS-ADDRESS.", "Add the TXT record below at your DNS provider."], record: { host: "_smtp._tls." + domain, type: "TXT", value: "v=TLSRPTv1; rua=mailto:YOUR-REPORTS-ADDRESS" }, links: RFC(8460) },
      };
    }
    if (!/rua=\s*(mailto:|https:)/i.test(records[0])) {
      return { ...base, status: "warn", records, headline: "The record has no valid report address", detail: "Reports need a rua= value starting with mailto: or https:.", fix: { steps: ["Add a valid rua= address to the record."], links: RFC(8460) } };
    }
    return { ...base, status: "pass", records, headline: "TLS reporting is set up", detail: "Mail systems that support it can send you reports about delivery encryption problems." };
  }

  function checkDnssec(mx) {
    const base = { id: "dnssec", title: "DNSSEC", plain: "Helps protect your DNS answers from being forged." };
    if (!mx.ok) return { ...couldNotCheck("dnssec", "DNSSEC"), plain: base.plain };
    if (mx.ad) return { ...base, status: "pass", records: [], headline: "DNSSEC validated", detail: "The DNS service confirmed that the answer for this domain was validated." };
    return {
      ...base, status: "optional", records: [],
      headline: "Not validated",
      detail: "The DNS service didn't confirm a signed answer, so this domain doesn't appear to use DNSSEC. Not every organisation needs it.",
      fix: { steps: ["Ask your domain registrar or DNS provider whether they can turn it on safely. Setting it up incorrectly can take your domain offline."] },
    };
  }

  function checkCaa(lookups) {
    const base = { id: "caa", title: "CAA", plain: "Limits which companies can issue security certificates for your domain." };
    let failed = false;
    for (const l of lookups) {
      if (!l.ok) { failed = true; break; }
      if (l.records.length) {
        return { ...base, status: "pass", records: l.records, headline: "Certificate companies are limited", detail: `The rules are published at ${l.name}. Check that the list matches the companies you use.` };
      }
    }
    if (failed) return { ...couldNotCheck("caa", "CAA"), plain: base.plain };
    return {
      ...base, status: "optional", records: [],
      headline: "No limits set",
      detail: "Without CAA, this DNS setting doesn't limit which certificate company can issue for your domain.",
      fix: { steps: ["Find out which company issues your website certificates.", "Add a CAA record for it at your DNS provider, because the wrong record can block certificate renewals."], links: RFC(8659) },
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
      return { domain, provider, noMail: false, checks: [], extras: [], verdict: { level: "unknown", title: "This domain doesn't exist", text: `DNS has no record of ${domain}. Check the spelling and try again.` } };
    }
    const noMail = data.mx.ok && (data.mx.records.length === 0 || isNullMx(data.mx.records));
    const checks = [
      checkSpf(data.spf, domain, provider, noMail, data.spfTree),
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
      verdict = { level: "pass", title: "No problems found", text: count("unknown") ? "Everything we could confirm looks good. One item needs a manual check." : "These three main settings look good. This doesn't test every part of your email security." };
    }
    const extras = data.caa ? [
      ...(noMail ? [] : [checkMtaSts(data.mtaSts, domain), checkTlsRpt(data.tlsRpt, domain)]),
      checkDnssec(data.mx),
      checkCaa(data.caa),
    ] : [];
    return { domain, provider, noMail, checks, extras, verdict };
  }

  return { DKIM_SELECTORS, normalizeDomain, dmarcCandidates, detectProvider, isNullMx, spfTerms, dkimKeyInfo, checkSpf, checkDmarc, checkDkim, checkMtaSts, checkTlsRpt, checkDnssec, checkCaa, buildReport };
});
