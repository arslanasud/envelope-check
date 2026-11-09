/*
 * Envelope Check - extra tools, pure logic only (no network, no page access), so
 * every rule here can be tested on its own. The UI layer (tools-ui.js) supplies
 * randomness and network results.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.EnvelopeTools = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---- Link checker -------------------------------------------------------
  // Reads a link's TEXT for phishing warning signs. It never visits the link.
  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"];
  const RISKY_TLDS = ["zip", "mov", "xyz", "top", "click", "country", "gq", "cf", "tk", "work", "link", "rest", "fit", "loan"];
  const BRANDS = ["paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon", "google", "netflix", "hmrc", "nhs", "hsbc", "barclays", "natwest", "lloyds", "santander", "monzo", "dhl", "royalmail", "fedex", "ups", "dpd", "evri"];

  function analyzeLink(input) {
    const raw = String(input == null ? "" : input).trim();
    if (!raw) return { ok: false, message: "Paste a link to check." };
    let url;
    try {
      url = new URL(raw.includes("://") ? raw : "http://" + raw);
    } catch (_) {
      return { ok: false, message: "That doesn't look like a link. Paste the whole web address." };
    }
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const labels = host.split(".");
    const sld = labels.length >= 2 ? labels[labels.length - 2] : host;
    const tld = labels[labels.length - 1];
    const flags = [];
    const add = (level, title, detail) => flags.push({ level, title, detail });

    if (url.username) add("fail", "The real destination is hidden", "Anything before the @ sign is ignored by browsers. This link actually leads to " + host + ".");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (host.includes(":") && /^[0-9a-f:]+$/.test(host))) {
      add("fail", "Uses a numeric address", "Real organisations use a name, not a raw numeric (IP) address like this.");
    }
    if (labels.some((l) => l.startsWith("xn--"))) add("warn", "Uses disguised characters", "Part of this address uses special characters that can imitate ordinary letters.");
    if (url.protocol === "http:") add("warn", "Not encrypted (http)", "This link uses http, not https, so the connection isn't protected.");
    if (SHORTENERS.includes(host)) add("warn", "Hides the real destination", "This is a shortened link, so you can't see where it really goes until you open it.");
    if (RISKY_TLDS.includes(tld)) add("warn", "Unusual address ending", "." + tld + " endings are often used in scams. It can be legitimate, so check carefully.");
    if (labels.length >= 5) add("warn", "Many parts in the address", "Long chains of sub-addresses are sometimes used to confuse. Read the main domain carefully.");

    const deleet = sld.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/4/g, "a");
    BRANDS.forEach((brand) => {
      if (deleet === brand && sld !== brand) add("fail", 'Looks like a fake "' + brand + '" address', 'The main part of this address imitates "' + brand + '" using look-alike characters.');
      else if (host.includes(brand) && sld !== brand) add("warn", 'Mentions "' + brand + '" but may not be official', 'The name "' + brand + '" appears in the address but not as the main domain. Scammers add trusted names to look real.');
    });

    const level = flags.some((f) => f.level === "fail") ? "fail" : flags.some((f) => f.level === "warn") ? "warn" : "pass";
    const mainDomain = labels.length >= 2 ? labels.slice(-2).join(".") : host;
    const verdict = {
      fail: { headline: "This link has serious warning signs", text: "Treat it as unsafe. Don't open it, and don't enter any details." },
      warn: { headline: "This link has some warning signs", text: "Be careful. Only open it if you're sure you trust the sender." },
      pass: { headline: "No obvious red flags", text: "This isn't a guarantee of safety - it only means the address text looks ordinary. Only open links you trust." },
    }[level];
    return { ok: true, href: url.href, host, mainDomain, flags, level, verdict };
  }

  // ---- Password strength (a rough guide, not a security guarantee) ---------
  const COMMON = ["password", "qwerty", "123456", "123456789", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon", "football", "abc123", "111111", "123123", "000000"];

  function assessPassword(pw) {
    const value = String(pw == null ? "" : pw);
    if (!value) return { score: 0, label: "Enter a password", suggestions: [] };
    const lower = value.toLowerCase();
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((re) => re.test(value)).length;
    const suggestions = [];
    let score = 0;
    if (value.length >= 8) score++;
    if (value.length >= 12) score++;
    if (value.length >= 16) score++;
    if (classes >= 2) score++;
    if (classes >= 3) score++;
    else suggestions.push("Mix in capitals, numbers or symbols, or add more words.");
    if (value.length < 12) suggestions.push("Make it longer - aim for at least 12 characters, or use several words.");

    const common = COMMON.some((c) => lower.includes(c));
    const sequential = /0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf/.test(lower);
    const repeated = /(.)\1\1/.test(value);
    if (common) suggestions.push("Avoid common words and passwords like “password” or “123456”.");
    if (sequential) suggestions.push("Avoid keyboard runs and sequences like “qwerty” or “1234”.");
    if (repeated) suggestions.push("Avoid repeating the same character many times.");
    if (common || sequential) score = Math.min(score, 1);
    else if (repeated) score = Math.min(score, 2);

    score = Math.max(0, Math.min(4, score));
    const label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score];
    return { score, label, suggestions: suggestions.slice(0, 3) };
  }

  // Parses the Have I Been Pwned range response (privacy-safe k-anonymity model).
  // text lines are "SUFFIX:COUNT"; returns how many breaches the suffix appears in.
  function parseBreachResponse(text, suffix) {
    const want = String(suffix || "").toUpperCase();
    const lines = String(text || "").split(/\r?\n/);
    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      if (line.slice(0, idx).toUpperCase() === want) return parseInt(line.slice(idx + 1), 10) || 0;
    }
    return 0;
  }

  // ---- Password generator (pure builders; UI supplies secure randomness) ---
  const WORDS = ("able acid acre army atom aunt baby band bank barn base bath beam bean bear bell belt bird blue boat bone book boot brush cake calm camp cane card cart cave cell chat chef chin city clay clip club coal coat code coin cola cold cook cord core corn cost crew crop cube curl dart dash date dawn deer desk dial dice dirt dish dock door dove draw drum duck dune dust earl earn east edge farm fern film fire fish flag flax foam fork frog fuel gate gear gift goat gold golf grid hand hawk herb hill hive hood hook horn hose iron jade jazz kite lace lake lamp land lane leaf lens lime lion lock loft lump mane mask mast maze milk mint mole moon moss moth nest node nose note oak oat oval owl palm park pear pine pink plum pond pony pool reed reef ring road rock rope rose ruby rust sail salt sand seal seed ship shoe silk snow soap sock soil song star stem swan tank tent tide tile tree tulip vase vine wave wind wolf wood wool yard yarn zinc").split(" ");

  function makePassphrase(wordIndices, numberSeed, separator) {
    const sep = separator || "-";
    const words = (wordIndices || []).map((i) => {
      const w = WORDS[((i % WORDS.length) + WORDS.length) % WORDS.length];
      return w.charAt(0).toUpperCase() + w.slice(1);
    });
    const number = 10 + (Math.abs(numberSeed | 0) % 90);
    return words.concat(String(number)).join(sep);
  }

  function buildPool(opts) {
    const o = opts || {};
    let pool = "";
    if (o.lower !== false) pool += "abcdefghijkmnpqrstuvwxyz"; // no l, o
    if (o.upper !== false) pool += "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
    if (o.digits !== false) pool += "23456789"; // no 0, 1
    if (o.symbols) pool += "!@#$%^&*-_=+?";
    return pool || "abcdefghijkmnpqrstuvwxyz";
  }

  function makePassword(bytes, length, opts) {
    const pool = buildPool(opts);
    let out = "";
    for (let i = 0; i < length; i++) out += pool.charAt(bytes[i % bytes.length] % pool.length);
    return out;
  }

  // ---- Reputation lookups (hand off to trusted services) ------------------
  // These build links to established threat-intelligence services. The fully
  // automatic in-app verdict would need a backend holding an API key; these
  // instead let the user look the item up directly, with no key and no backend.
  function virusTotalFileUrl(sha256) {
    return "https://www.virustotal.com/gui/file/" + encodeURIComponent(String(sha256 || ""));
  }
  function reputationLinks(url) {
    const q = encodeURIComponent(String(url || ""));
    return [
      { label: "Look up on VirusTotal", href: "https://www.virustotal.com/gui/search/" + q },
      { label: "Google Safe Browsing status", href: "https://transparencyreport.google.com/safe-browsing/search?url=" + q },
    ];
  }

  // ---- Security basics checklist -----------------------------------------
  const CHECKLIST = [
    { id: "mfa", title: "Turn on two-step login (MFA)", why: "Even if a password is stolen, a second step stops most break-ins.", how: "Switch it on for email first, then other important accounts. An app like Microsoft or Google Authenticator is safer than text messages." },
    { id: "manager", title: "Use a password manager", why: "It lets every account have a long, unique password without anyone memorising them.", how: "Pick a reputable password manager for the team, and stop reusing passwords across sites." },
    { id: "updates", title: "Keep devices and software updated", why: "Most attacks use known flaws that an update has already fixed.", how: "Turn on automatic updates for computers, phones and key apps." },
    { id: "backups", title: "Back up important data", why: "Backups let you recover from ransomware, theft or mistakes.", how: "Keep three copies, on two types of storage, with one kept separately. Test that a restore actually works." },
    { id: "email", title: "Lock down your email domain", why: "It stops criminals sending email that looks like it's from you.", how: "Use the Email & domain tab here to set up SPF, DKIM and DMARC." },
    { id: "admin", title: "Limit admin accounts", why: "Fewer powerful accounts means less damage if one is compromised.", how: "Give people only the access they need, and use a separate account for admin tasks." },
    { id: "phishing", title: "Help staff spot scams", why: "Most incidents start with a convincing email or message.", how: "Share how to check senders and links, and agree to verify money or bank-detail requests by phone." },
    { id: "devices", title: "Protect and encrypt devices", why: "A lost laptop or phone shouldn't mean lost data.", how: "Turn on device encryption and a screen lock, and enable remote wipe where you can." },
    { id: "plan", title: "Know who to call", why: "Acting fast limits the damage when something goes wrong.", how: "Write down who to contact and the key steps. In the UK you can report to Action Fraud and the NCSC." },
  ];

  return { analyzeLink, assessPassword, parseBreachResponse, WORDS, makePassphrase, buildPool, makePassword, virusTotalFileUrl, reputationLinks, CHECKLIST };
});
