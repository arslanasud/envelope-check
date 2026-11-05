/*
 * Envelope Check: public DNS lookups, using DNS over HTTPS from the browser.
 * It tries Cloudflare first and Google Public DNS if that fails.
 * A failed lookup returns { ok: false }, which is different from a domain having
 * no record. The rest of the tool never treats a failed lookup as a missing record.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("./checks.js"));
  else root.EnvelopeDns = factory(root.EnvelopeChecks);
})(typeof self !== "undefined" ? self : this, function (Checks) {
  "use strict";

  const RESOLVERS = [
    (name, type) => "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=" + type,
    (name, type) => "https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + type,
  ];
  const TYPE_NUMBER = { TXT: 16, MX: 15 };

  /** TXT answers arrive as quoted chunks: "v=spf1 " "-all" becomes v=spf1 -all */
  function joinTxt(data) {
    const chunks = String(data).match(/"(?:[^"\\]|\\.)*"/g);
    if (!chunks) return String(data);
    return chunks.map((c) => c.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
  }

  function parseAnswer(json, type) {
    // 0 = found, 3 = name doesn't exist. Anything else is a failed lookup.
    if (json.Status !== 0 && json.Status !== 3) return { ok: false, records: [] };
    const records = (json.Answer || [])
      .filter((a) => a.type === TYPE_NUMBER[type])
      .map((a) => (type === "TXT" ? joinTxt(a.data) : String(a.data)));
    return { ok: true, records, nx: json.Status === 3 };
  }

  async function lookup(name, type, fetchFn) {
    for (const url of RESOLVERS) {
      try {
        const res = await fetchFn(url(name, type), { headers: { accept: "application/dns-json" } });
        if (!res.ok) continue;
        const parsed = parseAnswer(await res.json(), type);
        if (parsed.ok) return parsed;
      } catch (_) {
        // Try the next resolver.
      }
    }
    return { ok: false, records: [] };
  }

  /** Runs every lookup for one domain and returns the data for buildReport. */
  async function gather(domain, fetchFn) {
    const f = fetchFn || ((...args) => fetch(...args));
    const names = Checks.dmarcCandidates(domain);
    const [mx, spf, dmarc, dkim] = await Promise.all([
      lookup(domain, "MX", f),
      lookup(domain, "TXT", f),
      Promise.all(names.map(async (name) => ({ name, ...(await lookup("_dmarc." + name, "TXT", f)) }))),
      Promise.all(Checks.DKIM_SELECTORS.map(async (selector) => ({ selector, ...(await lookup(selector + "._domainkey." + domain, "TXT", f)) }))),
    ]);
    return { mx, spf, dmarc, dkim };
  }

  return { joinTxt, parseAnswer, lookup, gather };
});
