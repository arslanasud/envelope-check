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
  const TYPE_NUMBER = { TXT: 16, MX: 15, CAA: 257 };

  /** TXT answers arrive as quoted chunks: "v=spf1 " "-all" becomes v=spf1 -all */
  function joinTxt(data) {
    const chunks = String(data).match(/"(?:[^"\\]|\\.)*"/g);
    if (!chunks) return String(data);
    return chunks.map((c) => c.slice(1, -1).replace(/\\(.)/g, "$1")).join("");
  }

  /** Some services return CAA as hex, such as: \\# 19 00 05 69 73 73 75 65 ... */
  function readCaa(data) {
    const text = String(data);
    if (!text.startsWith("\\#")) return text;
    const hex = text.split(/\s+/).slice(2).join("");
    const bytes = (hex.match(/../g) || []).map((b) => parseInt(b, 16));
    if (bytes.length < 2 || bytes.some(Number.isNaN)) return text;
    const tagEnd = 2 + bytes[1];
    const chars = (part) => String.fromCharCode(...part);
    return `${bytes[0]} ${chars(bytes.slice(2, tagEnd))} "${chars(bytes.slice(tagEnd))}"`;
  }

  function parseAnswer(json, type) {
    // 0 = found, 3 = name doesn't exist. Anything else is a failed lookup.
    if (json.Status !== 0 && json.Status !== 3) return { ok: false, records: [] };
    const records = (json.Answer || [])
      .filter((a) => a.type === TYPE_NUMBER[type])
      .map((a) => (type === "TXT" ? joinTxt(a.data) : type === "CAA" ? readCaa(a.data) : String(a.data)));
    return { ok: true, records, nx: json.Status === 3, ad: json.AD === true };
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

  /**
   * Follows SPF include and redirect entries to count lookups the way mail
   * systems do. It stops at safe limits so that a looping record can't run forever.
   */
  async function spfTree(record, f) {
    const result = { lookups: 0, broken: [], includes: [], incomplete: false };
    let queries = 0;
    async function walk(current, path) {
      const { lookups, targets } = Checks.spfTerms(current);
      result.lookups += lookups;
      for (const target of targets) {
        result.includes.push(target);
        if (target.includes("%")) { result.incomplete = true; continue; } // an SPF macro
        if (path.includes(target) || path.length >= 10 || queries >= 40) { result.incomplete = true; continue; }
        queries++;
        const answer = await lookup(target, "TXT", f);
        if (!answer.ok) { result.incomplete = true; continue; }
        const next = answer.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
        if (next.length !== 1) { result.broken.push(target); continue; }
        await walk(next[0], [...path, target]);
      }
    }
    await walk(record, []);
    return result;
  }

  /** Runs every lookup for one domain and returns the data for buildReport. */
  async function gather(domain, fetchFn) {
    const f = fetchFn || ((...args) => fetch(...args));
    const names = Checks.dmarcCandidates(domain);
    const [mx, spf, dmarc, dkim, mtaSts, tlsRpt, caa] = await Promise.all([
      lookup(domain, "MX", f),
      lookup(domain, "TXT", f),
      Promise.all(names.map(async (name) => ({ name, ...(await lookup("_dmarc." + name, "TXT", f)) }))),
      Promise.all(Checks.DKIM_SELECTORS.map(async (selector) => ({ selector, ...(await lookup(selector + "._domainkey." + domain, "TXT", f)) }))),
      lookup("_mta-sts." + domain, "TXT", f),
      lookup("_smtp._tls." + domain, "TXT", f),
      Promise.all(names.map(async (name) => ({ name, ...(await lookup(name, "CAA", f)) }))),
    ]);
    const spfRecords = spf.ok ? spf.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim())) : [];
    const tree = spfRecords.length === 1 ? await spfTree(spfRecords[0], f) : undefined;
    return { mx, spf, dmarc, dkim, mtaSts, tlsRpt, caa, spfTree: tree };
  }

  return { joinTxt, readCaa, parseAnswer, lookup, spfTree, gather };
});
