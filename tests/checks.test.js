const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../checks.js");
const D = require("../dns.js");

const found = (...records) => ({ ok: true, records });
const nothing = { ok: true, records: [] };
const failed = { ok: false, records: [] };
const spf = (r, provider = "other") => C.checkSpf(found(r), "example.org", provider, false);
const dmarc = (r, name = "example.org") => C.checkDmarc([{ name, ...found(r) }], "example.org", "microsoft", false);
const dkimNone = C.DKIM_SELECTORS.map((selector) => ({ selector, ...nothing }));

test("normalizeDomain accepts the ways people type a domain", () => {
  assert.equal(C.normalizeDomain("Example.ORG"), "example.org");
  assert.equal(C.normalizeDomain("https://www.example.org/contact?a=1"), "example.org");
  assert.equal(C.normalizeDomain("me@charity.org.uk"), "charity.org.uk");
  assert.equal(C.normalizeDomain("  example.org.  "), "example.org");
});

test("normalizeDomain rejects things that aren't domains", () => {
  for (const bad of ["", "localhost", "192.168.0.1", "not a domain", "<script>.org", "-bad.org"]) {
    assert.equal(C.normalizeDomain(bad), null, bad);
  }
});

test("dmarcCandidates walks up to the parent domains", () => {
  assert.deepEqual(C.dmarcCandidates("a.charity.org.uk"), ["a.charity.org.uk", "charity.org.uk", "org.uk"]);
});

test("detectProvider recognises common email services", () => {
  assert.equal(C.detectProvider(["0 x-org.mail.protection.outlook.com."]), "microsoft");
  assert.equal(C.detectProvider(["1 smtp.google.com."]), "google");
  assert.equal(C.detectProvider(["10 aspmx.l.google.com."]), "google");
  assert.equal(C.detectProvider(["10 mail.notgoogle.com."]), "other");
});

test("SPF results", () => {
  assert.equal(C.checkSpf(nothing, "example.org", "other", false).status, "fail");
  assert.equal(C.checkSpf(found("v=spf1 -all", "v=spf1 ~all"), "example.org", "other", false).status, "fail");
  assert.equal(spf("v=spf1 +all").status, "fail");
  assert.equal(spf("v=spf1 all").status, "fail");
  assert.equal(spf("v=spf1 include:a.example ?all").status, "warn");
  assert.equal(spf("v=spf1 include:a.example").status, "warn");
  assert.equal(spf("v=spf1 include:a.example ~all").status, "pass");
  assert.equal(spf("v=spf1 include:a.example -all").status, "pass");
  assert.equal(spf("v=spf1 redirect=_spf.example.net").status, "pass");
  assert.equal(spf("v=spf1 ptr -all").status, "warn");
  assert.equal(spf("v=spf1 " + "include:a.example ".repeat(11) + "-all").status, "fail");
  assert.equal(spf("v=spf1 " + "include:a.example ".repeat(10) + "-all").status, "pass");
});

test("non-SPF TXT records are ignored", () => {
  const r = C.checkSpf(found("google-site-verification=abc", "v=spf1x"), "example.org", "other", false);
  assert.equal(r.headline, "No SPF record found");
});

test("the missing-SPF fix matches the provider", () => {
  const value = (p) => C.checkSpf(nothing, "example.org", p, false).fix.record.value;
  assert.match(value("microsoft"), /spf\.protection\.outlook\.com/);
  assert.match(value("google"), /_spf\.google\.com/);
  assert.equal(C.checkSpf(nothing, "example.org", "other", true).fix.record.value, "v=spf1 -all");
});

test("DMARC results", () => {
  assert.equal(C.checkDmarc([{ name: "example.org", ...nothing }], "example.org", "other", false).status, "fail");
  assert.equal(dmarc("v=DMARC1; p=none; rua=mailto:a@example.org").status, "warn");
  assert.equal(dmarc("v=DMARC1; p=reject; rua=mailto:a@example.org").status, "pass");
  assert.equal(dmarc("v=DMARC1; p=quarantine; rua=mailto:a@example.org").status, "pass");
  assert.equal(dmarc("v=DMARC1; p=reject").status, "warn");
  assert.equal(dmarc("v=DMARC1; p=reject; rua=mailto:a@example.org; pct=50").status, "warn");
  assert.equal(dmarc("v=DMARC1; p=banana").status, "fail");
  assert.equal(C.checkDmarc([{ name: "example.org", ...found("v=DMARC1; p=none", "v=DMARC1; p=reject") }], "example.org", "other", false).status, "fail");
});

test("a subdomain inherits the parent's DMARC policy, using sp= if set", () => {
  const r = C.checkDmarc([
    { name: "news.example.org", ...nothing },
    { name: "example.org", ...found("v=DMARC1; p=reject; sp=none; rua=mailto:a@example.org") },
  ], "news.example.org", "other", false);
  assert.equal(r.status, "warn");
  assert.match(r.detail, /parent domain, example\.org/);
});

test("DKIM never claims a domain has none", () => {
  const r = C.checkDkim(dkimNone, "example.org", "microsoft", false);
  assert.equal(r.status, "unknown");
  assert.match(r.detail, /may still use DKIM/);
});

test("DKIM finds keys and spots revoked ones", () => {
  const one = (record) => [{ selector: "selector1", ...found(record) }, ...dkimNone.slice(1)];
  assert.equal(C.checkDkim(one("v=DKIM1; k=rsa; p=MIIBIjAN"), "example.org", "other", false).status, "pass");
  assert.equal(C.checkDkim(one("v=DKIM1; p="), "example.org", "other", false).status, "warn");
  assert.equal(C.checkDkim(one("unrelated text"), "example.org", "other", false).status, "unknown");
});

test("a failed lookup is never reported as a missing record", () => {
  const dkimFailed = C.DKIM_SELECTORS.map((selector) => ({ selector, ...failed }));
  const report = C.buildReport("example.org", { mx: failed, spf: failed, dmarc: [{ name: "example.org", ...failed }], dkim: dkimFailed });
  assert.ok(report.checks.every((c) => c.status === "unknown"));
  assert.equal(report.verdict.title, "This check is incomplete");
  assert.ok(!JSON.stringify(report).includes("No SPF record"));
});

test("buildReport gives an overall verdict", () => {
  const key = [{ selector: "selector1", ...found("v=DKIM1; p=abc") }];
  const good = C.buildReport("example.org", {
    mx: found("0 x.mail.protection.outlook.com."),
    spf: found("v=spf1 include:spf.protection.outlook.com -all"),
    dmarc: [{ name: "example.org", ...found("v=DMARC1; p=reject; rua=mailto:a@example.org") }],
    dkim: key,
  });
  assert.equal(good.verdict.level, "pass");
  assert.equal(good.provider, "microsoft");
  const bad = C.buildReport("example.org", { mx: found("10 mail.example.net."), spf: nothing, dmarc: [{ name: "example.org", ...nothing }], dkim: dkimNone });
  assert.equal(bad.verdict.title, "2 problems to fix first");
});

test("domains with no mail and missing domains are handled", () => {
  const noMail = C.buildReport("example.org", { mx: found("0 ."), spf: nothing, dmarc: [{ name: "example.org", ...nothing }], dkim: dkimNone });
  assert.equal(noMail.noMail, true);
  assert.equal(noMail.checks.find((c) => c.id === "dmarc").fix.record.value, "v=DMARC1; p=reject;");
  const gone = { ok: true, records: [], nx: true };
  assert.equal(C.buildReport("nope.example", { mx: gone, spf: gone, dmarc: [], dkim: [] }).verdict.title, "This domain doesn't exist");
});

test("joinTxt rebuilds split TXT records", () => {
  assert.equal(D.joinTxt('"v=spf1 include:a.example " "-all"'), "v=spf1 include:a.example -all");
  assert.equal(D.joinTxt('"say \\"hi\\""'), 'say "hi"');
  assert.equal(D.joinTxt("plain"), "plain");
});

test("parseAnswer separates missing records from failed lookups", () => {
  assert.deepEqual(D.parseAnswer({ Status: 3 }, "TXT"), { ok: true, records: [], nx: true, ad: false });
  assert.equal(D.parseAnswer({ Status: 2 }, "TXT").ok, false);
  const r = D.parseAnswer({ Status: 0, Answer: [{ type: 5, data: "x.example." }, { type: 16, data: '"v=DKIM1; p=abc"' }] }, "TXT");
  assert.deepEqual(r.records, ["v=DKIM1; p=abc"]);
});

test("lookup falls back to the second resolver, then reports failure", async () => {
  const urls = [];
  const flaky = async (url) => {
    urls.push(url);
    if (url.includes("cloudflare")) throw new Error("blocked");
    return { ok: true, json: async () => ({ Status: 0, Answer: [{ type: 16, data: '"v=spf1 -all"' }] }) };
  };
  assert.deepEqual((await D.lookup("example.org", "TXT", flaky)).records, ["v=spf1 -all"]);
  assert.equal(urls.length, 2);
  const down = async () => { throw new Error("down"); };
  assert.equal((await D.lookup("example.org", "TXT", down)).ok, false);
});

const crypto = require("node:crypto");
const pem = (bits) => crypto.generateKeyPairSync("rsa", { modulusLength: bits }).publicKey
  .export({ type: "spki", format: "der" }).toString("base64");

test("dkimKeyInfo measures real RSA keys", () => {
  for (const bits of [1024, 2048, 4096]) {
    assert.deepEqual(C.dkimKeyInfo(`v=DKIM1; k=rsa; p=${pem(bits)}`), { type: "rsa", bits });
  }
  assert.deepEqual(C.dkimKeyInfo("v=DKIM1; k=ed25519; p=abc"), { type: "ed25519" });
  assert.equal(C.dkimKeyInfo("v=DKIM1; p=not-a-key!"), null);
});

test("DKIM key strength changes the result", () => {
  const check = (bits) => C.checkDkim([{ selector: "s1", ...found(`v=DKIM1; p=${pem(bits)}`) }], "example.org", "other", false);
  assert.equal(check(512 + 512).status, "warn");
  assert.equal(check(2048).status, "pass");
  assert.match(check(2048).detail, /2048 bits/);
  assert.equal(C.checkDkim([{ selector: "s1", ...found(`v=DKIM1; p=${crypto.generateKeyPairSync("rsa", { modulusLength: 768 }).publicKey.export({ type: "spki", format: "der" }).toString("base64")}`) }], "example.org", "other", false).status, "fail");
});

test("SPF deeper checks find loopholes", () => {
  const tree = (o) => ({ lookups: 1, broken: [], includes: [], incomplete: false, ...o });
  const run = (r, t, p = "other") => C.checkSpf(found(r), "example.org", p, false, t);
  assert.equal(run("v=spf1 include:x.example -all", tree({ broken: ["x.example"] })).status, "fail");
  assert.equal(run("v=spf1 include:x.example -all", tree({ lookups: 11 })).status, "fail");
  assert.match(run("v=spf1 include:x.example -all", tree({ lookups: 11 })).detail, /including nested/);
  assert.equal(run("v=spf1 ip4:10.0.0.0/8 -all", tree({})).status, "warn");
  assert.equal(run("v=spf1 ip4:203.0.113.0/24 -all", tree({})).status, "pass");
  assert.equal(run("v=spf1 include:mail.example -all", tree({ includes: ["mail.example"] }), "microsoft").status, "warn");
  assert.equal(run("v=spf1 include:spf.protection.outlook.com -all", tree({ includes: ["spf.protection.outlook.com"] }), "microsoft").status, "pass");
});

test("DMARC flags open subdomains", () => {
  const r = dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:a@example.org");
  assert.equal(r.status, "warn");
  assert.match(r.detail, /Subdomains/);
  assert.equal(dmarc("v=DMARC1; p=reject; rua=a@example.org").status, "warn");
});

test("spfTree follows nesting, spots broken entries and survives loops", async () => {
  const zone = {
    "a.example": '"v=spf1 include:b.example mx -all"',
    "b.example": '"v=spf1 a ~all"',
    "loop.example": '"v=spf1 include:loop.example -all"',
    "none.example": '"not spf"',
  };
  const fake = async (url) => {
    const name = new URL(url).searchParams.get("name");
    return { ok: true, json: async () => ({ Status: 0, Answer: zone[name] ? [{ type: 16, data: zone[name] }] : [] }) };
  };
  const nested = await D.spfTree("v=spf1 include:a.example -all", fake);
  assert.equal(nested.lookups, 4);
  assert.deepEqual(nested.includes, ["a.example", "b.example"]);
  assert.deepEqual((await D.spfTree("v=spf1 include:none.example -all", fake)).broken, ["none.example"]);
  assert.equal((await D.spfTree("v=spf1 include:loop.example -all", fake)).incomplete, true);
  const down = async () => { throw new Error("down"); };
  assert.equal((await D.spfTree("v=spf1 include:a.example -all", down)).incomplete, true);
});

test("CAA is read in both formats", () => {
  assert.equal(D.readCaa('0 issue "letsencrypt.org"'), '0 issue "letsencrypt.org"');
  assert.equal(D.readCaa("\\# 12 00 05 69 73 73 75 65 61 2e 6f 72 67"), '0 issue "a.org"');
  assert.equal(D.parseAnswer({ Status: 0, AD: true, Answer: [{ type: 257, data: '0 issue "a.org"' }] }, "CAA").ad, true);
});

test("extra checks don't change the verdict, and failed lookups stay unknown", () => {
  const key = [{ selector: "s1", ...found("v=DKIM1; p=abc") }];
  const r = C.buildReport("example.org", {
    mx: found("10 mail.example.net."), spf: found("v=spf1 mx -all"),
    dmarc: [{ name: "example.org", ...found("v=DMARC1; p=reject; rua=mailto:a@example.org") }], dkim: key,
    mtaSts: nothing, tlsRpt: nothing, caa: [{ name: "example.org", ...nothing }],
  });
  assert.equal(r.verdict.level, "pass");
  assert.deepEqual(r.extras.map((c) => c.status), ["optional", "optional", "optional", "optional"]);
  assert.equal(C.checkMtaSts(failed, "example.org").status, "unknown");
  assert.equal(C.checkCaa([{ name: "example.org", ...failed }]).status, "unknown");
  assert.equal(C.checkMtaSts(found("v=STSv1; id=1"), "example.org").status, "pass");
  assert.equal(C.checkTlsRpt(found("v=TLSRPTv1; rua=mailto:a@example.org"), "example.org").status, "pass");
  assert.equal(C.checkTlsRpt(found("v=TLSRPTv1;"), "example.org").status, "warn");
  assert.equal(C.checkDnssec({ ok: true, records: [], ad: true }).status, "pass");
});
