# How Envelope Check works

Read this first if you're maintaining the code. You should be able to explain every step without notes.

## The journey of one check

1. **The form (`app.js`)**: The person enters a domain. `normalizeDomain` turns inputs like `me@charity.org.uk` into `charity.org.uk`.
2. **The lookups (`dns.js`)**: `gather` asks public DNS over HTTPS for the records below. Browsers can't send ordinary DNS queries, which is why it uses HTTPS.
3. **The rules (`checks.js`)**: `buildReport` turns the records into a status, an explanation and a fix for each check.
4. **The display (`app.js`)**: `render` draws the results.

| Lookup | Why |
|---|---|
| `MX` on the domain | Shows whether it receives email and which service it uses |
| `TXT` on the domain | Contains the SPF record |
| `TXT` on `_dmarc.<domain>` and its parents | Contains the DMARC record |
| `TXT` on `<selector>._domainkey.<domain>` | Contains a DKIM key, if that selector exists |

## Four design decisions you should be able to defend

1. **A failed lookup isn't a missing record.** Telling someone they have no SPF because a network request failed would be false. `dns.js` returns `ok: false`, and the result shows "We couldn't complete this check".
2. **DKIM not found isn't a failure.** DNS can't list selectors, so we only try common names. The status is "Check manually", and the person is told how to confirm it from email headers.
3. **DNS records are untrusted.** Anyone can publish `<script>` in a TXT record. `el()` in `app.js` adds text with `append`, and the code never uses `innerHTML`.
4. **The rules are separate from the page.** `checks.js` has no network or page code, so `node --test` can check every rule quickly.

## Questions to test yourself

- What's the difference between `~all` and `-all`?
- Why might `p=none` be a sensible first step, but a poor place to stay?
- How does DMARC use the results of SPF and DKIM? Look up "alignment", because this version doesn't check it.
- Why does SPF have a limit of 10 lookups?
- Why is scanning someone's systems without permission different from reading their public DNS records?

## Try these changes to learn the code

1. Add `mandrill` to `DKIM_SELECTORS` and run the tests.
2. Write a test for an SPF record with uppercase letters, such as `V=SPF1 -ALL`.
3. Add a fix guide for another email service.

## How the advanced checks work

- **Nested SPF:** `spfTree` follows `include` and `redirect` entries, counts lookups and notes broken entries. It stops at set limits so that a loop can't run forever.
- **DKIM key strength:** `dkimKeyInfo` decodes the public key and measures its size. A key under 1024 bits fails, and one under 2048 bits gets a warning.
- **Optional protections:** These use the `optional` status, so they don't change the overall verdict.
- **What it doesn't do:** It doesn't send traffic to the organisation's mail servers or websites. It only asks public DNS services for published records.
