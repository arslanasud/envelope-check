# Envelope Check

A free, open-source website that helps small charities and businesses check their public email security settings and fix what's missing, in plain English.

Many small organisations don't have a security team. Existing tools can show that a DNS record is missing, but it can still be hard to know what to do next. Envelope Check explains the result and gives steps based on the email service the domain appears to use.

## What it checks

| Check | What it tells you |
|---|---|
| **SPF** | Whether the domain lists who may send its email, including missing, duplicate and overly permissive records |
| **DKIM** | Whether a signing key is published at common selector names |
| **DMARC** | Whether the domain has a policy for failing email, how strict it is, and whether reports are requested |

It recognises Microsoft 365 and Google Workspace from the domain's MX records and adjusts its guidance.

## Known limits

- It can't prove that DKIM is off, because DNS can't list every selector. It reports this as a manual check.
- It only counts SPF lookups in the main record, not nested ones.
- It reads public DNS only. It doesn't check mailboxes, passwords, MFA or Microsoft 365 settings.
- A good result doesn't mean an organisation is fully protected.

## Privacy

There's no server, account, analytics or results database. The browser sends the domain to Cloudflare DNS, or Google Public DNS as a backup, for the lookup. Fonts load from Google Fonts.

## Run it

You need [Node.js](https://nodejs.org) 20 or later for the tests. The site itself has no dependencies.

```bash
node --test            # run the tests
python3 -m http.server # then open http://localhost:8000
```

## Publish it free on GitHub Pages

1. Create a public repository called `envelope-check` and upload these files.
2. Go to **Settings > Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, then select `main` and `/ (root)`.

Your site will appear at `https://YOUR-USERNAME.github.io/envelope-check/`.

## Project layout

| File | Purpose |
|---|---|
| `checks.js` | The security rules, with no network or page code |
| `dns.js` | Public DNS lookups |
| `app.js` | The form and results display |
| `tests/` | Automated tests |
| `docs/HOW-IT-WORKS.md` | A walkthrough of the code |

## Roadmap

- Count nested SPF lookups
- Add MTA-STS and TLS reporting checks
- Add fix guides for more email services and DNS providers
- Add a volunteer mode for people helping several organisations

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## How this was built

The first version was developed with help from Claude, an AI assistant. The maintainer reviews, tests and is responsible for the code.

## Licence

[MIT](LICENSE)
