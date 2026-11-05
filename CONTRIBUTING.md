# Contributing

Thank you for helping small organisations improve their email security.

Useful contributions include fix guides for more email services, clearer wording, bug reports and new checks.

1. Open an issue describing the problem or idea.
2. Make your change. Add or update a test if it changes a rule in `checks.js`.
3. Run `node --test`.
4. Open a pull request explaining what changed and link to a source for any security advice.

Please follow these rules:

- Use plain English that a non-technical person can act on.
- Never report a failed lookup as a missing record.
- Never insert DNS data into the page as HTML.
- Only run passive lookups of public records. This tool doesn't scan or probe systems.
- Don't add anything that sends or stores a person's results without a clear discussion first.
