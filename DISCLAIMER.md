# Disclaimer and authorised-use policy

`reconkit` is a **reporting tool**. It reads files that other tools already produced. It does not
scan, connect to, or interact with any remote system.

That does not make it harmless. The reports it generates describe how to attack real infrastructure,
and the rules it ships encode knowledge about insecure configurations. Read this before you use it.

## You may use reconkit when

* You have **written authorisation** from the system owner — a signed scope document, a statement of
  work, or the rules of engagement of a bug bounty programme that explicitly includes the asset.
* You are testing a system you personally own or operate, including lab environments, CTF platforms
  and deliberately vulnerable applications.
* You are working in an educational setting with the permission of the institution that owns the
  infrastructure.

## You may not use reconkit to

* Produce or distribute reports about systems you were not authorised to test.
* Publish scan output, client names, hostnames, IP addresses, credentials or vulnerability details
  from a real engagement. Bug bounty programme rules almost always forbid public disclosure before
  the vendor has remediated and consented.
* Build a portfolio, blog post or case study from someone else's infrastructure without permission.

## Repository hygiene

The `.gitignore` in this project excludes `scans/`, `engagements/`, `loot/` and `reports/`
specifically so that engagement material cannot be committed by accident. If any of those paths
appear in `git status`, stop and ask yourself whether you have written authorisation to publish
what is inside.

Before the first push, and again before every release:

```bash
grep -rniE "(client|confidential|internal)" --exclude-dir=.git .
gitleaks detect --no-git
trufflehog filesystem .
```

## Legal notice

Unauthorised access to computer systems is a criminal offence in most jurisdictions, including under
the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and equivalent provisions in
the criminal codes of CIS states. "I only ran a scanner" and "I did not change anything" are not
defences in most of those jurisdictions.

The authors of reconkit accept no liability for misuse. You are responsible for the lawfulness of
your own engagement.
