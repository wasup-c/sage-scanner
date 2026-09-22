# SAGE

**Security Analysis with Grounded Explanations**

An AI-assisted network security assessment and education tool for people who find raw scan output overwhelming.

**Core principle: security tools and trusted vulnerability databases determine the facts. The AI only explains them.**

The LLM never decides whether a host is vulnerable, never assigns risk, and never runs commands. Nmap observes, NVD and CISA KEV supply vulnerability intelligence, deterministic code scores risk, and the AI translates the result into plain language, then gets checked against the facts it was given.

## Status

Early development. What works today:

- [x] Versioned finding schema shared by every pipeline stage
- [x] Nmap XML parser with defenses against hostile input (entity expansion, log injection)
- [x] Safe scan execution: fixed profiles, scope allowlist, argument-injection-proof target validation, no shell
- [x] Local CISA KEV catalog
- [x] Fabricated-CVE detector for LLM output
- [ ] Local NVD mirror, queryable by CPE
- [ ] CPE resolution with confidence tiers (confirmed / probable / possible)
- [ ] Deterministic risk decision table
- [ ] LLM explanation layer behind a provider interface
- [ ] Predict-then-reveal learning mode
- [ ] Web dashboard

## Pipeline

```
Nmap (-oX) ──► Parser ──► Finding schema ──► CPE resolution ──► NVD + KEV lookup
                                                                     │
Dashboard ◄── Output validator ◄── LLM explanation ◄── Risk decision table
```

## Why "confidence tiers"

Scanner output is a hypothesis, not a fact. Nmap reports `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`, and NVD may list CVEs affecting OpenSSH 8.9p1 — but Ubuntu backports security fixes without changing the upstream version number, so the host may already be patched. Most tools report the match as if it were certain. This one labels how confident the match is and explains why.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest

sage profiles
sage parse tests/fixtures/sample_scan.xml
sage parse tests/fixtures/sample_scan.xml --json
sage kev-update
sage kev-check CVE-2021-44228
```

Scanning a live host (Nmap must be installed):

```bash
sage scan 10.10.10.10 --profile service
```

The `os` profile needs raw sockets. Rather than running the tool as root, grant only that capability to Nmap:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(which nmap)"
```

## Scope and authorization

**Only scan systems you own or are explicitly authorized to assess.**

This is enforced in code, not just stated here: by default the scanner refuses any target outside `10.10.10.0/24` (an isolated lab network). Override deliberately with:

```bash
export SAGE_ALLOWED_NETWORKS="10.10.10.0/24,10.20.0.0/24"
```

## Security design notes

The scan target is untrusted. Service banners are controlled by the remote host, so a hostile service can put an XSS payload, a prompt injection, or forged log lines into scan results. See `tests/fixtures/malicious_banner.xml`. Defenses are layered:

| Threat | Where it's handled |
|---|---|
| Entity expansion (billion laughs) | Parser uses `defusedxml` |
| Log injection via newlines | Parser strips control characters |
| Command / argument injection | Targets must parse as a single in-scope IP; argv list, no shell |
| XSS via banner text | Frontend must escape on render (not yet built) |
| Prompt injection via banner text | Scan data kept out of the LLM instruction channel (not yet built) |
| Fabricated CVEs in AI output | `validator.py` rejects any CVE the pipeline didn't retrieve |

## License

MIT
