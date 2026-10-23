# The Threat Intelligence Sharing Problem

Threat intelligence (TI) sharing helps defenders learn from each other's incidents. In practice it suffers from:

- **Trust:** who produced this indicator, and are they reliable?
- **Freshness and decay:** indicators expire, but feeds rarely say so.
- **Poisoning:** adversaries (or careless contributors) add false entries, causing outages or blinding detections.
- **Privacy and legal risk:** sharing can reveal victim identities or sensitive details.
- **Fragmentation:** each community uses different platforms and formats.

Web3 has a specific version: scam addresses, malicious contracts, phishing domains and drainer infrastructure are shared through many independent lists (wallet blocklists, explorer labels, community databases), with inconsistent provenance.

## Why the problems compound

Each problem makes the others worse. Without provenance you cannot score trust, so you cannot weigh a poisoned entry against a good one. Without validity windows, a domain that was malicious last year and has since been re-registered by a legitimate business stays blocked forever. Without privacy controls, the organisations with the best data (exchanges, wallet vendors, incident responders) share the least. And fragmentation means a fix in one list never reaches the others.

## The Web3 sharing landscape

| Source type | Examples | Typical content | Provenance today |
|---|---|---|---|
| Wallet blocklists | open-source phishing lists maintained by wallet vendors | domains | Git history, maintainer review |
| Explorer labels | block explorers' address tags | addresses, contracts | explorer staff; rarely per-label evidence |
| Community scam databases | Chainabuse, ScamSniffer data | addresses, domains, reports | reporter accounts; variable verification |
| Detection networks | Forta-style bots | alerts on transactions | bot developer identity |
| Incident channels | SEAL 911, private groups | attacker addresses during live incidents | personal trust in the sender |
| Commercial analytics | Chainalysis, TRM, Elliptic | clustered entity labels | vendor methodology, not public |

Every row has value, and every row answers "who said this, and why should I believe it?" differently. The rest of this book is about making that answer explicit and machine-checkable.

## What "decentralised" should mean here

Not "put everything on a blockchain", but:
1. **Verifiable provenance:** each claim is signed by an identifiable producer.
2. **No single gatekeeper:** consumers choose which producers to trust.
3. **Portability:** standard formats, so claims move across platforms.
4. **Revocability:** producers can retract claims, and consumers see retractions.

Notice that none of these needs a blockchain. Signatures and transparency logs (Chapter 3) give provenance and history; standards (Chapter 2) give portability. On-chain registries (Chapter 4) are one option among several, most useful when the consumer is itself on-chain.

## Worked example

_Not executed in this book's CI; verify locally. Outputs shown are expected results, not captured runs._

Goal: measure how much two public Web3 domain blocklists agree, and what that tells you about coverage. Pick two open lists (for example a wallet vendor's phishing list and a community scam-domain list, both published on GitHub). File paths and JSON layouts change; read each repository's README first.

1. Fetch both lists and normalise to one lowercase domain per line.

```bash
mkdir lists && cd lists
curl -sL -o a.json "https://raw.githubusercontent.com/<org-a>/<repo-a>/<branch>/<path-to-blocklist>.json"
curl -sL -o b.json "https://raw.githubusercontent.com/<org-b>/<repo-b>/<branch>/<path-to-domains>.json"
jq -r '.blacklist[]? // .[]?' a.json | tr 'A-Z' 'a-z' | sed 's/^www\.//' | sort -u > a.txt
jq -r '.[]?' b.json | tr 'A-Z' 'a-z' | sed 's/^www\.//' | sort -u > b.txt
wc -l a.txt b.txt
```

2. Compute overlap.

```bash
comm -12 a.txt b.txt | wc -l      # in both
comm -23 a.txt b.txt | wc -l      # only in A
comm -13 a.txt b.txt | wc -l      # only in B
```

3. Sample twenty entries that appear in only one list and check each manually (is the domain still registered, what does passive DNS or an archive show, does the other list have a near-variant?).

Expected result: three counts and a short table of sampled disagreements. Lists built by different methods commonly overlap far less than people assume; the sampled disagreements usually split into "real but missed by the other list", "stale", and "possibly wrong". That split is your first, informal producer-accuracy measurement (Chapter 6).

4. Write down, for each list, what provenance you could find for a single entry: who added it, when, and with what evidence.

## Common pitfalls

- Treating the union of all available lists as "maximum safety". It maximises false positives and poisoning exposure too.
- Consuming feeds with no record of which source contributed which entry, so a bad source cannot be removed cleanly.
- Ignoring decay. Domains are re-registered; addresses can be reused by new owners in some designs.
- Equating "decentralised" with "on-chain" and paying permanence and privacy costs for no benefit.
- Sharing victim-identifying details because the format had a free-text field.

## Exercises

1. List the TI sources your organisation consumes and what you know about each source's provenance.
2. Find two wallet or explorer blocklists and compare their entries for a recent drainer campaign.
3. Describe a poisoning attack that would cause your own outage.
4. For one source, write the provenance fields you would need to trust it automatically.

## Further reading

- ENISA, "Actionable Information for Security Incident Response" (2014)
- FIRST CTI SIG: <https://www.first.org/global/sigs/cti/>
- OASIS CTI TC (STIX/TAXII): <https://oasis-open.github.io/cti-documentation/>
- Chainabuse: <https://www.chainabuse.com>
- SEAL 911: <https://securityalliance.org>
