# Privacy-Preserving Sharing

Sometimes the most valuable intelligence is the most sensitive: victim lists, internal telemetry, customer addresses. Cryptographic techniques allow useful sharing without full disclosure.

## Techniques

| Technique | Use |
|---|---|
| Hashing indicators | share hashes of indicators; others check membership (weak: low-entropy indicators can be brute-forced) |
| Bloom filters | compact membership tests with false positives; same brute-force caveat |
| Private Set Intersection (PSI) | two parties learn only the intersection of their sets |
| Traffic Light Protocol (TLP) | policy labels on sharing scope (not cryptographic) |
| Aggregation with differential privacy | share statistics without individual data |
| TEEs | process pooled data in an enclave (see **tee-attack-engineering**) |

## Choosing a technique

Start from the question the recipient needs answered, not from the cryptography.

| Recipient's question | Fitting technique | Why |
|---|---|---|
| "Is this one item on your list?" | rate-limited query service, or PSI | hashing leaks the list to guessing |
| "Which of my items are on your list?" | PSI | both sides keep non-matching items private |
| "How many of our customers were hit?" | PSI cardinality, or aggregation | answer is a count, not identities |
| "What is the trend this month?" | aggregation with differential privacy | protects individuals in published statistics |
| "May I forward this?" | TLP 2.0 labels | a policy question, not a cryptographic one |

TLP is a handling agreement. It works only among parties who honour it, but it is cheap and universally understood, so label everything regardless of which other technique you use. TLP 2.0 defines CLEAR, GREEN, AMBER, AMBER+STRICT and RED.

## Why hashing is weak

Hashing protects an indicator only if the indicator is hard to guess. There are about 4.3 billion IPv4 addresses; a modern GPU hashes that many with SHA-256 in seconds to minutes. Domains in a known namespace, email addresses at a known company, and small integer IDs fall just as quickly. Salting does not help when the salt has to be shared with the recipient so they can check membership. Treat hashed lists of low-entropy values as *public*.

## Example: exchanges checking attacker addresses

Exchanges want to know whether deposit addresses match a confidential list of attacker addresses held by an investigator. PSI allows the check without either side revealing its full list. Since addresses are high-entropy, hashing is somewhat safer than for IPs, but lists of *known* addresses can still be tested by guessing, so PSI or rate-limited query services are preferable.

The guessing risk is concrete in Web3: an exchange can hash every address that ever appeared on-chain (hundreds of millions, an easy computation) and recover the investigator's whole hashed list. On a public ledger, "high-entropy" stops meaning "unguessable" because the candidate set is published.

## Worked example

_Step 1 was executed locally with Python 3 while writing this chapter (output shown is observed). Step 2 was not executed; verify locally. Neither step runs in this book's CI._

Goal: first show why hashed sharing fails for IPv4, then run a PSI between two small address sets.

1. Reverse a hashed IPv4 indicator by brute force over a /16 (a full sweep is the same idea, only longer).

```python
import hashlib, ipaddress, time
secret = "203.0.113.77"                                  # documentation range (RFC 5737)
target = hashlib.sha256(secret.encode()).hexdigest()
t = time.time()
for ip in ipaddress.ip_network("203.0.0.0/16"):
    if hashlib.sha256(str(ip).encode()).hexdigest() == target:
        print("recovered", ip, f"in {time.time()-t:.2f}s"); break
```

Observed output on the author's machine: `recovered 203.0.113.77 in 1.29s` (timing varies by hardware). Scale the estimate to 2^32 and compare with what a GPU tool would do.

2. PSI between an investigator's set and an exchange's deposit set with OpenMined PSI (`pip install openmined.psi`). The API below follows the project's README at the time of writing; check the README for your version.

```python
import private_set_intersection.python as psi
investigator = ["0x...a1", "0x...b2", "0x...c3"]        # server-side, confidential
exchange     = ["0x...b2", "0x...d4"]                   # client-side, confidential
server = psi.server.CreateWithNewKey(True)
client = psi.client.CreateWithNewKey(True)
setup    = server.CreateSetupMessage(1e-9, len(exchange), investigator)
request  = client.CreateRequest(exchange)
response = server.ProcessRequest(request)
idx = client.GetIntersection(setup, response)
print([exchange[i] for i in idx])
```

Expected output: `['0x...b2']`. The exchange learns which of its own deposits match; it does not learn the investigator's other addresses. The investigator learns the size of the exchange's query but not its contents.

3. Note the residual leakage in your write-up: the client could submit a huge candidate set (for example, every active address) and learn the whole list. Rate limits, query-size limits and agreements are still needed.

## Common pitfalls

- Sharing hashed low-entropy indicators and calling them private.
- Assuming crypto addresses are unguessable when the full candidate set is public on-chain.
- Running PSI without limits on query size, which lets one party enumerate the other's set.
- Forgetting TLP labels on data shared through a privacy-preserving channel; the output still needs handling rules.
- Publishing aggregate statistics from very small groups, which can identify individuals.

## Exercises

1. Show that a hashed list of IPv4 indicators can be reversed by brute force.
2. Implement a simple PSI using an open-source library between two sets of addresses.
3. Label five sample indicators with TLP 2.0 and explain each choice.
4. Estimate the time to reverse a hashed list of Ethereum addresses using all addresses seen on-chain as the candidate set.

## Further reading

- FIRST TLP 2.0: <https://www.first.org/tlp/>
- OpenMined PSI library: <https://github.com/OpenMined/PSI>
- Dwork & Roth, "The Algorithmic Foundations of Differential Privacy"
- RFC 5737, IPv4 address blocks reserved for documentation: <https://www.rfc-editor.org/rfc/rfc5737>
