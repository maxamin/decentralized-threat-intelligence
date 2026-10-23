# Standards: STIX, TAXII and MISP

## STIX 2.1

A JSON-based language for TI objects: indicators, malware, threat actors, campaigns, observed data, relationships, sightings. Every object has an ID, creator reference, creation/modification times, and optional confidence and validity windows (`valid_from`, `valid_until`).

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2026-10-01T00:00:00Z",
  "modified": "2026-10-01T00:00:00Z",
  "name": "Drainer receiver contract",
  "pattern": "[x-crypto-address:value = '0x0000000000000000000000000000000000000000']",
  "pattern_type": "stix",
  "valid_from": "2026-10-01T00:00:00Z",
  "valid_until": "2027-01-01T00:00:00Z",
  "confidence": 80
}
```

(The address above is a placeholder.) Crypto addresses are not a core STIX observable type; communities use custom objects/extensions, which is an interoperability gap worth standardising.

STIX 2.1 offers a cleaner route than ad hoc custom types: the **extension definition** object. A producer publishes an `extension-definition` describing a new observable (for example, an address with a chain ID) or new properties, with a JSON schema. Objects then reference it by ID. Consumers that understand the extension can validate it; consumers that do not can still parse the rest of the bundle. For crypto addresses, always include the chain (for EVM chains, the EIP-155 chain ID), because the same hex string can be a contract on one chain and an unused address on another.

Relationships and sightings carry most of the analytical value. An indicator says "this pattern is bad"; a `relationship` says "this indicator indicates that malware or campaign"; a `sighting` says "we saw it, here, at this time". Sightings are the raw material for the decay and trust scoring in Chapter 6.

## TAXII 2.1

An HTTPS API for exchanging STIX: collections, polling, and pushing.

A TAXII server exposes API roots, each with collections. Consumers poll a collection with `added_after` to fetch only new objects. Producers with write permission add objects. OASIS maintains a reference server (medallion) and a Python client (taxii2-client) that are useful for labs.

## MISP

A widely used open-source TI platform with its own data model, sharing groups, sync between instances, galaxies (actor/tool taxonomies) and warning lists to reduce false positives. MISP supports STIX import/export.

MISP events group attributes (single values such as a domain) and objects (structured groups of attributes). Each attribute has an `to_ids` flag that says whether it is suitable for automated detection, which is a simple but effective guard against pushing context-only data into blocking systems.

## Gaps for this book's goals

- Provenance is per-platform account, not cryptographically portable.
- Revocation and decay handling is inconsistent across consumers.

| Need | STIX/TAXII | MISP |
|---|---|---|
| Portable format across vendors | strong | via STIX export |
| Community platform with UI and correlation | none (format and API only) | strong |
| Sharing scopes | TLP markings | sharing groups + TLP tags |
| Validity windows | `valid_from` / `valid_until` | decaying models, `first_seen` / `last_seen` |
| Cryptographic provenance | not built in | not built in (instance sync is authenticated, not signed per claim) |

## Choosing between them

Use MISP when a community needs a shared platform with sharing groups, correlation and a UI. Use STIX/TAXII when you exchange data between different products or organisations that run different platforms. Most mature teams use both: MISP internally, STIX exports for partners. Whatever you choose, record the producer, confidence and validity window on every object, because those fields drive the trust and decay logic in later chapters.

## Worked example

_Not executed in this book's CI; verify locally. Outputs shown are expected results, not captured runs._

Goal: produce a valid STIX 2.1 bundle for a fictional drainer campaign with the `stix2` Python library, validate it, and serve it over TAXII locally.

1. Install tools.

```bash
python -m venv v && . v/bin/activate
pip install stix2 stix2-validator taxii2-client medallion
```

2. Build the bundle with a producer identity, an indicator, a campaign and a relationship.

```python
from stix2 import Identity, Indicator, Campaign, Relationship, Bundle, TLP_GREEN
me = Identity(name="Example Wallet Security Team", identity_class="organization")
camp = Campaign(name="Fictional Drainer Campaign Lab-01", created_by_ref=me.id)
ind = Indicator(
    name="Phishing domain for Lab-01",
    pattern="[domain-name:value = 'claim-airdrop.example.com']",
    pattern_type="stix", valid_from="2026-10-01T00:00:00Z", valid_until="2026-12-31T00:00:00Z",
    confidence=70, created_by_ref=me.id, object_marking_refs=[TLP_GREEN])
rel = Relationship(ind, "indicates", camp, created_by_ref=me.id)
open("bundle.json", "w").write(Bundle(me, camp, ind, rel).serialize(pretty=True))
```

3. Validate.

```bash
stix2_validator bundle.json
```

Expected output: a report stating the bundle is valid, possibly with warnings for recommended properties. Introduce an error (delete `pattern_type`) and confirm the validator rejects it.

4. Serve it over TAXII with medallion. Create a medallion configuration with one API root and one collection (the medallion README includes a sample config with in-memory backend), load `bundle.json` into it, start the server, then poll.

```python
from taxii2client.v21 import Collection
c = Collection("http://127.0.0.1:5000/api1/collections/<collection-id>/", user="lab", password="lab")
print(len(c.get_objects()["objects"]))
```

Expected output: `4`, the number of objects you published. Use HTTPS and real credentials for anything beyond a local lab.

## Common pitfalls

- Using a custom `x-crypto-address` type without a chain identifier.
- Omitting `valid_until`, so consumers keep indicators forever.
- Exporting MISP attributes with `to_ids` false into blocking systems.
- Treating `confidence` as comparable between producers without calibration.
- Sharing STIX bundles with free-text descriptions that leak victim details.

## Exercises

1. Set up a local MISP instance and create an event for a fictional drainer campaign.
2. Export it as STIX 2.1 and validate with the STIX validator.
3. Design a STIX extension for crypto addresses with chain ID.
4. Add a `sighting` object to the worked-example bundle and explain how a consumer should use it.

## Further reading

- STIX 2.1 spec: <https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html>
- TAXII 2.1 spec: <https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html>
- MISP: <https://www.misp-project.org>
- cti-stix-validator: <https://github.com/oasis-open/cti-stix-validator>
- cti-python-stix2: <https://github.com/oasis-open/cti-python-stix2>
- medallion TAXII server: <https://github.com/oasis-open/cti-taxii-server>
