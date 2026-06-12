# meok-eu-cra-mcp

> EU Cyber Resilience Act (CRA, Regulation (EU) 2024/2847) compliance MCP server by [MEOK AI Labs](https://meok.ai).

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/meok-eu-cra-mcp)](https://pypi.org/project/meok-eu-cra-mcp/)

The MCP for **CRA** — the EU Cyber Resilience Act (Reg (EU) 2024/2847). Applies to every product with software sold in the EU, including AI systems, IoT devices, and standalone software.

| Date | What |
|---|---|
| **10 Dec 2024** | CRA entered into force |
| **11 Sep 2026** | Vulnerability reporting obligations start (Art 11, Art 14) |
| **11 Dec 2027** | Full applicability — every product must comply |

CRA co-exists with **NIS2** (for the *organisation* operating the product) and **EU AI Act** (for the *AI capabilities* of the product). Most regulated entities need to comply with both.

## 4 obligations covered

| Obligation | What | Why it bites |
|---|---|---|
| **Art 6 + Annex I — Essential cybersecurity requirements** | Risk-based security at design, no known vulns at placement, secure-by-default config, encryption, integrity, DoS resilience, attack surface reduction, security update mechanism | Every product on the EU market. Penalty: €15M or 2.5% of global turnover |
| **Art 10 — Vulnerability handling** | Identify, document, test, fix, disseminate, free, throughout product lifetime or 5 years (shorter) | Every product. ENISA 24h reporting for actively exploited vulns starts 11 Sep 2026 |
| **Art 13 — Conformity assessment** | Self-assessment (Class I) or Notified Body (Class II) before placing on market | Every product. Class II is required for the 5 critical categories in Annex III (password managers, identity/auth, VPN, network management, SIEM, PKI issuers) |
| **Annex I §2 — SBOM + secure-by-default** | Software Bill of Materials (CycloneDX or SPDX), auto-update enabled, factory-reset procedure for end-of-life | Every product. SBOM is the de facto machine-readable compliance evidence |

## Install

```bash
pip install meok-eu-cra-mcp
meok-eu-cra-mcp
```

## Tools (5)

### `cra_overview()`

CRA framework summary: scope, key dates, penalty structure, exclusions (medical devices, motor vehicles, aviation, FOSS-no-commercial), and how it co-exists with NIS2, EU AI Act, GDPR, and the Product Liability Directive 2024/2853.

### `classify_cra_obligations(places_product_on_eu_market, has_internet_connectivity, handles_personal_data, is_critical_infrastructure, is_iot_or_connected_device, is_ai_system_under_ai_act, is_free_and_open_source_no_commercial, is_medical_device, is_motor_vehicle, is_aviation_product)`

Map product characteristics to the 4 CRA obligations + criticality class (Class I self-assessment vs Class II Notified Body) + ENISA reporting requirement + 24h reporting window + 2027-12-11 full applicability date. Exclusions handled first: medical devices, motor vehicles, aviation, FOSS-no-commercial.

### `audit_cra_pipeline(tenant_id, has_sbom, sbom_format, has_security_txt, has_vulnerability_disclosure_policy, has_signed_releases, has_auto_update_mechanism, has_data_removal_procedure, has_threat_model, has_ssa_or_penetration_test, has_secure_sdlc_documented, sample_sbom_components)`

Audit an existing product pipeline for CRA compliance gaps. Checks for missing SBOM, security.txt, VDP, signed releases, auto-update, data-removal procedure, threat model, security testing, Secure SDLC. Also scans sample SBOM components for known-vulnerable packages (log4j 1.x, openssl 1.0.1, etc.) and flags critical if found.

### `sign_cra_attestation(entity_name, product_name, criticality_class, compliance_score, has_sbom, has_vdp, has_signed_releases, contact_email)`

Generate a hash-chained CRA compliance attestation via the canonical meok-attestation-api `/sign` endpoint. Returns `cert_id`, `signature`, `verify_url`, `audit_url`, `issued_at`, `expires_at`, `kid`. Requires `MEOK_API_KEY` env var (free tier: 1 cert/day; Pro tier £199/mo: unlimited).

### `crosswalk_cra_to_nis2()`

Side-by-side CRA ↔ NIS2 crosswalk: 10 rows (scope, effective date, authority, reporting, vulnerability handling, secure-by-default, SBOM, penalty, conformity assessment, pen-test cadence). Practical note: CRA is product-side; NIS2 is org-side. A cloud-hosted AI product is CRA-regulated (as a product) AND the cloud provider is NIS2-regulated (as an essential entity). One assessment, both regimes, different deliverables.

## Honest limits

- **No actual SBOM generation**: you bring the SBOM (or run Syft/cdxgen first). The MCP tells you the format + standards
- **No ENISA reporting submission**: the ENISA single reporting platform is a separate portal (URL TBD by ENISA, available from 11 Sep 2026)
- **No Notified Body contact**: Notified Bodies are designated by member states; you need to find one in your category
- **No actual conformity assessment**: the MCP tells you the procedure (self-assessment vs Notified Body) and the deliverables (DoC, CE marking, technical documentation per Annex VII)
- **No Cybersecurity Act integration**: the MCP doesn't pull from the EU Cybersecurity Act certification database; you bring your own cert

## Tests

```bash
cd eu-cra-mcp
pip install mcp httpx pytest
pytest tests/test_eu_cra_mcp.py -v
```

11 tests across all 5 tools + exclusions, no live API required.

## Cross-region

- **NIS2** — `crosswalk_cra_to_nis2()` covers the 10 most divergent requirements
- **EU AI Act** — high-risk AI must satisfy both CRA (product cyber) + EU AI Act (AI risk management)
- **GDPR** — CRA Art 6(g) data minimisation overlaps with GDPR Art 5(1)(c)
- **Product Liability Directive 2024/2853** — CRA violation is evidence of defect
- **UK** — UK Product Security and Telecommunications Infrastructure Act 2022 (PSTI) covers similar ground; UK NCSC is the authority
- **US** — no federal equivalent; California SB-327 (IoT security) + NY DFS Part 500 (financial services) are the closest

## See also

- `meok-pipl-mcp` — China PIPL (data side; this one covers the product side)
- `meok-fda-samd-mcp` — US FDA SaMD (healthcare-specific, similar structure)
- `meok-eu-ai-act-mcp` — EU AI Act (companion to CRA for AI products)
- `meok-owasp-agentic-mcp` — OWASP Agentic Top 10 (security testing patterns)
- `meok-compliance-gateway` — 13-framework crosswalk
- `meok-attestation-api` — canonical SIGIL signer (Ed25519, kid d4cb0eaa)

## License

MIT — MEOK AI Labs, UK Companies House 16939677.
