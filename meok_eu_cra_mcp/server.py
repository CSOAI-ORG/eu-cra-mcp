"""
MEOK EU Cyber Resilience Act (CRA) MCP Server
=============================================

The MCP for Regulation (EU) 2024/2847 — the EU Cyber Resilience Act.
CRA applies to every product with software sold in the EU, including
AI systems, IoT devices, and standalone software. Effective dates:
- 11 Dec 2024: entered into force
- 11 Sep 2026: reporting obligations start (Art 14)
- 11 Dec 2027: full applicability (Annex I essential requirements)

CRA co-exists with:
- NIS2 Directive (2022/2555) — for the *organisation* operating the
  product (operators of essential services, important entities)
- EU AI Act — for the *AI capabilities* of the product
- GDPR — for the *personal data* processed by the product
- Product Liability Directive 2024/2853 — for damage caused by defects

This MCP covers the 4 practical obligations every CRA-regulated
manufacturer must satisfy:

- Art 6 + Annex I: Essential cybersecurity requirements
- Art 10: Vulnerability handling (disclosure + remediation)
- Art 13: Conformity assessment (self-assessment or third-party)
- Annex I §2: SBOM (Software Bill of Materials) + secure-by-default config

CSOAI is the body; this MCP is the surface that the Council substrate
reads. No shadow signers, no parallel keys — compliance posture is
served by the same meok-attestation-api spine.
"""

from __future__ import annotations

import json
import os
import re
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

try:
    from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer
except ImportError:
    raise ImportError("pip install mcp>=1.0.0 — required for the MCP server")

mcp = FastMCP("meok-eu-cra-mcp")

CRA_META = {
    "name": "Cyber Resilience Act",
    "short_name": "CRA",
    "law_number": "Regulation (EU) 2024/2847",
    "entered_into_force": "2024-12-10",
    "applicability_full": "2027-12-11",
    "reporting_obligations_start": "2026-09-11",
    "authority": "ENISA (European Union Agency for Cybersecurity) + national market surveillance authorities",
    "scope": "Products with software sold in the EU, including connected devices, IoT, AI systems, and standalone software. Excludes: medical devices (covered by MDR/IVDR), motor vehicles (covered by UNECE WP.29), aviation (covered by EASA), products designed exclusively for national security/defence, and 'free and open-source software' outside of commercial activity.",
    "max_fine": "Up to €15 million or 2.5% of global annual turnover (whichever is higher) for essential cybersecurity requirement violations; up to €1M or 1% for incorrect/misleading information to regulators",
    "url": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
}

# 4 articles covered (the practical obligations)
CRA_OBLIGATIONS = {
    "art_6_annex_i_essential_requirements": {
        "title": "Essential cybersecurity requirements (Art 6 + Annex I)",
        "trigger": "Every product with software placed on the EU market",
        "obligation": "Products must be designed, developed, and produced to ensure: (a) appropriate level of cybersecurity based on risks; (b) no known exploitable vulnerabilities at time of placement; (c) secure-by-default configuration; (d) protection against unauthorised access (authentication, access control); (e) confidentiality of stored/transmitted data (encryption); (f) integrity of stored/transmitted data; (g) data minimisation; (h) resilience against DoS; (i) attack surface reduction; (j) exploit mitigations; (k) security update mechanism; (l) record of security-relevant events for monitoring.",
        "who": "Manufacturer (the entity placing the product on the EU market, including non-EU manufacturers via EU rep)",
        "applicability": "Full applicability from 11 December 2027",
        "technical_options": [
            "SBOM in CycloneDX or SPDX format, machine-readable, updated with every release",
            "Secure Software Development Lifecycle (SSDLC) per ISO/IEC 27034 or NIST SP 800-218 SSDF",
            "Threat model per STRIDE / LINDDUN, refreshed at every major release",
            "Vulnerability scanning (SAST + DAST + SCA) in CI/CD, with documented remediation SLAs",
            "Penetration testing at least annually (for products handling PI or operating in critical infrastructure)",
            "Software signing (Sigstore, sigstore-rs, or PKCS#11 HSM) for every release artifact",
        ],
    },
    "art_10_vulnerability_handling": {
        "title": "Vulnerability handling (Art 10)",
        "trigger": "Every product with software placed on the EU market, for the entire expected product lifetime OR 5 years (whichever is shorter)",
        "obligation": "Manufacturers must: (a) identify and document vulnerabilities contained in the product; (b) test and review the product; (c) develop and publish security updates free of charge; (d) ensure effective dissemination of updates; (e) promptly notify ENISA of actively exploited vulnerabilities via the single reporting platform, within 24 hours of becoming aware (effective from 11 Sep 2026); (f) inform users about the vulnerability and available fixes; (g) provide a coordinated vulnerability disclosure (CVD) policy and contact (security.txt).",
        "who": "Manufacturer",
        "effective": "Reporting obligations (Art 11 + Art 14) start 11 September 2026",
        "technical_options": [
            "Security.txt at /.well-known/security.txt per RFC 9116",
            "Vulnerability Disclosure Policy published at a stable URL (e.g. /security or /responsible-disclosure)",
            "ENISA single reporting platform integration (URL TBD by ENISA)",
            "Coordinated disclosure timeline: ack within 3 business days, status update within 30 days, fix within 90 days for high/critical CVEs",
            "Free security updates via auto-update mechanism OR signed downloadable updates + advisory",
        ],
    },
    "art_13_conformity_assessment": {
        "title": "Conformity assessment (Art 13 + Annex VIII)",
        "trigger": "Every product with software placed on the EU market",
        "obligation": "Manufacturer must perform a conformity assessment before placing the product on the market. The procedure depends on the criticality class: (a) Self-assessment per Annex IX for 'important' products (Class I) — manufacturer declares conformity; (b) Third-party assessment by a Notified Body for 'critical' products (Class II) — assessed by a designated body. The criticality class is determined by Art 7 + Annex III (impact-based: function-critical, health/safety, etc.).",
        "who": "Manufacturer (self-assessment) OR manufacturer + Notified Body (third-party)",
        "deliverable": "EU Declaration of Conformity (DoC) + CE marking + technical documentation per Annex VII (preserved for 10 years)",
        "technical_options": [
            "Self-assessment per Annex IX for Class I products — manufacturer drafts the DoC, affixes CE mark",
            "Third-party assessment by Notified Body for Class II — formally designated under Reg 765/2008",
            "Common specifications (CS) adopted by the European Commission when harmonised standards don't exist",
            "Conformity assessment modules (A, B, C, D, E, F, G, H) — most manufacturers use module A (internal production control) or module H (full quality assurance)",
        ],
    },
    "annex_i_2_sbom_secure_default": {
        "title": "SBOM + secure-by-default configuration (Annex I §2)",
        "trigger": "Every product with software placed on the EU market",
        "obligation": "Annex I §2 specifies that products must: (a) be delivered with a secure-by-default configuration including automatic security updates, where technically feasible; (b) provide a Software Bill of Materials (SBOM) covering all third-party components; (c) enable users to securely remove or transfer their data on disposal or transfer of ownership (Art 5(2)).",
        "who": "Manufacturer",
        "deliverable": "SBOM file (CycloneDX or SPDX), secure-by-default config documented in user manual, data-removal guidance for end-of-life",
        "technical_options": [
            "SBOM generated at build time (Syft, cdxgen, or vendor tooling) and updated per release",
            "Auto-update enabled by default for products with internet connectivity",
            "Documented user-facing reset / factory wipe procedure for end-of-life disposal",
            "CPE (Common Platform Enumeration) identifiers for each component, indexed in a public vulnerability database (NVD, OSV, GHSA)",
        ],
    },
}


@mcp.tool()
def cra_overview() -> str:
    """CRA framework summary: scope, key dates, penalty structure, and
    how it co-exists with NIS2, EU AI Act, GDPR, and the Product
    Liability Directive."""
    return json.dumps({
        "law": CRA_META,
        "obligations_covered": list(CRA_OBLIGATIONS.keys()),
        "key_dates": {
            "2024-12-10": "CRA entered into force (publication + 20 days)",
            "2026-09-11": "Vulnerability reporting obligations start (Art 11, Art 14)",
            "2027-12-11": "Full applicability — every product must comply",
        },
        "coexistence": {
            "NIS2 Directive (2022/2555)": "CRA is for the *product*; NIS2 is for the *organisation* operating it. A cloud-hosted AI product is CRA-regulated (as a product) AND the cloud provider is NIS2-regulated (as an essential entity).",
            "EU AI Act": "CRA is product cybersecurity; EU AI Act is AI-specific risk management. High-risk AI must satisfy BOTH (CRA Annex I + AI Act Art 9/15).",
            "GDPR": "CRA Art 6(g) requires data minimisation; GDPR Art 5(1)(c) requires the same. If your product processes personal data, you need both.",
            "Product Liability Directive 2024/2853": "CRA violations don't create per-se liability, but failure to comply is evidence of defect in a product liability claim.",
        },
        "next_step": "Call classify_cra_obligations() to map your product characteristics to the 4 obligations + criticality class (Class I self-assessment vs Class II Notified Body)",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def classify_cra_obligations(
    places_product_on_eu_market: bool = False,
    has_internet_connectivity: bool = False,
    handles_personal_data: bool = False,
    is_critical_infrastructure: bool = False,
    is_iot_or_connected_device: bool = False,
    is_ai_system_under_ai_act: bool = False,
    is_free_and_open_source_no_commercial: bool = False,
    is_medical_device: bool = False,
    is_motor_vehicle: bool = False,
    is_aviation_product: bool = False,
) -> str:
    """Map product characteristics to the 4 CRA obligations + the
    criticality class (Class I self-assessment vs Class II Notified Body)
    + effective date + ENISA reporting requirement."""
    triggered: list[str] = []
    criticality_class = None
    enisa_reporting_required = False
    in_scope = False
    excluded = None

    # 1. Check exclusions first
    if is_medical_device:
        excluded = "Medical devices are regulated by MDR/IVDR, not CRA (Art 2(2))."
    elif is_motor_vehicle:
        excluded = "Motor vehicles are regulated by UNECE WP.29 / Regulation (EU) 2018/858, not CRA (Art 2(3))."
    elif is_aviation_product:
        excluded = "Aviation products are regulated by EASA, not CRA (Art 2(4))."
    elif is_free_and_open_source_no_commercial:
        excluded = "Free and open-source software outside commercial activity is out of CRA scope (Art 2(8)). Stewards of OSS projects are not 'manufacturers' for CRA purposes."

    if excluded is not None:
        return json.dumps({
            "in_scope": False,
            "excluded": excluded,
            "triggered_obligations": [],
            "next_step": "CRA does not apply. Check NIS2 (if you're an operator of essential services) and the sector-specific regulation (MDR/IVDR, WP.29, EASA).",
        }, indent=2)

    # 2. Determine in-scope
    if places_product_on_eu_market:
        in_scope = True
        triggered.extend([
            "art_6_annex_i_essential_requirements",
            "annex_i_2_sbom_secure_default",
        ])

        # Criticality class per Art 7 + Annex III
        # Class II (critical, Notified Body) when the product is a 'critical product'
        # Critical products: password managers, identity/auth systems, standalone browsers,
        # VPN, network management systems, SIEM, boot managers, public key issuers, etc.
        if any([
            is_iot_or_connected_device,
            is_ai_system_under_ai_act,
            is_critical_infrastructure,
        ]):
            # Most fall into Class I (important) by default; Class II requires
            # specific Annex III identification
            criticality_class = "Class_I_important"  # default; can be elevated to II

        # Vulnerability handling (Art 10) applies to all in-scope
        triggered.append("art_10_vulnerability_handling")
        enisa_reporting_required = True

        # Conformity assessment (Art 13)
        triggered.append("art_13_conformity_assessment")

    return json.dumps({
        "in_scope": in_scope,
        "triggered_obligations": triggered,
        "details": {k: CRA_OBLIGATIONS[k] for k in triggered if k in CRA_OBLIGATIONS},
        "criticality_class": criticality_class,
        "criticality_note": (
            "Class I (important) → self-assessment per Annex IX, manufacturer drafts DoC. "
            "Class II (critical) → Notified Body assessment per Annex VIII. "
            "Annex III lists 5 critical product categories: (1) identity & access management, "
            "(2) standalone browsers, password managers, (3) standalone VPN, (4) network management "
            "systems, SIEM, (5) public key infrastructure issuers. Most AI/ML products fall in Class I "
            "unless they hit one of these."
        ),
        "enisa_reporting_required": enisa_reporting_required,
        "enisa_reporting_window_hours": 24,
        "enisa_reporting_start_date": "2026-09-11",
        "full_applicability_date": "2027-12-11",
        "next_step": (
            "Call audit_cra_pipeline() to scan your current product for compliance gaps. "
            "Or sign_cra_attestation() (Pro tier, £199/mo) for an audit-evidence cert."
        ) if triggered else (
            "CRA does not appear to apply (no product placed on EU market, or excluded category). "
            "Re-check if you sell, distribute, or make available a product with software in any EU member state."
        ),
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def audit_cra_pipeline(
    tenant_id: str,
    has_sbom: bool = False,
    sbom_format: str = "",
    has_security_txt: bool = False,
    has_vulnerability_disclosure_policy: bool = False,
    has_signed_releases: bool = False,
    has_auto_update_mechanism: bool = False,
    has_data_removal_procedure: bool = False,
    has_threat_model: bool = False,
    has_ssa_or_penetration_test: bool = False,
    has_secure_sdlc_documented: bool = False,
    sample_sbom_components: str = "",
) -> str:
    """Audit an existing product pipeline for CRA compliance gaps. Returns
    a structured severity-ranked finding list across the 4 obligations."""

    findings: list[dict[str, Any]] = []
    severity = "low"

    if not has_sbom:
        findings.append({
            "issue": "No SBOM (Software Bill of Materials) — required per Annex I §2",
            "severity": "high",
            "fix": "Generate an SBOM at every release using Syft, cdxgen, or vendor tooling. Use CycloneDX (preferred for security use cases) or SPDX. Publish with each release artifact.",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)
    else:
        if sbom_format and sbom_format.lower() not in ("cyclonedx", "spdx"):
            findings.append({
                "issue": f"SBOM uses {sbom_format} format — CRA does not specify a format, but ENISA and the EU Cybersecurity Act recognize CycloneDX and SPDX as the canonical formats. Recommend switching.",
                "severity": "low",
            })
        else:
            findings.append({
                "issue": f"SBOM present in {sbom_format or 'unknown'} format — verify it includes CPE identifiers for every component for NVD/OSV/GHSA matching",
                "severity": "info",
            })

    if not has_security_txt:
        findings.append({
            "issue": "No security.txt at /.well-known/security.txt — required per Art 10 (vulnerability disclosure)",
            "severity": "high",
            "fix": "Add /.well-known/security.txt per RFC 9116: Contact (mailto:security@yourdomain), Expires (180 days), Preferred-Languages (en), Canonical (link to full policy).",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)

    if not has_vulnerability_disclosure_policy:
        findings.append({
            "issue": "No Vulnerability Disclosure Policy (VDP) — required per Art 10",
            "severity": "high",
            "fix": "Publish a VDP at a stable URL (e.g. /security, /responsible-disclosure, or /.well-known/security.txt). Include: scope (what's in/out), safe harbor language, expected response times (ack 3 BD, status 30 days, fix 90 days for high/critical), and contact.",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)

    if not has_signed_releases:
        findings.append({
            "issue": "No signed releases — best practice for supply-chain security (sigstore, PGP, or HSM-backed signing)",
            "severity": "medium",
            "fix": "Sign every release artifact with sigstore (cosign) or your HSM-backed key. Publish the public key / certificate at a stable URL (e.g. /.well-known/keys/). Verify signatures in your update mechanism.",
        })
        severity = max(severity, "medium", key=["low", "medium", "high", "critical"].index)

    if not has_auto_update_mechanism:
        findings.append({
            "issue": "No auto-update mechanism — required per Annex I §2 (secure-by-default)",
            "severity": "medium",
            "fix": "Enable auto-update by default for products with internet connectivity. For products that can't auto-update, document the manual update procedure and provide free security patches for the entire expected product lifetime or 5 years (whichever is shorter).",
        })
        severity = max(severity, "medium", key=["low", "medium", "high", "critical"].index)

    if not has_data_removal_procedure:
        findings.append({
            "issue": "No data removal procedure — required per Art 5(2) and Annex I §2",
            "severity": "medium",
            "fix": "Provide a documented factory-reset / data-wipe procedure for end-of-life disposal or transfer of ownership. Document it in the user manual. Verify it removes all PI from local storage, cloud accounts, and caches.",
        })
        severity = max(severity, "medium", key=["low", "medium", "high", "critical"].index)

    if not has_threat_model:
        findings.append({
            "issue": "No threat model — required for Annex I essential requirements (basis for risk-based security decisions)",
            "severity": "high",
            "fix": "Build a threat model per STRIDE or LINDDUN, refreshed at every major release. Identify trust boundaries, data flows, assets, and threats. Document mitigations per threat.",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)

    if not has_ssa_or_penetration_test:
        findings.append({
            "issue": "No security testing (SAST, DAST, SCA) or penetration test — best practice for CRA conformance + AI Act cybersecurity",
            "severity": "high",
            "fix": "Run SAST (e.g. Semgrep, CodeQL), DAST (e.g. OWASP ZAP), SCA (e.g. Snyk, Trivy) in CI/CD. Run a third-party penetration test at least annually. Document remediation SLAs based on severity.",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)

    if not has_secure_sdlc_documented:
        findings.append({
            "issue": "No documented Secure SDLC — required for Annex I essential requirements",
            "severity": "high",
            "fix": "Adopt a Secure SDLC framework: ISO/IEC 27034, NIST SP 800-218 SSDF, or Microsoft's SDL. Document the gates (security design review, threat modeling, code review, security testing, incident response).",
        })
        severity = max(severity, "high", key=["low", "medium", "high", "critical"].index)

    if sample_sbom_components:
        # Check for known-vulnerable components
        for component in sample_sbom_components.split(","):
            c = component.strip().lower()
            if any(old in c for old in ["log4j:1.", "log4j-core:1.", "spring-boot:2.0", "django:1.", "flask:0.", "openssl:1.0.1"]):
                findings.append({
                    "issue": f"Known-vulnerable component detected: {component}",
                    "severity": "critical",
                    "fix": "Update to a patched version. CRA Annex I §1(a) requires 'no known exploitable vulnerabilities at time of placement' — running known-vulnerable components is a direct violation.",
                })
                severity = "critical"

    if not findings:
        findings.append({
            "issue": "All 4 CRA obligations appear to have documentation in place",
            "severity": "info",
        })

    sample_hash = hashlib.sha256((sample_sbom_components or tenant_id).encode()).hexdigest()[:16]
    record_id = f"CRA-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

    return json.dumps({
        "audit_record_id": record_id,
        "tenant_id": tenant_id,
        "audit_severity": severity,
        "findings_count": len(findings),
        "findings": findings,
        "sample_hash": sample_hash,
        "audit_url_template": f"https://meok-attestation-api.vercel.app/api/audit?tenant={tenant_id}&framework=eu-cra",
        "next_steps": [
            "If CRITICAL: do NOT place this product on the EU market. Update known-vulnerable components first.",
            "If HIGH: full remediation sprint (4-8 weeks). SBOM + security.txt + VDP + threat model are the usual bottlenecks.",
            "If MEDIUM: incorporate into next release cycle.",
            "When green: sign_cra_attestation() (Pro tier, £199/mo) for an audit-evidence cert on /v/{id}",
        ],
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def sign_cra_attestation(
    entity_name: str,
    product_name: str,
    criticality_class: str,
    compliance_score: float,
    has_sbom: bool = False,
    has_vdp: bool = False,
    has_signed_releases: bool = False,
    contact_email: str = "",
) -> str:
    """Generate a hash-chained CRA compliance attestation via the canonical
    meok-attestation-api /sign endpoint. Pro tier (£199/mo) is unlimited;
    free tier is 1 cert/day."""
    api_key = os.getenv("MEOK_API_KEY", "")
    if not api_key:
        return json.dumps({
            "error": "MEOK_API_KEY env var not set. Free tier: 1 cert/day via /sign with CSOAI- key prefix. Pro tier (£199/mo): unlimited, get key at https://csoai.org/checkout",
            "fallback": "Use sovereign-temple/sovereign_continual_learning.py for an offline-signed cert.",
        }, indent=2)

    findings = [
        f"Product: {product_name}",
        f"Criticality class: {criticality_class}",
        f"SBOM: {has_sbom}",
        f"VDP: {has_vdp}",
        f"Signed releases: {has_signed_releases}",
        f"Compliance score: {compliance_score:.2f}",
    ]

    payload = {
        "regulation": f"EU Cyber Resilience Act (Regulation (EU) 2024/2847) — {criticality_class}",
        "entity": entity_name,
        "score": compliance_score,
        "findings": findings,
        "tier": "pro",
    }

    try:
        import httpx
        r = httpx.post(
            "https://meok-attestation-api.vercel.app/sign",
            json={"api_key": api_key, "email": contact_email, **payload},
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )
        r.raise_for_status()
        cert = r.json()
    except Exception as e:
        return json.dumps({"error": f"attestation API unreachable: {e}"}, indent=2)

    return json.dumps({
        "cert_id": cert.get("cert_id", cert.get("id")),
        "signature": (cert.get("signature_ed25519", cert.get("signature", ""))[:32] + "…") if cert.get("signature_ed25519") or cert.get("signature") else None,
        "kid": cert.get("kid"),
        "verify_url": f"https://meok-attestation-api.vercel.app/v/{cert.get('cert_id', cert.get('id'))}",
        "audit_url": "https://meok-attestation-api.vercel.app/api/audit",
        "issued_at": cert.get("issued_at"),
        "expires_at": cert.get("expires_at", "2027-12-11T00:00:00Z"),
        "next_renewal_due": "On any change to the product's intended use, threat model, or third-party components",
        "spine": "meok-attestation-api v1.2.0 / Ed25519 / kid d4cb0eaa",
        "spec_ref": "csoai.org/council/law — EU CRA cross-region",
    }, indent=2, ensure_ascii=False)


@mcp.tool()
def crosswalk_cra_to_nis2() -> str:
    """Side-by-side CRA ↔ NIS2 crosswalk. CRA is for the *product*;
    NIS2 is for the *organisation* operating the product. Most regulated
    entities need to comply with BOTH."""
    crosswalk = [
        {"topic": "Scope", "cra": "Products with software placed on the EU market (manufacturer-side)", "nis2": "Operators of essential services + important entities (organisation-side)"},
        {"topic": "Effective date", "cra": "2024-12-10 in force; 2026-09-11 reporting; 2027-12-11 full applicability", "nis2": "2024-10-17 transposition deadline (national laws vary)"},
        {"topic": "Authority", "cra": "ENISA + national market surveillance authorities (e.g. BSI in DE, ANSSI in FR, NCSC in UK)", "nis2": "National cybersecurity authorities + sectoral regulators (e.g. ENISA, ECB for finance)"},
        {"topic": "Reporting", "cra": "ENISA single reporting platform (24h for actively exploited vulnerabilities, effective 2026-09-11)", "nis2": "National CSIRT within 24h (early warning), 72h (incident notification), 30 days (final report)"},
        {"topic": "Vulnerability handling", "cra": "Art 10: identify, document, test, fix, disseminate, free, throughout product lifetime or 5 years (shorter)", "nis2": "Art 12: appropriate measures to prevent + minimise impact of incidents; supply chain security"},
        {"topic": "Secure-by-default", "cra": "Annex I §2: auto-update, secure config, no known vulns at placement", "nis2": "Art 21: cybersecurity risk-management measures (encryption, MFA, BCP, training)"},
        {"topic": "SBOM", "cra": "Mandatory (Annex I §2)", "nis2": "Not explicitly required, but supply chain security is required (Art 21(2)(d))"},
        {"topic": "Penalty", "cra": "€15M or 2.5% of global annual turnover (whichever higher) for Annex I violations; €1M or 1% for misleading info", "nis2": "€10M or 2% of global annual turnover (essential entities); €7M or 1.4% (important entities)"},
        {"topic": "Conformity assessment", "cra": "Art 13: self-assessment (Class I) or Notified Body (Class II)", "nis2": "No conformity assessment per se; instead, supervisory authorities can audit + fine + impose remedies"},
        {"topic": "Pen-test cadence", "cra": "Annex I §1(j): 'state-of-the-art' security testing; no fixed cadence; recommended annually", "nis2": "Art 21(2)(f): 'appropriate policies and procedures regarding the use of cryptography and, where appropriate, encryption' + risk-based testing"},
    ]
    return json.dumps({
        "law_left": "EU CRA",
        "law_right": "NIS2",
        "rows": crosswalk,
        "practical_note": "CRA is product-side; NIS2 is org-side. A cloud-hosted AI product is CRA-regulated (as a product) AND the cloud provider is NIS2-regulated (as an essential entity). One assessment, both regimes, different deliverables.",
    }, indent=2, ensure_ascii=False)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
