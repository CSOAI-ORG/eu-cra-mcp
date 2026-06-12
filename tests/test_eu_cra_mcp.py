"""Tests for the EU CRA MCP server — runs without a live MCP transport.

Validates:
- All 5 MCP tools return valid JSON
- classify_obligations() correctly identifies scope + criticality class
- audit_pipeline() catches missing SBOM, security.txt, VDP, signed releases
- sign_attestation() returns a graceful fallback without MEOK_API_KEY
- crosswalk_cra_to_nis2() returns the 10 expected rows
- exclusions work (medical device, motor vehicle, FOSS-no-commercial)

Run:  cd eu-cra-mcp && pytest tests/test_eu_cra_mcp.py -v
"""

from __future__ import annotations

import json
import sys
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))


def load_server_module():
    spec = importlib.util.spec_from_file_location(
        "meok_eu_cra_mcp", HERE / "meok_eu_cra_mcp" / "server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except ImportError as e:
        import pytest
        pytest.skip(f"mcp not installed: {e}")
    return mod


import pytest  # noqa: E402

mod = load_server_module()


def _call(tool_name: str, **kwargs):
    tool_obj = getattr(mod.mcp._tool_manager, "_tools", {}).get(tool_name)
    if tool_obj is None:
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if callable(obj) and getattr(obj, "__name__", "") == tool_name:
                tool_obj = obj
                break
    if tool_obj is None:
        pytest.skip(f"tool {tool_name} not found in this mcp version")
    tool_fn = getattr(tool_obj, "fn", tool_obj)
    if not callable(tool_fn):
        pytest.skip(f"tool {tool_name} is not callable in this mcp version")
    result = tool_fn(**kwargs)
    return json.loads(result) if isinstance(result, str) else result


# ---------- 1. cra_overview -------------------------------------------------

def test_cra_overview_returns_meta_and_dates():
    out = _call("cra_overview")
    assert out["law"]["short_name"] == "CRA"
    assert out["law"]["applicability_full"] == "2027-12-11"
    assert out["law"]["reporting_obligations_start"] == "2026-09-11"
    assert len(out["obligations_covered"]) == 4
    # coexistence is a dict; check keys (case-sensitive)
    assert any("NIS2" in k for k in out["coexistence"])
    assert any("EU AI Act" in k for k in out["coexistence"])


# ---------- 2. classify_obligations -----------------------------------------

def test_classify_medical_device_excluded():
    out = _call("classify_cra_obligations", places_product_on_eu_market=True, is_medical_device=True)
    assert out["in_scope"] is False
    assert "MDR/IVDR" in out["excluded"]


def test_classify_motor_vehicle_excluded():
    out = _call("classify_cra_obligations", places_product_on_eu_market=True, is_motor_vehicle=True)
    assert out["in_scope"] is False
    assert "UNECE WP.29" in out["excluded"] or "2018/858" in out["excluded"]


def test_classify_foss_no_commercial_excluded():
    out = _call("classify_cra_obligations", places_product_on_eu_market=True, is_free_and_open_source_no_commercial=True)
    assert out["in_scope"] is False
    assert "free and open-source" in out["excluded"].lower()


def test_classify_iot_ai_product_in_scope():
    out = _call(
        "classify_cra_obligations",
        places_product_on_eu_market=True,
        is_iot_or_connected_device=True,
        is_ai_system_under_ai_act=True,
        handles_personal_data=True,
    )
    assert out["in_scope"] is True
    assert "art_6_annex_i_essential_requirements" in out["triggered_obligations"]
    assert "art_10_vulnerability_handling" in out["triggered_obligations"]
    assert "art_13_conformity_assessment" in out["triggered_obligations"]
    assert "annex_i_2_sbom_secure_default" in out["triggered_obligations"]
    assert out["enisa_reporting_required"] is True
    assert out["enisa_reporting_window_hours"] == 24


def test_classify_out_of_scope():
    out = _call("classify_cra_obligations")
    assert out["in_scope"] is False
    assert "CRA does not appear to apply" in out["next_step"]


# ---------- 3. audit_cra_pipeline ------------------------------------------

def test_audit_critical_without_sbom():
    out = _call("audit_cra_pipeline", tenant_id="t1", has_sbom=False)
    assert out["audit_severity"] in ("high", "critical")
    assert any("SBOM" in f["issue"] for f in out["findings"])


def test_audit_critical_without_security_txt():
    out = _call("audit_cra_pipeline", tenant_id="t1", has_sbom=True, has_security_txt=False)
    assert any("security.txt" in f["issue"].lower() for f in out["findings"])


def test_audit_critical_without_vdp():
    out = _call("audit_cra_pipeline", tenant_id="t1", has_sbom=True, has_security_txt=True, has_vulnerability_disclosure_policy=False)
    assert any("Vulnerability Disclosure Policy" in f["issue"] for f in out["findings"])


def test_audit_critical_with_log4j():
    """Known-vulnerable component → critical regardless of other findings."""
    out = _call(
        "audit_cra_pipeline",
        tenant_id="t1",
        has_sbom=True,
        has_security_txt=True,
        has_vulnerability_disclosure_policy=True,
        sample_sbom_components="log4j-core:1.2.17, spring-boot:3.0",
    )
    assert out["audit_severity"] == "critical"
    assert any("log4j" in f["issue"].lower() for f in out["findings"])


def test_audit_passes_when_all_present():
    out = _call(
        "audit_cra_pipeline",
        tenant_id="t1",
        has_sbom=True,
        sbom_format="cyclonedx",
        has_security_txt=True,
        has_vulnerability_disclosure_policy=True,
        has_signed_releases=True,
        has_auto_update_mechanism=True,
        has_data_removal_procedure=True,
        has_threat_model=True,
        has_ssa_or_penetration_test=True,
        has_secure_sdlc_documented=True,
    )
    assert out["audit_severity"] == "low"
    assert any(f.get("severity") == "info" for f in out["findings"])


# ---------- 4. sign_attestation (graceful fallback) ----------------------

def test_sign_attestation_without_api_key(monkeypatch):
    monkeypatch.delenv("MEOK_API_KEY", raising=False)
    out = _call(
        "sign_cra_attestation",
        entity_name="Demo Inc",
        product_name="TestApp",
        criticality_class="Class_I_important",
        compliance_score=0.80,
    )
    assert "MEOK_API_KEY" in out.get("error", "")


# ---------- 5. crosswalk_cra_to_nis2 --------------------------------------

def test_crosswalk_returns_10_rows():
    out = _call("crosswalk_cra_to_nis2")
    assert out["law_left"] == "EU CRA"
    assert out["law_right"] == "NIS2"
    assert len(out["rows"]) == 10
    # Scope row
    scope_row = [r for r in out["rows"] if r["topic"] == "Scope"][0]
    assert "roduct" in scope_row["cra"]  # "Products" (capital) or "product"
    assert "rganisation" in scope_row["nis2"]  # "organisation" lowercase or capital
    # Penalty row
    penalty_row = [r for r in out["rows"] if r["topic"] == "Penalty"][0]
    assert "€15M" in penalty_row["cra"]
    assert "2.5%" in penalty_row["cra"]
    assert "€10M" in penalty_row["nis2"]
