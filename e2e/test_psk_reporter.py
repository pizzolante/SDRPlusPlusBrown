#!/usr/bin/env python3
"""
E2E Test: PSK Reporter Integration for FT8 Decoder

Tests that the PSK Reporter feature in the FT8 decoder module:
- Saves and loads configuration keys (pskReporterSoftware, pskReporterRig,
  pskReporterAntenna, enablePSKReporter)
- Exposes the correct config via the debug command interface
- Defaults to software="SDR++ Brown" and enabled=False

This test does NOT verify actual UDP packet sending (that would require a real
FT8 signal and network access). It verifies the config persistence and UI state.

Environment Variables:
    E2E_VERBOSE=1      - Enable verbose output
    E2E_HTTP_PORT=NNNN - Use specific HTTP port
"""

import json
import sys
from e2e_common import (
    SDRPPTestContext, get_base_config, get_radio_config,
    stats, STATS_MODE,
    assert_response_ok, assert_field_equals
)


def get_ft8_config(
    enable_psk_reporter=False,
    software="SDR++ Brown",
    rig="",
    antenna=""
):
    """Return an FT8 decoder config dict with PSK Reporter settings."""
    return {
        "processingEnabledFT8": True,
        "processingEnabledFT4": False,
        "enablePSKReporter": enable_psk_reporter,
        "pskReporterSoftware": software,
        "pskReporterRig": rig,
        "pskReporterAntenna": antenna,
        "secondsToKeepResults": 120,
        "nthreads": 1,
        "enableALLTXT": False,
        "allTxtPath": ""
    }


def test_psk_reporter():
    """Test PSK Reporter config persistence and debug commands."""
    if not STATS_MODE:
        stats.section("Testing PSK Reporter Configuration")

    total_tests = 0
    passed_tests = 0

    # ── Config: PSK Reporter enabled, rig and antenna set ──────────────────
    software_val = "SDR++ Brown Test"
    rig_val = "SDRplay RSPdx"
    antenna_val = "Dipole 40m"

    main_config = get_base_config()
    # Add ft8_decoder module instance
    main_config["moduleInstances"]["FT8 Decoder"] = {
        "module": "ft8_decoder",
        "enabled": True
    }
    # Operator callsign and locator
    main_config["operatorCallsign"] = "IU0TST"
    main_config["operatorLocation"] = "JN61FV"

    radio_config = get_radio_config(demod_id=5, bandwidth=3000.0, demod_name="USB")
    ft8_config = get_ft8_config(
        enable_psk_reporter=True,
        software=software_val,
        rig=rig_val,
        antenna=antenna_val
    )

    with SDRPPTestContext() as ctx:
        ctx.write_configs(main_config, radio_config, ft8_config)

        if not ctx.start():
            stats.final_summary(0, 0, 1)
            return False

        # ── Test 1: Module is listed ────────────────────────────────────────
        total_tests += 1
        modules = ctx.http_get("/modules")
        if isinstance(modules, dict) and "FT8 Decoder" in modules:
            stats.record("FT8 Decoder module listed", True)
            passed_tests += 1
        else:
            stats.record("FT8 Decoder module listed", False,
                         f"modules response: {modules}")

        # ── Test 2: enablePSKReporter loaded from config ────────────────────
        total_tests += 1
        resp = ctx.module_cmd("FT8 Decoder", "get_psk_reporter_config")
        ok = isinstance(resp, dict) and resp.get("enablePSKReporter") is True
        stats.record("enablePSKReporter=True loaded from config", ok,
                     f"response: {resp}" if not ok else "")
        if ok:
            passed_tests += 1

        # ── Test 3: pskReporterSoftware loaded from config ──────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("pskReporterSoftware") == software_val
        stats.record("pskReporterSoftware loaded from config", ok,
                     f"got: {resp.get('pskReporterSoftware') if isinstance(resp, dict) else resp}")
        if ok:
            passed_tests += 1

        # ── Test 4: pskReporterRig loaded from config ───────────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("pskReporterRig") == rig_val
        stats.record("pskReporterRig loaded from config", ok,
                     f"got: {resp.get('pskReporterRig') if isinstance(resp, dict) else resp}")
        if ok:
            passed_tests += 1

        # ── Test 5: pskReporterAntenna loaded from config ───────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("pskReporterAntenna") == antenna_val
        stats.record("pskReporterAntenna loaded from config", ok,
                     f"got: {resp.get('pskReporterAntenna') if isinstance(resp, dict) else resp}")
        if ok:
            passed_tests += 1

    # ── Second context: verify defaults ────────────────────────────────────
    ft8_config_defaults = get_ft8_config()  # all defaults

    with SDRPPTestContext() as ctx:
        ctx.write_configs(main_config, radio_config, ft8_config_defaults)

        if not ctx.start():
            stats.final_summary(passed_tests, total_tests, 0)
            return False

        resp = ctx.module_cmd("FT8 Decoder", "get_psk_reporter_config")

        # ── Test 6: default enablePSKReporter=False ─────────────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("enablePSKReporter") is False
        stats.record("default enablePSKReporter=False", ok,
                     f"got: {resp}" if not ok else "")
        if ok:
            passed_tests += 1

        # ── Test 7: default software="SDR++ Brown" ──────────────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("pskReporterSoftware") == "SDR++ Brown"
        stats.record("default pskReporterSoftware='SDR++ Brown'", ok,
                     f"got: {resp.get('pskReporterSoftware') if isinstance(resp, dict) else resp}")
        if ok:
            passed_tests += 1

        # ── Test 8: default rig and antenna empty ───────────────────────────
        total_tests += 1
        ok = isinstance(resp, dict) and resp.get("pskReporterRig", None) == "" and \
             resp.get("pskReporterAntenna", None) == ""
        stats.record("default rig and antenna empty", ok,
                     f"got: rig={resp.get('pskReporterRig')}, ant={resp.get('pskReporterAntenna')}"
                     if not ok else "")
        if ok:
            passed_tests += 1

    failed = total_tests - passed_tests
    stats.final_summary(passed_tests, total_tests, failed)
    return passed_tests == total_tests


if __name__ == "__main__":
    success = test_psk_reporter()
    sys.exit(0 if success else 1)
