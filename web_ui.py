#!/usr/bin/env python3
"""Local web UI for Intel TDX quote verification (offline + Intel online)."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import struct
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import verify_tdx_quote as verifier


PROJECT_ROOT = Path(__file__).resolve().parent
WEB_ROOT = Path(__file__).resolve().parent / "web"
DEFAULT_INTEL_BASE_URL = "https://api.trustauthority.intel.com"


class RequestError(Exception):
    """Raised for user-input/request validation failures."""


def _normalize_hex(value: str) -> str:
    return value.lower().strip().removeprefix("0x")


def _make_check(
    check_id: str,
    title: str,
    status: str,
    description: str,
    refs: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "description": description,
        "refs": refs or [],
        "evidence": evidence or [],
    }


def _parse_pasted_input(raw_input: Any) -> dict[str, Any]:
    if isinstance(raw_input, dict):
        payload = raw_input
    elif isinstance(raw_input, str):
        text = raw_input.strip()
        if not text:
            raise RequestError("Input is empty. Paste quote JSON or hex quote bytes.")
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            cleaned = _normalize_hex(text)
            if not re.fullmatch(r"[0-9a-f]+", cleaned) or len(cleaned) % 2 != 0:
                raise RequestError(
                    "Input is not valid JSON and not valid even-length hex. Paste full quote JSON or hex quote bytes."
                )
            payload = {"quote": cleaned}
        else:
            if not isinstance(decoded, dict):
                raise RequestError("Top-level JSON must be an object.")
            payload = decoded
    else:
        raise RequestError("Input must be a string or object.")

    if "intel_quote" not in payload and "quote" not in payload:
        raise RequestError("Input JSON does not contain 'intel_quote' or 'quote'.")

    return payload


def _build_offline_checks(payload: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    context: dict[str, Any] = {}

    try:
        quote = verifier.extract_quote_bytes(payload)
        context["quote"] = quote
        checks.append(
            _make_check(
                "quote_blob",
                "Quote Blob Is Present",
                "pass",
                "The input contains a parseable hex quote blob.",
                refs=["quote.byte_length", "quote.sha256"],
                evidence=[
                    {"label": "quote_length_bytes", "value": str(len(quote))},
                    {"label": "quote_sha256", "value": hashlib.sha256(quote).hexdigest(), "ref": "quote.sha256"},
                ],
            )
        )
    except Exception as exc:
        checks.append(
            _make_check(
                "quote_blob",
                "Quote Blob Is Present",
                "fail",
                f"Failed to decode quote bytes: {exc}",
                refs=["quote"],
            )
        )
        return checks, context

    quote = context["quote"]

    if len(quote) < verifier.QUOTE_HEADER_SIZE:
        checks.append(
            _make_check(
                "quote_header_size",
                "Quote Header Size",
                "fail",
                f"Quote is too short ({len(quote)} bytes) to contain a valid header.",
                refs=["quote.byte_length"],
            )
        )
        return checks, context

    version, att_key_type, tee_type = struct.unpack_from("<HHI", quote, 0)
    checks.append(
        _make_check(
            "header_version",
            "Quote Version",
            "pass" if version == 4 else "fail",
            "Intel TDX quote format expected by this verifier is version 4.",
            refs=["header.version"],
            evidence=[
                {"label": "actual", "value": str(version), "ref": "header.version"},
                {"label": "expected", "value": "4"},
            ],
        )
    )
    checks.append(
        _make_check(
            "header_attestation_key_type",
            "Attestation Key Type",
            "pass" if att_key_type == 2 else "warn",
            "Expected ECDSA-P256 (type 2). Other types may still be valid in some environments.",
            refs=["header.attestation_key_type", "header.attestation_key_type_name"],
            evidence=[
                {"label": "actual", "value": f"{att_key_type}"},
                {"label": "actual_name", "value": verifier.ATTESTATION_KEY_TYPE_NAMES.get(att_key_type, "UNKNOWN")},
                {"label": "expected", "value": "2 (ECDSA-P256)"},
            ],
        )
    )
    checks.append(
        _make_check(
            "header_tee_type",
            "TEE Type",
            "pass" if tee_type == 0x81 else "fail",
            "Expected Intel TDX TEE type (0x00000081).",
            refs=["header.tee_type", "header.tee_type_name"],
            evidence=[
                {"label": "actual", "value": f"0x{tee_type:08x}", "ref": "header.tee_type"},
                {"label": "actual_name", "value": verifier.TEE_TYPE_NAMES.get(tee_type, "UNKNOWN")},
                {"label": "expected", "value": "0x00000081 (TDX)"},
            ],
        )
    )

    if len(quote) < verifier.SIGNED_QUOTE_PART_SIZE + 4:
        checks.append(
            _make_check(
                "signature_data_length_field",
                "Signature Data Length Field",
                "fail",
                "Quote does not include the signature-data length field.",
                refs=["quote.byte_length", "signature_data"],
            )
        )
        return checks, context

    sig_data_len = struct.unpack_from("<I", quote, verifier.SIGNED_QUOTE_PART_SIZE)[0]
    sig_data_start = verifier.SIGNED_QUOTE_PART_SIZE + 4
    sig_data_end = sig_data_start + sig_data_len
    context["sig_data_len"] = sig_data_len
    context["sig_data_start"] = sig_data_start
    context["sig_data_end"] = sig_data_end

    if sig_data_end > len(quote):
        checks.append(
            _make_check(
                "signature_data_bounds",
                "Signature Data Bounds",
                "fail",
                "Declared signature data length extends beyond the quote buffer.",
                refs=["signature_data.declared_size", "signature_data.end_offset", "quote.byte_length"],
                evidence=[
                    {"label": "declared_size", "value": str(sig_data_len), "ref": "signature_data.declared_size"},
                    {"label": "declared_end_offset", "value": str(sig_data_end), "ref": "signature_data.end_offset"},
                    {"label": "quote_length", "value": str(len(quote)), "ref": "quote.byte_length"},
                ],
            )
        )
        return checks, context

    trailing = quote[sig_data_end:]
    checks.append(
        _make_check(
            "signature_data_bounds",
            "Signature Data Bounds",
            "warn" if trailing else "pass",
            (
                "Quote structure is internally consistent, but trailing bytes exist after the declared signature data. "
                "Trailing bytes are not covered by the quote signature."
                if trailing
                else "Signature data boundaries are consistent with quote length."
            ),
            refs=["signature_data.declared_size", "signature_data.end_offset", "signature_data.trailing_bytes_after_declared"],
            evidence=[
                {"label": "declared_size", "value": str(sig_data_len), "ref": "signature_data.declared_size"},
                {"label": "trailing_bytes", "value": str(len(trailing)), "ref": "signature_data.trailing_bytes_after_declared"},
            ],
        )
    )

    report_body = quote[verifier.QUOTE_HEADER_SIZE : verifier.SIGNED_QUOTE_PART_SIZE]
    sig_data_blob = quote[sig_data_start:sig_data_end]

    td_body: verifier.TdReportBody | None = None
    sig_data: verifier.QuoteSignatureData | None = None
    qe_data: verifier.QeReportCertificationData | None = None

    try:
        td_body = verifier.parse_td_report_body(report_body)
        context["td_body"] = td_body
        checks.append(
            _make_check(
                "td_report_body_parse",
                "TD Report Body Parse",
                "pass",
                "TD report body parses cleanly into expected fields (MRTD, RTMRs, REPORTDATA).",
                refs=["td_report_body.parsed"],
            )
        )
    except Exception as exc:
        checks.append(
            _make_check(
                "td_report_body_parse",
                "TD Report Body Parse",
                "fail",
                f"Failed to parse TD report body: {exc}",
                refs=["td_report_body"],
            )
        )

    try:
        sig_data = verifier.parse_quote_signature_data(sig_data_blob)
        context["sig_data"] = sig_data
        checks.append(
            _make_check(
                "signature_data_parse",
                "Signature Data Parse",
                "pass",
                "Signature section parses into quote signature, attestation public key, and certification data.",
                refs=["signature_data.parsed.quote_signature", "signature_data.parsed.attestation_public_key", "signature_data.parsed.certification_data"],
            )
        )
    except Exception as exc:
        checks.append(
            _make_check(
                "signature_data_parse",
                "Signature Data Parse",
                "fail",
                f"Failed to parse signature data: {exc}",
                refs=["signature_data"],
            )
        )

    if sig_data is not None:
        outer_type = sig_data.certification_data_type
        outer_type_name = verifier.CERTIFICATION_TYPE_NAMES.get(outer_type, "UNKNOWN")
        checks.append(
            _make_check(
                "outer_certification_type",
                "Outer Certification Data Type",
                "pass" if outer_type in verifier.CERTIFICATION_TYPE_NAMES else "warn",
                "Certification type describes what collateral accompanies the quote.",
                refs=["signature_data.parsed.certification_data.certification_data_type", "signature_data.parsed.certification_data.certification_data_type_name"],
                evidence=[
                    {"label": "outer_type", "value": str(outer_type), "ref": "signature_data.parsed.certification_data.certification_data_type"},
                    {"label": "outer_type_name", "value": outer_type_name, "ref": "signature_data.parsed.certification_data.certification_data_type_name"},
                ],
            )
        )

        if outer_type == 6:
            try:
                qe_data = verifier.parse_qe_report_certification_data(sig_data.certification_data)
                context["qe_data"] = qe_data
                nested_type = qe_data.nested_type
                nested_name = verifier.CERTIFICATION_TYPE_NAMES.get(nested_type, "UNKNOWN")
                checks.append(
                    _make_check(
                        "nested_certification_type",
                        "Nested Certification Data Type",
                        "pass" if nested_type in verifier.CERTIFICATION_TYPE_NAMES else "warn",
                        "For outer type 6 (QE report cert), nested certification data carries platform identification/certs.",
                        refs=[
                            "signature_data.parsed.certification_data.parsed.nested_certification_data.certification_data_type",
                            "signature_data.parsed.certification_data.parsed.nested_certification_data.certification_data_type_name",
                        ],
                        evidence=[
                            {
                                "label": "nested_type",
                                "value": str(nested_type),
                                "ref": "signature_data.parsed.certification_data.parsed.nested_certification_data.certification_data_type",
                            },
                            {
                                "label": "nested_type_name",
                                "value": nested_name,
                                "ref": "signature_data.parsed.certification_data.parsed.nested_certification_data.certification_data_type_name",
                            },
                        ],
                    )
                )

                checks.append(
                    _make_check(
                        "intel_online_collateral_hint",
                        "Intel Online Collateral Compatibility Hint",
                        "pass" if nested_type == 5 else "warn",
                        (
                            "Nested certification type 5 (PCK_CERT_CHAIN) is typically easiest for online verifiers to derive FMSPC/CA directly."
                            if nested_type == 5
                            else "Nested type is not 5 (PCK_CERT_CHAIN). Some online verifiers may fail to derive FMSPC/CA from quote alone."
                        ),
                        refs=["signature_data.parsed.certification_data.parsed.nested_certification_data.certification_data_type"],
                        evidence=[
                            {"label": "nested_type", "value": str(nested_type)},
                            {"label": "nested_type_name", "value": nested_name},
                        ],
                    )
                )
            except Exception as exc:
                checks.append(
                    _make_check(
                        "nested_certification_type",
                        "Nested Certification Data Type",
                        "fail",
                        f"Failed to parse nested QE certification data: {exc}",
                        refs=["signature_data.parsed.certification_data"],
                    )
                )

    if sig_data is not None:
        signed_data = quote[: verifier.SIGNED_QUOTE_PART_SIZE]
        signed_data_hash = hashlib.sha256(signed_data).hexdigest()
        try:
            verifier.verify_quote_signature(sig_data.attest_pub_key, sig_data.quote_signature, signed_data)
            checks.append(
                _make_check(
                    "quote_signature",
                    "ECDSA Quote Signature",
                    "pass",
                    "The ECDSA signature in the quote verifies against the embedded attestation public key over header+TD report bytes.",
                    refs=["signature_data.parsed.quote_signature", "signature_data.parsed.attestation_public_key"],
                    evidence=[
                        {"label": "signed_region_length", "value": str(len(signed_data))},
                        {"label": "signed_region_sha256", "value": signed_data_hash},
                        {"label": "signature_r", "value": sig_data.quote_signature[:32].hex(), "ref": "signature_data.parsed.quote_signature_r"},
                        {"label": "signature_s", "value": sig_data.quote_signature[32:].hex(), "ref": "signature_data.parsed.quote_signature_s"},
                        {"label": "pubkey_x", "value": sig_data.attest_pub_key[:32].hex(), "ref": "signature_data.parsed.attestation_public_key_x"},
                        {"label": "pubkey_y", "value": sig_data.attest_pub_key[32:].hex(), "ref": "signature_data.parsed.attestation_public_key_y"},
                    ],
                )
            )
        except Exception as exc:
            checks.append(
                _make_check(
                    "quote_signature",
                    "ECDSA Quote Signature",
                    "fail",
                    f"Quote signature verification failed: {exc.__class__.__name__}",
                    refs=["signature_data.parsed.quote_signature", "signature_data.parsed.attestation_public_key"],
                    evidence=[
                        {"label": "signed_region_sha256", "value": signed_data_hash},
                    ],
                )
            )

    if sig_data is not None and qe_data is not None:
        hash_input = sig_data.attest_pub_key + qe_data.qe_auth_data
        computed = hashlib.sha256(hash_input).digest()
        qe_report_data = qe_data.qe_report_body[320:384]
        prefix_match = computed == qe_report_data[:32]
        suffix_zero = qe_report_data[32:] == b"\x00" * 32
        status = "pass" if (prefix_match and suffix_zero) else "fail"
        checks.append(
            _make_check(
                "qe_report_binding",
                "QE Report Binds Attestation Key + QE Auth Data",
                status,
                "Verifier computes SHA-256(attestation_public_key || qe_auth_data). It must equal the first 32 bytes of QE report_data; remaining 32 bytes must be zero.",
                refs=[
                    "signature_data.parsed.attestation_public_key",
                    "signature_data.parsed.certification_data.parsed.qe_auth_data",
                    "signature_data.parsed.certification_data.parsed.qe_report_report_data",
                ],
                evidence=[
                    {"label": "hash_input_hex", "value": hash_input.hex()},
                    {"label": "computed_sha256", "value": computed.hex()},
                    {"label": "qe_report_data_prefix", "value": qe_report_data[:32].hex(), "ref": "signature_data.parsed.certification_data.parsed.qe_report_report_data"},
                    {"label": "qe_report_data_suffix", "value": qe_report_data[32:].hex(), "ref": "signature_data.parsed.certification_data.parsed.qe_report_report_data"},
                    {"label": "prefix_matches", "value": str(prefix_match).lower()},
                    {"label": "suffix_is_all_zero", "value": str(suffix_zero).lower()},
                ],
            )
        )

    tcb_info = payload.get("tcb_info")
    if td_body is not None and isinstance(tcb_info, dict):
        expected = {
            "mrtd": td_body.mr_td.hex(),
            "rtmr0": td_body.rtmr[0].hex(),
            "rtmr1": td_body.rtmr[1].hex(),
            "rtmr2": td_body.rtmr[2].hex(),
            "rtmr3": td_body.rtmr[3].hex(),
        }
        present = [k for k in expected if isinstance(tcb_info.get(k), str)]
        mismatches: list[str] = []
        for key in present:
            if _normalize_hex(tcb_info[key]) != expected[key]:
                mismatches.append(key)

        if not present:
            checks.append(
                _make_check(
                    "tcb_info_consistency",
                    "tcb_info Consistency",
                    "warn",
                    "tcb_info object present but does not include mrtd/rtmr0..rtmr3 string fields.",
                    refs=["td_report_body.parsed.mr_td", "td_report_body.parsed.rtmr0", "td_report_body.parsed.rtmr1", "td_report_body.parsed.rtmr2", "td_report_body.parsed.rtmr3"],
                )
            )
        else:
            status = "fail" if mismatches else "pass"
            checks.append(
                _make_check(
                    "tcb_info_consistency",
                    "tcb_info Consistency",
                    status,
                    (
                        "tcb_info measurements match quote measurements."
                        if not mismatches
                        else f"tcb_info mismatch in: {', '.join(mismatches)}"
                    ),
                    refs=["td_report_body.parsed.mr_td", "td_report_body.parsed.rtmr0", "td_report_body.parsed.rtmr1", "td_report_body.parsed.rtmr2", "td_report_body.parsed.rtmr3"],
                    evidence=[
                        {"label": "present_fields", "value": ",".join(present)},
                    ],
                )
            )

    event_log = payload.get("event_log")
    if td_body is not None and isinstance(event_log, list):
        calc = [b"\x00" * 48 for _ in range(4)]
        counts = [0, 0, 0, 0]
        digest_errors: list[str] = []

        for idx, event in enumerate(event_log):
            imr = event.get("imr")
            if not isinstance(imr, int) or not (0 <= imr <= 3):
                continue
            digest_hex = event.get("digest")
            if not isinstance(digest_hex, str):
                digest_errors.append(f"event[{idx}]: digest not string")
                continue
            try:
                digest = bytes.fromhex(digest_hex)
            except Exception:
                digest_errors.append(f"event[{idx}]: digest not hex")
                continue
            if len(digest) != 48:
                digest_errors.append(f"event[{idx}]: digest len {len(digest)} != 48")
                continue

            calc[imr] = hashlib.sha384(calc[imr] + digest).digest()
            counts[imr] += 1

        matches = [calc[i] == td_body.rtmr[i] for i in range(4)]
        status = "pass" if all(matches) and not digest_errors else "fail"
        checks.append(
            _make_check(
                "event_log_rtmr",
                "Event Log Replays to RTMRs",
                status,
                "For each IMR, verifier starts with 48 zero bytes and repeatedly extends: next = SHA384(prev || event_digest). Final values must equal RTMR0..RTMR3 in quote.",
                refs=[
                    "event_log",
                    "td_report_body.parsed.rtmr0",
                    "td_report_body.parsed.rtmr1",
                    "td_report_body.parsed.rtmr2",
                    "td_report_body.parsed.rtmr3",
                ],
                evidence=[
                    {"label": "imr0_events", "value": str(counts[0])},
                    {"label": "imr1_events", "value": str(counts[1])},
                    {"label": "imr2_events", "value": str(counts[2])},
                    {"label": "imr3_events", "value": str(counts[3])},
                    {"label": "computed_rtmr0", "value": calc[0].hex()},
                    {"label": "quote_rtmr0", "value": td_body.rtmr[0].hex(), "ref": "td_report_body.parsed.rtmr0"},
                    {"label": "computed_rtmr1", "value": calc[1].hex()},
                    {"label": "quote_rtmr1", "value": td_body.rtmr[1].hex(), "ref": "td_report_body.parsed.rtmr1"},
                    {"label": "computed_rtmr2", "value": calc[2].hex()},
                    {"label": "quote_rtmr2", "value": td_body.rtmr[2].hex(), "ref": "td_report_body.parsed.rtmr2"},
                    {"label": "computed_rtmr3", "value": calc[3].hex()},
                    {"label": "quote_rtmr3", "value": td_body.rtmr[3].hex(), "ref": "td_report_body.parsed.rtmr3"},
                    {"label": "digest_errors", "value": "; ".join(digest_errors) if digest_errors else "none"},
                ],
            )
        )
    elif td_body is not None:
        checks.append(
            _make_check(
                "event_log_rtmr",
                "Event Log Replays to RTMRs",
                "warn",
                "event_log is missing; replay check skipped.",
                refs=[
                    "event_log",
                    "td_report_body.parsed.rtmr0",
                    "td_report_body.parsed.rtmr1",
                    "td_report_body.parsed.rtmr2",
                    "td_report_body.parsed.rtmr3",
                ],
            )
        )

    return checks, context


def _build_online_check(request: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    quote = context.get("quote")
    if not isinstance(quote, (bytes, bytearray)):
        return _make_check(
            "intel_online",
            "Intel Online Verification",
            "fail",
            "Cannot run online verification because quote bytes are unavailable.",
        )

    api_key_raw = request.get("intel_api_key")
    api_key = api_key_raw.strip() if isinstance(api_key_raw, str) and api_key_raw.strip() else os.environ.get("INTEL_TRUST_AUTHORITY_API_KEY", "").strip()
    if not api_key:
        return _make_check(
            "intel_online",
            "Intel Online Verification",
            "fail",
            "Online verification requested, but Intel API key was not provided.",
            evidence=[
                {"label": "expected", "value": "intel_api_key in request or INTEL_TRUST_AUTHORITY_API_KEY env var"},
            ],
        )

    base_url = request.get("intel_base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        base_url = os.environ.get("INTEL_TRUST_AUTHORITY_BASE_URL", DEFAULT_INTEL_BASE_URL)

    policy_ids = request.get("policy_ids")
    if not isinstance(policy_ids, list):
        policy_ids = []
    policy_ids = [str(x) for x in policy_ids if str(x).strip()]

    timeout_seconds = request.get("timeout_seconds")
    try:
        timeout_seconds_f = float(timeout_seconds) if timeout_seconds is not None else 30.0
    except Exception:
        timeout_seconds_f = 30.0

    result = verifier.verify_quote_with_intel_trust_authority(
        quote=bytes(quote),
        api_key=api_key,
        base_url=base_url,
        timeout_seconds=timeout_seconds_f,
        policy_ids=policy_ids,
    )

    if not result.success:
        return _make_check(
            "intel_online",
            "Intel Online Verification",
            "fail",
            "Intel Trust Authority did not accept this quote.",
            evidence=[
                {"label": "endpoint", "value": result.endpoint or ""},
                {"label": "http_status", "value": str(result.status_code) if result.status_code is not None else "n/a"},
                {"label": "error", "value": result.error or "unknown error"},
            ],
        )

    evidence: list[dict[str, Any]] = [
        {"label": "endpoint", "value": result.endpoint or ""},
        {"label": "http_status", "value": str(result.status_code) if result.status_code is not None else "n/a"},
    ]

    if result.claims:
        iss = result.claims.get("iss")
        if isinstance(iss, str):
            evidence.append({"label": "token_issuer", "value": iss})

        exp = result.claims.get("exp")
        if isinstance(exp, int):
            exp_utc = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
            evidence.append({"label": "token_exp_utc", "value": exp_utc.isoformat()})

        sub = result.claims.get("sub")
        if isinstance(sub, str):
            evidence.append({"label": "token_sub", "value": sub})

    if result.token:
        evidence.append({"label": "token_preview", "value": f"{result.token[:48]}..."})

    return _make_check(
        "intel_online",
        "Intel Online Verification",
        "pass",
        "Intel Trust Authority accepted the quote and returned an attestation token.",
        evidence=evidence,
    )


def _summarize_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for check in checks:
        status = check.get("status")
        if status in counts:
            counts[status] += 1

    overall = "fail" if counts["fail"] > 0 else "pass"
    return {
        "overall": overall,
        "counts": counts,
        "total": len(checks),
    }


def process_verification_request(request_data: dict[str, Any]) -> dict[str, Any]:
    raw_input = request_data.get("input")
    payload = _parse_pasted_input(raw_input)

    dump = verifier.build_quote_debug_dump(payload, include_raw=True)

    checks, context = _build_offline_checks(payload)
    online_requested = bool(request_data.get("online", True))

    if online_requested:
        checks.append(_build_online_check(request_data, context))
    else:
        checks.append(
            _make_check(
                "intel_online",
                "Intel Online Verification",
                "fail",
                "Intel online verification was disabled by the user. This verifier treats skipping Intel online verification as an error.",
            )
        )

    summary = _summarize_checks(checks)

    return {
        "ok": summary["overall"] != "fail",
        "summary": summary,
        "checks": checks,
        "dump": dump,
        "meta": {
            "offline_checks": len([c for c in checks if c["id"] != "intel_online"]),
            "online_requested": online_requested,
        },
    }


class QuoteUIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/verify":
            self._send_json(404, {"ok": False, "error": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "Invalid Content-Length"})
            return

        raw_body = self.rfile.read(content_length)
        try:
            request_data = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            self._send_json(400, {"ok": False, "error": f"Invalid JSON request body: {exc}"})
            return

        if not isinstance(request_data, dict):
            self._send_json(400, {"ok": False, "error": "Request body must be a JSON object"})
            return

        try:
            response = process_verification_request(request_data)
        except RequestError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"Internal error: {exc}"})
            return

        self._send_json(200, response)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/examples/"):
            rel = parsed.path.lstrip("/")
            file_path = (PROJECT_ROOT / rel).resolve()
            examples_root = (PROJECT_ROOT / "examples").resolve()
            if not str(file_path).startswith(str(examples_root)) or not file_path.is_file():
                self._send_json(404, {"ok": False, "error": "Example file not found"})
                return

            raw = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path in {"", "/"}:
            self.path = "/index.html"
        return super().do_GET()


def run(host: str, port: int) -> None:
    if not WEB_ROOT.exists():
        raise SystemExit(f"Web assets directory not found: {WEB_ROOT}")

    server = ThreadingHTTPServer((host, port), QuoteUIHandler)
    print(f"Serving UI at http://{host}:{port}")
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    args = parser.parse_args()
    run(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
