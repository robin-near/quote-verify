#!/usr/bin/env python3
"""Simple verifier for Intel TDX ECDSA quote blobs with optional Intel online attestation."""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
except Exception as exc:  # pragma: no cover
    print(f"error: failed to import cryptography package: {exc}", file=sys.stderr)
    sys.exit(2)


QUOTE_HEADER_SIZE = 48
TDX_REPORT_BODY_SIZE = 584
SIGNED_QUOTE_PART_SIZE = QUOTE_HEADER_SIZE + TDX_REPORT_BODY_SIZE
QE_REPORT_BODY_SIZE = 384

ATTESTATION_KEY_TYPE_NAMES = {
    2: "ECDSA-P256",
    3: "ECDSA-P384",
}

TEE_TYPE_NAMES = {
    0x00000000: "SGX",
    0x00000081: "TDX",
}

CERTIFICATION_TYPE_NAMES = {
    1: "PPID_CLEARTEXT",
    2: "PPID_RSA2048_ENCRYPTED",
    3: "PPID_RSA3072_ENCRYPTED",
    4: "PCK_CLEARTEXT",
    5: "PCK_CERT_CHAIN",
    6: "ECDSA_SIG_AUX_DATA (QE_REPORT_CERT)",
}


@dataclass
class Result:
    checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def ok(self, message: str) -> None:
        self.checks.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def fail(self, message: str) -> None:
        self.errors.append(message)


@dataclass
class OnlineAttestationResult:
    success: bool
    status_code: int | None = None
    token: str | None = None
    claims: dict[str, Any] | None = None
    error: str | None = None
    endpoint: str | None = None


@dataclass
class TdReportBody:
    tee_tcb_svn: bytes
    mr_seam: bytes
    mr_signer_seam: bytes
    seam_attributes: bytes
    td_attributes: bytes
    xfam: bytes
    mr_td: bytes
    mr_config_id: bytes
    mr_owner: bytes
    mr_owner_config: bytes
    rtmr: list[bytes]
    report_data: bytes


@dataclass
class QuoteSignatureData:
    quote_signature: bytes
    attest_pub_key: bytes
    certification_data_type: int
    certification_data: bytes


@dataclass
class QeReportCertificationData:
    qe_report_body: bytes
    qe_report_signature: bytes
    qe_auth_data: bytes
    nested_type: int
    nested_data: bytes


def _normalize_hex(value: str) -> str:
    return value.lower().strip().removeprefix("0x")


def _must_hex_to_bytes(label: str, value: str) -> bytes:
    cleaned = _normalize_hex(value)
    if not re.fullmatch(r"[0-9a-f]*", cleaned):
        raise ValueError(f"{label} is not valid hex")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{label} has odd hex length")
    return bytes.fromhex(cleaned)


def extract_quote_bytes(payload: dict[str, Any]) -> bytes:
    quote_hex: str | None = None
    quote_field: str | None = None

    for field in ("intel_quote", "quote"):
        candidate = payload.get(field)
        if isinstance(candidate, str):
            quote_hex = candidate
            quote_field = field
            break

    if quote_hex is None or quote_field is None:
        raise ValueError("missing or invalid 'intel_quote' or 'quote' field")

    return _must_hex_to_bytes(quote_field, quote_hex)


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("attestation token is not a JWT")

    payload_b64 = parts[1]
    payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
    payload_raw = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
    decoded = json.loads(payload_raw.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("JWT claims payload is not an object")
    return decoded


def _hex_preview(data: bytes, max_len: int = 64) -> str:
    if len(data) <= max_len:
        return data.hex()
    return f"{data[:max_len].hex()}...(+{len(data) - max_len} bytes)"


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    allowed = set(range(32, 127)) | {9, 10, 13}
    printable = sum(1 for b in data if b in allowed)
    return printable / len(data) > 0.95


def _yaml_scalar(value: Any) -> str | None:
    if isinstance(value, (dict, list)):
        return None
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if "\n" in value:
            return None
        if value == "":
            return "''"
        if all(ch.isalnum() or ch in "_./:+-=,()[]{}" for ch in value):
            return value
        return json.dumps(value)
    return json.dumps(value)


def _to_yaml_like_lines(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines: list[str] = []

    if isinstance(value, dict):
        if not value:
            return [f"{pad}{{}}"]
        for key, item in value.items():
            scalar = _yaml_scalar(item)
            if scalar is not None:
                lines.append(f"{pad}{key}: {scalar}")
                continue

            if isinstance(item, str) and "\n" in item:
                lines.append(f"{pad}{key}: |")
                for text_line in item.splitlines():
                    lines.append(f"{pad}  {text_line}")
                if item.endswith("\n"):
                    lines.append(f"{pad}  ")
                continue

            lines.append(f"{pad}{key}:")
            lines.extend(_to_yaml_like_lines(item, indent + 2))
        return lines

    if isinstance(value, list):
        if not value:
            return [f"{pad}[]"]
        for item in value:
            scalar = _yaml_scalar(item)
            if scalar is not None:
                lines.append(f"{pad}- {scalar}")
                continue

            if isinstance(item, str) and "\n" in item:
                lines.append(f"{pad}- |")
                for text_line in item.splitlines():
                    lines.append(f"{pad}  {text_line}")
                if item.endswith("\n"):
                    lines.append(f"{pad}  ")
                continue

            lines.append(f"{pad}-")
            lines.extend(_to_yaml_like_lines(item, indent + 2))
        return lines

    scalar = _yaml_scalar(value)
    return [f"{pad}{scalar if scalar is not None else json.dumps(value)}"]


def format_yaml_like(value: Any) -> str:
    return "\n".join(_to_yaml_like_lines(value))


def _td_attributes_u64(td_attributes: bytes) -> int:
    if len(td_attributes) != 8:
        raise ValueError(f"TDATTRIBUTES must be 8 bytes, got {len(td_attributes)}")
    return int.from_bytes(td_attributes, "little")


def _decode_td_attributes(td_attributes: bytes) -> dict[str, Any]:
    value = _td_attributes_u64(td_attributes)
    return {
        "raw_hex": td_attributes.hex(),
        "raw_u64": value,
        "tud_bits": value & 0xFF,
        "sec_bits": (value >> 8) & 0xFFFFFF,
        "other_bits": (value >> 32) & 0xFFFFFFFF,
        "flags": {
            "debug": bool(value & (1 << 0)),
            "sept_ve_disable": bool(value & (1 << 28)),
            "pks": bool(value & (1 << 30)),
            "kl": bool(value & (1 << 31)),
            "perfmon": bool(value & (1 << 63)),
        },
    }


def _extract_pem_certificates(data: bytes) -> list[x509.Certificate]:
    pem_pattern = re.compile(
        b"-----BEGIN CERTIFICATE-----\\s+.+?\\s+-----END CERTIFICATE-----",
        re.DOTALL,
    )
    certs: list[x509.Certificate] = []
    for block in pem_pattern.findall(data):
        certs.append(x509.load_pem_x509_certificate(block))
    return certs


def _verify_ecdsa_raw_signature(public_key: Any, signature: bytes, payload: bytes) -> None:
    if len(signature) != 64:
        raise ValueError(f"expected 64-byte ECDSA signature, got {len(signature)}")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_sig = utils.encode_dss_signature(r, s)
    public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))


def _find_expected_value(payload: dict[str, Any], *keys: str) -> Any:
    sources: list[dict[str, Any]] = []
    for source_key in ("expected_td", "expected_td_quote_body", "tcb_info"):
        source = payload.get(source_key)
        if isinstance(source, dict):
            sources.append(source)
    sources.append(payload)

    for source in sources:
        for key in keys:
            if key in source:
                return source[key]
    return None


def _parse_expected_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty string")
        try:
            return int(text, 0)
        except ValueError:
            cleaned = _normalize_hex(text)
            if not re.fullmatch(r"[0-9a-f]+", cleaned):
                raise
            return int(cleaned, 16)
    raise ValueError(f"unsupported type {type(value).__name__}")


def _parse_sgx_report_body_debug(body: bytes) -> dict[str, Any]:
    if len(body) != QE_REPORT_BODY_SIZE:
        raise ValueError(f"invalid SGX report body length: {len(body)}")

    o = 0
    cpu_svn = body[o : o + 16]
    o += 16
    misc_select = struct.unpack_from("<I", body, o)[0]
    o += 4
    reserved1 = body[o : o + 28]
    o += 28
    attributes = body[o : o + 16]
    o += 16
    mr_enclave = body[o : o + 32]
    o += 32
    reserved2 = body[o : o + 32]
    o += 32
    mr_signer = body[o : o + 32]
    o += 32
    reserved3 = body[o : o + 96]
    o += 96
    isv_prod_id = struct.unpack_from("<H", body, o)[0]
    o += 2
    isv_svn = struct.unpack_from("<H", body, o)[0]
    o += 2
    reserved4 = body[o : o + 60]
    o += 60
    report_data = body[o : o + 64]
    o += 64
    if o != len(body):
        raise ValueError("internal parse error in SGX QE report body")

    return {
        "cpu_svn": cpu_svn.hex(),
        "misc_select": misc_select,
        "attributes": attributes.hex(),
        "mr_enclave": mr_enclave.hex(),
        "mr_signer": mr_signer.hex(),
        "isv_prod_id": isv_prod_id,
        "isv_svn": isv_svn,
        "report_data": report_data.hex(),
        "reserved": {
            "reserved1": reserved1.hex(),
            "reserved2": reserved2.hex(),
            "reserved3": _hex_preview(reserved3),
            "reserved4": reserved4.hex(),
        },
    }


def _parse_ppid_cert_info(cert_type: int, cert_data: bytes, include_raw: bool) -> dict[str, Any]:
    if cert_type == 1:
        expected = 36
        enc_ppid_len = 16
    elif cert_type == 2:
        expected = 276
        enc_ppid_len = 256
    else:  # cert_type == 3
        expected = 404
        enc_ppid_len = 384

    info: dict[str, Any] = {
        "certification_data_size": len(cert_data),
        "expected_size_for_type": expected,
    }
    if len(cert_data) < expected:
        info["parse_error"] = "certification data shorter than expected"
        info["certification_data_hex_preview"] = _hex_preview(cert_data)
        return info

    enc_ppid = cert_data[:enc_ppid_len]
    cpu_svn = cert_data[enc_ppid_len : enc_ppid_len + 16]
    pce_isv_svn = struct.unpack_from("<H", cert_data, enc_ppid_len + 16)[0]
    pce_id = struct.unpack_from("<H", cert_data, enc_ppid_len + 18)[0]
    extra = cert_data[expected:]

    if cert_type == 1:
        info["ppid"] = enc_ppid.hex()
    else:
        info["encrypted_ppid"] = enc_ppid.hex() if include_raw else _hex_preview(enc_ppid)
        info["encrypted_ppid_sha256"] = hashlib.sha256(enc_ppid).hexdigest()

    info["cpu_svn"] = cpu_svn.hex()
    info["pce_isv_svn"] = pce_isv_svn
    info["pce_id"] = pce_id
    info["extra_bytes_after_expected"] = len(extra)
    if extra:
        info["extra_bytes_hex"] = extra.hex() if include_raw else _hex_preview(extra)
    return info


def _parse_certification_data_debug(cert_type: int, cert_data: bytes, include_raw: bool, depth: int = 0) -> dict[str, Any]:
    result: dict[str, Any] = {
        "certification_data_type": cert_type,
        "certification_data_type_name": CERTIFICATION_TYPE_NAMES.get(cert_type, "UNKNOWN"),
        "certification_data_size": len(cert_data),
        "certification_data_sha256": hashlib.sha256(cert_data).hexdigest(),
    }

    if depth > 4:
        result["note"] = "max certification nesting depth reached"
        return result

    if cert_type in (1, 2, 3):
        result["parsed"] = _parse_ppid_cert_info(cert_type, cert_data, include_raw)
        return result

    if cert_type in (4, 5):
        result["data_hex"] = cert_data.hex() if include_raw else _hex_preview(cert_data)
        if _looks_like_text(cert_data):
            text = cert_data.decode("utf-8", errors="replace")
            result["data_text"] = text if include_raw else text[:1000]
        return result

    if cert_type == 6:
        try:
            qe_cert = parse_qe_report_certification_data(cert_data)
            qe_report_data = qe_cert.qe_report_body[320:384]
            binding_hash = hashlib.sha256(qe_cert.nested_data if qe_cert.nested_data else b"").hexdigest()
            result["parsed"] = {
                "qe_report_body": _parse_sgx_report_body_debug(qe_cert.qe_report_body),
                "qe_report_signature": qe_cert.qe_report_signature.hex(),
                "qe_auth_data_size": len(qe_cert.qe_auth_data),
                "qe_auth_data": qe_cert.qe_auth_data.hex() if include_raw else _hex_preview(qe_cert.qe_auth_data),
                "qe_auth_data_sha256": hashlib.sha256(qe_cert.qe_auth_data).hexdigest(),
                "qe_report_report_data": qe_report_data.hex(),
                "nested_certification_data": _parse_certification_data_debug(
                    qe_cert.nested_type,
                    qe_cert.nested_data,
                    include_raw,
                    depth=depth + 1,
                ),
                "nested_data_sha256": binding_hash,
            }
        except Exception as exc:
            result["parse_error"] = str(exc)
            result["certification_data_hex"] = cert_data.hex() if include_raw else _hex_preview(cert_data)
        return result

    result["certification_data_hex"] = cert_data.hex() if include_raw else _hex_preview(cert_data)
    return result


def build_quote_debug_dump(payload: dict[str, Any], include_raw: bool = False) -> dict[str, Any]:
    dump: dict[str, Any] = {}

    try:
        quote = extract_quote_bytes(payload)
    except ValueError as exc:
        dump["error"] = str(exc)
        return dump

    dump["quote"] = {
        "byte_length": len(quote),
        "sha256": hashlib.sha256(quote).hexdigest(),
        "hex_preview": _hex_preview(quote, max_len=96),
    }
    if include_raw:
        dump["quote"]["hex"] = quote.hex()

    errors: list[str] = []
    warnings: list[str] = []

    if len(quote) >= QUOTE_HEADER_SIZE:
        version, att_key_type, tee_type = struct.unpack_from("<HHI", quote, 0)
        reserved = quote[8:12]
        qe_vendor_id = quote[12:28]
        user_data = quote[28:48]
        dump["header"] = {
            "version": version,
            "attestation_key_type": att_key_type,
            "attestation_key_type_name": ATTESTATION_KEY_TYPE_NAMES.get(att_key_type, "UNKNOWN"),
            "tee_type": f"0x{tee_type:08x}",
            "tee_type_name": TEE_TYPE_NAMES.get(tee_type, "UNKNOWN"),
            "reserved": reserved.hex(),
            "qe_vendor_id": qe_vendor_id.hex(),
            "user_data": user_data.hex(),
        }
    else:
        errors.append("quote shorter than header size")

    if len(quote) >= SIGNED_QUOTE_PART_SIZE:
        report_body = quote[QUOTE_HEADER_SIZE:SIGNED_QUOTE_PART_SIZE]
        td_dump: dict[str, Any] = {"byte_length": len(report_body)}
        try:
            td = parse_td_report_body(report_body)
            td_attr_decoded = _decode_td_attributes(td.td_attributes)

            td_dump["parsed"] = {
                "tee_tcb_svn": td.tee_tcb_svn.hex(),
                "mr_seam": td.mr_seam.hex(),
                "mr_signer_seam": td.mr_signer_seam.hex(),
                "seam_attributes": td.seam_attributes.hex(),
                "td_attributes": td.td_attributes.hex(),
                "td_attributes_decoded": td_attr_decoded,
                "xfam": td.xfam.hex(),
                "xfam_u64": int.from_bytes(td.xfam, "little"),
                "mr_td": td.mr_td.hex(),
                "mr_config_id": td.mr_config_id.hex(),
                "mr_owner": td.mr_owner.hex(),
                "mr_owner_config": td.mr_owner_config.hex(),
                "rtmr0": td.rtmr[0].hex(),
                "rtmr1": td.rtmr[1].hex(),
                "rtmr2": td.rtmr[2].hex(),
                "rtmr3": td.rtmr[3].hex(),
                "report_data": td.report_data.hex(),
            }
        except Exception as exc:
            td_dump["parse_error"] = str(exc)
            td_dump["raw_hex"] = report_body.hex() if include_raw else _hex_preview(report_body)
        dump["td_report_body"] = td_dump
    else:
        errors.append("quote shorter than signed quote part size")

    if len(quote) >= SIGNED_QUOTE_PART_SIZE + 4:
        sig_data_len = struct.unpack_from("<I", quote, SIGNED_QUOTE_PART_SIZE)[0]
        sig_data_start = SIGNED_QUOTE_PART_SIZE + 4
        sig_data_end = sig_data_start + sig_data_len
        sig_data_blob = quote[sig_data_start:min(sig_data_end, len(quote))]
        trailing = quote[sig_data_end:] if sig_data_end <= len(quote) else b""

        sig_dump: dict[str, Any] = {
            "offset": sig_data_start,
            "declared_size": sig_data_len,
            "available_size": len(sig_data_blob),
            "end_offset": sig_data_end,
            "quote_length": len(quote),
            "has_declared_overflow": sig_data_end > len(quote),
            "trailing_bytes_after_declared": len(trailing),
        }
        if trailing:
            sig_dump["trailing_bytes_hex"] = trailing.hex() if include_raw else _hex_preview(trailing)

        if sig_data_end <= len(quote):
            try:
                sig_data = parse_quote_signature_data(sig_data_blob)
                sig_dump["parsed"] = {
                    "quote_signature": sig_data.quote_signature.hex(),
                    "quote_signature_r": sig_data.quote_signature[:32].hex(),
                    "quote_signature_s": sig_data.quote_signature[32:].hex(),
                    "attestation_public_key": sig_data.attest_pub_key.hex(),
                    "attestation_public_key_x": sig_data.attest_pub_key[:32].hex(),
                    "attestation_public_key_y": sig_data.attest_pub_key[32:].hex(),
                    "certification_data": _parse_certification_data_debug(
                        sig_data.certification_data_type,
                        sig_data.certification_data,
                        include_raw,
                    ),
                }
            except Exception as exc:
                sig_dump["parse_error"] = str(exc)
                sig_dump["raw_hex"] = sig_data_blob.hex() if include_raw else _hex_preview(sig_data_blob)
        else:
            errors.append("declared signature data overflows quote length")
            sig_dump["raw_hex"] = sig_data_blob.hex() if include_raw else _hex_preview(sig_data_blob)

        dump["signature_data"] = sig_dump
    else:
        errors.append("quote shorter than signature-data length field")

    if warnings:
        dump["warnings"] = warnings
    if errors:
        dump["errors"] = errors

    if "event_log" in payload:
        event_log = payload.get("event_log")
        if isinstance(event_log, list):
            dump["event_log"] = event_log
        else:
            dump["event_log"] = {"error": f"expected list, got {type(event_log).__name__}"}

    return dump


def verify_quote_with_intel_trust_authority(
    quote: bytes,
    api_key: str,
    base_url: str,
    timeout_seconds: float,
    policy_ids: list[str],
) -> OnlineAttestationResult:
    endpoint = f"{base_url.rstrip('/')}/appraisal/v1/attest"
    body: dict[str, Any] = {"quote": base64.b64encode(quote).decode("ascii")}
    if policy_ids:
        body["policy_ids"] = policy_ids

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "x-api-key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(response.getcode())
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        detail = raw.decode("utf-8", errors="replace").strip()
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict):
                maybe_message = parsed.get("message")
                maybe_error = parsed.get("error")
                detail = str(maybe_message or maybe_error or parsed)
        except Exception:
            pass
        return OnlineAttestationResult(
            success=False,
            status_code=int(exc.code),
            error=detail or str(exc),
            endpoint=endpoint,
        )
    except urllib.error.URLError as exc:
        return OnlineAttestationResult(
            success=False,
            error=f"network error: {exc}",
            endpoint=endpoint,
        )

    try:
        response_json = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return OnlineAttestationResult(
            success=False,
            status_code=status_code,
            error=f"invalid JSON from Intel API: {exc}",
            endpoint=endpoint,
        )

    token = response_json.get("token") if isinstance(response_json, dict) else None
    if not isinstance(token, str):
        return OnlineAttestationResult(
            success=False,
            status_code=status_code,
            error="Intel API response does not contain a string 'token'",
            endpoint=endpoint,
        )

    claims: dict[str, Any] | None = None
    try:
        claims = _decode_jwt_claims(token)
    except Exception:
        # Token parsing is best effort; Intel API accepted the quote regardless.
        claims = None

    return OnlineAttestationResult(
        success=True,
        status_code=status_code,
        token=token,
        claims=claims,
        endpoint=endpoint,
    )


def parse_td_report_body(body: bytes) -> TdReportBody:
    if len(body) != TDX_REPORT_BODY_SIZE:
        raise ValueError(f"invalid TDX report body length: {len(body)}")

    o = 0
    tee_tcb_svn = body[o : o + 16]
    o += 16
    mr_seam = body[o : o + 48]
    o += 48
    mr_signer_seam = body[o : o + 48]
    o += 48
    seam_attributes = body[o : o + 8]
    o += 8
    td_attributes = body[o : o + 8]
    o += 8
    xfam = body[o : o + 8]
    o += 8

    mr_td = body[o : o + 48]
    o += 48

    mr_config_id = body[o : o + 48]
    o += 48
    mr_owner = body[o : o + 48]
    o += 48
    mr_owner_config = body[o : o + 48]
    o += 48

    rtmr = []
    for _ in range(4):
        rtmr.append(body[o : o + 48])
        o += 48

    report_data = body[o : o + 64]
    o += 64

    if o != len(body):
        raise ValueError("internal parse error in TDX report body")

    return TdReportBody(
        tee_tcb_svn=tee_tcb_svn,
        mr_seam=mr_seam,
        mr_signer_seam=mr_signer_seam,
        seam_attributes=seam_attributes,
        td_attributes=td_attributes,
        xfam=xfam,
        mr_td=mr_td,
        mr_config_id=mr_config_id,
        mr_owner=mr_owner,
        mr_owner_config=mr_owner_config,
        rtmr=rtmr,
        report_data=report_data,
    )


def parse_quote_signature_data(sig_data: bytes) -> QuoteSignatureData:
    # Quote v4 TDX quote signature data layout:
    #   quote_signature[64]
    #   attest_pub_key[64]
    #   cert_data_type[u16] + cert_data_size[u32] + cert_data
    min_len = 64 + 64 + 2 + 4
    if len(sig_data) < min_len:
        raise ValueError("signature data too short")

    o = 0
    quote_signature = sig_data[o : o + 64]
    o += 64
    attest_pub_key = sig_data[o : o + 64]
    o += 64

    cert_data_type = struct.unpack_from("<H", sig_data, o)[0]
    o += 2
    cert_data_size = struct.unpack_from("<I", sig_data, o)[0]
    o += 4

    if o + cert_data_size != len(sig_data):
        raise ValueError(
            "signature data certification section length mismatch "
            f"(declared={cert_data_size}, actual={len(sig_data) - o})"
        )

    cert_data = sig_data[o : o + cert_data_size]

    return QuoteSignatureData(
        quote_signature=quote_signature,
        attest_pub_key=attest_pub_key,
        certification_data_type=cert_data_type,
        certification_data=cert_data,
    )


def parse_qe_report_certification_data(data: bytes) -> QeReportCertificationData:
    # QE_REPORT_CERT data (cert type 6) layout:
    #   qe_report_body[384]
    #   qe_report_signature[64]
    #   qe_auth_data_size[u16] + qe_auth_data
    #   nested_cert_data_type[u16] + nested_cert_data_size[u32] + nested_cert_data
    min_len = 384 + 64 + 2 + 2 + 4
    if len(data) < min_len:
        raise ValueError("QE report certification data too short")

    o = 0
    qe_report_body = data[o : o + 384]
    o += 384

    qe_report_signature = data[o : o + 64]
    o += 64

    qe_auth_data_size = struct.unpack_from("<H", data, o)[0]
    o += 2
    if o + qe_auth_data_size + 6 > len(data):
        raise ValueError("QE auth data length exceeds QE cert data size")

    qe_auth_data = data[o : o + qe_auth_data_size]
    o += qe_auth_data_size

    nested_type = struct.unpack_from("<H", data, o)[0]
    o += 2
    nested_size = struct.unpack_from("<I", data, o)[0]
    o += 4

    if o + nested_size != len(data):
        raise ValueError(
            "nested certification section length mismatch "
            f"(declared={nested_size}, actual={len(data) - o})"
        )

    nested_data = data[o : o + nested_size]

    return QeReportCertificationData(
        qe_report_body=qe_report_body,
        qe_report_signature=qe_report_signature,
        qe_auth_data=qe_auth_data,
        nested_type=nested_type,
        nested_data=nested_data,
    )


def verify_quote_signature(attest_pub_key: bytes, quote_signature: bytes, signed_quote: bytes) -> None:
    if len(attest_pub_key) != 64:
        raise ValueError("attestation public key must be 64 bytes")
    if len(quote_signature) != 64:
        raise ValueError("quote signature must be 64 bytes")

    x = int.from_bytes(attest_pub_key[:32], "big")
    y = int.from_bytes(attest_pub_key[32:], "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    r = int.from_bytes(quote_signature[:32], "big")
    s = int.from_bytes(quote_signature[32:], "big")
    der_sig = utils.encode_dss_signature(r, s)

    pub.verify(der_sig, signed_quote, ec.ECDSA(hashes.SHA256()))


def verify_qe_report_binding(
    qe_report: QeReportCertificationData,
    attest_pub_key: bytes,
) -> None:
    # For QE report body (384 bytes), report_data is bytes [320:384].
    report_data = qe_report.qe_report_body[320:384]
    expected = hashlib.sha256(attest_pub_key + qe_report.qe_auth_data).digest()

    if report_data[:32] != expected:
        raise ValueError("QE report_data hash mismatch")
    if report_data[32:] != b"\x00" * 32:
        raise ValueError("QE report_data trailing 32 bytes are not zero")


def verify_qe_report_signature_with_pck(qe_report: QeReportCertificationData) -> None:
    # The type-6 payload wraps a nested certification data blob that should contain
    # a PCK certificate chain (type 5) for verifying the QE report signature.
    if qe_report.nested_type != 5:
        raise ValueError(
            f"cannot verify QE report signature with nested certification type {qe_report.nested_type} (expected 5)"
        )

    certs = _extract_pem_certificates(qe_report.nested_data)
    if not certs:
        raise ValueError("nested certification data does not contain a PEM certificate chain")

    pck_cert = certs[0]
    public_key = pck_cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("PCK certificate public key is not ECDSA")

    _verify_ecdsa_raw_signature(public_key, qe_report.qe_report_signature, qe_report.qe_report_body)


def verify_event_log_against_rtmr(event_log: list[dict[str, Any]], rtmr: list[bytes]) -> None:
    calc = [b"\x00" * 48 for _ in range(4)]
    for idx, event in enumerate(event_log):
        imr = event.get("imr")
        if not isinstance(imr, int) or not (0 <= imr <= 3):
            continue

        digest_hex = event.get("digest")
        if not isinstance(digest_hex, str):
            raise ValueError(f"event_log[{idx}] has non-string digest")

        digest = _must_hex_to_bytes(f"event_log[{idx}].digest", digest_hex)
        if len(digest) != 48:
            raise ValueError(
                f"event_log[{idx}].digest must be 48 bytes for SHA-384, got {len(digest)}"
            )

        calc[imr] = hashlib.sha384(calc[imr] + digest).digest()

    for i in range(4):
        if calc[i] != rtmr[i]:
            raise ValueError(f"RTMR{i} mismatch after replaying event log")


def verify_quote_payload(payload: dict[str, Any]) -> Result:
    result = Result()

    try:
        quote = extract_quote_bytes(payload)
    except ValueError as exc:
        result.fail(str(exc))
        return result

    if len(quote) < SIGNED_QUOTE_PART_SIZE + 4:
        result.fail("quote blob is too short")
        return result

    # Quote header
    version, att_key_type, tee_type = struct.unpack_from("<HHI", quote, 0)
    if version != 4:
        result.fail(f"unsupported quote version: {version} (expected 4)")
    else:
        result.ok("quote version is 4")

    if att_key_type != 2:
        result.warn(f"unexpected attestation key type: {att_key_type} (expected 2 for ECDSA-P256)")
    else:
        result.ok("attestation key type is ECDSA-P256")

    if tee_type != 0x81:
        result.fail(f"unexpected TEE type: 0x{tee_type:08x} (expected 0x00000081 for TDX)")
    else:
        result.ok("TEE type is Intel TDX")

    sig_data_len = struct.unpack_from("<I", quote, SIGNED_QUOTE_PART_SIZE)[0]
    sig_data_start = SIGNED_QUOTE_PART_SIZE + 4
    sig_data_end = sig_data_start + sig_data_len

    if sig_data_end > len(quote):
        result.fail(
            f"signature data exceeds quote length (sig_data_end={sig_data_end}, quote_len={len(quote)})"
        )
        return result

    trailing = quote[sig_data_end:]
    if trailing:
        result.warn(
            f"quote contains {len(trailing)} trailing byte(s) after declared quote structure; "
            "they are not covered by quote signature"
        )

    quote_header_and_body = quote[:SIGNED_QUOTE_PART_SIZE]
    report_body = quote[QUOTE_HEADER_SIZE:SIGNED_QUOTE_PART_SIZE]

    try:
        td_body = parse_td_report_body(report_body)
    except ValueError as exc:
        result.fail(str(exc))
        return result

    td_attr_u64 = _td_attributes_u64(td_body.td_attributes)
    td_tud_bits = td_attr_u64 & 0xFF
    td_reserved_mask = 0
    td_reserved_mask |= ((1 << 20) - 1) << 8  # SEC reserved bits 27:8
    td_reserved_mask |= 1 << 29  # SEC reserved bit 29
    td_reserved_mask |= ((1 << 31) - 1) << 32  # OTHER reserved bits 62:32
    td_reserved_bits = td_attr_u64 & td_reserved_mask

    if td_tud_bits == 0:
        result.ok("TDATTRIBUTES.TUD (bits 7:0) is zero (not under debug)")
    else:
        result.fail(f"TDATTRIBUTES.TUD is non-zero (0x{td_tud_bits:02x}); TD is under debug/untrusted")

    if td_reserved_bits == 0:
        result.ok("TDATTRIBUTES reserved bits are zero")
    else:
        result.warn(
            "TDATTRIBUTES has non-zero reserved bits "
            f"(mask value=0x{td_reserved_bits:016x}); verify platform policy compatibility"
        )

    if td_body.seam_attributes == b"\x00" * 8:
        result.ok("SEAMATTRIBUTES is zero")
    else:
        result.warn(
            "SEAMATTRIBUTES is non-zero "
            f"(0x{td_body.seam_attributes.hex()}); TDX 1.0 expects zero"
        )

    try:
        sig_data = parse_quote_signature_data(quote[sig_data_start:sig_data_end])
    except ValueError as exc:
        result.fail(str(exc))
        return result

    try:
        verify_quote_signature(sig_data.attest_pub_key, sig_data.quote_signature, quote_header_and_body)
        result.ok("quote signature verifies against embedded attestation key")
    except Exception as exc:
        result.fail(f"quote signature verification failed: {exc.__class__.__name__}")

    if sig_data.certification_data_type == 6:
        try:
            qe_data = parse_qe_report_certification_data(sig_data.certification_data)
            verify_qe_report_binding(qe_data, sig_data.attest_pub_key)
            result.ok("QE report_data binds attestation key and QE auth data")
            result.ok(
                "parsed QE certification data "
                f"(nested type={qe_data.nested_type}, nested_size={len(qe_data.nested_data)})"
            )
            if qe_data.nested_type == 5:
                try:
                    verify_qe_report_signature_with_pck(qe_data)
                    result.ok("QE report signature verifies with public key from nested PCK certificate")
                except Exception as exc:
                    result.fail(f"QE report signature verification failed: {exc}")
            else:
                result.warn(
                    "QE report signature check skipped because nested certification type is not 5 "
                    "(PCK_CERT_CHAIN)"
                )
        except Exception as exc:
            result.fail(f"failed QE certification data checks: {exc}")
    else:
        result.warn(
            "quote certification data is not QE_REPORT_CERT (type 6); "
            "skipping QE binding checks"
        )

    result.warn(
        "offline checks do not validate PCK certificate chain, CRLs, QE identity, "
        "or Intel collateral freshness; use Intel online verification for those checks"
    )

    expected_fields = [
        (("mrtd", "mr_td"), "MRTD", td_body.mr_td),
        (("rtmr0",), "RTMR0", td_body.rtmr[0]),
        (("rtmr1",), "RTMR1", td_body.rtmr[1]),
        (("rtmr2",), "RTMR2", td_body.rtmr[2]),
        (("rtmr3",), "RTMR3", td_body.rtmr[3]),
        (("mr_config_id", "mrconfigid"), "MRCONFIGID", td_body.mr_config_id),
        (("mr_owner", "mrowner"), "MROWNER", td_body.mr_owner),
        (("mr_owner_config", "mrownerconfig"), "MROWNERCONFIG", td_body.mr_owner_config),
    ]

    identity_policy_fields = {"MRTD", "MRCONFIGID", "MROWNER", "MROWNERCONFIG"}
    identity_policy_checks = 0
    for key_aliases, label, actual in expected_fields:
        expected_value = _find_expected_value(payload, *key_aliases)
        if not isinstance(expected_value, str):
            continue
        if label in identity_policy_fields:
            identity_policy_checks += 1
        try:
            parsed = _must_hex_to_bytes(label, expected_value)
        except ValueError as exc:
            result.fail(f"{label} expected value is invalid: {exc}")
            continue
        if len(parsed) != len(actual):
            result.fail(
                f"{label} expected value length is {len(parsed)} bytes (expected {len(actual)})"
            )
            continue
        if parsed == actual:
            result.ok(f"{label} matches expected value")
        else:
            result.fail(f"{label} mismatch against expected value")

    if identity_policy_checks == 0:
        result.warn(
            "no expected MRTD/MRCONFIGID/MROWNER/MROWNERCONFIG policy values were provided"
        )

    expected_xfam = _find_expected_value(payload, "xfam", "expected_xfam")
    actual_xfam = int.from_bytes(td_body.xfam, "little")
    if expected_xfam is None:
        result.warn("no expected XFAM policy value was provided")
    else:
        try:
            parsed_expected_xfam = _parse_expected_int(expected_xfam)
        except ValueError as exc:
            result.fail(f"XFAM expected value is invalid: {exc}")
        else:
            if parsed_expected_xfam == actual_xfam:
                result.ok("XFAM matches expected value")
            else:
                result.fail(
                    f"XFAM mismatch against expected value "
                    f"(actual=0x{actual_xfam:016x}, expected=0x{parsed_expected_xfam:016x})"
                )

    event_log = payload.get("event_log")
    if isinstance(event_log, list):
        try:
            verify_event_log_against_rtmr(event_log, td_body.rtmr)
            result.ok("event_log replays to RTMR0..RTMR3")
        except ValueError as exc:
            result.fail(str(exc))

    return result


def print_local_result(result: Result) -> None:
    for check in result.checks:
        print(f"[OK] {check}")
    for warning in result.warnings:
        print(f"[WARN] {warning}")
    for error in result.errors:
        print(f"[FAIL] {error}")

    if result.errors:
        print(f"\nLOCAL VERDICT: FAIL ({len(result.errors)} error(s))")
        return

    print(f"\nLOCAL VERDICT: PASS ({len(result.checks)} check(s), {len(result.warnings)} warning(s))")


def print_quote_dump(payload: dict[str, Any], dump_format: str, include_raw: bool) -> None:
    dump = build_quote_debug_dump(payload, include_raw=include_raw)
    if dump_format == "json":
        print(json.dumps(dump, indent=2, sort_keys=False))
    else:
        print(format_yaml_like(dump))


def print_online_result(result: OnlineAttestationResult, save_token_path: str | None) -> None:
    if result.endpoint:
        print(f"\nIntel online endpoint: {result.endpoint}")

    if not result.success:
        prefix = f"HTTP {result.status_code}" if result.status_code is not None else "request failed"
        print(f"[FAIL] Intel online attestation failed ({prefix})")
        if result.error:
            print(f"[FAIL] {result.error}")
        print("\nONLINE VERDICT: FAIL")
        return

    print("[OK] Intel Trust Authority accepted quote and returned attestation token")
    if result.status_code is not None:
        print(f"[OK] HTTP status {result.status_code}")

    if result.claims is not None:
        exp = result.claims.get("exp")
        if isinstance(exp, int):
            exp_time = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
            print(f"[OK] token exp (UTC): {exp_time.isoformat()}")

        iss = result.claims.get("iss")
        if isinstance(iss, str):
            print(f"[OK] token issuer: {iss}")

    if save_token_path and result.token is not None:
        try:
            Path(save_token_path).write_text(result.token + "\n")
            print(f"[OK] wrote attestation token to {save_token_path}")
        except OSError as exc:
            print(f"[WARN] failed to write token to {save_token_path}: {exc}")

    print("\nONLINE VERDICT: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        default="quote.json",
        help="Path to quote JSON file (default: quote.json)",
    )
    parser.add_argument(
        "--dump-quote",
        action="store_true",
        help="Print detailed, structured dump of quote contents (header/body/certification data).",
    )
    parser.add_argument(
        "--dump-format",
        choices=("yaml", "json"),
        default="yaml",
        help="Output format for --dump-quote (default: yaml).",
    )
    parser.add_argument(
        "--dump-raw",
        action="store_true",
        help="Include full raw hex for large variable-size sections in quote dump.",
    )
    parser.add_argument(
        "--dump-only",
        action="store_true",
        help="Only print quote dump and skip local/online verification checks.",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Also verify with Intel Trust Authority (/appraisal/v1/attest).",
    )
    parser.add_argument(
        "--online-only",
        action="store_true",
        help="Skip local checks and only perform Intel online attestation.",
    )
    parser.add_argument(
        "--intel-api-key",
        default=os.environ.get("INTEL_TRUST_AUTHORITY_API_KEY"),
        help="Intel Trust Authority API key (default: INTEL_TRUST_AUTHORITY_API_KEY env var).",
    )
    parser.add_argument(
        "--intel-base-url",
        default=os.environ.get("INTEL_TRUST_AUTHORITY_BASE_URL", "https://api.trustauthority.intel.com"),
        help="Intel Trust Authority base URL (default: https://api.trustauthority.intel.com).",
    )
    parser.add_argument(
        "--policy-id",
        action="append",
        default=[],
        help="Optional policy ID for Intel appraisal API. Repeat flag for multiple IDs.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="HTTP timeout for Intel online verification (default: 30).",
    )
    parser.add_argument(
        "--save-token",
        help="Optional path to save returned Intel attestation JWT token.",
    )
    args = parser.parse_args()

    if args.online_only:
        args.online = True
    if args.dump_only:
        args.online = False

    path = Path(args.input)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(path.read_text())
    except Exception as exc:
        print(f"error: failed to parse JSON from {path}: {exc}", file=sys.stderr)
        return 2

    exit_code = 0

    if args.dump_quote:
        print_quote_dump(payload, dump_format=args.dump_format, include_raw=args.dump_raw)
        if not args.dump_only:
            print()

    if args.dump_only:
        return 0

    if not args.online_only:
        local_result = verify_quote_payload(payload)
        print_local_result(local_result)
        if local_result.errors:
            exit_code = 1

    if args.online:
        if not isinstance(args.intel_api_key, str) or not args.intel_api_key.strip():
            print(
                "error: online verification requires --intel-api-key or "
                "INTEL_TRUST_AUTHORITY_API_KEY",
                file=sys.stderr,
            )
            return 2

        try:
            quote = extract_quote_bytes(payload)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        online_result = verify_quote_with_intel_trust_authority(
            quote=quote,
            api_key=args.intel_api_key.strip(),
            base_url=args.intel_base_url,
            timeout_seconds=args.timeout_seconds,
            policy_ids=args.policy_id,
        )
        print_online_result(online_result, args.save_token)
        if not online_result.success:
            exit_code = 1

    if args.online:
        if exit_code == 0:
            print("\nFINAL VERDICT: PASS")
        else:
            print("\nFINAL VERDICT: FAIL")
        return exit_code

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
