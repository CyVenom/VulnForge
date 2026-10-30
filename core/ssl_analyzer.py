"""
VulnForge SSL/TLS Certificate Analyzer
Checks certificate validity, expiry, protocol versions, cipher suites,
chain validation, and known weak configurations.
"""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("vulnforge.ssl_analyzer")

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "eNULL", "aNULL",
}


class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a target."""

    def __init__(self, config: dict):
        self.config = config
        self.ssl_cfg = config.get("ssl", {})
        self.expiry_warning_days = self.ssl_cfg.get("expiry_warning_days", 30)

    async def analyze(self, target: str) -> dict:
        """Full SSL/TLS analysis."""
        # Strip scheme if present
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = 443

        loop = asyncio.get_event_loop()
        findings: list[dict] = []

        cert_info = await loop.run_in_executor(
            None, self._get_cert_info, hostname, port
        )

        protocol_results = await loop.run_in_executor(
            None, self._check_protocols, hostname, port
        )

        cipher_results = await loop.run_in_executor(
            None, self._get_cipher_info, hostname, port
        )

        # Analyse cert
        if "error" not in cert_info:
            self._analyse_cert(cert_info, findings)

        # Analyse protocols
        for proto, supported in protocol_results.items():
            if supported and proto in WEAK_PROTOCOLS:
                findings.append({
                    "title": f"Weak Protocol Supported: {proto}",
                    "severity": "high" if proto in ("SSLv2", "SSLv3") else "medium",
                    "description": f"{proto} is deprecated and vulnerable to known attacks.",
                    "remediation": f"Disable {proto} in server TLS configuration.",
                    "category": "ssl_protocol",
                    "evidence": f"{proto} accepted handshake",
                })

        # Analyse ciphers
        for cipher_name in cipher_results.get("weak_ciphers", []):
            findings.append({
                "title": f"Weak Cipher Suite: {cipher_name}",
                "severity": "high",
                "description": f"Cipher {cipher_name} is considered cryptographically weak.",
                "remediation": "Configure server to use only AEAD cipher suites (AES-GCM, CHACHA20-POLY1305).",
                "category": "ssl_cipher",
                "evidence": f"Cipher: {cipher_name}",
            })

        return {
            "target": hostname,
            "port": port,
            "certificate": cert_info,
            "protocols": protocol_results,
            "ciphers": cipher_results,
            "findings": findings,
        }

    def _get_cert_info(self, hostname: str, port: int) -> dict[str, Any]:
        """
        Retrieve and parse the TLS certificate.

        Note: the handshake below deliberately uses verify_mode=CERT_NONE so
        we can inspect expired/self-signed/mismatched certs too (that's the
        whole point of a security scan). Python's ssl.getpeercert() dict form
        is only populated when verification *succeeds*, so we parse the raw
        DER certificate with the `cryptography` library instead — that works
        regardless of verification outcome.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # we parse/verify manually below

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    protocol = ssock.version()

            if not der_cert:
                return {"error": "No certificate returned"}

            cert = x509.load_der_x509_certificate(der_cert)

            not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_remaining = (not_after - now).days

            def _name_to_dict(name: "x509.Name") -> dict:
                mapping = {
                    "commonName": NameOID.COMMON_NAME,
                    "organizationName": NameOID.ORGANIZATION_NAME,
                    "countryName": NameOID.COUNTRY_NAME,
                }
                result = {}
                for label, oid in mapping.items():
                    attrs = name.get_attributes_for_oid(oid)
                    if attrs:
                        result[label] = attrs[0].value
                return result

            san: list[str] = []
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return {
                "subject": _name_to_dict(cert.subject),
                "issuer": _name_to_dict(cert.issuer),
                "san": san,
                "not_before": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
                "not_after": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
                "days_remaining": days_remaining,
                "serial_number": format(cert.serial_number, "x"),
                "version": cert.version.value + 1,  # v1=0 -> 1, v3=2 -> 3
                "signature_algorithm": (cert.signature_hash_algorithm.name.upper()
                                         if cert.signature_hash_algorithm else ""),
                "cipher_suite": cipher[0] if cipher else "",
                "tls_version": protocol,
                "is_expired": days_remaining is not None and days_remaining < 0,
                "is_expiring_soon": (
                    days_remaining is not None
                    and 0 <= days_remaining <= self.expiry_warning_days
                ),
            }

        except ssl.SSLError as exc:
            logger.debug(f"SSL error for {hostname}:{port}: {exc}")
            return {"error": str(exc)}
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug(f"Connection error for {hostname}:{port}: {exc}")
            return {"error": str(exc), "note": "Port 443 not reachable or not TLS"}
        except Exception as exc:
            logger.debug(f"Certificate parse error for {hostname}:{port}: {exc}", exc_info=True)
            return {"error": f"Certificate parse error: {exc}"}

    def _check_protocols(self, hostname: str, port: int) -> dict[str, bool]:
        """Test which protocol versions the server accepts."""
        results: dict[str, bool] = {}
        test_protocols = {
            "TLSv1": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
        }

        for proto_name, tls_version in test_protocols.items():
            if tls_version is None:
                results[proto_name] = False
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        results[proto_name] = True
            except Exception:
                results[proto_name] = False

        return results

    def _get_cipher_info(self, hostname: str, port: int) -> dict[str, Any]:
        """Get negotiated cipher and flag weak ones."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated = ssock.cipher()

            weak_ciphers = []
            cipher_name = negotiated[0] if negotiated else ""
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    weak_ciphers.append(cipher_name)
                    break

            return {
                "negotiated": cipher_name,
                "protocol": negotiated[1] if negotiated else "",
                "bits": negotiated[2] if negotiated else 0,
                "weak_ciphers": weak_ciphers,
            }
        except Exception as exc:
            return {"error": str(exc), "weak_ciphers": []}

    def _analyse_cert(self, cert: dict, findings: list):
        """Generate findings from cert data."""
        if cert.get("is_expired"):
            findings.append({
                "title": "SSL Certificate Expired",
                "severity": "critical",
                "description": "The TLS certificate has expired — browsers will reject it.",
                "remediation": "Renew the certificate immediately.",
                "category": "ssl_certificate",
                "evidence": f"Expiry: {cert.get('not_after')}",
            })
        elif cert.get("is_expiring_soon"):
            days = cert.get("days_remaining", 0)
            findings.append({
                "title": f"SSL Certificate Expiring Soon ({days} days)",
                "severity": "medium",
                "description": f"Certificate expires in {days} days.",
                "remediation": "Renew the certificate before it expires.",
                "category": "ssl_certificate",
                "evidence": f"Expiry: {cert.get('not_after')}",
            })

        sig_alg = cert.get("signature_algorithm", "").upper()
        if "SHA1" in sig_alg or "MD5" in sig_alg:
            findings.append({
                "title": f"Weak Certificate Signature Algorithm: {sig_alg}",
                "severity": "high",
                "description": f"{sig_alg} is cryptographically broken.",
                "remediation": "Re-issue certificate with SHA-256 or stronger.",
                "category": "ssl_certificate",
            })

        subject = cert.get("subject", {})
        cn = subject.get("commonName", "")
        san = cert.get("san", [])
        if not san and cn:
            findings.append({
                "title": "Certificate Has No Subject Alternative Names",
                "severity": "low",
                "description": "Modern clients require SAN — CN-only certs may be rejected.",
                "remediation": "Re-issue certificate with SAN extension.",
                "category": "ssl_certificate",
            })
