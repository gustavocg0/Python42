"""Device-certificate signing against the stamp-internal issuing CA (ADR-0006).

SEC-8: the CSR is proof-of-possession ONLY — subject/SAN content supplied by
the client is ignored entirely (the agent sends an EMPTY-subject PKCS#10,
ECDSA P-256, per the ratified §10 contract). The server assigns identity:
  subject  CN=<device_id>
  URI SAN  urn:platform:tenant:<tenant_id>:device:<device_id>
  lifetime 90 days (settings.cert_lifetime_days)
Serials are stored as lowercase hex (devices.cert_serial) and MUST match the
serial nginx forwards in X-Client-Cert-Serial (allowlist check, SEC-10).

CA cert+key paths come from DP_CA_CERT / DP_CA_KEY (compose dev CA per
SEC-9; production key custody is cloud-platform's domain).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_BACKDATE = timedelta(minutes=5)  # clock-skew tolerance
_MIN_RSA_BITS = 2048


class CsrError(ValueError):
    """CSR unparseable / bad signature / unsupported key — 400 to the client."""


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    certificate_pem: str
    ca_chain_pem: str
    serial_hex: str
    issued_at: datetime
    expires_at: datetime
    public_key_fingerprint: str  # sha256 hex of SPKI DER (devices column)


def san_uri(tenant_id: UUID, device_id: str) -> str:
    """ADR-0006 identity URI (binding for gateway header mapping)."""
    return f"urn:platform:tenant:{tenant_id}:device:{device_id}"


class CertificateAuthority:
    def __init__(
        self,
        ca_cert_pem: bytes,
        ca_key_pem: bytes,
        *,
        lifetime_days: int = 90,
    ) -> None:
        self._ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        key = serialization.load_pem_private_key(ca_key_pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
            raise ValueError("CA key must be EC or RSA")
        self._ca_key = key
        self._lifetime = timedelta(days=lifetime_days)
        self._ca_chain_pem = ca_cert_pem.decode("ascii")

    @classmethod
    def from_files(
        cls, cert_path: str, key_path: str, *, lifetime_days: int = 90
    ) -> CertificateAuthority:
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
        return cls(cert_pem, key_pem, lifetime_days=lifetime_days)

    @property
    def ca_chain_pem(self) -> str:
        return self._ca_chain_pem

    @staticmethod
    def validate_csr(csr_pem: str) -> x509.CertificateSigningRequest:
        """Parse + proof-of-possession check; SUBJECT CONTENT IS IGNORED (SEC-8)."""
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise CsrError("csr_pem is not a valid PEM PKCS#10 request") from exc
        if not csr.is_signature_valid:
            raise CsrError("CSR signature invalid (proof-of-possession failed)")
        public_key = csr.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < _MIN_RSA_BITS:
                raise CsrError(f"RSA keys must be >= {_MIN_RSA_BITS} bits")
        elif not isinstance(
            public_key, ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
        ):
            raise CsrError("unsupported CSR key type (expect ECDSA P-256)")
        return csr

    @staticmethod
    def spki_fingerprint(csr: x509.CertificateSigningRequest) -> str:
        spki = csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return sha256(spki).hexdigest()

    def sign_device_csr(
        self,
        csr_pem: str,
        *,
        tenant_id: UUID,
        device_id: str,
        now: datetime | None = None,
    ) -> IssuedCertificate:
        csr = self.validate_csr(csr_pem)
        issued_at = now or datetime.now(UTC)
        expires_at = issued_at + self._lifetime
        serial = x509.random_serial_number()
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(issued_at - _BACKDATE)
            .not_valid_after(expires_at)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(san_uri(tenant_id, device_id))]
                ),
                critical=False,
            )
        )
        certificate = builder.sign(self._ca_key, hashes.SHA256())
        return IssuedCertificate(
            certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            ca_chain_pem=self._ca_chain_pem,
            serial_hex=format(serial, "x"),
            issued_at=issued_at,
            expires_at=expires_at,
            public_key_fingerprint=self.spki_fingerprint(csr),
        )
