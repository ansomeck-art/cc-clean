"""Stable TLS identity with exact-host limits encoded in the issuing certificate.

Chromium ignores macOS hostname trust settings. A critical NameConstraints
extension is enforced by TLS verifiers themselves, including trust anchors.
"""
import datetime
import ipaddress
import os
from pathlib import Path

HOSTS = ('claude.ai', 'api.anthropic.com', 'a-api.anthropic.com',
         'o1158394.ingest.us.sentry.io', 'browser-intake-us5-datadoghq.com',
         'http-intake.logs.us5.datadoghq.com')
CERTIFICATE_NAME = 'regionguard-scoped-ca-cert.pem'
AUTHORITY_IDENTITY_NAME = 'regionguard-scoped-ca.pem'
SERVER_CERTIFICATE_NAME = 'regionguard-server-cert.pem'
SERVER_IDENTITY_NAME = 'regionguard-server.pem'


def _valid_now(cert):
    now = datetime.datetime.now(datetime.timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError('tls_identity_expired')


def validate_authority_certificate(data):
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert = x509.load_pem_x509_certificate(data)
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not basic.ca or basic.path_length != 0 or cert.issuer != cert.subject:
        raise ValueError('authority_must_not_delegate_to_another_ca')
    extension = cert.extensions.get_extension_for_class(x509.NameConstraints)
    constraints = extension.value
    excluded = {x509.DNSName('.' + h) for h in HOSTS} | {
        x509.IPAddress(ipaddress.ip_network('0.0.0.0/0')),
        x509.IPAddress(ipaddress.ip_network('::/0'))}
    if (not extension.critical or len(constraints.permitted_subtrees or []) != len(HOSTS)
            or len(constraints.excluded_subtrees or []) != len(excluded)
            or set(constraints.permitted_subtrees) != {x509.DNSName(h) for h in HOSTS}
            or set(constraints.excluded_subtrees) != excluded):
        raise ValueError('authority_must_constrain_exactly_six_hosts')
    if set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) != {ExtendedKeyUsageOID.SERVER_AUTH}:
        raise ValueError('authority_must_only_authenticate_tls_servers')
    _valid_now(cert)
    return cert


def validate_server_certificate(data):
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    cert = x509.load_pem_x509_certificate(data)
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('server_identity_must_not_be_a_ca')
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if set(names.get_values_for_type(x509.DNSName)) != set(HOSTS) or len(names) != len(HOSTS):
        raise ValueError('unexpected_server_identity_hosts')
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if usage.key_cert_sign or usage.crl_sign:
        raise ValueError('server_identity_must_not_issue_certificates')
    if set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) != {ExtendedKeyUsageOID.SERVER_AUTH}:
        raise ValueError('server_identity_must_only_authenticate_tls_servers')
    _valid_now(cert)
    return cert


def _write(path, data):
    temporary = path.with_suffix('.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    os.replace(temporary, path)
    path.chmod(0o600)


def prepare_server_identity(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.exceptions import InvalidSignature
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    directory = Path(directory)
    authority_public, authority_private = directory / CERTIFICATE_NAME, directory / AUTHORITY_IDENTITY_NAME
    now = datetime.datetime.now(datetime.timezone.utc)
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pem = serialization.Encoding.PEM
    issuer = issuer_key = None
    if authority_public.is_file() and authority_private.is_file():
        try:
            issuer = validate_authority_certificate(authority_public.read_bytes())
            issuer_key = serialization.load_pem_private_key(authority_private.read_bytes(), None)
            if issuer_key.public_key().public_bytes(*public_format) != issuer.public_key().public_bytes(*public_format):
                raise ValueError('authority_key_mismatch')
            issuer.public_key().verify(issuer.signature, issuer.tbs_certificate_bytes,
                                       padding.PKCS1v15(), issuer.signature_hash_algorithm)
        except (ValueError, InvalidSignature, x509.ExtensionNotFound):
            issuer = issuer_key = None
    if issuer is None:
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'RegionGuard'),
                         x509.NameAttribute(NameOID.COMMON_NAME, 'RegionGuard Restricted HTTPS CA')])
        issuer = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(issuer_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=1095))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(h) for h in HOSTS],
                excluded_subtrees=[x509.DNSName('.' + h) for h in HOSTS] + [
                    x509.IPAddress(ipaddress.ip_network('0.0.0.0/0')),
                    x509.IPAddress(ipaddress.ip_network('::/0'))]), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=None, decipher_only=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256()))
        secret = issuer_key.private_bytes(pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        _write(authority_private, secret + issuer.public_bytes(pem))
        _write(authority_public, issuer.public_bytes(pem))
        validate_authority_certificate(authority_public.read_bytes())
    certificate, identity = directory / SERVER_CERTIFICATE_NAME, directory / SERVER_IDENTITY_NAME
    if certificate.is_file() and identity.is_file():
        try:
            cert = validate_server_certificate(certificate.read_bytes())
            private = serialization.load_pem_private_key(identity.read_bytes(), None)
            if private.public_key().public_bytes(*public_format) != cert.public_key().public_bytes(*public_format):
                raise ValueError('server_identity_key_mismatch')
            issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                       padding.PKCS1v15(), cert.signature_hash_algorithm)
            if x509.load_pem_x509_certificate(identity.read_bytes()) != cert:
                raise ValueError('server_identity_certificate_mismatch')
            return certificate, identity, cert, authority_public, issuer
        except (ValueError, InvalidSignature, x509.ExtensionNotFound):
            pass
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'RegionGuard'),
                                 x509.NameAttribute(NameOID.COMMON_NAME, 'RegionGuard Local HTTPS')]))
        .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(min(now + datetime.timedelta(days=365), issuer.not_valid_after_utc))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in HOSTS]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256()))
    public = cert.public_bytes(pem)
    secret = key.private_bytes(pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    _write(identity, secret + public + issuer.public_bytes(pem))
    _write(certificate, public)
    return certificate, identity, validate_server_certificate(public), authority_public, issuer
