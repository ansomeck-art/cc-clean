"""Exact trust-scope and stable identity regression; no system trust changes."""
import datetime
import ipaddress
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry_certificates import HOSTS, prepare_server_identity, validate_authority_certificate

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
except ImportError:
    x509 = None


@unittest.skipIf(x509 is None, 'full HTTPS build requires Python 3.12 cryptography wheels')
class CertificateTests(unittest.TestCase):
    def test_identity_survives_worker_restart_and_limits_authority_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            first = prepare_server_identity(directory)
            before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            second = prepare_server_identity(directory)
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})
            self.assertEqual(first[4], second[4])
            authority = validate_authority_certificate(first[3].read_bytes())
            self.assertEqual(authority.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length, 0)
            scope = authority.extensions.get_extension_for_class(x509.NameConstraints)
            self.assertTrue(scope.critical)
            self.assertEqual(set(scope.value.permitted_subtrees), {x509.DNSName(h) for h in HOSTS})
            self.assertIn(x509.IPAddress(ipaddress.ip_network('0.0.0.0/0')), scope.value.excluded_subtrees)
            self.assertIn(x509.IPAddress(ipaddress.ip_network('::/0')), scope.value.excluded_subtrees)
            self.assertTrue(all((p.stat().st_mode & 0o077) == 0 for p in Path(directory).iterdir()))

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS native TLS verification')
    def test_native_tls_accepts_only_six_hosts_and_rejects_foreign_certificates(self):
        import Foundation
        import Security
        def native(cert):
            der = cert.public_bytes(serialization.Encoding.DER)
            return Security.SecCertificateCreateWithData(None, Foundation.NSData.dataWithBytes_length_(der, len(der)))
        with tempfile.TemporaryDirectory() as directory:
            public, identity, server_cert, authority_public, issuer = prepare_server_identity(directory)
            anchor = native(issuer)
            for host in HOSTS + ('example.com', 'api.stripe.com', 'sub.claude.ai'):
                code, trust = Security.SecTrustCreateWithCertificates(native(server_cert),
                    Security.SecPolicyCreateSSL(True, host), None)
                self.assertEqual(code, 0)
                Security.SecTrustSetAnchorCertificates(trust, [anchor])
                Security.SecTrustSetAnchorCertificatesOnly(trust, True)
                Security.SecTrustSetNetworkFetchAllowed(trust, False)
                accepted, _ = Security.SecTrustEvaluateWithError(trust, None)
                self.assertEqual(bool(accepted), host in HOSTS, host)
            # Even an identity signed with this CA's own key cannot authenticate
            # an unrelated host, a subdomain, or a bare IPv4/IPv6 address.
            from telemetry_certificates import AUTHORITY_IDENTITY_NAME
            issuer_key = serialization.load_pem_private_key((Path(directory) / AUTHORITY_IDENTITY_NAME).read_bytes(), None)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.datetime.now(datetime.timezone.utc)
            for host in ('example.com', 'api.stripe.com', 'sub.claude.ai', '1.1.1.1', '2001:4860:4860::8888'):
                try:
                    san = x509.IPAddress(ipaddress.ip_address(host))
                except ValueError:
                    san = x509.DNSName(host)
                forged = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
                    .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([san]), False)
                    .add_extension(x509.BasicConstraints(False, None), True)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                    .sign(issuer_key, hashes.SHA256()))
                _, trust = Security.SecTrustCreateWithCertificates(native(forged), Security.SecPolicyCreateSSL(True, host), None)
                Security.SecTrustSetAnchorCertificates(trust, [anchor])
                Security.SecTrustSetAnchorCertificatesOnly(trust, True)
                Security.SecTrustSetNetworkFetchAllowed(trust, False)
                accepted, _ = Security.SecTrustEvaluateWithError(trust, None)
                self.assertFalse(accepted, host)


if __name__ == '__main__':
    unittest.main()
