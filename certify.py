from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes



def create_selfsigned_certificate(private_key, email):
    # in self-signed certificate we will make the subject same as issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EGY"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{email}@ca_self-signed.com"),
    ])
    # create the certificate
    ca = x509.CertificateBuilder().subject_name(
                                                    subject
                                                ).issuer_name(
                                                    issuer
                                                ).public_key(
                                                    private_key.public_key()  # Accessing the public key from private_key
                                                ).serial_number(
                                                    x509.random_serial_number()
                                                ).not_valid_before(
                                                    datetime.now(timezone.utc)  # Use timezone.utc here
                                                ).not_valid_after(
                                                    datetime.now(timezone.utc) + timedelta(days=365)  # Use timezone.utc here
                                                ).sign(private_key, hashes.SHA256())  
    return ca


def verify_certificate(public_key, certificate_pem, email):
    try:
        # convert pem object to certificate object
        cert = x509.load_pem_x509_certificate(certificate_pem, default_backend())

        # verifty that certificate public key is the same as shared one
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

        # check the certificate issuer
        issuer_common_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        expected_issuer_common_name = f"{email}@ca_self-signed.com"
        if issuer_common_name != expected_issuer_common_name:
            return False

        # check the certificate validity period
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        if now < not_valid_before or now > not_valid_after:
            return False

        return True    
    except (ValueError, IndexError, x509.InvalidSignature):
        return False