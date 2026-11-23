import os
import sys
import datetime
import ipaddress


def generate_with_cryptography(cert_path, key_path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SSL Secure Web App"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cyber Security Lab"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return True


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    certs_dir = os.path.join(base, "certs")
    os.makedirs(certs_dir, exist_ok=True)
    cert_path = os.path.join(certs_dir, "cert.pem")
    key_path = os.path.join(certs_dir, "key.pem")

    try:
        generate_with_cryptography(cert_path, key_path)
    except Exception:
        cmd = (
            f'openssl req -x509 -newkey rsa:2048 -nodes '
            f'-keyout "{key_path}" -out "{cert_path}" -days 365 '
            f'-subj "/CN=127.0.0.1/O=SecureApp"'
        )
        rc = os.system(cmd)
        if rc != 0:
            print("Failed to generate certificate.", file=sys.stderr)
            sys.exit(1)

    try:
        import shutil
        shutil.copyfile(cert_path, os.path.join(base, "cert.pem"))
        shutil.copyfile(key_path, os.path.join(base, "key.pem"))
    except Exception:
        pass

    print("Certificates generated successfully.")


if __name__ == "__main__":
    main()
