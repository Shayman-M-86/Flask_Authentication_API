from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

def test_ed25519():
    # Generate a private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    # Get the corresponding public key
    public_key = private_key.public_key()
    # Serialize the private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.PKCS8,
        encryption_algorithm=ser.NoEncryption()
    )
    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PublicFormat.SubjectPublicKeyInfo
    )
    # Print the PEM-encoded keys    print("Private Key PEM:")
    print(private_pem.decode())
    print("Public Key PEM:")
    print(public_pem.decode())

if __name__ == "__main__":
    test_ed25519()