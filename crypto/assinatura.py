"""
CAMADA 1 - CRIPTOGRAFIA | Assinaturas digitais RSA (Integrante 1)

Único ponto do projeto que usa uma biblioteca pronta (`cryptography`), o que é
permitido pelo enunciado ("bibliotecas de assinatura RSA").

- RSA de 2048 bits, expoente público 65537.
- Esquema PSS com SHA-256 (padding probabilístico, recomendado no lugar do
  PKCS#1 v1.5).
- Sempre assinamos os bytes de `canonico(...)`, nunca um JSON "qualquer".
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                   salt_length=padding.PSS.MAX_LENGTH)


def gerar_par_rsa():
    """Devolve (chave_privada_pem, chave_publica_pem) como strings."""
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return priv_pem, chave_publica_de(priv_pem)


def chave_publica_de(chave_privada_pem: str) -> str:
    """Deriva a chave pública (PEM) a partir da privada."""
    privada = serialization.load_pem_private_key(chave_privada_pem.encode(), password=None)
    return privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def assinar(chave_privada_pem: str, dados: bytes) -> str:
    """Assina os bytes e devolve a assinatura em hexadecimal."""
    privada = serialization.load_pem_private_key(chave_privada_pem.encode(), password=None)
    return privada.sign(dados, _PSS, hashes.SHA256()).hex()


def verificar(chave_publica_pem: str, dados: bytes, assinatura_hex: str) -> bool:
    """True se a assinatura confere com a chave pública e os bytes."""
    try:
        publica = serialization.load_pem_public_key(chave_publica_pem.encode())
        publica.verify(bytes.fromhex(assinatura_hex), dados, _PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False
