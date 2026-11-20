"""
CAMADA 1 - CRIPTOGRAFIA | Serialização canônica e hash (Integrante 1)

Tudo que é ASSINADO ou passa por HASH precisa virar exatamente os mesmos bytes
em qualquer módulo (eleitor, servidor, autoridades e auditor). Por isso existe
uma única função `canonico` e ninguém reimplementa.
"""

import hashlib
import json


def canonico(obj) -> bytes:
    """JSON com chaves ordenadas e sem espaços -> sempre os mesmos bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(dados: bytes) -> str:
    """Hash SHA-256 em hexadecimal minúsculo."""
    return hashlib.sha256(dados).hexdigest()


def int_para_hex(n: int) -> str:
    """Inteiros de 2048 bits não cabem com segurança em JSON: gravamos como hex."""
    return format(n, "x")


def hex_para_int(s: str) -> int:
    return int(s, 16)
