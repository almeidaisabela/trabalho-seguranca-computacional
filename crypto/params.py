"""
CAMADA 1 - CRIPTOGRAFIA | Parâmetros do grupo (Integrante 1)

Usamos o grupo MODP de 2048 bits da RFC 3526 (grupo 14), um grupo padronizado.

- p é um "primo seguro": p = 2q + 1, com q também primo.
- Trabalhamos no subgrupo de ordem q de Z_p*. Nesse subgrupo o problema do
  logaritmo discreto (e o problema de Diffie-Hellman) é considerado difícil.
- g = 2 gera esse subgrupo de ordem q (conferido em `conferir_parametros`).

Todos os expoentes secretos (r das cifras, x_i das autoridades) são sorteados
em [1, q-1].
"""

import secrets

NOME_GRUPO = "RFC3526-MODP-2048"

# Primo p de 2048 bits copiado da RFC 3526, seção 3.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P = int(_P_HEX, 16)   # módulo
Q = (P - 1) // 2      # ordem do subgrupo
G = 2                 # gerador do subgrupo de ordem Q


def expoente_aleatorio() -> int:
    """Sorteia um expoente secreto em [1, q-1] com gerador criptograficamente seguro."""
    return secrets.randbelow(Q - 1) + 1


def pertence_ao_grupo(x: int) -> bool:
    """x está no subgrupo de ordem q? (1 <= x < p e x^q = 1 mod p)."""
    return 1 <= x < P and pow(x, Q, P) == 1


def conferir_parametros() -> bool:
    """Checagens baratas de sanidade: tamanho, relação p = 2q + 1 e ordem de g."""
    return P.bit_length() == 2048 and P == 2 * Q + 1 and pow(G, Q, P) == 1
