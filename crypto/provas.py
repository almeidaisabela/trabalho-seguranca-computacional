"""
CAMADA 1 - CRIPTOGRAFIA | Provas de conhecimento nulo (Integrante 1)

Duas provas pequenas que protegem contra AUTORIDADES DESONESTAS. As duas usam a
heurística de Fiat-Shamir: o "desafio" c, que num protocolo interativo viria do
verificador, é calculado como um hash dos dados públicos. Assim a prova vira um
par de números que qualquer um (inclusive o auditor) confere depois.

1) Prova de Schnorr: "eu conheço x_i tal que h_i = g^x_i".
   Impede o ataque da chave maliciosa: sem ela, a última autoridade poderia
   publicar h_3 = g^y / (h_1 * h_2). Aí h = h_1 h_2 h_3 = g^y e ela conheceria
   sozinha a chave privada completa y. Com a prova, ela teria de conhecer o log
   de h_3, que não sabe calcular.

2) Prova de Chaum-Pedersen: "D = C1^x_i usa o MESMO x_i de h_i = g^x_i".
   Impede que uma autoridade publique uma decifração parcial falsa
   (por exemplo D * g^-k) para alterar o total de votos de um candidato.

Nenhuma das provas revela x_i: z = w + c*x_i fica "mascarado" pelo w aleatório.
"""

from crypto.params import G, P, Q, expoente_aleatorio
from crypto.serial import canonico, hex_para_int, int_para_hex, sha256_hex


def _desafio(*valores) -> int:
    """Desafio de Fiat-Shamir: hash dos valores públicos, reduzido mod q."""
    textos = [v if isinstance(v, str) else int_para_hex(v) for v in valores]
    return hex_para_int(sha256_hex(canonico(textos))) % Q


# ---------------------------------------------------------------- Schnorr
def provar_schnorr(x: int, h: int, contexto: str) -> dict:
    w = expoente_aleatorio()
    a = pow(G, w, P)                  # compromisso
    c = _desafio("schnorr", contexto, h, a)
    z = (w + c * x) % Q               # resposta
    return {"a": int_para_hex(a), "z": int_para_hex(z)}


def verificar_schnorr(h: int, prova: dict, contexto: str) -> bool:
    a, z = hex_para_int(prova["a"]), hex_para_int(prova["z"])
    c = _desafio("schnorr", contexto, h, a)
    # g^z = g^(w + c x) = g^w * (g^x)^c = a * h^c
    return pow(G, z, P) == (a * pow(h, c, P)) % P


# ---------------------------------------------------------- Chaum-Pedersen
def provar_chaum_pedersen(x: int, h: int, c1: int, d: int) -> dict:
    w = expoente_aleatorio()
    a = pow(G, w, P)
    b = pow(c1, w, P)
    c = _desafio("chaum-pedersen", h, c1, d, a, b)
    z = (w + c * x) % Q
    return {"a": int_para_hex(a), "b": int_para_hex(b), "z": int_para_hex(z)}


def verificar_chaum_pedersen(h: int, c1: int, d: int, prova: dict) -> bool:
    a, b, z = (hex_para_int(prova[k]) for k in ("a", "b", "z"))
    c = _desafio("chaum-pedersen", h, c1, d, a, b)
    # Mesmo z funciona nas duas bases -> o expoente é o mesmo x nas duas.
    return (pow(G, z, P) == (a * pow(h, c, P)) % P
            and pow(c1, z, P) == (b * pow(d, c, P)) % P)
