"""
CAMADA 1 - CRIPTOGRAFIA | ElGamal exponencial e apuração homomórfica (Integrante 1)

Cifra de um valor m (0 ou 1) com a chave pública h = g^x:

    c1 = g^r mod p
    c2 = g^m * h^r mod p          (r novo e aleatório para CADA cifra)

Propriedade homomórfica: multiplicando duas cifras componente a componente,

    (g^r1 * g^r2,  g^m1 h^r1 * g^m2 h^r2) = (g^(r1+r2),  g^(m1+m2) * h^(r1+r2))

obtemos uma cifra da SOMA m1 + m2. Assim, multiplicando as cifras de todas as
cédulas para um candidato, obtemos uma cifra do TOTAL de votos dele, sem decifrar
nenhum voto individual.

Decifrar dá g^total (e não o total). Como o total é pequeno (no máximo o
número de cédulas), achamos o total por busca: g^0, g^1, g^2, ...
"""

from typing import List, Optional, Tuple

from crypto.params import G, P, expoente_aleatorio

Cifra = Tuple[int, int]   # (c1, c2)


def cifrar(m: int, h: int) -> Cifra:
    """Cifra m com a chave pública h. O r é usado e DESCARTADO aqui dentro."""
    r = expoente_aleatorio()
    c1 = pow(G, r, P)
    c2 = (pow(G, m, P) * pow(h, r, P)) % P
    return c1, c2


def cifrar_cedula(escolha: int, n_candidatos: int, h: int) -> List[Cifra]:
    """Uma cifra por candidato: 1 para o escolhido e 0 para os demais."""
    if not 0 <= escolha < n_candidatos:
        raise ValueError("candidato inexistente")
    return [cifrar(1 if j == escolha else 0, h) for j in range(n_candidatos)]


def multiplicar(a: Cifra, b: Cifra) -> Cifra:
    """Produto componente a componente = cifra da soma dos valores."""
    return (a[0] * b[0]) % P, (a[1] * b[1]) % P


def agregar(cedulas: List[List[Cifra]]) -> List[Cifra]:
    """Multiplica todas as cédulas, candidato por candidato.

    Resultado: uma cifra (C1_j, C2_j) do total de votos de cada candidato j.
    Começamos de (1, 1), que é o elemento neutro da multiplicação.
    """
    if not cedulas:
        return []
    n = len(cedulas[0])
    produtos = [(1, 1)] * n
    for cedula in cedulas:
        for j in range(n):
            produtos[j] = multiplicar(produtos[j], cedula[j])
    return produtos


def log_discreto(alvo: int, max_m: int) -> Optional[int]:
    """Acha m em [0, max_m] tal que g^m = alvo. Devolve None se não existir."""
    atual = 1  # g^0
    for m in range(max_m + 1):
        if atual == alvo:
            return m
        atual = (atual * G) % P
    return None
