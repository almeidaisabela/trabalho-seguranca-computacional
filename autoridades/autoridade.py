"""
CAMADA 3 - APLICAÇÃO | Autoridade eleitoral (Integrante 2)

Cada autoridade i, de forma independente:
  1. Sorteia sua chave privada x_i em [1, q-1] e a guarda SÓ no próprio arquivo.
  2. Publica h_i = g^x_i e uma prova de Schnorr de que conhece x_i.
     A chave pública da eleição é h = h_1 * h_2 * ... * h_n = g^(x_1 + ... + x_n).
     A chave privada "completa" x = x_1 + ... + x_n NUNCA é calculada por ninguém.
  3. Depois do encerramento, publica a decifração parcial D_i = C1^x_i do
     PRODUTO de todas as cédulas (nunca de uma cédula individual), junto com uma
     prova de Chaum-Pedersen de que usou o mesmo x_i de h_i.

Por que a autoridade calcula o produto sozinha a partir do quadro público?
Se ela aceitasse decifrar "qualquer C1" que o administrador mandasse, o
administrador poderia pedir a decifração de UMA cédula e descobrir o voto.
Lendo o quadro e conferindo o encerramento, ela só decifra o total, e só
depois que a votação acabou (propriedade de justiça). Além disso, ela decifra
um único quadro na eleição inteira (ver `decifracao_parcial`).
"""

from typing import List

from armazenamento import arquivos
from crypto import elgamal, params, provas
from crypto.serial import hex_para_int, int_para_hex
from servidor import quadro


class ErroApuracao(Exception):
    """A apuração não pôde ser concluída."""


def _arquivo(autoridade_id: str) -> str:
    return f"autoridades/{autoridade_id}.json"


def gerar_chave(autoridade_id: str) -> dict:
    """Gera x_i (privado) e devolve só a parte pública: h_i e a prova de Schnorr."""
    x_i = params.expoente_aleatorio()
    h_i = pow(params.G, x_i, params.P)
    arquivos.salvar_privado(_arquivo(autoridade_id),
                            {"id": autoridade_id, "x_i": int_para_hex(x_i)})
    return {"id": autoridade_id, "h_i": int_para_hex(h_i),
            "prova": provas.provar_schnorr(x_i, h_i, autoridade_id)}


def cifras_do_quadro(registros: List[dict]) -> List[List[elgamal.Cifra]]:
    """Extrai as cifras de todas as cédulas do quadro como inteiros."""
    return [[(hex_para_int(c["c1"]), hex_para_int(c["c2"])) for c in r["cifras"]]
            for r in registros if r["tipo"] == "cedula"]


def produtos_do_quadro(config: dict, registros: List[dict]) -> List[elgamal.Cifra]:
    """Produto homomórfico de todas as cédulas: uma cifra do total por candidato."""
    cedulas = cifras_do_quadro(registros)
    if not cedulas:
        return [(1, 1)] * len(config["candidatos"])  # cifra "trivial" de 0
    return elgamal.agregar(cedulas)


def decifracao_parcial(autoridade_id: str) -> dict:
    """Executada por UMA autoridade, usando só o próprio x_i e dados públicos."""
    config = arquivos.ler_publico("config.json")
    registros = quadro.carregar()["registros"]
    servidor_pub = arquivos.ler_publico("servidor_pub.json")["chave_publica_pem"]

    # A autoridade se recusa a participar se o quadro estiver quebrado ou aberto.
    if quadro.verificar_cadeia(config, registros):
        raise ErroApuracao(f"{autoridade_id}: cadeia de hashes do quadro inválida")
    if not quadro.encerramento_valido(config, registros, servidor_pub):
        raise ErroApuracao(f"{autoridade_id}: votação ainda não encerrada; recuso decifrar")

    # Só apura UM quadro por eleição. O administrador tem a chave do servidor e
    # poderia forjar um quadro com a cédula de uma única pessoa: o "total" desse
    # quadro seria o voto dela. Anotando o hash do primeiro quadro apurado, um
    # segundo quadro diferente é recusado.
    privado = arquivos.ler_privado(_arquivo(autoridade_id))
    hash_quadro = registros[-1]["hash"]
    if "quadro_decifrado" not in privado:
        privado["quadro_decifrado"] = hash_quadro      # primeira apuração: anota
        arquivos.salvar_privado(_arquivo(autoridade_id), privado)
    elif privado["quadro_decifrado"] != hash_quadro:
        raise ErroApuracao(f"{autoridade_id}: já apurei outro quadro; recuso apurar um segundo")

    x_i = hex_para_int(privado["x_i"])
    h_i = pow(params.G, x_i, params.P)

    d_lista, provas_lista = [], []
    for c1, _c2 in produtos_do_quadro(config, registros):
        d = pow(c1, x_i, params.P)                        # D_i = C1^x_i
        d_lista.append(int_para_hex(d))
        provas_lista.append(provas.provar_chaum_pedersen(x_i, h_i, c1, d))
    return {"autoridade_id": autoridade_id, "D": d_lista, "provas": provas_lista}
