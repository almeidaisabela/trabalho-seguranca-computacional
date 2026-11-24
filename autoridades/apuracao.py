"""
CAMADA 3 - APLICAÇÃO | Apuração conjunta (Integrante 2)

Para cada candidato j temos o produto (C1_j, C2_j) = (g^R, g^total * h^R),
onde R é a soma dos r de todas as cédulas. Como h = h_1 * ... * h_n:

    h^R = (g^x_1 ... g^x_n)^R = C1^x_1 * ... * C1^x_n = D_1 * ... * D_n

Então:   C2_j / (D_1 * D_2 * ... * D_n) = g^total   ->   busca o total.

Se faltar a autoridade k, a divisão deixa sobrar o fator h_k^R, que é um
número "aleatório" do grupo. A busca por g^0, g^1, ..., g^num_cedulas não o
encontra, e a apuração FALHA. É exatamente o comportamento exigido.
"""

from typing import List

from armazenamento import arquivos
from autoridades.autoridade import ErroApuracao, decifracao_parcial, produtos_do_quadro
from crypto import elgamal, params, provas
from crypto.serial import hex_para_int, int_para_hex
from servidor import quadro


def decifrar_resultado(config: dict, produtos: List[elgamal.Cifra],
                       parciais: List[dict], num_cedulas: int) -> List[int]:
    """Combina as decifrações parciais. Falha se faltar autoridade ou prova."""
    h_de = {a["id"]: hex_para_int(a["h_i"]) for a in config["autoridades"]}
    recebidas = {p["autoridade_id"]: p for p in parciais}
    faltando = [aid for aid in h_de if aid not in recebidas]

    # 1. Cada decifração parcial precisa vir com prova de Chaum-Pedersen válida.
    for aid, parcial in recebidas.items():
        if aid not in h_de:
            raise ErroApuracao(f"{aid} não é uma autoridade desta eleição")
        for j, (c1, _c2) in enumerate(produtos):
            d = hex_para_int(parcial["D"][j])
            if not provas.verificar_chaum_pedersen(h_de[aid], c1, d, parcial["provas"][j]):
                raise ErroApuracao(f"decifração parcial de {aid} para o candidato {j} é falsa")

    # 2. Divide C2 pelo produto dos D_i e procura o total.
    totais = []
    for j, (_c1, c2) in enumerate(produtos):
        produto_d = 1
        for parcial in recebidas.values():
            produto_d = (produto_d * hex_para_int(parcial["D"][j])) % params.P
        g_total = (c2 * pow(produto_d, -1, params.P)) % params.P   # C2 / ∏D
        totais.append(elgamal.log_discreto(g_total, num_cedulas))

    if faltando or None in totais:
        tentativa = ", ".join(f"candidato {j}: {'não encontrado' if t is None else t}"
                              for j, t in enumerate(totais))
        raise ErroApuracao(
            f"apuração falhou. Faltam decifrações parciais de: {faltando or 'nenhuma'}. "
            f"Resultado da busca do log discreto -> {tentativa}")
    return totais


def apurar(participantes: List[str]) -> dict:
    """Cada participante decifra sua parte (com a chave do próprio arquivo)."""
    return publicar_resultado([decifracao_parcial(aid) for aid in participantes])


def publicar_resultado(parciais: List[dict]) -> dict:
    """Combina as decifrações parciais recebidas e publica o resultado."""
    config = arquivos.ler_publico("config.json")
    registros = quadro.carregar()["registros"]
    num_cedulas = sum(1 for r in registros if r["tipo"] == "cedula")
    produtos = produtos_do_quadro(config, registros)
    totais = decifrar_resultado(config, produtos, parciais, num_cedulas)

    resultado = {
        "eleicao_id": config["eleicao_id"],
        "num_cedulas": num_cedulas,
        "produtos": [{"candidato": j, "C1": int_para_hex(c1), "C2": int_para_hex(c2)}
                     for j, (c1, c2) in enumerate(produtos)],
        "parciais": parciais,
        "totais": [{"candidato": j, "votos": v} for j, v in enumerate(totais)],
    }
    arquivos.salvar_publico("resultado.json", resultado)
    return resultado
