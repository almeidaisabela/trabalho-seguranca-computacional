"""
AUDITOR INDEPENDENTE (Integrante 5)

Programa separado do servidor de votação. Regras de independência:
  - lê SOMENTE os arquivos de uma pasta pública (padrão: dados_publicos/);
  - não importa nada de servidor/, autoridades/, eleitor/ nem armazenamento/;
  - usa apenas a camada 1 (primitivas: grupo, hash, RSA, verificação de provas).
    Até o hash de cada registro e o produto das cédulas são recalculados aqui.

Assim, qualquer pessoa com a pasta pública consegue refazer a conferência e
chegar à mesma conclusão, sem precisar confiar no administrador.

Uso:  python -m auditor [pasta_publica]
"""

import json
from pathlib import Path

from crypto import assinatura, params, provas
from crypto.serial import canonico, hex_para_int, sha256_hex

PASTA_PADRAO = Path(__file__).resolve().parent.parent / "dados_publicos"


class Relatorio:
    def __init__(self):
        self.falhas = []

    def checar(self, ok: bool, descricao: str) -> bool:
        print(f"  [{'OK' if ok else 'FALHA'}] {descricao}")
        if not ok:
            self.falhas.append(descricao)
        return ok


def _ler(pasta: Path, nome: str):
    caminho = pasta / nome
    if not caminho.exists():
        return None
    return json.loads(caminho.read_text(encoding="utf-8"))


def _hash_registro(reg: dict) -> str:
    return sha256_hex(canonico({k: v for k, v in reg.items() if k != "hash"}))


def _assinatura_servidor_ok(pub_pem, eleicao_id, reg) -> bool:
    obj = {"eleicao_id": eleicao_id, "tipo": reg.get("tipo"),
           "hash_anterior": reg.get("hash_anterior")}
    if reg.get("tipo") == "abertura":
        obj["hash_eleitores"] = reg.get("hash_eleitores")
    return assinatura.verificar(pub_pem, canonico(obj), reg.get("assinatura_servidor", ""))


# ---------------------------------------------------------------- verificações
def verificar_config(rel: Relatorio, config: dict) -> None:
    print("\n1. Configuração e chave conjunta")
    grupo = config["grupo"]
    rel.checar(hex_para_int(grupo["p"]) == params.P and hex_para_int(grupo["q"]) == params.Q
               and hex_para_int(grupo["g"]) == params.G and params.conferir_parametros(),
               "grupo é o RFC 3526 MODP-2048 (p = 2q + 1, g de ordem q)")
    rel.checar(len(config["candidatos"]) >= 2, "pelo menos 2 candidatos")
    rel.checar(len(config["autoridades"]) >= 3, "pelo menos 3 autoridades")

    produto = 1
    for aut in config["autoridades"]:
        h_i = hex_para_int(aut["h_i"])
        rel.checar(params.pertence_ao_grupo(h_i)
                   and provas.verificar_schnorr(h_i, aut["prova"], aut["id"]),
                   f"autoridade {aut['id']}: h_i no grupo e prova de Schnorr válida")
        produto = (produto * h_i) % params.P
    rel.checar(produto == hex_para_int(config["h"]), "h = produto dos h_i (chave conjunta)")


def verificar_quadro(rel, config, eleitores, servidor_pub, registros) -> list:
    """Devolve a lista de cédulas (como inteiros) se o quadro existir."""
    print("\n2. Cadeia de hashes do quadro")
    esperado = sha256_hex(canonico(config))
    cadeia_ok = True
    for i, reg in enumerate(registros):
        ok = (reg.get("indice") == i and reg.get("hash_anterior") == esperado
              and _hash_registro(reg) == reg.get("hash"))
        if not ok:
            rel.checar(False, f"registro {i}: índice, hash_anterior ou hash não confere")
            cadeia_ok = False
        esperado = reg.get("hash")
    if cadeia_ok:
        rel.checar(True, f"{len(registros)} registros encadeados corretamente desde a config")

    print("\n3. Abertura e encerramento")
    tipos = [r.get("tipo") for r in registros]
    abertura_ok = bool(registros) and tipos[0] == "abertura" and tipos.count("abertura") == 1
    rel.checar(abertura_ok, "primeiro registro é a única abertura")
    if abertura_ok:
        rel.checar(registros[0]["hash_eleitores"] == sha256_hex(canonico(eleitores)),
                   "cadastro de eleitores é o mesmo congelado na abertura")
        rel.checar(_assinatura_servidor_ok(servidor_pub, config["eleicao_id"], registros[0]),
                   "assinatura do servidor na abertura")
    enc_ok = bool(registros) and tipos[-1] == "encerramento" and tipos.count("encerramento") == 1
    rel.checar(enc_ok, "último registro é o único encerramento (nada entra depois)")
    if enc_ok:
        rel.checar(_assinatura_servidor_ok(servidor_pub, config["eleicao_id"], registros[-1]),
                   "assinatura do servidor no encerramento")

    print("\n4. Cédulas: elegibilidade, unicidade e assinaturas")
    cadastro = {e["id"]: e["chave_publica_pem"] for e in eleitores}
    vistos, cedulas = set(), []
    for reg in registros:
        if reg.get("tipo") != "cedula":
            continue
        eid = reg.get("eleitor_id")
        rotulo = f"registro {reg.get('indice')} ({eid})"
        if not rel.checar(eid in cadastro, f"{rotulo}: eleitor cadastrado"):
            continue
        rel.checar(eid not in vistos, f"{rotulo}: primeira cédula deste eleitor")
        vistos.add(eid)
        dados = canonico({"eleicao_id": config["eleicao_id"], "eleitor_id": eid,
                          "cifras": reg["cifras"]})
        rel.checar(assinatura.verificar(cadastro[eid], dados, reg["assinatura_eleitor"]),
                   f"{rotulo}: assinatura do eleitor")
        cifras = [(hex_para_int(c["c1"]), hex_para_int(c["c2"])) for c in reg["cifras"]]
        rel.checar(len(cifras) == len(config["candidatos"])
                   and all(params.pertence_ao_grupo(a) and params.pertence_ao_grupo(b)
                           for a, b in cifras),
                   f"{rotulo}: uma cifra por candidato, todas no grupo")
        cedulas.append(cifras)
    return cedulas


def verificar_resultado(rel, config, registros, cedulas, resultado) -> None:
    print("\n5. Apuração homomórfica e decifração conjunta")
    if resultado is None:
        print("  (resultado.json ainda não publicado: apuração não verificada)")
        return
    n = len(config["candidatos"])
    rel.checar(resultado["num_cedulas"] == len(cedulas), "número de cédulas confere")
    rel.checar(bool(registros) and resultado.get("hash_quadro") == registros[-1].get("hash"),
               "resultado se refere a este quadro (hash do último registro)")

    # Recalcula o produto de todas as cédulas, candidato por candidato.
    produtos = [(1, 1)] * n
    for cifras in cedulas:
        produtos = [((p1 * c1) % params.P, (p2 * c2) % params.P)
                    for (p1, p2), (c1, c2) in zip(produtos, cifras)]
    publicados = [(hex_para_int(x["C1"]), hex_para_int(x["C2"])) for x in resultado["produtos"]]
    rel.checar(produtos == publicados, "produto homomórfico recalculado = produto publicado")

    h_de = {a["id"]: hex_para_int(a["h_i"]) for a in config["autoridades"]}
    parciais = {p["autoridade_id"]: p for p in resultado["parciais"]}
    rel.checar(set(parciais) == set(h_de), "todas as autoridades publicaram decifração parcial")
    for aid, parcial in parciais.items():
        ok = aid in h_de and all(
            provas.verificar_chaum_pedersen(h_de[aid], c1, hex_para_int(parcial["D"][j]),
                                            parcial["provas"][j])
            for j, (c1, _) in enumerate(produtos))
        rel.checar(ok, f"autoridade {aid}: provas de Chaum-Pedersen válidas")

    soma = 0
    for j, (_c1, c2) in enumerate(produtos):
        votos = resultado["totais"][j]["votos"]
        soma += votos
        lado_esq = pow(params.G, votos, params.P)
        for parcial in parciais.values():
            lado_esq = (lado_esq * hex_para_int(parcial["D"][j])) % params.P
        nome = config["candidatos"][j]["nome"]
        rel.checar(lado_esq == c2, f"{nome}: g^{votos} * prod(D_i) = C2 (total correto)")
    rel.checar(soma == len(cedulas),
               "soma dos votos = número de cédulas (sem cédula com mais de um voto)")


def auditar(pasta=PASTA_PADRAO) -> bool:
    pasta = Path(pasta)
    print(f"AUDITORIA INDEPENDENTE - lendo apenas {pasta}")
    config = _ler(pasta, "config.json")
    eleitores = _ler(pasta, "eleitores.json")
    servidor_pub = _ler(pasta, "servidor_pub.json")
    quadro = _ler(pasta, "quadro.json")
    if None in (config, eleitores, servidor_pub, quadro):
        print("\nFaltam arquivos públicos (config, eleitores, servidor_pub ou quadro).")
        print("\n>>> ELEIÇÃO ADULTERADA (dados públicos incompletos)")
        return False

    rel = Relatorio()
    verificar_config(rel, config)
    registros = quadro["registros"]
    cedulas = verificar_quadro(rel, config, eleitores,
                               servidor_pub["chave_publica_pem"], registros)
    verificar_resultado(rel, config, registros, cedulas, _ler(pasta, "resultado.json"))

    if rel.falhas:
        print(f"\n>>> ELEIÇÃO ADULTERADA ({len(rel.falhas)} falha(s)):")
        for f in rel.falhas:
            print(f"    - {f}")
        return False
    print("\n>>> ELEIÇÃO VÁLIDA")
    return True

