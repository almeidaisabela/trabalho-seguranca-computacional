"""Testes do auditor independente (Integrante 5)."""
import copy

from armazenamento import arquivos
from autoridades import apuracao
from auditor.auditor import auditar
from crypto.serial import canonico, sha256_hex


def _apurada(pasta):
    apuracao.apurar(["A1", "A2", "A3"])
    return pasta / "dados_publicos"


def _rehash(registros, config):
    anterior = sha256_hex(canonico(config))
    for i, r in enumerate(registros):
        r["indice"], r["hash_anterior"] = i, anterior
        r["hash"] = sha256_hex(canonico({k: v for k, v in r.items() if k != "hash"}))
        anterior = r["hash"]


def test_eleicao_valida(eleicao_encerrada):
    assert auditar(_apurada(eleicao_encerrada))


def test_detecta_cifra_alterada(eleicao_encerrada):
    pasta = _apurada(eleicao_encerrada)
    q = arquivos.ler_publico("quadro.json")
    c = q["registros"][2]["cifras"]
    c[0], c[1] = c[1], c[0]
    arquivos.salvar_publico("quadro.json", q)
    assert not auditar(pasta)


def test_detecta_remocao_com_hashes_recalculados(eleicao_encerrada):
    pasta = _apurada(eleicao_encerrada)
    q = arquivos.ler_publico("quadro.json")
    config = arquivos.ler_publico("config.json")
    del q["registros"][1]
    _rehash(q["registros"], config)
    arquivos.salvar_publico("quadro.json", q)
    assert not auditar(pasta)


def test_detecta_cedula_duplicada_inserida(eleicao_encerrada):
    pasta = _apurada(eleicao_encerrada)
    q = arquivos.ler_publico("quadro.json")
    config = arquivos.ler_publico("config.json")
    q["registros"].insert(2, copy.deepcopy(q["registros"][1]))   # mesmo eleitor 2x
    _rehash(q["registros"], config)
    arquivos.salvar_publico("quadro.json", q)
    assert not auditar(pasta)


def test_detecta_resultado_alterado(eleicao_encerrada):
    pasta = _apurada(eleicao_encerrada)
    r = arquivos.ler_publico("resultado.json")
    r["totais"][0]["votos"], r["totais"][1]["votos"] = 0, 2
    arquivos.salvar_publico("resultado.json", r)
    assert not auditar(pasta)


def test_detecta_eleitor_inserido_no_cadastro(eleicao_encerrada):
    pasta = _apurada(eleicao_encerrada)
    eleitores = arquivos.ler_publico("eleitores.json")
    eleitores.append({"id": "fantasma", "chave_publica_pem": eleitores[0]["chave_publica_pem"]})
    arquivos.salvar_publico("eleitores.json", eleitores)
    assert not auditar(pasta)
