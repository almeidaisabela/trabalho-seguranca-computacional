"""Testes das autoridades e da apuração conjunta (Integrante 2)."""
import pytest

from armazenamento import arquivos
from autoridades import apuracao, autoridade
from autoridades.autoridade import ErroApuracao
from crypto import params
from crypto.serial import hex_para_int, int_para_hex


def test_chave_conjunta_e_produto_dos_hi(eleicao_aberta):
    config = arquivos.ler_publico("config.json")
    produto = 1
    for a in config["autoridades"]:
        produto = (produto * hex_para_int(a["h_i"])) % params.P
    assert produto == hex_para_int(config["h"])
    assert "x_i" not in str(config)   # nenhuma chave privada vai para o público


def test_apuracao_com_todas(eleicao_encerrada):
    resultado = apuracao.apurar(["A1", "A2", "A3"])
    assert [t["votos"] for t in resultado["totais"]] == [2, 0, 1]


def test_apuracao_sem_uma_autoridade_falha(eleicao_encerrada):
    with pytest.raises(ErroApuracao):
        apuracao.apurar(["A1", "A3"])
    assert not arquivos.existe_publico("resultado.json")


def test_autoridade_recusa_antes_do_encerramento(eleicao_aberta):
    from eleitor import cliente
    cliente.votar("e1", 1)
    with pytest.raises(ErroApuracao):
        autoridade.decifracao_parcial("A1")


def test_decifracao_parcial_falsa_e_rejeitada(eleicao_encerrada):
    config = arquivos.ler_publico("config.json")
    from servidor import quadro
    registros = quadro.carregar()["registros"]
    produtos = autoridade.produtos_do_quadro(config, registros)
    parciais = [autoridade.decifracao_parcial(a) for a in ("A1", "A2", "A3")]
    # A2 tenta tirar 1 voto do candidato 0: D * g
    d = hex_para_int(parciais[1]["D"][0])
    parciais[1]["D"][0] = int_para_hex((d * params.G) % params.P)
    with pytest.raises(ErroApuracao, match="falsa"):
        apuracao.decifrar_resultado(config, produtos, parciais, 3)
