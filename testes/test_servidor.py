"""Testes do servidor e do quadro público (Integrante 4)."""
import pytest

from armazenamento import arquivos
from eleitor import cliente
from servidor import quadro, servidor
from servidor.servidor import ErroVotacao


def test_voto_duplo_rejeitado(eleicao_aberta):
    cliente.votar("e1", 0)
    with pytest.raises(ErroVotacao, match="já votou"):
        cliente.votar("e1", 1)


def test_reenvio_da_mesma_cedula_rejeitado(eleicao_aberta):
    cedula = cliente.montar_cedula("e1", 0)
    servidor.receber_cedula(cedula)
    with pytest.raises(ErroVotacao, match="já votou"):
        servidor.receber_cedula(cedula)


def test_eleitor_nao_cadastrado_rejeitado(eleicao_aberta):
    cedula = cliente.montar_cedula("e1", 0)
    cedula["eleitor_id"] = "intruso"
    with pytest.raises(ErroVotacao, match="não está cadastrado"):
        servidor.receber_cedula(cedula)


def test_assinatura_de_outro_eleitor_rejeitada(eleicao_aberta):
    cedula = cliente.montar_cedula("e1", 0)   # assinada por e1
    cedula["eleitor_id"] = "e2"               # tenta votar em nome de e2
    with pytest.raises(ErroVotacao, match="assinatura"):
        servidor.receber_cedula(cedula)


def test_cadastro_depois_da_abertura_rejeitado(eleicao_aberta):
    with pytest.raises(ErroVotacao):
        cliente.cadastrar("atrasado")


def test_voto_depois_do_encerramento_rejeitado(eleicao_encerrada):
    with pytest.raises(ErroVotacao, match="não está aberta"):
        cliente.votar("e1", 1)


def test_cadeia_detecta_alteracao_remocao_e_reordenacao(eleicao_encerrada):
    config = arquivos.ler_publico("config.json")
    original = quadro.carregar()["registros"]
    assert quadro.verificar_cadeia(config, original) == []

    alterado = [dict(r) for r in original]
    alterado[0]["eleitor_id"] = "e9"
    assert quadro.verificar_cadeia(config, alterado)

    assert quadro.verificar_cadeia(config, original[1:])                          # remoção
    assert quadro.verificar_cadeia(config, [original[1], original[0]] + original[2:])  # reordenação

