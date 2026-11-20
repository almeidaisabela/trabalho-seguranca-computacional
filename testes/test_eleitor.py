"""Testes do cliente do eleitor: recibo e verificação individual (Integrante 3)."""
from armazenamento import arquivos
from eleitor import cliente


def test_recibo_assinado_pelo_servidor(eleicao_aberta):
    recibo = cliente.votar("e1", 1)
    assert cliente.verificar_recibo(recibo)
    falso = dict(recibo, indice=recibo["indice"] + 1)
    assert not cliente.verificar_recibo(falso)


def test_recibo_nao_contem_voto_nem_aleatoriedade(eleicao_aberta):
    recibo = cliente.votar("e1", 1)
    assert set(recibo) == {"eleicao_id", "eleitor_id", "indice", "hash_registro",
                           "assinatura_servidor"}


def test_verificacao_individual(eleicao_aberta):
    cliente.votar("e1", 1)
    ok, _ = cliente.conferir_no_quadro("e1")
    assert ok

    q = arquivos.ler_publico("quadro.json")
    reg = q["registros"][1]
    reg["cifras"][0], reg["cifras"][1] = reg["cifras"][1], reg["cifras"][0]
    arquivos.salvar_publico("quadro.json", q)
    ok, _ = cliente.conferir_no_quadro("e1")
    assert not ok
