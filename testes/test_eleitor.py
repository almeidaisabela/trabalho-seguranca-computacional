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
    reg = q["registros"][0]
    reg["cifras"][0], reg["cifras"][1] = reg["cifras"][1], reg["cifras"][0]
    arquivos.salvar_publico("quadro.json", q)
    ok, _ = cliente.conferir_no_quadro("e1")
    assert not ok


def test_eleitora_pode_entregar_a_propria_chave(eleicao_aberta):
    from crypto import elgamal
    from crypto.serial import hex_para_int
    from servidor import servidor
    priv = arquivos.ler_texto_privado("eleitores/e1.pem")
    h = hex_para_int(arquivos.ler_publico("config.json")["h"])
    cedula = cliente.assinar_cedula("e1", elgamal.cifrar_cedula(0, 3, h), priv)
    recibo = cliente.enviar_cedula("e1", cedula)
    assert cliente.conferir_no_quadro("e1", priv)[0]
    # com a chave de outra eleitora, a conferência falha
    assert not cliente.conferir_no_quadro("e1", arquivos.ler_texto_privado("eleitores/e2.pem"))[0]
    assert recibo["eleitor_id"] == "e1" and servidor.estado() == "aberta"
