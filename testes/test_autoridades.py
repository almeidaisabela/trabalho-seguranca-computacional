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


def _forjar_quadro_com_uma_cedula():
    """Ataque do administrador: quadro só com a 1ª cédula e encerramento reassinado."""
    from crypto import assinatura
    from crypto.serial import canonico, sha256_hex
    from servidor import quadro
    config = arquivos.ler_publico("config.json")
    q = quadro.carregar()
    regs = q["registros"][:1]                         # só a 1ª cédula
    anterior = sha256_hex(canonico(config))
    for i, r in enumerate(regs):
        r["indice"], r["hash_anterior"] = i, anterior
        r["hash"] = quadro.hash_registro(r)
        anterior = r["hash"]
    chave = arquivos.ler_texto_privado("servidor/servidor_priv.pem")
    enc = {"indice": 1, "tipo": "encerramento", "hash_anterior": anterior}
    enc["assinatura_servidor"] = assinatura.assinar(
        chave, quadro.dados_assinados_encerramento(config["eleicao_id"], anterior))
    enc["hash"] = quadro.hash_registro(enc)
    q["registros"] = regs + [enc]
    arquivos.salvar_publico("quadro.json", q)


def test_autoridade_decifra_um_unico_quadro(eleicao_encerrada):
    autoridade.decifracao_parcial("A1")
    autoridade.decifracao_parcial("A1")               # o mesmo quadro de novo: permitido
    _forjar_quadro_com_uma_cedula()
    with pytest.raises(ErroApuracao, match="já apurei outro quadro"):
        autoridade.decifracao_parcial("A1")


def test_quadro_falso_bloqueia_a_apuracao_verdadeira(eleicao_encerrada):
    """Se o ataque acontecer primeiro, a apuração verdadeira passa a falhar (fica visível)."""
    from servidor import quadro
    verdadeiro = quadro.carregar()
    _forjar_quadro_com_uma_cedula()
    apuracao.apurar(["A1", "A2", "A3"])               # o ataque funciona uma vez
    arquivos.salvar_publico("quadro.json", verdadeiro)
    with pytest.raises(ErroApuracao, match="já apurei outro quadro"):
        apuracao.apurar(["A1", "A2", "A3"])


def test_autoridade_pode_entregar_a_propria_chave(eleicao_encerrada):
    x_maria = hex_para_int(arquivos.ler_privado("autoridades/A1.json")["x_i"])
    parcial = autoridade.decifracao_parcial("A1", x_maria)     # chave entregue por ela
    assert parcial["autoridade_id"] == "A1"


def test_chave_de_outra_autoridade_e_recusada(eleicao_encerrada):
    x_outra = hex_para_int(arquivos.ler_privado("autoridades/A2.json")["x_i"])
    with pytest.raises(ErroApuracao, match="essa chave não é a de A1"):
        autoridade.decifracao_parcial("A1", x_outra)
