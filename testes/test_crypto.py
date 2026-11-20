"""Testes da camada 1 - criptografia (Integrante 1)."""
from crypto import assinatura, elgamal, params, provas
from crypto.params import G, P


def decifrar_com_x(cifra, x, max_m=10):
    c1, c2 = cifra
    return elgamal.log_discreto((c2 * pow(pow(c1, x, P), -1, P)) % P, max_m)


def test_parametros_do_grupo():
    assert params.conferir_parametros()
    assert params.pertence_ao_grupo(G)


def test_cifra_e_decifra_0_e_1():
    x = params.expoente_aleatorio()
    h = pow(G, x, P)
    assert decifrar_com_x(elgamal.cifrar(0, h), x) == 0
    assert decifrar_com_x(elgamal.cifrar(1, h), x) == 1


def test_cifras_do_mesmo_valor_sao_diferentes():
    h = pow(G, params.expoente_aleatorio(), P)
    assert elgamal.cifrar(1, h) != elgamal.cifrar(1, h)   # r novo a cada cifra


def test_soma_homomorfica():
    x = params.expoente_aleatorio()
    h = pow(G, x, P)
    cedulas = [elgamal.cifrar_cedula(e, 3, h) for e in (0, 2, 0, 1, 0)]
    totais = [decifrar_com_x(c, x) for c in elgamal.agregar(cedulas)]
    assert totais == [3, 1, 1]


def test_schnorr():
    x = params.expoente_aleatorio()
    h = pow(G, x, P)
    prova = provas.provar_schnorr(x, h, "A1")
    assert provas.verificar_schnorr(h, prova, "A1")
    assert not provas.verificar_schnorr(h, prova, "A2")            # outro contexto
    assert not provas.verificar_schnorr((h * G) % P, prova, "A1")  # outra chave


def test_chaum_pedersen_rejeita_decifracao_falsa():
    x = params.expoente_aleatorio()
    h = pow(G, x, P)
    c1 = pow(G, params.expoente_aleatorio(), P)
    d = pow(c1, x, P)
    prova = provas.provar_chaum_pedersen(x, h, c1, d)
    assert provas.verificar_chaum_pedersen(h, c1, d, prova)
    assert not provas.verificar_chaum_pedersen(h, c1, (d * G) % P, prova)


def test_assinatura_rsa():
    priv, pub = assinatura.gerar_par_rsa()
    sig = assinatura.assinar(priv, b"mensagem")
    assert assinatura.verificar(pub, b"mensagem", sig)
    assert not assinatura.verificar(pub, b"mensagem alterada", sig)
    assert assinatura.chave_publica_de(priv) == pub
