"""
OPÇÕES 5 A 7: VOTAÇÃO

    5. votar     6. a eleitora confere o próprio recibo     7. encerrar

As funções que precisam da chave privada recebem `obter_chave`, que pede a
chave ao sistema (simulacao.py) ou à própria eleitora (interacao.py).
"""
from tela import (candidatos, curto, enter, escolher_candidato, mostra, passo,
                  perguntar, titulo)

from armazenamento import arquivos
from crypto import assinatura, params
from crypto.params import G, P
from crypto.serial import hex_para_int
from eleitor import cliente
from servidor import quadro, servidor


def cifrar_mostrando(escolha):
    """Cifra a cédula mostrando cada conta. O r é descartado em seguida."""
    h = hex_para_int(servidor.ler_config()["h"])
    print("\n   (O valor de m só aparece porque é uma demonstração.)")
    cifras = []
    for j, nome in enumerate(candidatos()):
        m = 1 if j == escolha else 0
        r = params.expoente_aleatorio()
        c1 = pow(G, r, P)
        c2 = (pow(G, m, P) * pow(h, r, P)) % P
        passo(f"{nome}: m = {m}")
        mostra("r sorteado (descartado em seguida):", curto(r))
        mostra("c1 = g^r mod p:", curto(c1))
        mostra("c2 = g^m * h^r mod p:", curto(c2))
        cifras.append((c1, c2))
        del r
    return cifras


def mostrar_recibo(nome, recibo):
    passo("Servidor conferiu: votação aberta, cadastro, assinatura, primeiro voto, cifras válidas")
    registro = quadro.carregar()["registros"][recibo["indice"]]
    passo(f"Publicado no quadro como registro {registro['indice']}")
    mostra("hash_anterior:", registro["hash_anterior"][:32] + "...")
    mostra("hash deste registro:", registro["hash"][:32] + "...")
    passo(f"Recibo que {nome} guarda (assinado pelo servidor)")
    mostra("índice:", recibo["indice"])
    mostra("hash do registro:", recibo["hash_registro"][:32] + "...")
    mostra("assinatura do servidor:", curto(hex_para_int(recibo["assinatura_servidor"])))


def op_votar(obter_chave):
    nome = perguntar("Quem vai votar?")
    if not nome:
        return
    escolha = escolher_candidato()
    titulo(f"VOTO DE {nome.upper()}")
    cifras = cifrar_mostrando(escolha)

    priv_pem = obter_chave(nome)
    if priv_pem is None:
        # Não cadastrada: ela cria uma chave por conta própria e tenta assim mesmo.
        print(f"\n   {nome} não está cadastrada. Ela gera uma chave RSA própria e tenta votar.")
        priv_pem, _pub = assinatura.gerar_par_rsa()

    cedula = cliente.assinar_cedula(nome, cifras, priv_pem)
    passo(f"{nome} assina a cédula com a chave privada (RSA-PSS + SHA-256)")
    mostra("assinatura:", curto(hex_para_int(cedula["assinatura_eleitor"])))
    enter(nome, "enviar a cédula ao servidor")
    mostrar_recibo(nome, cliente.enviar_cedula(nome, cedula))   # o servidor pode recusar


def op_conferir(obter_chave):
    nome = perguntar("Quem vai conferir o próprio recibo?")
    if not arquivos.existe_privado(f"eleitores/{nome}_recibo.json"):
        raise ValueError(f"{nome} não tem recibo (ainda não votou)")
    priv_pem = obter_chave(nome)     # para conferir a assinatura com a PRÓPRIA chave
    if priv_pem is None:
        raise ValueError(f"{nome} precisa da própria chave para conferir")
    titulo(f"VERIFICAÇÃO INDIVIDUAL - {nome.upper()}")
    ok, mensagens = cliente.conferir_no_quadro(nome, priv_pem)
    for m in mensagens:
        print(f"     {m}")
    print(f"\n     {'Cédula confirmada no quadro.' if ok else 'PROBLEMA: cédula ausente ou alterada!'}")


def op_encerrar():
    servidor.encerrar()
    ultimo = quadro.carregar()["registros"][-1]
    passo(f"Registro {ultimo['indice']} do quadro: ENCERRAMENTO, assinado pelo servidor")
    print("     Nenhuma cédula pode entrar depois dele sem ser detectada.")
