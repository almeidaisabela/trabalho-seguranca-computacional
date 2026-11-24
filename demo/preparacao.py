"""
OPÇÕES 1 A 4: PREPARAÇÃO DA ELEIÇÃO

    1. ver o número primo         3. cadastrar as eleitoras
    2. criar a chave conjunta     4. abrir a votação

As funções que mexem com chave privada recebem `guardar`, que diz ONDE a chave
fica: no sistema (simulacao.py) ou com a própria pessoa (interacao.py).
"""
from tela import (AUTORIDADES, CANDIDATOS_PADRAO, ELEITORAS, curto, enter, mostra,
                  nomes, passo, perguntar, titulo)

from armazenamento import arquivos
from autoridades import autoridade
from crypto.params import G, P, Q
from crypto.serial import hex_para_int, sha256_hex
from eleitor import cliente
from servidor import servidor
from servidor.servidor import ErroVotacao


def op_primo():
    titulo("O NÚMERO PRIMO DA ELEIÇÃO")
    print("""
   Toda a criptografia acontece "módulo p", com p um PRIMO SEGURO: p = 2q + 1,
   com q também primo. Usamos o primo PADRONIZADO de 2048 bits da RFC 3526
   (grupo 14), que o enunciado permite. Gerar um primo seguro desse tamanho
   pode levar muitos minutos; um grupo padronizado é público, foi analisado
   por muita gente e ninguém pode ter escolhido um primo "com defeito". Ele é:""")
    texto = format(P, "x")
    for i in range(0, len(texto), 64):
        print("     " + texto[i:i + 64])
    enter("Integrante 1", "conferir os parâmetros do grupo")
    mostra("p tem 2048 bits?", P.bit_length() == 2048)
    mostra("p = 2q + 1?", P == 2 * Q + 1)
    mostra("g = 2 tem ordem q? (g^q mod p = 1)", pow(G, Q, P) == 1)


def op_configurar(guardar):
    if servidor.estado() != "inexistente":
        raise ErroVotacao("já existe uma eleição; use a opção R para recomeçar")
    lista = nomes(perguntar("Candidatos, separados por vírgula", ", ".join(CANDIDATOS_PADRAO)))
    titulo("AS AUTORIDADES CRIAM A CHAVE DA ELEIÇÃO")
    print("""
   Cada autoridade sorteia um número secreto x_i e publica só h_i = g^x_i mod p.
   A chave pública da eleição será h = h_Maria * h_Leticia * h_Natalie.""")
    publicas = []
    for nome in AUTORIDADES:
        enter(nome, "sortear sua chave secreta")
        x_i, publica = autoridade.nova_chave(nome)
        passo(nome)
        mostra("[SEGREDO] x_i sorteado:", curto(x_i))
        mostra("[SEGREDO] guardado em:", guardar(nome, x_i))
        mostra("[PÚBLICO] h_i = g^x_i mod p:", curto(hex_para_int(publica["h_i"])))
        mostra("[PÚBLICO] prova de Schnorr (a):", curto(hex_para_int(publica["prova"]["a"])))
        mostra("[PÚBLICO] prova de Schnorr (z):", curto(hex_para_int(publica["prova"]["z"])))
        print(f"     {nome} ENVIA ao servidor: h_i e a prova. O x_i fica com ela.")
        publicas.append(publica)

    enter("Administrador", "montar a eleição no servidor")
    config = servidor.configurar("eleicao-2026-01", "Eleição da turma", lista, publicas)
    passo("Servidor")
    mostra("provas de Schnorr conferidas:", f"{len(publicas)} de {len(publicas)} válidas")
    mostra("h = h_1 * h_2 * h_3 mod p:", curto(hex_para_int(config["h"])))
    print("     Isso é g^(x_Maria + x_Leticia + x_Natalie), mas NINGUÉM conhece essa soma.")


def op_cadastrar(guardar):
    for nome in nomes(perguntar("Nome da eleitora", ", ".join(ELEITORAS))):
        enter(nome, "gerar seu par de chaves RSA")
        priv_pem = cliente.novo_cadastro(nome)    # o servidor recusa se a votação já abriu
        pub = next(e["chave_publica_pem"] for e in arquivos.ler_publico("eleitores.json")
                   if e["id"] == nome)
        passo(nome)
        mostra("[SEGREDO] chave privada em:", guardar(nome, priv_pem))
        mostra("[PÚBLICO] impressão digital da pública:", sha256_hex(pub.encode())[:32] + "...")
        print(f"     {nome} ENVIA: a chave pública. A privada fica com ela.")


def op_abrir():
    servidor.abrir()
    passo("Votação ABERTA. A partir de agora, ninguém mais se cadastra.")
