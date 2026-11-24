"""
SIMULAÇÃO DA ELEIÇÃO (demonstração ao vivo)

Um menu em que vocês escolhem o que fazer, quem faz e em que ordem. Cada ação
usa o sistema de verdade e mostra na tela a criptografia envolvida. Os ataques
são feitos por vocês; quem barra é o sistema.

Papéis:
    Autoridades: Maria, Leticia, Natalie  -> guardam x_i; enviam h_i e D_i
    Eleitoras:   Bianca, Isabela, Ana     -> guardam a chave RSA; enviam a cédula assinada
    Administrador (quem narrar)           -> opera o servidor

Arquivos da demonstração (pasta demo/):
    tela.py         exibição e perguntas
    preparacao.py   opções 1 a 4      votacao.py   opções 5 a 7
    resultado.py    opções 8 a 10     ataques.py   opções 11 e 12
    menu.py         o menu
    simulacao.py    ESTE: o sistema guarda as chaves privadas
    interacao.py    cada pessoa guarda e entrega a própria chave

Uso (na raiz do projeto, com o venv ativo):
    python demo/simulacao.py
"""
from tela import enter, passo, perguntar

import menu
from armazenamento import arquivos
from autoridades import autoridade
from servidor import servidor


# Na SIMULAÇÃO, o sistema guarda a chave de cada pessoa em dados_privados/,
# fazendo o papel do computador dela.
def guardar_chave_autoridade(nome, x_i):
    autoridade.salvar_chave(nome, x_i)
    return f"dados_privados/autoridades/{nome}.json (o sistema guarda)"


def chave_da_autoridade(nome):
    enter(nome, "usar sua chave secreta e enviar a decifração parcial")
    return None   # None = a autoridade lê a chave do próprio arquivo


def guardar_chave_eleitora(nome, priv_pem):
    arquivos.salvar_texto_privado(f"eleitores/{nome}.pem", priv_pem)
    return f"dados_privados/eleitores/{nome}.pem (o sistema guarda)"


def chave_da_eleitora(nome):
    """Devolve a chave privada da eleitora, ou None se ela não tiver uma."""
    caminho = f"eleitores/{nome}.pem"
    return arquivos.ler_texto_privado(caminho) if arquivos.existe_privado(caminho) else None


def recomecar():
    if perguntar("Apagar a eleição atual e recomeçar? (s/n)", "n").lower() == "s":
        servidor.resetar()
        passo("Tudo apagado. Comece pela opção 2.")


if __name__ == "__main__":
    menu.executar(menu.montar_menu(guardar_chave_autoridade, chave_da_autoridade,
                                   guardar_chave_eleitora, chave_da_eleitora, recomecar),
                  "SIMULAÇÃO DA ELEIÇÃO")
