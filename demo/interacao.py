"""
INTERAÇÃO: a mesma eleição da simulação, mas o sistema NÃO guarda as chaves
privadas. Cada pessoa recebe a própria chave num arquivo e a ENTREGA quando
precisar dela (arrastando o arquivo para o terminal):

    Maria, Leticia, Natalie -> chaveiro/<nome>.chave  (o número secreto x_i)
    Bianca, Isabela, Ana    -> chaveiro/<nome>.pem    (a chave privada RSA)

Depois de receber, cada uma pode mover o arquivo para onde quiser (pendrive,
outra pasta) e arrastar de lá na hora de usar.

O que continua com o sistema:
    - as chaves PÚBLICAS: existem para que todos possam conferir assinaturas e provas;
    - a chave do servidor: é do próprio servidor (dados_privados/servidor/).

Uso (na raiz do projeto, com o venv ativo):
    python demo/interacao.py
"""
import shutil
from pathlib import Path

from tela import RAIZ, passo, perguntar

import menu
from servidor import servidor

CHAVEIRO = Path(RAIZ) / "chaveiro"


# ========================================= entregar a chave para a pessoa
def _entregar(arquivo: Path, conteudo: str) -> str:
    CHAVEIRO.mkdir(exist_ok=True)
    arquivo.write_text(conteudo, encoding="utf-8")
    return f"chaveiro/{arquivo.name}  <- é SUA; o sistema não guarda cópia"


def guardar_chave_autoridade(nome, x_i):
    return _entregar(CHAVEIRO / f"{nome}.chave", format(x_i, "x") + "\n")   # em hexadecimal


def guardar_chave_eleitora(nome, priv_pem):
    return _entregar(CHAVEIRO / f"{nome}.pem", priv_pem)


# ========================================= a pessoa entrega a própria chave
def _receber(nome, opcional=False):
    """Pede o arquivo da chave. O Terminal escreve o caminho ao arrastar o arquivo."""
    dica = " (Enter se não tiver)" if opcional else ""
    texto = input(f"\n   [{nome}] arraste aqui o arquivo da SUA chave{dica}: ").strip()
    if not texto:
        if opcional:
            return None
        raise ValueError(f"{nome} não entregou a chave")
    caminho = Path(texto.strip("'\"").replace("\\ ", " "))
    if not caminho.is_file():
        raise ValueError(f"arquivo não encontrado: {caminho}")
    return caminho.read_text(encoding="utf-8")


def chave_da_autoridade(nome):
    conteudo = _receber(nome).strip()
    try:
        return int(conteudo, 16)
    except ValueError:
        raise ValueError("esse arquivo não é a chave de uma autoridade")


def chave_da_eleitora(nome):
    conteudo = _receber(nome, opcional=True)
    if conteudo is not None and "PRIVATE KEY" not in conteudo:
        raise ValueError("esse arquivo não é a chave RSA de uma eleitora")
    return conteudo


def recomecar():
    if perguntar("Apagar a eleição atual e as chaves do chaveiro? (s/n)", "n").lower() == "s":
        servidor.resetar()
        shutil.rmtree(CHAVEIRO, ignore_errors=True)
        passo("Tudo apagado. Comece pela opção 2.")


if __name__ == "__main__":
    menu.executar(menu.montar_menu(guardar_chave_autoridade, chave_da_autoridade,
                                   guardar_chave_eleitora, chave_da_eleitora, recomecar),
                  "INTERAÇÃO: CADA UMA GUARDA A PRÓPRIA CHAVE")
