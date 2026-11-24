"""
TELA: funções de exibição e de perguntas usadas por toda a demonstração.

Também ajusta o caminho do Python para que os arquivos da pasta demo/ consigam
importar o projeto (servidor, autoridades, eleitor...). Por isso, nos outros
arquivos da demo, "tela" é sempre o primeiro import.
"""
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)
os.chdir(RAIZ)

from servidor import servidor  # noqa: E402  (só depois de ajustar o caminho)

AUTORIDADES = ["Maria", "Leticia", "Natalie"]
ELEITORAS = ["Bianca", "Isabela", "Ana"]
CANDIDATOS_PADRAO = ["Chapa Azul", "Chapa Verde", "Chapa Roxa"]


def titulo(texto):
    print("\n" + "-" * 74 + f"\n  {texto}\n" + "-" * 74)


def passo(texto):
    print(f"\n>> {texto}")


def mostra(rotulo, valor):
    print(f"     {rotulo:<40} {valor}")


def curto(n: int) -> str:
    """Número grande abreviado: início...fim (tamanho em bits)."""
    s = format(n, "x")
    return s if len(s) <= 24 else f"{s[:12]}...{s[-8:]}  ({n.bit_length()} bits)"


def enter(quem, acao):
    input(f"\n   [{quem}] pressione Enter para {acao}... ")


def perguntar(texto, padrao=""):
    resposta = input(f"\n   {texto}{f' [Enter = {padrao}]' if padrao else ''}: ").strip()
    return resposta or padrao


def nomes(texto):
    """'Maria, Leticia' -> ['Maria', 'Leticia']"""
    return [n.strip() for n in texto.split(",") if n.strip()]


def candidatos():
    return [c["nome"] for c in servidor.ler_config()["candidatos"]]


def escolher_candidato():
    lista = candidatos()
    opcoes = ", ".join(f"{i}={c}" for i, c in enumerate(lista))
    while True:
        texto = perguntar(f"Número do candidato ({opcoes})")
        if texto.isdigit() and int(texto) < len(lista):
            return int(texto)
