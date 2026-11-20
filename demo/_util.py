"""Funções auxiliares dos scripts de demonstração."""
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)          # permite "python demo/x.py" a partir da raiz
os.chdir(RAIZ)

import main  # noqa: E402

PAUSAR = "--pausar" in sys.argv


def titulo(texto: str) -> None:
    print("\n" + "=" * 70 + f"\n {texto}\n" + "=" * 70)
    if PAUSAR:
        input("   (Enter para continuar) ")


def executar(*args: str) -> int:
    """Mostra o comando como se fosse digitado e executa a CLI."""
    print(f"\n$ python main.py {' '.join(args)}")
    return main.main(list(args))
