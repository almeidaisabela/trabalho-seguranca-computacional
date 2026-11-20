"""
CAMADA 2 - PERSISTÊNCIA | Leitura e gravação de arquivos (Integrante 4)

Esta camada é a única (fora o auditor) que sabe ONDE os dados ficam no disco.
As camadas de cima só pedem "leia o quadro" ou "salve a chave da A1".

- dados_publicos/  -> tudo que qualquer um pode ler (e o auditor lê).
- dados_privados/  -> chaves privadas e estado interno. Cada entidade lê só o
                      que é seu (a autoridade A1 lê só A1.json, etc.).

A variável de ambiente VOTACAO_RAIZ permite usar outra pasta (usado nos testes).
"""

import json
import os
import shutil
from pathlib import Path

RAIZ = Path(os.environ.get("VOTACAO_RAIZ", Path(__file__).resolve().parent.parent))
PUBLICOS = RAIZ / "dados_publicos"
PRIVADOS = RAIZ / "dados_privados"


def _gravar_json(caminho: Path, obj) -> None:
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def _ler_json(caminho: Path):
    return json.loads(caminho.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ públicos
def existe_publico(nome: str) -> bool:
    return (PUBLICOS / nome).exists()


def ler_publico(nome: str):
    return _ler_json(PUBLICOS / nome)


def salvar_publico(nome: str, obj) -> None:
    _gravar_json(PUBLICOS / nome, obj)


# ------------------------------------------------------------------ privados
def existe_privado(caminho_relativo: str) -> bool:
    return (PRIVADOS / caminho_relativo).exists()


def ler_privado(caminho_relativo: str):
    return _ler_json(PRIVADOS / caminho_relativo)


def salvar_privado(caminho_relativo: str, obj) -> None:
    _gravar_json(PRIVADOS / caminho_relativo, obj)


def ler_texto_privado(caminho_relativo: str) -> str:
    return (PRIVADOS / caminho_relativo).read_text(encoding="utf-8")


def salvar_texto_privado(caminho_relativo: str, texto: str) -> None:
    caminho = PRIVADOS / caminho_relativo
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(texto, encoding="utf-8")
    os.chmod(caminho, 0o600)  # chave privada: só o dono lê


# ------------------------------------------------------------------- limpeza
def limpar_dados() -> None:
    """Apaga os dados gerados de uma eleição anterior (mantém os .gitkeep)."""
    for pasta in (PUBLICOS, PRIVADOS):
        pasta.mkdir(parents=True, exist_ok=True)
        for item in pasta.iterdir():
            if item.name == ".gitkeep":
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
