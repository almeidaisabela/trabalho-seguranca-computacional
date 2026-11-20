"""
CAMADA 3 - APLICAÇÃO | Quadro público encadeado por hash (Integrante 4)

O quadro é uma lista de registros SOMENTE DE ACRÉSCIMO. Cada registro guarda o
hash do anterior, formando uma cadeia (como um blockchain simples):

    hash_anterior(registro 0) = SHA-256(config)       -> liga o quadro à eleição
    hash_anterior(registro i) = hash(registro i-1)
    hash(registro i)          = SHA-256(registro i sem o campo "hash")

Se alguém alterar, remover, reordenar ou inserir um registro no meio, o hash
daquele registro muda e deixa de bater com o `hash_anterior` do seguinte.

Tipos de registro:
    abertura      -> hash da lista de eleitores (congela o cadastro), assinado pelo servidor
    cedula        -> eleitor_id, cifras e assinatura do eleitor
    encerramento  -> marca o fim da votação, assinado pelo servidor

Não há data/hora nos registros: o momento do voto não fica registrado.
"""

from typing import List

from armazenamento import arquivos
from crypto import assinatura
from crypto.serial import canonico, sha256_hex

ARQUIVO = "quadro.json"


def hash_genese(config: dict) -> str:
    return sha256_hex(canonico(config))


def hash_registro(registro: dict) -> str:
    """Hash do registro sem o próprio campo "hash"."""
    sem_hash = {k: v for k, v in registro.items() if k != "hash"}
    return sha256_hex(canonico(sem_hash))


def dados_assinados_servidor(eleicao_id: str, registro: dict) -> bytes:
    """Bytes que o servidor assina nos registros de abertura e encerramento."""
    obj = {"eleicao_id": eleicao_id, "tipo": registro["tipo"],
           "hash_anterior": registro["hash_anterior"]}
    if registro["tipo"] == "abertura":
        obj["hash_eleitores"] = registro["hash_eleitores"]
    return canonico(obj)


def criar_vazio(eleicao_id: str) -> None:
    arquivos.salvar_publico(ARQUIVO, {"eleicao_id": eleicao_id, "registros": []})


def carregar() -> dict:
    return arquivos.ler_publico(ARQUIVO)


def ultimo_hash() -> str:
    """Hash do último registro (ou o hash da config, se o quadro estiver vazio)."""
    registros = carregar()["registros"]
    if registros:
        return registros[-1]["hash"]
    return hash_genese(arquivos.ler_publico("config.json"))


def acrescentar(dados: dict) -> dict:
    """Acrescenta um registro no FIM do quadro, calculando índice e hashes."""
    anterior = ultimo_hash()
    quadro = carregar()
    registros = quadro["registros"]
    registro = {"indice": len(registros), **dados, "hash_anterior": anterior}
    registro["hash"] = hash_registro(registro)
    registros.append(registro)
    arquivos.salvar_publico(ARQUIVO, quadro)
    return registro


def verificar_cadeia(config: dict, registros: List[dict]) -> List[str]:
    """Confere índices e encadeamento. Devolve a lista de problemas (vazia = ok)."""
    problemas = []
    esperado = hash_genese(config)
    for i, reg in enumerate(registros):
        if reg.get("indice") != i:
            problemas.append(f"registro {i}: índice fora de ordem ({reg.get('indice')})")
        if reg.get("hash_anterior") != esperado:
            problemas.append(f"registro {i}: hash_anterior não confere com o registro anterior")
        if hash_registro(reg) != reg.get("hash"):
            problemas.append(f"registro {i}: conteúdo alterado (hash recalculado não confere)")
        esperado = reg.get("hash")
    return problemas


def encerramento_valido(config: dict, registros: List[dict], servidor_pub_pem: str) -> bool:
    """O último registro é um encerramento com assinatura válida do servidor?"""
    if not registros or registros[-1].get("tipo") != "encerramento":
        return False
    ultimo = registros[-1]
    return assinatura.verificar(servidor_pub_pem,
                                dados_assinados_servidor(config["eleicao_id"], ultimo),
                                ultimo["assinatura_servidor"])
