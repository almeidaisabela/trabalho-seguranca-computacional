"""
CAMADA 3 - APLICAÇÃO | Servidor de votação (Integrante 4)

Responsabilidades do servidor:
  1. Publicar a configuração da eleição (candidatos, grupo, chave conjunta h).
  2. Manter o cadastro de eleitores (chaves públicas RSA) ANTES da abertura.
  3. Receber cédulas, aplicar as regras (elegibilidade, assinatura, unicidade)
     e publicá-las no quadro.
  4. Emitir um RECIBO assinado para cada cédula aceita.
  5. Encerrar a votação.

O que o servidor NÃO tem: nenhuma chave privada das autoridades. Ele só vê
cifras, então não consegue saber o voto de ninguém (sigilo), nem calcular
totais parciais (justiça).

Ciclo de estados (nunca volta atrás):  configurada -> aberta -> encerrada -> apurada
"""

import re
from typing import List

from armazenamento import arquivos
from crypto import assinatura, params, provas
from crypto.serial import canonico, hex_para_int, int_para_hex, sha256_hex
from servidor import quadro

ARQ_ESTADO = "servidor/estado.json"
ARQ_CHAVE = "servidor/servidor_priv.pem"
ID_VALIDO = re.compile(r"^[A-Za-z0-9_-]{1,32}$")  # evita ids estranhos (ex.: "../x")


class ErroVotacao(Exception):
    """Operação recusada pelo servidor."""


# ------------------------------------------------------------- estado interno
def ler_config() -> dict:
    return arquivos.ler_publico("config.json")


def resetar() -> None:
    """Apaga a eleição anterior (só para testes e demonstração)."""
    arquivos.limpar_dados()


def estado() -> str:
    if not arquivos.existe_privado(ARQ_ESTADO):
        return "inexistente"
    return arquivos.ler_privado(ARQ_ESTADO)["estado"]


def _mudar_estado(de: str, para: str) -> None:
    atual = estado()
    if atual != de:
        raise ErroVotacao(f"operação exige estado '{de}', mas a eleição está '{atual}'")
    arquivos.salvar_privado(ARQ_ESTADO, {"estado": para})


def _assinar(dados: bytes) -> str:
    return assinatura.assinar(arquivos.ler_texto_privado(ARQ_CHAVE), dados)


# ------------------------------------------------------------------- etapa 1
def configurar(eleicao_id: str, titulo: str, candidatos: List[str],
               autoridades_publicas: List[dict]) -> dict:
    """Publica config.json. Recebe só as partes PÚBLICAS das autoridades (h_i + prova)."""
    if arquivos.existe_publico("config.json"):
        raise ErroVotacao("já existe uma eleição configurada; rode 'resetar' antes")
    if len(candidatos) < 2:
        raise ErroVotacao("são necessários pelo menos 2 candidatos")
    if len(autoridades_publicas) < 3:
        raise ErroVotacao("são necessárias pelo menos 3 autoridades")

    # Confere cada h_i: está no grupo e a autoridade prova que conhece x_i.
    h = 1
    for aut in autoridades_publicas:
        h_i = hex_para_int(aut["h_i"])
        if not params.pertence_ao_grupo(h_i):
            raise ErroVotacao(f"h_i da autoridade {aut['id']} fora do grupo")
        if not provas.verificar_schnorr(h_i, aut["prova"], aut["id"]):
            raise ErroVotacao(f"prova de conhecimento da autoridade {aut['id']} inválida")
        h = (h * h_i) % params.P          # chave conjunta: h = h_1 * h_2 * ... * h_n

    config = {
        "eleicao_id": eleicao_id,
        "titulo": titulo,
        "candidatos": [{"id": i, "nome": nome} for i, nome in enumerate(candidatos)],
        "grupo": {"nome": params.NOME_GRUPO, "p": int_para_hex(params.P),
                  "q": int_para_hex(params.Q), "g": int_para_hex(params.G)},
        "hash": "SHA-256",
        "autoridades": autoridades_publicas,
        "h": int_para_hex(h),
    }

    # Par de chaves RSA do servidor (assina recibos, abertura e encerramento).
    priv_pem, pub_pem = assinatura.gerar_par_rsa()
    arquivos.salvar_texto_privado(ARQ_CHAVE, priv_pem)
    arquivos.salvar_publico("servidor_pub.json", {"chave_publica_pem": pub_pem})

    arquivos.salvar_publico("config.json", config)
    arquivos.salvar_publico("eleitores.json", [])
    quadro.criar_vazio(eleicao_id)
    arquivos.salvar_privado(ARQ_ESTADO, {"estado": "configurada"})
    return config


# ------------------------------------------------------------------- etapa 2
def registrar_eleitor(eleitor_id: str, chave_publica_pem: str) -> None:
    """Cadastra a chave pública de um eleitor. Só é permitido antes da abertura."""
    if estado() != "configurada":
        raise ErroVotacao("o cadastro só é permitido antes da abertura da votação")
    if not ID_VALIDO.match(eleitor_id):
        raise ErroVotacao("id de eleitor inválido (use letras, números, _ ou -)")
    eleitores = arquivos.ler_publico("eleitores.json")
    if any(e["id"] == eleitor_id for e in eleitores):
        raise ErroVotacao(f"eleitor {eleitor_id} já cadastrado")
    eleitores.append({"id": eleitor_id, "chave_publica_pem": chave_publica_pem})
    arquivos.salvar_publico("eleitores.json", eleitores)


# ------------------------------------------------------------------- etapa 3
def abrir() -> None:
    """Abre a votação e grava no quadro o hash do cadastro (que fica congelado)."""
    eleitores = arquivos.ler_publico("eleitores.json")
    if not eleitores:
        raise ErroVotacao("nenhum eleitor cadastrado")
    _mudar_estado("configurada", "aberta")

    config = arquivos.ler_publico("config.json")
    hash_eleitores = sha256_hex(canonico(eleitores))
    assin = _assinar(quadro.dados_assinados_servidor(config["eleicao_id"], {
        "tipo": "abertura", "hash_eleitores": hash_eleitores,
        "hash_anterior": quadro.ultimo_hash()}))
    quadro.acrescentar({"tipo": "abertura", "hash_eleitores": hash_eleitores,
                        "assinatura_servidor": assin})


# ------------------------------------------------------------------- etapa 4
def receber_cedula(cedula: dict) -> dict:
    """Valida a cédula, publica no quadro e devolve o recibo assinado."""
    config = arquivos.ler_publico("config.json")

    # Regra 1: votação aberta (justiça: nada entra antes nem depois).
    if estado() != "aberta":
        raise ErroVotacao("a votação não está aberta")
    if cedula.get("eleicao_id") != config["eleicao_id"]:
        raise ErroVotacao("cédula de outra eleição")

    # Regra 2: elegibilidade -> o eleitor precisa estar no cadastro.
    eleitor_id = cedula.get("eleitor_id")
    cadastro = {e["id"]: e["chave_publica_pem"] for e in arquivos.ler_publico("eleitores.json")}
    if eleitor_id not in cadastro:
        raise ErroVotacao(f"eleitor {eleitor_id} não está cadastrado")

    # Regra 3: assinatura do eleitor sobre (eleição, eleitor, cifras).
    a_assinar = canonico({"eleicao_id": cedula["eleicao_id"], "eleitor_id": eleitor_id,
                          "cifras": cedula["cifras"]})
    if not assinatura.verificar(cadastro[eleitor_id], a_assinar, cedula["assinatura_eleitor"]):
        raise ErroVotacao("assinatura do eleitor inválida")

    # Regra 4: unicidade -> no máximo uma cédula por eleitor.
    registros = quadro.carregar()["registros"]
    if any(r.get("eleitor_id") == eleitor_id for r in registros):
        raise ErroVotacao(f"eleitor {eleitor_id} já votou")

    # Regra 5: formato -> uma cifra por candidato, todas dentro do grupo.
    if len(cedula["cifras"]) != len(config["candidatos"]):
        raise ErroVotacao("número de cifras diferente do número de candidatos")
    for cifra in cedula["cifras"]:
        if not (params.pertence_ao_grupo(hex_para_int(cifra["c1"]))
                and params.pertence_ao_grupo(hex_para_int(cifra["c2"]))):
            raise ErroVotacao("cifra fora do grupo")

    # Regra 6: publica no quadro e emite o recibo.
    registro = quadro.acrescentar({
        "tipo": "cedula",
        "eleitor_id": eleitor_id,
        "cifras": cedula["cifras"],
        "assinatura_eleitor": cedula["assinatura_eleitor"],
    })
    recibo = {"eleicao_id": config["eleicao_id"], "eleitor_id": eleitor_id,
              "indice": registro["indice"], "hash_registro": registro["hash"]}
    recibo["assinatura_servidor"] = _assinar(canonico(recibo))
    return recibo


# ------------------------------------------------------------------- etapa 5
def encerrar() -> None:
    """Fecha a votação e grava o registro de encerramento assinado."""
    _mudar_estado("aberta", "encerrada")
    config = arquivos.ler_publico("config.json")
    assin = _assinar(quadro.dados_assinados_servidor(config["eleicao_id"], {
        "tipo": "encerramento", "hash_anterior": quadro.ultimo_hash()}))
    quadro.acrescentar({"tipo": "encerramento", "assinatura_servidor": assin})


def marcar_apurada() -> None:
    _mudar_estado("encerrada", "apurada")
