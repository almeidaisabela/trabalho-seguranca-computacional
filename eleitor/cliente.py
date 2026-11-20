"""
CAMADA 3 - APLICAÇÃO | Cliente do eleitor (Integrante 3)

O que roda "no computador do eleitor":
  1. cadastrar: gera o par RSA do eleitor; a privada fica com ele e a pública
     é registrada no servidor (antes da abertura).
  2. votar: cifra a cédula com a chave conjunta h, assina e envia ao servidor.
     Recebe um recibo assinado pelo servidor e confere a assinatura.
  3. verificar: confere que a sua cédula está no quadro público, sem alteração.

Sobre o recibo: ele contém só o índice e o hash do registro. Os valores
aleatórios r usados na cifragem são descartados dentro de `elgamal.cifrar`, então
o eleitor não tem como provar a um terceiro em quem votou (dificulta a venda de
votos e a coação).
"""

from typing import List, Tuple

from armazenamento import arquivos
from crypto import assinatura, elgamal
from crypto.serial import canonico, hex_para_int, int_para_hex
from servidor import quadro, servidor


def _chave(eleitor_id: str) -> str:
    return f"eleitores/{eleitor_id}.pem"


def _recibo(eleitor_id: str) -> str:
    return f"eleitores/{eleitor_id}_recibo.json"


def cadastrar(eleitor_id: str) -> None:
    priv_pem, pub_pem = assinatura.gerar_par_rsa()
    servidor.registrar_eleitor(eleitor_id, pub_pem)   # falha -> não salva a privada
    arquivos.salvar_texto_privado(_chave(eleitor_id), priv_pem)


def montar_cedula(eleitor_id: str, escolha: int) -> dict:
    """Cifra uma cédula (1 para o escolhido, 0 para os demais) e assina."""
    config = arquivos.ler_publico("config.json")
    h = hex_para_int(config["h"])
    cifras = elgamal.cifrar_cedula(escolha, len(config["candidatos"]), h)
    cifras_hex = [{"c1": int_para_hex(c1), "c2": int_para_hex(c2)} for c1, c2 in cifras]

    a_assinar = canonico({"eleicao_id": config["eleicao_id"], "eleitor_id": eleitor_id,
                          "cifras": cifras_hex})
    priv_pem = arquivos.ler_texto_privado(_chave(eleitor_id))
    return {"eleicao_id": config["eleicao_id"], "eleitor_id": eleitor_id,
            "cifras": cifras_hex,
            "assinatura_eleitor": assinatura.assinar(priv_pem, a_assinar)}


def verificar_recibo(recibo: dict) -> bool:
    """O recibo foi mesmo assinado pelo servidor?"""
    pub = arquivos.ler_publico("servidor_pub.json")["chave_publica_pem"]
    dados = {k: recibo[k] for k in ("eleicao_id", "eleitor_id", "indice", "hash_registro")}
    return assinatura.verificar(pub, canonico(dados), recibo["assinatura_servidor"])


def votar(eleitor_id: str, escolha: int) -> dict:
    cedula = montar_cedula(eleitor_id, escolha)
    recibo = servidor.receber_cedula(cedula)          # "envio pela rede"
    if not verificar_recibo(recibo):
        raise ValueError("recibo com assinatura inválida do servidor")
    arquivos.salvar_privado(_recibo(eleitor_id), recibo)
    return recibo


def conferir_no_quadro(eleitor_id: str) -> Tuple[bool, List[str]]:
    """Verificação individual: minha cédula está no quadro e não foi alterada?"""
    recibo = arquivos.ler_privado(_recibo(eleitor_id))
    registros = quadro.carregar()["registros"]
    msgs = []

    msgs.append(("ok " if verificar_recibo(recibo) else "FALHA ") +
                "assinatura do servidor no recibo")
    idx = recibo["indice"]
    if idx >= len(registros):
        return False, msgs + [f"FALHA registro {idx} não existe no quadro"]
    reg = registros[idx]

    checagens = [
        (reg.get("eleitor_id") == eleitor_id, "o registro pertence a este eleitor"),
        (quadro.hash_registro(reg) == recibo["hash_registro"],
         "o conteúdo do registro tem o mesmo hash do recibo"),
        (reg.get("hash") == recibo["hash_registro"], "o hash publicado é o do recibo"),
    ]
    # A assinatura no quadro precisa conferir com a MINHA chave (derivada da privada).
    minha_pub = assinatura.chave_publica_de(arquivos.ler_texto_privado(_chave(eleitor_id)))
    dados = canonico({"eleicao_id": recibo["eleicao_id"], "eleitor_id": eleitor_id,
                      "cifras": reg.get("cifras")})
    checagens.append((assinatura.verificar(minha_pub, dados, reg.get("assinatura_eleitor", "")),
                      "as cifras do quadro são as que eu assinei"))

    for ok, texto in checagens:
        msgs.append(("ok " if ok else "FALHA ") + texto)
    return all(m.startswith("ok") for m in msgs), msgs
