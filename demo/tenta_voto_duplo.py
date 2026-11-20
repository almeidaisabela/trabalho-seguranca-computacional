"""
Cenário 2: eleitor tenta votar duas vezes (e um não cadastrado tenta votar).

Pré-condição: votação aberta e eleitor1 já votou (rode a 1ª parte do roteiro).
    python demo/tenta_voto_duplo.py
"""
from _util import executar, titulo

from crypto import assinatura, elgamal
from crypto.serial import canonico, hex_para_int, int_para_hex
from armazenamento import arquivos
from servidor import servidor


def tentar_voto_duplo():
    titulo("ATAQUE: eleitor1 tenta votar de novo (unicidade)")
    executar("votar", "eleitor1", "1")


def tentar_eleitor_nao_cadastrado():
    titulo("ATAQUE: 'intruso' gera um par RSA próprio e envia cédula (elegibilidade)")
    config = arquivos.ler_publico("config.json")
    priv, _pub = assinatura.gerar_par_rsa()        # chave que NUNCA foi cadastrada
    cifras = elgamal.cifrar_cedula(1, len(config["candidatos"]), hex_para_int(config["h"]))
    cifras = [{"c1": int_para_hex(a), "c2": int_para_hex(b)} for a, b in cifras]
    dados = {"eleicao_id": config["eleicao_id"], "eleitor_id": "intruso", "cifras": cifras}
    cedula = {**dados, "assinatura_eleitor": assinatura.assinar(priv, canonico(dados))}
    try:
        servidor.receber_cedula(cedula)
        print("ACEITA?! (não deveria acontecer)")
    except servidor.ErroVotacao as erro:
        print(f"Servidor recusou: {erro}")


if __name__ == "__main__":
    tentar_voto_duplo()
    tentar_eleitor_nao_cadastrado()
