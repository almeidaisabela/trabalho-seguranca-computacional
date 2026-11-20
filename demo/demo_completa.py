"""
Cenário 1: eleição completa com 3 autoridades e 3 eleitores.

    python demo/demo_completa.py            (direto)
    python demo/demo_completa.py --pausar   (espera Enter entre as etapas)
"""
from _util import executar, titulo


def preparar_e_votar():
    titulo("CONFIGURAÇÃO: 3 candidatos, 3 autoridades geram a chave conjunta")
    executar("resetar")
    executar("config", "--candidatos", "Ana", "Bruno", "Carla", "--autoridades", "3")

    titulo("CADASTRO: cada eleitor gera seu par RSA antes da abertura")
    executar("cadastrar", "eleitor1", "eleitor2", "eleitor3")

    titulo("VOTAÇÃO: cada voto é cifrado, assinado e publicado no quadro")
    executar("abrir")
    executar("votar", "eleitor1", "0")
    executar("votar", "eleitor2", "2")
    executar("votar", "eleitor3", "0")

    titulo("VERIFICAÇÃO INDIVIDUAL: eleitor2 confere o recibo no quadro")
    executar("verificar", "eleitor2")


def encerrar_apurar_auditar():
    titulo("ENCERRAMENTO")
    executar("encerrar")
    titulo("APURAÇÃO: as 3 autoridades decifram só o TOTAL")
    executar("apurar")
    titulo("AUDITORIA INDEPENDENTE")
    executar("auditar")


if __name__ == "__main__":
    preparar_e_votar()
    encerrar_apurar_auditar()
