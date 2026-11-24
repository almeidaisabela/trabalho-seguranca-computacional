"""
CAMADA 4 - APRESENTAÇÃO | Interface de linha de comando (Integrante 3)

Esta camada só lê os argumentos, chama a camada de aplicação e mostra o
resultado. Não há nenhuma regra de segurança aqui: todas as regras ficam no
servidor, nas autoridades, no eleitor e no auditor.

Comandos (na ordem de uma eleição):
    python main.py resetar
    python main.py config --candidatos Ana Bruno Carla --autoridades 3
    python main.py cadastrar eleitor1 eleitor2 eleitor3
    python main.py abrir
    python main.py votar eleitor1 0
    python main.py verificar eleitor1
    python main.py encerrar
    python main.py apurar [--sem A2]
    python main.py auditar [pasta_publica]
"""

import argparse
import sys

from autoridades import apuracao, autoridade
from eleitor import cliente
from servidor import servidor


def cmd_resetar(_args):
    servidor.resetar()
    print("Dados de eleições anteriores apagados (dados_publicos/ e dados_privados/).")


def cmd_config(args):
    servidor.garantir_sem_eleicao()   # antes de gerar chaves: não sobrescrever eleição existente
    ids = [f"A{i}" for i in range(1, args.autoridades + 1)]
    print(f"Cada autoridade gera sua chave privada x_i em segredo: {', '.join(ids)}")
    publicas = [autoridade.gerar_chave(aid) for aid in ids]   # só h_i e prova saem daqui
    config = servidor.configurar(args.id, args.titulo, args.candidatos, publicas)
    print(f"Eleição '{config['titulo']}' configurada.")
    for c in config["candidatos"]:
        print(f"  candidato {c['id']}: {c['nome']}")
    print(f"Chave conjunta h = h_1 * ... * h_{len(ids)}  (início: {config['h'][:24]}...)")


def cmd_cadastrar(args):
    for eid in args.ids:
        cliente.cadastrar(eid)
        print(f"Eleitor {eid} cadastrado (chave privada guardada só com o eleitor).")


def cmd_abrir(_args):
    servidor.abrir()
    print("Votação ABERTA. Novos cadastros não são mais aceitos.")


def cmd_votar(args):
    recibo = cliente.votar(args.id, args.candidato)
    print(f"Voto de {args.id} aceito. Recibo assinado pelo servidor:")
    print(f"  índice no quadro: {recibo['indice']}")
    print(f"  hash do registro: {recibo['hash_registro']}")


def cmd_verificar(args):
    ok, msgs = cliente.conferir_no_quadro(args.id)
    for m in msgs:
        print(f"  {m}")
    print("Cédula confirmada no quadro." if ok else "PROBLEMA: cédula ausente ou alterada!")
    return ok


def cmd_encerrar(_args):
    servidor.encerrar()
    print("Votação ENCERRADA. Registro de encerramento assinado no quadro.")


def cmd_apurar(args):
    config = servidor.ler_config()
    todas = [a["id"] for a in config["autoridades"]]
    participantes = [a for a in todas if a not in args.sem]
    print(f"Autoridades participando: {', '.join(participantes)}")
    if args.sem:
        print(f"Autoridades AUSENTES: {', '.join(args.sem)}")
    resultado = apuracao.apurar(participantes)
    servidor.marcar_apurada()
    print(f"Resultado ({resultado['num_cedulas']} cédulas):")
    for t in resultado["totais"]:
        nome = config["candidatos"][t["candidato"]]["nome"]
        print(f"  {nome}: {t['votos']} voto(s)")


def cmd_auditar(args):
    from auditor.auditor import auditar   # o auditor só lê a pasta pública
    return auditar(args.pasta) if args.pasta else auditar()


def montar_parser():
    p = argparse.ArgumentParser(description="Sistema de votação eletrônica seguro")
    sub = p.add_subparsers(dest="comando", required=True)

    sub.add_parser("resetar", help="apaga os dados da eleição anterior")

    c = sub.add_parser("config", help="configura a eleição e as autoridades")
    c.add_argument("--candidatos", nargs="+", default=["Candidato A", "Candidato B"])
    c.add_argument("--autoridades", type=int, default=3)
    c.add_argument("--titulo", default="Eleição de teste")
    c.add_argument("--id", default="eleicao-2026-01")

    c = sub.add_parser("cadastrar", help="cadastra eleitores (antes da abertura)")
    c.add_argument("ids", nargs="+")

    sub.add_parser("abrir", help="abre a votação")

    c = sub.add_parser("votar", help="eleitor vota")
    c.add_argument("id")
    c.add_argument("candidato", type=int)

    c = sub.add_parser("verificar", help="eleitor confere sua cédula no quadro")
    c.add_argument("id")

    sub.add_parser("encerrar", help="encerra a votação")

    c = sub.add_parser("apurar", help="decifração conjunta pelas autoridades")
    c.add_argument("--sem", nargs="*", default=[], help="autoridades que NÃO participam")

    c = sub.add_parser("auditar", help="auditor independente")
    c.add_argument("pasta", nargs="?")
    return p


COMANDOS = {"resetar": cmd_resetar, "config": cmd_config, "cadastrar": cmd_cadastrar,
            "abrir": cmd_abrir, "votar": cmd_votar, "verificar": cmd_verificar,
            "encerrar": cmd_encerrar, "apurar": cmd_apurar, "auditar": cmd_auditar}


def main(argv=None) -> int:
    args = montar_parser().parse_args(argv)
    try:
        ok = COMANDOS[args.comando](args)
    except (servidor.ErroVotacao, autoridade.ErroApuracao, ValueError) as erro:
        print(f"ERRO: {erro}")
        return 1
    except FileNotFoundError as erro:
        print(f"ERRO: arquivo não encontrado ({erro.filename}). A etapa anterior foi feita?")
        return 1
    return 0 if ok is not False else 1


if __name__ == "__main__":
    sys.exit(main())
