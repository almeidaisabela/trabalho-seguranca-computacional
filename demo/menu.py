"""
MENU compartilhado pela simulação e pela interação.

`montar_menu` recebe as funções que dizem onde ficam as chaves privadas.
É a ÚNICA diferença entre simulacao.py e interacao.py.
"""
from tela import AUTORIDADES, candidatos

import ataques
import preparacao
import resultado
import votacao
from armazenamento import arquivos
from autoridades.autoridade import ErroApuracao
from servidor import quadro, servidor
from servidor.servidor import ErroVotacao


def montar_menu(guardar_chave_autoridade, chave_da_autoridade,
                guardar_chave_eleitora, chave_da_eleitora, recomecar):
    return [
        ("PREPARAÇÃO", None, None),
        ("1", "Ver o número primo da eleição", preparacao.op_primo),
        ("2", "Autoridades geram as chaves e o servidor configura",
         lambda: preparacao.op_configurar(guardar_chave_autoridade)),
        ("3", "Cadastrar eleitora", lambda: preparacao.op_cadastrar(guardar_chave_eleitora)),
        ("4", "Abrir a votação", preparacao.op_abrir),
        ("VOTAÇÃO", None, None),
        ("5", "Votar", lambda: votacao.op_votar(chave_da_eleitora)),
        ("6", "Eleitora confere o próprio recibo", lambda: votacao.op_conferir(chave_da_eleitora)),
        ("7", "Encerrar a votação", votacao.op_encerrar),
        ("APURAÇÃO E AUDITORIA", None, None),
        ("8", "Apurar (escolher quais autoridades participam)",
         lambda: resultado.op_apurar(chave_da_autoridade)),
        ("9", "Auditar", resultado.op_auditar),
        ("10", "Ver o quadro público", resultado.op_ver_quadro),
        ("ATAQUES", None, None),
        ("11", "Votar em nome de outra eleitora",
         lambda: ataques.op_votar_como_outra(chave_da_eleitora)),
        ("12", "Administrador troca as cifras de uma cédula", ataques.op_adulterar),
        ("OUTROS", None, None),
        ("R", "Recomeçar do zero", recomecar),
        ("0", "Sair", None),
    ]


def cabecalho(menu, nome_programa):
    estado = servidor.estado()
    print("\n" + "=" * 74 + f"\n  {nome_programa}   |   estado: {estado.upper()}")
    if estado != "inexistente":
        cadastradas = [e["id"] for e in arquivos.ler_publico("eleitores.json")]
        votaram = [r["eleitor_id"] for r in quadro.carregar()["registros"]
                   if r["tipo"] == "cedula"]
        print(f"  candidatos:  {', '.join(candidatos())}")
        print(f"  autoridades: {', '.join(AUTORIDADES)}")
        print(f"  cadastradas: {', '.join(cadastradas) or '-'}")
        print(f"  já votaram:  {', '.join(votaram) or '-'}")
    print("=" * 74)
    for chave, texto, _acao in menu:
        print(f"\n  {chave}" if texto is None else f"   {chave:>2}) {texto}")


def executar(menu, nome_programa):
    """Mostra o menu até escolherem 0. Recusas do sistema aparecem como BLOQUEADO."""
    acoes = {chave.lower(): acao for chave, _t, acao in menu if acao}
    try:
        while True:
            cabecalho(menu, nome_programa)
            escolha = input("\n  Escolha uma opção: ").strip().lower()
            if escolha == "0":
                break
            if escolha not in acoes:
                continue
            try:
                acoes[escolha]()
            except (ErroVotacao, ErroApuracao, ValueError) as erro:
                print(f"\n   BLOQUEADO PELO SISTEMA: {erro}")
            except FileNotFoundError:
                print("\n   Ainda não existe eleição configurada: use a opção 2.")
            input("\n   (Enter para voltar ao menu) ")
    except (EOFError, KeyboardInterrupt):
        print()
