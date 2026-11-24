"""
OPÇÕES 8 A 10: APURAÇÃO E AUDITORIA

    8. apurar (escolhendo quais autoridades participam)
    9. auditar
   10. ver o quadro público

op_apurar recebe `obter_chave`, que pede a chave da autoridade ao sistema
(simulacao.py) ou à própria autoridade (interacao.py).
"""
from tela import candidatos, curto, enter, mostra, nomes, passo, perguntar, titulo

from auditor.auditor import auditar
from autoridades import apuracao, autoridade
from crypto.params import G, P
from crypto.serial import hex_para_int
from servidor import quadro, servidor


def op_apurar(obter_chave):
    config = servidor.ler_config()
    todas = [a["id"] for a in config["autoridades"]]
    participantes = nomes(perguntar("Quais autoridades participam? (separe por vírgula)",
                                    ", ".join(todas)))
    for nome in participantes:
        if nome not in todas:
            raise ValueError(f"{nome} não é autoridade desta eleição")
    registros = quadro.carregar()["registros"]
    produtos = autoridade.produtos_do_quadro(config, registros)
    num_cedulas = sum(1 for r in registros if r["tipo"] == "cedula")

    titulo("APURAÇÃO SEM ABRIR NENHUM VOTO")
    print(f"\n   Multiplicamos as {num_cedulas} cédulas, candidato por candidato."
          "\n   Como g^a * g^b = g^(a+b), o resultado é uma cifra da SOMA dos votos:")
    for nome, (c1, c2) in zip(candidatos(), produtos):
        passo(nome)
        mostra("C1 = produto dos c1:", curto(c1))
        mostra("C2 = produto dos c2:", curto(c2))

    parciais = []
    for nome in participantes:
        # recusa se a votação não acabou ou se a chave não for a dela
        parcial = autoridade.decifracao_parcial(nome, obter_chave(nome))
        passo(f"{nome} calcula D = C1^x_i com o x_i que só ela tem")
        for cand, d in zip(candidatos(), parcial["D"]):
            mostra(f"D para {cand}:", curto(hex_para_int(d)))
        print(f"     {nome} ENVIA: os D e as provas de Chaum-Pedersen. O x_i fica com ela.")
        parciais.append(parcial)

    faltam = [a for a in todas if a not in participantes]
    enter("Todas", "juntar as partes e procurar os totais")
    for j, (nome, (_c1, c2)) in enumerate(zip(candidatos(), produtos)):
        mostrar_busca(nome, c2, [p["D"][j] for p in parciais], num_cedulas, faltam)

    # O resultado oficial é calculado e conferido pelo sistema (falha se faltar autoridade).
    resultado = apuracao.publicar_resultado(parciais)
    if servidor.estado() == "encerrada":
        servidor.marcar_apurada()
    titulo("RESULTADO OFICIAL (publicado em dados_publicos/resultado.json)")
    for nome, t in zip(candidatos(), resultado["totais"]):
        print(f"     {nome:<16} {t['votos']} voto(s)")


def mostrar_busca(nome, c2, lista_d, num_cedulas, faltam):
    """Só para mostrar na tela: C2 / (D_1 * D_2 * D_3) = g^total, e a busca do total."""
    produto_d = 1
    for d in lista_d:
        produto_d = (produto_d * hex_para_int(d)) % P
    alvo = (c2 * pow(produto_d, -1, P)) % P
    passo(f"{nome}: C2 / (produto dos D) = g^total ?")
    for k in range(num_cedulas + 1):
        if pow(G, k, P) == alvo:
            print(f"     g^{k} é igual? SIM -> {k} voto(s)")
            return
        print(f"     g^{k} é igual? não")
    print(f"     nenhum g^k serviu: falta o fator de {', '.join(faltam)}")


def op_auditar():
    titulo("AUDITORIA INDEPENDENTE")
    auditar()


def op_ver_quadro():
    """Mostra o quadro público: quem votou, as cifras, a assinatura e os hashes."""
    titulo("QUADRO PÚBLICO (dados_publicos/quadro.json)")
    for r in quadro.carregar()["registros"]:
        passo(f"registro {r['indice']}: {r['tipo']} {r.get('eleitor_id', '')}")
        for j, c in enumerate(r.get("cifras", [])):
            mostra(f"cifra {j}: c1 =", curto(hex_para_int(c["c1"])))
        if "assinatura_eleitor" in r:
            mostra("assinatura da eleitora:", curto(hex_para_int(r["assinatura_eleitor"])))
        mostra("hash_anterior:", r["hash_anterior"][:32] + "...")
        mostra("hash:", r["hash"][:32] + "...")
