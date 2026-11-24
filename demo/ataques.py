"""
OPÇÕES 11 E 12: ATAQUES

   11. uma eleitora tenta votar em nome de outra
   12. o administrador troca as cifras de uma cédula no quadro

Outros ataques não precisam de opção própria: basta usar o menu "errado",
por exemplo votar duas vezes (opção 5), apurar sem uma autoridade (opção 8)
ou cadastrar depois da abertura (opção 3). Quem barra é sempre o sistema.
"""
from tela import candidatos, enter, escolher_candidato, perguntar, titulo

from armazenamento import arquivos
from eleitor import cliente
from servidor import quadro, servidor
from votacao import cifrar_mostrando


def op_votar_como_outra(obter_chave):
    titulo("[ATAQUE] VOTAR EM NOME DE OUTRA ELEITORA")
    fraudadora = perguntar("Quem está tentando fraudar?")
    vitima = perguntar(f"Em nome de quem {fraudadora} vai votar?")
    escolha = escolher_candidato()
    cifras = cifrar_mostrando(escolha)
    priv_pem = obter_chave(fraudadora)
    if priv_pem is None:
        raise ValueError(f"{fraudadora} não tem chave; escolha uma eleitora cadastrada")
    cedula = cliente.assinar_cedula(fraudadora, cifras, priv_pem)
    cedula["eleitor_id"] = vitima
    print(f"\n   A cédula diz que é de {vitima}, mas foi assinada com a chave de {fraudadora}.")
    enter(fraudadora, "enviar a cédula falsa ao servidor")
    servidor.receber_cedula(cedula)


def op_adulterar():
    nome = perguntar("Cédula de qual eleitora o administrador vai adulterar?")
    q = quadro.carregar()
    reg = next((r for r in q["registros"] if r.get("eleitor_id") == nome), None)
    if reg is None:
        raise ValueError(f"{nome} não tem cédula no quadro")

    titulo("[ATAQUE] O ADMINISTRADOR ADULTERA O QUADRO")
    lista = candidatos()
    print(f"""
   Ele não sabe em quem {nome} votou, mas pode TROCAR as cifras de lugar:
   a cifra de {lista[0]} vai para {lista[1]} e vice-versa.""")
    reg["cifras"][0], reg["cifras"][1] = reg["cifras"][1], reg["cifras"][0]
    enter("Administrador", "gravar o quadro adulterado")
    arquivos.salvar_publico("quadro.json", q)
    print(f"\n   Quadro adulterado. Agora testem: 'Auditar' e '{nome} confere o recibo'."
          "\n   (Para continuar com uma eleição íntegra, recomece pela opção R.)")
