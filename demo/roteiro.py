"""
ROTEIRO DA APRESENTAÇÃO (cabe em ~5 minutos de execução)

Cobre os 4 itens obrigatórios da demonstração ao vivo, na ordem:
  1. eleição com 3 eleitores e 3 autoridades
  2. eleitor tentando votar duas vezes -> rejeitado
  3. apuração sem todas as autoridades -> falha
  4. adulteração de uma cédula no quadro -> detectada pelo auditor

    python demo/roteiro.py --pausar
"""
import adultera_quadro
import demo_completa
import tenta_voto_duplo
from _util import executar, titulo

if __name__ == "__main__":
    demo_completa.preparar_e_votar()                 # item 1 (parte 1)
    tenta_voto_duplo.tentar_voto_duplo()             # item 2
    tenta_voto_duplo.tentar_eleitor_nao_cadastrado()

    titulo("ENCERRAMENTO")
    executar("encerrar")
    titulo("ATAQUE: apurar sem a autoridade A3")      # item 3
    executar("apurar", "--sem", "A3")

    titulo("APURAÇÃO com as 3 autoridades")            # item 1 (parte 2)
    executar("apurar")
    titulo("AUDITORIA da eleição íntegra")
    executar("auditar")

    titulo("ATAQUE: administrador troca as cifras da cédula do eleitor2")   # item 4
    adultera_quadro.adulterar(recalcular=False)
    executar("auditar")
    titulo("Mesmo recalculando todos os hashes, a fraude é detectada")
    adultera_quadro.restaurar()
    adultera_quadro.adulterar(recalcular=True)
    executar("auditar")
    executar("verificar", "eleitor2")
    adultera_quadro.restaurar()
