"""
Cenário 4: apuração sem uma das autoridades (deve falhar).

Pré-condição: votação encerrada.
    python demo/tenta_apurar_sem_autoridade.py [A3]
"""
import sys

from _util import executar, titulo

if __name__ == "__main__":
    ausente = next((a for a in sys.argv[1:] if not a.startswith("--")), "A3")
    titulo(f"ATAQUE: apurar sem a autoridade {ausente}")
    print("Sem D_" + ausente + ", C2 / prod(D_i) = g^total * h_" + ausente +
          "^R, que não é uma potência pequena de g -> a busca do total falha.")
    executar("apurar", "--sem", ausente)
