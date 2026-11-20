"""
Cenário 3: adulteração de uma cédula no quadro público e detecção pelo auditor.

Pré-condição: eleição apurada (rode antes o demo_completa ou o roteiro).

    python demo/adultera_quadro.py             troca as cifras de uma cédula
    python demo/adultera_quadro.py --recalcula além disso, recalcula todos os hashes
                                               (administrador malicioso "esperto")
    python demo/adultera_quadro.py --restaurar devolve o quadro original

Trocar as cifras do candidato 0 com as do candidato 1 muda o voto SEM precisar
decifrar nada. Mesmo que o atacante recalcule a cadeia de hashes, a assinatura
do eleitor e o recibo deixam de bater.
"""
import json
import shutil
import sys

from _util import executar, titulo

from armazenamento import arquivos
from crypto.serial import canonico, sha256_hex

QUADRO = arquivos.PUBLICOS / "quadro.json"
BACKUP = arquivos.PRIVADOS / "quadro_original_demo.json"


def adulterar(recalcular: bool, alvo: str = "eleitor2") -> None:
    if not BACKUP.exists():
        shutil.copy(QUADRO, BACKUP)
    quadro = json.loads(QUADRO.read_text(encoding="utf-8"))
    registros = quadro["registros"]
    reg = next(r for r in registros if r.get("eleitor_id") == alvo)
    reg["cifras"][0], reg["cifras"][1] = reg["cifras"][1], reg["cifras"][0]
    print(f"Cifras dos candidatos 0 e 1 trocadas no registro {reg['indice']} ({alvo}).")

    if recalcular:
        config = json.loads((arquivos.PUBLICOS / "config.json").read_text(encoding="utf-8"))
        anterior = sha256_hex(canonico(config))
        for r in registros:
            r["hash_anterior"] = anterior
            r["hash"] = sha256_hex(canonico({k: v for k, v in r.items() if k != "hash"}))
            anterior = r["hash"]
        print("Todos os hashes da cadeia foram recalculados pelo atacante.")
    QUADRO.write_text(json.dumps(quadro, indent=2, ensure_ascii=False), encoding="utf-8")


def restaurar() -> None:
    if BACKUP.exists():
        shutil.move(BACKUP, QUADRO)
        print("Quadro original restaurado.")


if __name__ == "__main__":
    if "--restaurar" in sys.argv:
        restaurar()
        sys.exit(0)
    recalcula = "--recalcula" in sys.argv
    titulo("ATAQUE: adulteração de uma cédula no quadro público"
           + (" (com hashes recalculados)" if recalcula else ""))
    adulterar(recalcula)
    titulo("DETECÇÃO pelo auditor independente")
    executar("auditar")
    titulo("DETECÇÃO pelo próprio eleitor (verificação individual)")
    executar("verificar", "eleitor2")
    print("\nPara desfazer: python demo/adultera_quadro.py --restaurar")
