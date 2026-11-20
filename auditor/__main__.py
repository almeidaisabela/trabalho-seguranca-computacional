"""Permite rodar o auditor como programa separado:  python -m auditor [pasta]"""
import sys

from auditor.auditor import PASTA_PADRAO, auditar

sys.exit(0 if auditar(sys.argv[1] if len(sys.argv) > 1 else PASTA_PADRAO) else 1)
