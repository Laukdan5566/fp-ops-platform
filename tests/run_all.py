"""Roda todos os testes do projeto, um processo por arquivo (cada um monta o proprio banco temporario).

Uso:  python tests/run_all.py          (da raiz do projeto)
Sai com codigo 1 se qualquer teste falhar; usado tambem pelo GitHub Actions.
"""
import os
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
# worker/worker.py faz sombra no pacote "worker": o teste do helpdesk importa "worker.xxx", os demais usam os modulos soltos.
CAMINHOS = {"test_helpdesk_candidate.py": ["app", "."]}
PADRAO = ["app", "worker"]

falhas = []
for teste in sorted((RAIZ / "tests").glob("test_*.py")):
    caminhos = CAMINHOS.get(teste.name, PADRAO)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(RAIZ / c) for c in caminhos), "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("DB_PATH", None)
    env.pop("DATABASE_URL", None)
    resultado = subprocess.run([sys.executable, str(teste)], cwd=RAIZ, env=env, capture_output=True, text=True)
    ultima = (resultado.stdout.strip().splitlines() or [""])[-1]
    print(f"{'OK   ' if resultado.returncode == 0 else 'FALHA'} {teste.name}  {ultima}")
    if resultado.returncode != 0:
        falhas.append(teste.name)
        print((resultado.stderr or resultado.stdout)[-1500:])

print(f"\n{len(falhas)} falha(s)" if falhas else "\ntodos os testes passaram")
sys.exit(1 if falhas else 0)
