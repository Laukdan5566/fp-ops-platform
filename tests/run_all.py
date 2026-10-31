"""Roda todos os testes do projeto, um processo por arquivo (cada um monta o proprio banco temporario).

Uso:  python tests/run_all.py                    (da raiz do projeto; SQLite temporario)
      python tests/run_all.py --postgres URL     (cada teste ganha um banco Postgres novo, criado e apagado aqui;
                                                  URL = servidor com permissao de criar bancos, ex.: postgresql://postgres:senha@localhost:5432/postgres)
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

# Testes que so fazem sentido no SQLite (mexem no arquivo do banco) e por isso ficam de fora da rodada em Postgres: {arquivo: motivo}.
SO_SQLITE = {"test_retencao.py": "confere a copia do ARQUIVO do banco antes de limpar; no Postgres o backup e o pg_dump do servidor"}


def banco_novo(admin_url, nome):
    """Cria um banco vazio no servidor e devolve (url_do_banco, apagar)."""
    import psycopg2
    from psycopg2 import sql
    base = admin_url.rpartition("/")[0]
    con = psycopg2.connect(admin_url)
    con.autocommit = True
    cur = con.cursor()
    cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(nome)))
    cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(nome)))

    def apagar():
        cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(nome)))
        con.close()
    return f"{base}/{nome}", apagar


def main(admin_url=None):
    falhas = []
    for teste in sorted((RAIZ / "tests").glob("test_*.py")):
        if admin_url and teste.name in SO_SQLITE:
            print(f"PULOU {teste.name}  ({SO_SQLITE[teste.name]})")
            continue
        caminhos = CAMINHOS.get(teste.name, PADRAO)
        env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(RAIZ / c) for c in caminhos), "PYTHONDONTWRITEBYTECODE": "1"}
        for variavel in ("DB_PATH", "DATABASE_URL", "TEST_DATABASE_URL"):
            env.pop(variavel, None)
        apagar = None
        if admin_url:
            url, apagar = banco_novo(admin_url, "fpops_" + teste.stem.replace("test_", ""))
            env["TEST_DATABASE_URL"] = url
        try:
            resultado = subprocess.run([sys.executable, str(teste)], cwd=RAIZ, env=env, capture_output=True, text=True)
        finally:
            if apagar:
                apagar()
        ultima = (resultado.stdout.strip().splitlines() or [""])[-1]
        print(f"{'OK   ' if resultado.returncode == 0 else 'FALHA'} {teste.name}  {ultima}")
        if resultado.returncode != 0:
            falhas.append(teste.name)
            print((resultado.stderr or resultado.stdout)[-1500:])

    print(f"\n{len(falhas)} falha(s)" if falhas else "\ntodos os testes passaram")
    return 1 if falhas else 0


if __name__ == "__main__":
    url = sys.argv[sys.argv.index("--postgres") + 1] if "--postgres" in sys.argv else None
    sys.exit(main(url))
