"""Migracoes numeradas: cada uma roda uma vez, em ordem; falha para na que quebrou e nao repete as anteriores."""
import os
import tempfile
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-migracoes-test-"))
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")

from db import aplicar_migracoes, get_db, init_db  # noqa: E402

init_db()
chamadas = []
def cria_tabela(cur):
    chamadas.append("a")
    cur.execute("CREATE TABLE teste_migracao (id INTEGER)")
def quebra(cur):
    raise RuntimeError("migracao ruim")

migracoes = [(102, "segunda", lambda cur: chamadas.append("b")), (101, "primeira", cria_tabela)]
aplicar_migracoes(migracoes)
aplicar_migracoes(migracoes)  # repetir nao reaplica
assert chamadas == ["a", "b"], chamadas  # rodou em ordem de versao, uma vez cada
db = get_db()
assert [r["versao"] for r in db.execute("SELECT versao FROM schema_migrations ORDER BY versao").fetchall()] == [1, 101, 102]  # a 1 e a real (worker_tarefas), aplicada pelo init_db
db.close()

try:
    aplicar_migracoes(migracoes + [(103, "ruim", quebra), (104, "depois", lambda cur: chamadas.append("d"))])
    raise AssertionError("era para falhar")
except RuntimeError:
    pass
assert chamadas == ["a", "b"], "a 104 nao pode rodar depois da 103 que falhou"
init_db()  # o arranque normal (lista real, vazia) segue funcionando com a tabela ja criada
print("OK: migracoes numeradas")
