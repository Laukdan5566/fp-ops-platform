"""Retencao dos logs (retencao.py): compacta log antigo, mantem o recente, registra a execucao e so roda 1x por dia no modo automatico."""
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-ret-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "")
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from db import get_db, init_db
from retencao import executar_retencao, retention_config, talvez_executar_retencao_automatica

init_db()
db = get_db()
retention_config(db)
velho = (datetime.now() - timedelta(days=200)).strftime("%Y-%m-%d %H:%M:%S")
novo = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S")
db.execute("INSERT INTO logs_email (servidor_log, status, data_email, conteudo_raw, message_id) VALUES ('S', 'success', ?, 'texto velho', 'm1')", (velho,))
db.execute("INSERT INTO logs_email (servidor_log, status, data_email, conteudo_raw, message_id) VALUES ('S', 'success', ?, 'texto novo', 'm2')", (novo,))
db.commit()
db.close()

stats, backup = executar_retencao(manual=True)
assert stats["logs_compactados"] == 1, stats
assert Path(backup).is_file(), "deve guardar copia do banco antes de limpar"

db = get_db()
textos = {r["message_id"]: r["conteudo_raw"] for r in db.execute("SELECT message_id, conteudo_raw FROM logs_email").fetchall()}
assert textos == {"m1": None, "m2": "texto novo"}, textos
runs = db.execute("SELECT status, detail FROM maintenance_runs WHERE action='retention'").fetchall()
assert [r["status"] for r in runs] == ["success"], [dict(r) for r in runs]
db.close()

# automatico: ja houve execucao hoje -> nao roda de novo
talvez_executar_retencao_automatica()
db = get_db()
assert db.execute("SELECT COUNT(*) AS c FROM maintenance_runs WHERE action='retention'").fetchone()["c"] == 1
db.close()
print("OK: retencao dos logs")
