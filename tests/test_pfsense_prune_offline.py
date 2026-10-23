"""Firewall fora do ar tambem precisa perder os backups locais mais velhos que a retencao.

Antes, prune_backups so rodava depois de uma checagem bem-sucedida: firewall que parava de responder
(ex.: FAE AUTO PECAS, timeout desde 21/09) ficava com backups de 60 dias na pasta e no banco.
Rodar: PYTHONPATH=app:worker python tests/test_pfsense_prune_offline.py
"""
import os
import socket
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-prune-test-"))
backup_dir = temp_dir / "pfsense-backups"
backup_dir.mkdir()
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["PFSENSE_BACKUP_DIR"] = str(backup_dir)

import pfsense_agent
from db import get_db, init_db

pfsense_agent.BACKUP_ROOT = backup_dir


def conectar_falha(_firewall):
    raise socket.timeout("timed out")


pfsense_agent.connect_firewall = conectar_falha

init_db()
db = get_db()
firewall_id = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active, last_status, backup_retention_days) "
    "VALUES ('FW fora do ar', '192.0.2.20', 'x', 'fp', 1, 'error', 30)"
).lastrowid


def novo_backup(dias):
    pasta = backup_dir / str(firewall_id)
    pasta.mkdir(exist_ok=True)
    arquivo = pasta / f"pfsense-{dias}d.xml.fernet"
    arquivo.write_bytes(b"x")
    criado = (datetime.now() - timedelta(days=dias)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO pfsense_backups (firewall_id, created_at, config_hash, file_path, size_bytes, status) VALUES (?, ?, 'h', ?, 1, 'success')",
        (firewall_id, criado, str(arquivo)),
    )
    return arquivo


velho = novo_backup(90)
velho2 = novo_backup(61)
ultimo = novo_backup(45)  # o mais novo e a unica copia boa do firewall: nunca some, mesmo acima da retencao
db.commit()
firewall = dict(db.execute("SELECT * FROM pfsense_firewalls WHERE id=?", (firewall_id,)).fetchone())
db.close()

resultado = pfsense_agent.run_firewall_check(firewall)
assert resultado["status"] == "error", resultado

db = get_db()
restantes = [r["file_path"] for r in db.execute("SELECT file_path FROM pfsense_backups WHERE firewall_id=?", (firewall_id,)).fetchall()]
db.close()

assert restantes == [str(ultimo)], restantes
assert ultimo.is_file(), "o backup mais novo precisa ser preservado, mesmo acima da retencao"
assert not velho.exists() and not velho2.exists(), "arquivos acima da retencao deveriam ter sido apagados mesmo com o firewall fora do ar"
print("OK: firewall fora do ar apaga backups acima da retencao e guarda o mais recente")
