"""Retencao no FTP: so apaga backups de firewall (nome do monitor) acima do prazo; nunca outro arquivo.

O FTP guarda tambem backups de clientes; a limpeza do monitor nao pode encostar neles.
Rodar: PYTHONPATH=app:worker python tests/test_pfsense_ftp_retention.py
"""
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-ftp-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

import pfsense_storage as ps
from db import get_db, init_db


def nome(dias, hash12="a" * 12, firewall="Firewall-Teste"):
    quando = (datetime.now() - timedelta(days=dias)).strftime("%Y%m%d-%H%M%S")
    return f"{firewall}-pfsense-{quando}-{hash12}.xml.fernet"


class FtpFalso:
    def __init__(self, arquivos):
        self.arquivos = list(arquivos)
        self.apagados = []

    def cwd(self, _parte):
        pass

    def mkd(self, _parte):
        pass

    def mlsd(self):
        return iter([(n, {}) for n in self.arquivos])

    def delete(self, n):
        self.arquivos.remove(n)
        self.apagados.append(n)

    def quit(self):
        pass


antigo, antigo2, recente = nome(100, "b" * 12), nome(91, "c" * 12, "Outro-FW"), nome(10, "d" * 12)
alheios = ["ROTA_ALTERDATA001.zip", "foto-2006.jpg", "pfsense-semprefixo.txt", "Firewall-pfsense-20200101-000000-xyz.xml.fernet"]
ftp = FtpFalso([antigo, antigo2, recente] + alheios)
ps._connect = lambda storage: ftp

storage = {"retention_days": 90, "remote_dir": "/ftp/___FIREWALLS"}
r = ps.prune_remote_backups(storage)
assert r["status"] == "success", r
assert sorted(ftp.apagados) == sorted([antigo, antigo2]), ftp.apagados
assert recente in ftp.arquivos
assert all(a in ftp.arquivos for a in alheios), "nunca apagar arquivo que nao e backup de firewall do monitor"

# cleanup_storage: so roda 1x/24 h, atualiza o status e marca como expirado o que saiu do FTP
init_db()
db = get_db()
fw = db.execute(
    "INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint) VALUES ('Firewall Teste', '192.0.2.40', 'x', 'fp')"
).lastrowid
db.execute(
    "INSERT INTO pfsense_backups (firewall_id, created_at, config_hash, file_path, status, remote_status, remote_path) "
    "VALUES (?, '2026-01-01 00:00:00', 'h', '/x', 'success', 'success', ?)",
    (fw, "/ftp/___FIREWALLS/" + antigo),
)
db.execute(
    "INSERT INTO pfsense_storage (id, protocol, host, port, username_enc, password_enc, remote_dir, active, retention_enabled, retention_days) "
    "VALUES (1, 'ftp', '192.0.2.50', 21, 'x', 'x', '/ftp/___FIREWALLS', 1, 1, 90)"
)
db.commit()
ftp2 = FtpFalso([antigo, recente] + alheios)
ps._connect = lambda storage: ftp2
res = ps.cleanup_storage(db, force=False)
db.commit()
assert res["status"] == "success" and res["deleted"] == 1, res
row = db.execute("SELECT remote_status, remote_path FROM pfsense_backups WHERE firewall_id=?", (fw,)).fetchone()
assert row["remote_status"] == "expired" and row["remote_path"] is None, dict(row)
assert ps.cleanup_storage(db, force=False)["status"] == "not_due", "segunda chamada no mesmo dia nao limpa de novo"
db.execute("UPDATE pfsense_storage SET retention_enabled=0 WHERE id=1")
db.commit()
assert ps.cleanup_storage(db, force=True)["status"] == "disabled"
db.close()
print("OK: retencao no FTP so apaga backup de firewall vencido")
