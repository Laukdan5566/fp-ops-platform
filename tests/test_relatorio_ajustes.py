"""Telas de ajuste do relatorio: expediente, papel dos links, nome/tipo das redes e observacoes. So admin; erro nao grava nada; muda o relatorio."""
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet

temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-ajustes-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db import get_db  # noqa: E402
from main import app  # noqa: E402
from relatorio_dados import coletar_dados  # noqa: E402
from sessao import hash_password  # noqa: E402

db = get_db()
fw = db.execute("INSERT INTO pfsense_firewalls (name, address, username_enc, host_key_fingerprint, active) VALUES ('Cliente X', '192.0.2.9', 'x', 'fp', 1)").lastrowid
l1 = db.execute("INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active, preferred) VALUES (?, 'NWT', 'NWT', 'wan', 'igb0', 'WAN_NWT', 1, 0)", (fw,)).lastrowid
l2 = db.execute("INSERT INTO pfsense_links (firewall_id, name, provider, interface_key, device_name, gateway_name, active, preferred) VALUES (?, 'EXOS', 'EXOS', 'opt1', 'igb1', 'WAN_EXOS', 1, 1)", (fw,)).lastrowid
r1 = db.execute("INSERT INTO pfsense_networks (firewall_id, interface_key, name, kind, cidr, vlan) VALUES (?, 'lan', 'LAN', 'cabeada', '10.0.0.0/24', NULL)", (fw,)).lastrowid
r2 = db.execute("INSERT INTO pfsense_networks (firewall_id, interface_key, name, kind, cidr, vlan) VALUES (?, 'opt2', 'OPT2', 'cabeada', '10.0.1.0/24', 10)", (fw,)).lastrowid
adm = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('adm', ?, 'admin', 1)", (hash_password("x"),)).lastrowid
ope = db.execute("INSERT INTO usuarios (username, senha_hash, tipo, ativo) VALUES ('ope', ?, 'operador', 1)", (hash_password("x"),)).lastrowid
for uid, nome, sid in ((adm, "adm", "s1"), (ope, "ope", "s2")):
    db.execute("INSERT INTO user_sessions (session_id, user_id, username, created_at, last_seen, ativo) VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)", (sid, uid, nome))
db.commit()
db.close()

url = f"/pfsense/{fw}/relatorio/ajustes"
anonimo = app.test_client()
assert anonimo.get(url).status_code == 302 and anonimo.post(url, data={}).status_code == 302

operador = app.test_client()
with operador.session_transaction() as s:
    s.update(user_id=ope, username="ope", tipo="operador", session_id="s2", helpdesk_csrf_token="tok")
_g, _p = operador.get(url).status_code, operador.post(url, data={"_csrf_token": "tok", "expediente_inicio": "9", "expediente_fim": "17"}).status_code
assert _g == 403 and _p == 403, (_g, _p)

http = app.test_client()
with http.session_transaction() as s:
    s.update(user_id=adm, username="adm", tipo="admin", session_id="s1", helpdesk_csrf_token="tok")
pagina = http.get(url)
texto = pagina.get_data(as_text=True)
assert pagina.status_code == 200 and "Ajustes do relatório de internet" in texto and "Cliente X" in texto
assert 'name="expediente_inicio"' in texto and f'name="role_{l1}"' in texto and f'name="rede_nome_{r1}"' in texto
assert http.get("/pfsense/99999/relatorio/ajustes").status_code == 404

valido = {
    "_csrf_token": "tok", "expediente_inicio": "9", "expediente_fim": "17", "report_notes": "NWT com upload baixo desde a instalação.\nChamado aberto.",
    f"role_{l1}": "principal", f"role_{l2}": "reserva",
    f"rede_nome_{r1}": "Rede principal (cabeada)", f"rede_tipo_{r1}": "cabeada", f"rede_incluir_{r1}": "on",
    f"rede_nome_{r2}": "Wi-Fi Clientes", f"rede_tipo_{r2}": "wifi", f"rede_incluir_{r2}": "on",
}

# sem o token do formulario, a protecao global barra (e nada e gravado)
assert http.post(url, data={k: v for k, v in valido.items() if k != "_csrf_token"}).status_code == 400

# erros: nada e gravado
db = get_db()
def estado():
    d = get_db()
    try:
        f = d.execute("SELECT report_expediente, report_notes FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone()
        return (f["report_expediente"], f["report_notes"], d.execute("SELECT role FROM pfsense_links WHERE id=?", (l1,)).fetchone()["role"],
                d.execute("SELECT name FROM pfsense_networks WHERE id=?", (r1,)).fetchone()["name"])
    finally:
        d.close()
db.close()
antes = estado()
for alteracao, trecho in (
    ({"expediente_inicio": "18", "expediente_fim": "8"}, "começar antes de terminar"),
    ({"expediente_inicio": "abc"}, "números inteiros"),
    ({"expediente_fim": "25"}, "começar antes de terminar"),
    ({f"role_{l2}": "principal"}, "Só um link"),
    ({f"role_{l1}": "chefe"}, "Papel de link inválido"),
    ({f"rede_tipo_{r1}": "satelite"}, "Tipo de rede inválido"),
    ({f"rede_nome_{r1}": "  "}, "precisa de um nome"),
    ({"report_notes": "x" * 1501}, "1.500"),
):
    r = http.post(url, data={**valido, **alteracao})
    corpo = r.get_data(as_text=True)
    assert r.status_code == 400 and trecho in corpo, (alteracao, r.status_code, trecho, corpo[corpo.find("alert-danger") - 20: corpo.find("alert-danger") + 220])
assert estado() == antes, "um pedido invalido gravou alguma coisa"

# salvar de verdade
r = http.post(url, data=valido)
assert r.status_code == 302 and r.headers["Location"].endswith("?salvo=1"), r.status_code
assert "Ajustes salvos" in http.get(url + "?salvo=1").get_data(as_text=True)
depois = estado()
assert depois == ("9-17", "NWT com upload baixo desde a instalação.\nChamado aberto.", "principal", "Rede principal (cabeada)"), depois
db = get_db()
assert db.execute("SELECT kind FROM pfsense_networks WHERE id=?", (r2,)).fetchone()["kind"] == "wifi"
assert db.execute("SELECT role FROM pfsense_links WHERE id=?", (l2,)).fetchone()["role"] == "reserva"

# efeito no relatorio: expediente, papel (NWT principal e EXOS preferencial => "fora do padrao") e observacoes
dados = coletar_dados(db, fw, datetime(2026, 10, 26), datetime(2026, 10, 30, 12, 0))
assert dados["expediente"] == (9, 17) and dados["observacoes"] == ["NWT com upload baixo desde a instalação.", "Chamado aberto."], dados
assert {l["nome"]: l["funcao"] for l in dados["links"]} == {"NWT": "principal", "EXOS": "reserva"}
assert [l["nome"] for l in dados["links"] if l["preferencial"]] == ["EXOS"]
db.close()
pagina = http.get(f"/pfsense/{fw}/relatorio-tecnico?inicio=2026-10-26&fim=2026-10-30").get_data(as_text=True)
assert "Observações do técnico" in pagina and "Chamado aberto." in pagina and "Link preferencial fora do padrão" in pagina

# desmarcar "incluir" tira a rede do relatorio; vazio volta ao automatico
http.post(url, data={**{k: v for k, v in valido.items() if k != f"rede_incluir_{r1}"}, f"role_{l1}": "", f"role_{l2}": "", "report_notes": ""})
db = get_db()
assert db.execute("SELECT include_in_report FROM pfsense_networks WHERE id=?", (r1,)).fetchone()["include_in_report"] == 0
assert db.execute("SELECT role FROM pfsense_links WHERE id=?", (l1,)).fetchone()["role"] is None
assert db.execute("SELECT report_notes FROM pfsense_firewalls WHERE id=?", (fw,)).fetchone()["report_notes"] is None
db.close()
print("OK: ajustes do relatorio (so admin, valida sem gravar, salva e muda o relatorio)")
