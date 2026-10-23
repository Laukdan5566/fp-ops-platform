"""Congela a lista de rotas (URL + metodos): reorganizar o main.py em modulos nao pode perder nem mudar rota.

Para aceitar uma mudanca de proposito:  python tests/test_rotas.py --atualizar
"""
import os
import sys
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

raiz = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(raiz / "app"))
temp_dir = Path(tempfile.mkdtemp(prefix="fp-ops-rotas-test-"))
key_file = temp_dir / "credential.keys"
key_file.write_bytes(Fernet.generate_key() + b"\n")
os.environ["SECRET_KEY"] = "test-only-session-secret"
os.environ["DATABASE_URL"] = ""
os.environ["DB_PATH"] = str(temp_dir / "test.db")
os.environ["CREDENTIAL_KEY_FILE"] = str(key_file)

from main import app

atuais = sorted(
    f"{','.join(sorted(m for m in regra.methods if m not in ('HEAD', 'OPTIONS')))} {regra.rule}"
    for regra in app.url_map.iter_rules()
    if regra.endpoint != "static"
)
arquivo = raiz / "tests" / "rotas_esperadas.txt"
if "--atualizar" in sys.argv:
    arquivo.write_text("\n".join(atuais) + "\n", encoding="utf-8")
    print(f"{len(atuais)} rotas gravadas")
    sys.exit(0)

esperadas = [linha for linha in arquivo.read_text(encoding="utf-8").splitlines() if linha]
faltando = sorted(set(esperadas) - set(atuais))
novas = sorted(set(atuais) - set(esperadas))
assert not faltando and not novas, f"rotas sumiram: {faltando}\nrotas novas: {novas}\n(se for proposital: python tests/test_rotas.py --atualizar)"
assert len(atuais) == len(esperadas)
print(f"OK: {len(atuais)} rotas iguais ao esperado")
