"""Limite de tentativas de senha no login: bloqueia por usuario e por IP durante uma janela deslizante.

Guarda so as FALHAS (tabela login_falhas, compartilhada pelos 2 processos do gunicorn). Quando o numero de falhas na janela
chega ao limite, o login fica bloqueado ate a falha mais antiga sair da janela. Login correto limpa as falhas do usuario.
"""
import ipaddress
from datetime import datetime, timedelta

JANELA_MIN = 15
LIMITE_POR_USUARIO = 10   # falhas de qualquer origem para o mesmo usuario
LIMITE_POR_IP = 20        # falhas da mesma origem (qualquer usuario)
GUARDAR_DIAS = 2


def ip_do_cliente(request):
    """O painel fica atras de um proxy na rede interna: ai o IP real e o ultimo item de X-Forwarded-For (o que o proxy viu).
    Vindo direto, vale o endereco da conexao. A origem so reforca o limite por usuario, que nao depende de cabecalho."""
    origem = request.remote_addr or ""
    try:
        interno = ipaddress.ip_address(origem).is_private
    except ValueError:
        interno = False
    encaminhado = request.headers.get("X-Forwarded-For", "")
    if interno and encaminhado:
        ultimo = encaminhado.split(",")[-1].strip()
        try:
            return str(ipaddress.ip_address(ultimo))
        except ValueError:
            pass
    return origem


def _texto(momento):
    return momento.strftime("%Y-%m-%d %H:%M:%S")


def _segundos_ate_liberar(db, coluna, valor, limite, agora):
    """0 se nao esta bloqueado; senao, quantos segundos faltam para a falha que fecha o limite sair da janela."""
    if not valor:
        return 0
    corte = _texto(agora - timedelta(minutes=JANELA_MIN))
    # coluna vem das constantes abaixo, nunca de entrada do usuario
    linhas = db.execute(f"SELECT falhou_em FROM login_falhas WHERE {coluna}=? AND falhou_em>=? ORDER BY falhou_em", (valor, corte)).fetchall()
    if len(linhas) < limite:
        return 0
    decisiva = datetime.strptime(linhas[len(linhas) - limite]["falhou_em"], "%Y-%m-%d %H:%M:%S")
    return max(1, int((decisiva + timedelta(minutes=JANELA_MIN) - agora).total_seconds()))


def segundos_bloqueado(db, username, ip, agora=None):
    agora = agora or datetime.now()
    return max(
        _segundos_ate_liberar(db, "username", (username or "").lower(), LIMITE_POR_USUARIO, agora),
        _segundos_ate_liberar(db, "ip", ip, LIMITE_POR_IP, agora),
    )


def registrar_falha(db, username, ip, agora=None):
    agora = agora or datetime.now()
    db.execute("INSERT INTO login_falhas (username, ip, falhou_em) VALUES (?, ?, ?)", ((username or "").lower(), ip, _texto(agora)))
    db.execute("DELETE FROM login_falhas WHERE falhou_em<?", (_texto(agora - timedelta(days=GUARDAR_DIAS)),))
    db.commit()


def limpar_falhas_do_usuario(db, username):
    db.execute("DELETE FROM login_falhas WHERE username=?", ((username or "").lower(),))
    db.commit()


def mensagem_bloqueio(segundos):
    minutos = max(1, -(-segundos // 60))
    return f"Muitas tentativas de login. Tente novamente em {minutos} minuto{'s' if minutos != 1 else ''}."
