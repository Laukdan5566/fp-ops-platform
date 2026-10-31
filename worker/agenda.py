"""Agenda do worker: cada grupo de trabalho roda no seu proprio laco (thread), com seu proprio intervalo.

Antes tudo rodava em fila num laco so: um firewall lento atrasava o e-mail, os alertas e a fila de WhatsApp, e um erro no IMAP
pulava o resto do ciclo. Agora uma tarefa lenta ou com erro so atrasa a si mesma. Os passos de UMA tarefa continuam em fila
(ex.: checar firewalls e depois testar links), e um erro em um passo nao impede os seguintes.
"""
import logging
import threading
import time
from datetime import datetime

log = logging.getLogger("worker")

AVISO_PASSO_LENTO_S = 120     # passo que demorar mais que isso aparece no log
TAREFA_PARADA_FATOR = 4       # tarefa que nao termina um ciclo em N x o intervalo (minimo 10 min) e considerada parada


class Tarefa:
    def __init__(self, nome, passos, intervalo_s):
        self.nome = nome
        self.passos = list(passos)          # lista de (rotulo, funcao sem argumentos)
        self.intervalo_s = intervalo_s
        self.ultimo_ciclo = None            # time.monotonic() do fim do ultimo ciclo
        self.iniciada_em = time.monotonic()
        self.ciclos = 0
        self.erros = 0
        self.ultimo_ciclo_em = None         # horario local, para mostrar na tela de saude
        self.ultimo_erro = None
        self.ultimo_erro_em = None

    def rodar_ciclo(self):
        for rotulo, passo in self.passos:
            inicio = time.monotonic()
            try:
                passo()
            except Exception as exc:
                self.erros += 1
                self.ultimo_erro = f"{rotulo}: {exc}"[:300]
                self.ultimo_erro_em = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.exception("Tarefa %s, passo %s falhou", self.nome, rotulo)
            duracao = time.monotonic() - inicio
            if duracao > AVISO_PASSO_LENTO_S:
                log.warning("Tarefa %s, passo %s levou %.0f s", self.nome, rotulo, duracao)
        self.ciclos += 1
        self.ultimo_ciclo = time.monotonic()
        self.ultimo_ciclo_em = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def parada(self, agora):
        limite = max(600, self.intervalo_s * TAREFA_PARADA_FATOR)
        referencia = self.ultimo_ciclo if self.ultimo_ciclo is not None else self.iniciada_em
        return agora - referencia > limite


def laco(tarefa, parar, registrar=None):
    tarefa.iniciada_em = time.monotonic()
    while not parar.is_set():
        inicio = time.monotonic()
        tarefa.rodar_ciclo()
        if registrar:
            try:
                registrar(tarefa)
            except Exception:
                log.exception("Nao consegui registrar o estado da tarefa %s", tarefa.nome)
        # se o ciclo demorou mais que o intervalo, ainda assim respira antes do proximo
        parar.wait(max(min(1.0, tarefa.intervalo_s), tarefa.intervalo_s - (time.monotonic() - inicio)))


def iniciar(tarefas, parar=None, registrar=None):
    """Sobe uma thread por tarefa. `registrar(tarefa)` e chamado ao fim de cada ciclo. Devolve (threads, evento_de_parada)."""
    parar = parar or threading.Event()
    threads = []
    for tarefa in tarefas:
        tarefa.iniciada_em = time.monotonic()
        thread = threading.Thread(target=laco, args=(tarefa, parar, registrar), name=f"tarefa-{tarefa.nome}", daemon=True)
        thread.start()
        threads.append(thread)
    return threads, parar


def vigiar(tarefas, parar, verificar_a_cada_s=30):
    """Fica no thread principal: avisa no log quando uma tarefa para de completar ciclos (travou numa conexao, por exemplo)."""
    avisadas = set()
    while not parar.wait(verificar_a_cada_s):
        agora = time.monotonic()
        for tarefa in tarefas:
            if tarefa.parada(agora):
                if tarefa.nome not in avisadas:
                    log.error("Tarefa %s nao completa um ciclo ha mais de %.0f s (travada?)", tarefa.nome, agora - (tarefa.ultimo_ciclo or tarefa.iniciada_em))
                    avisadas.add(tarefa.nome)
            else:
                avisadas.discard(tarefa.nome)
