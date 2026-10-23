"""Funcoes puras de data/hora e formatacao usadas pelo painel e pelos modulos de rotas."""
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import hashlib
import re


def parse_data(valor):
    if not valor:
        return None

    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(valor)[:19], formato)
        except ValueError:
            pass

    return None


def agora_sql():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def formatar_idade(minutos):
    if minutos is None:
        return "-"
    if minutos < 60:
        return f"{minutos} min"

    horas = minutos // 60
    mins = minutos % 60
    if horas < 48:
        return f"{horas}h {mins}min"

    dias = horas // 24
    horas_restantes = horas % 24
    return f"{dias}d {horas_restantes}h"


def enriquecer_uptime_pfsense(metrics, checked_at=None):
    result = dict(metrics or {})
    try:
        uptime_seconds = max(0, int(result.get("UPTIME_SECONDS")))
    except (TypeError, ValueError):
        result["UPTIME_LABEL"] = "-"
        result["BOOT_AT"] = None
        result["RECENT_REBOOT"] = False
        return result
    if uptime_seconds > 10 * 365 * 24 * 60 * 60:
        result["UPTIME_LABEL"] = "-"
        result["BOOT_AT"] = None
        result["RECENT_REBOOT"] = False
        return result

    result["UPTIME_LABEL"] = (
        "< 1 min" if uptime_seconds < 60 else formatar_idade(uptime_seconds // 60)
    )
    collected_at = parse_data(checked_at)
    if collected_at:
        boot_utc = collected_at.replace(tzinfo=timezone.utc) - timedelta(seconds=uptime_seconds)
        result["BOOT_AT"] = boot_utc.astimezone(
            ZoneInfo("America/Sao_Paulo")
        ).strftime("%d/%m/%Y %H:%M")
    else:
        result["BOOT_AT"] = None
    result["RECENT_REBOOT"] = uptime_seconds < 24 * 60 * 60
    return result


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_conteudo(texto):
    return hashlib.sha256((texto or "").encode()).hexdigest()


def normalizar_servidor(nome):
    return re.sub(r"\s+", "_", (nome or "").strip().upper())
