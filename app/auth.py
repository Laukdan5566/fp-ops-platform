"""Decoradores de acesso compartilhados pelo painel (main.py) e pelo helpdesk (helpdesk.py)."""
from functools import wraps

from flask import abort, make_response, redirect, session


def _negado():
    abort(make_response("Acesso negado", 403))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("tipo") != "admin":
            _negado()
        return view(*args, **kwargs)
    return wrapped


def support_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("tipo") not in ("admin", "operador"):
            _negado()
        return view(*args, **kwargs)
    return wrapped
