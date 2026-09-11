import ftplib
import os
import re
import ssl
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

from secret_store import decrypt_secret


FTP_TIMEOUT_SECONDS = int(os.getenv("PFSENSE_FTP_TIMEOUT_SECONDS", "25"))
BACKUP_FILENAME_RE = re.compile(
    r"(?:^|-)pfsense-(?P<timestamp>\d{8}-\d{6})-[0-9a-f]{12}\.xml\.fernet$"
)


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_remote_dir(value):
    value = (value or "/pfsense-backups").strip().replace("\\", "/")
    if not value.startswith("/"):
        value = "/" + value
    parts = [part for part in value.split("/") if part]
    if any(part in (".", "..") for part in parts):
        raise ValueError("Diretorio remoto invalido.")
    if any(not re.fullmatch(r"[A-Za-z0-9_. -]+", part) for part in parts):
        raise ValueError("Diretorio remoto contem caracteres nao permitidos.")
    return "/" + "/".join(parts)


def _connect(storage):
    protocol = (storage["protocol"] or "ftps").lower()
    host = (storage["host"] or "").strip()
    port = int(storage["port"] or 21)
    username = decrypt_secret(storage["username_enc"])
    password = decrypt_secret(storage["password_enc"])
    if protocol == "ftps":
        context = ssl.create_default_context()
        if not storage["verify_tls"]:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        ftp = ftplib.FTP_TLS(context=context, timeout=FTP_TIMEOUT_SECONDS)
    elif protocol == "ftp":
        ftp = ftplib.FTP(timeout=FTP_TIMEOUT_SECONDS)
    else:
        raise ValueError("Protocolo de armazenamento invalido.")
    ftp.connect(host, port, timeout=FTP_TIMEOUT_SECONDS)
    ftp.login(username, password)
    ftp.set_pasv(bool(storage["passive"]))
    if protocol == "ftps":
        ftp.prot_p()
    return ftp


def _ensure_directory(ftp, remote_dir):
    directory = normalize_remote_dir(remote_dir)
    ftp.cwd("/")
    for part in PurePosixPath(directory).parts:
        if part == "/":
            continue
        try:
            ftp.cwd(part)
        except ftplib.error_perm as exc:
            if not str(exc).startswith("550"):
                raise
            ftp.mkd(part)
            ftp.cwd(part)
    return directory


def test_storage_connection(storage):
    ftp = None
    try:
        ftp = _connect(storage)
        directory = _ensure_directory(ftp, storage["remote_dir"])
        ftp.voidcmd("NOOP")
        return {"status": "success", "remote_dir": directory}
    except Exception as exc:
        return {"status": "error", "error": str(exc)[:500]}
    finally:
        if ftp:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass


def upload_backup(storage, firewall, backup_path):
    path = Path(backup_path)
    if not path.is_file():
        return {"status": "error", "error": "Arquivo local de backup indisponivel."}
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", firewall["name"]).strip("-") or "pfsense"
    remote_name = f"{safe_name}-{path.name}"
    temporary_name = remote_name + ".part"
    ftp = None
    try:
        ftp = _connect(storage)
        directory = _ensure_directory(ftp, storage["remote_dir"])
        try:
            ftp.delete(temporary_name)
        except ftplib.error_perm:
            pass
        with path.open("rb") as handle:
            ftp.storbinary(f"STOR {temporary_name}", handle, blocksize=1024 * 128)
        ftp.rename(temporary_name, remote_name)
        return {
            "status": "success",
            "remote_path": f"{directory.rstrip('/')}/{remote_name}",
            "uploaded_at": now_text(),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)[:500]}
    finally:
        if ftp:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass


def upload_backup_from_db(db, firewall, backup_path):
    storage = db.execute(
        "SELECT * FROM pfsense_storage WHERE id=1 AND active=1"
    ).fetchone()
    if not storage:
        return {"status": "disabled"}
    return upload_backup(storage, firewall, backup_path)


def prune_remote_backups(storage):
    retention_days = max(1, min(3650, int(storage["retention_days"] or 90)))
    cutoff = datetime.now() - timedelta(days=retention_days)
    ftp = None
    deleted_paths = []
    examined = 0
    try:
        ftp = _connect(storage)
        directory = _ensure_directory(ftp, storage["remote_dir"])
        try:
            names = [name for name, _facts in ftp.mlsd()]
        except (AttributeError, ftplib.error_perm, ftplib.error_temp):
            names = [PurePosixPath(name).name for name in ftp.nlst()]
        for name in names:
            safe_name = PurePosixPath(name).name
            match = BACKUP_FILENAME_RE.search(safe_name)
            if not match:
                continue
            examined += 1
            created_at = datetime.strptime(match.group("timestamp"), "%Y%m%d-%H%M%S")
            if created_at >= cutoff:
                continue
            ftp.delete(safe_name)
            deleted_paths.append(f"{directory.rstrip('/')}/{safe_name}")
        return {
            "status": "success", "deleted": len(deleted_paths),
            "examined": examined, "deleted_paths": deleted_paths,
        }
    except Exception as exc:
        return {
            "status": "error", "error": str(exc)[:500], "deleted": len(deleted_paths),
            "examined": examined, "deleted_paths": deleted_paths,
        }
    finally:
        if ftp:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass


def cleanup_storage(db, force=False):
    storage = db.execute("SELECT * FROM pfsense_storage WHERE id=1").fetchone()
    if not storage or not storage["active"] or not storage["retention_enabled"]:
        return {"status": "disabled", "deleted": 0}
    if not force and storage["last_cleanup_at"]:
        try:
            last_cleanup = datetime.strptime(str(storage["last_cleanup_at"])[:19], "%Y-%m-%d %H:%M:%S")
            if datetime.now() - last_cleanup < timedelta(hours=24):
                return {"status": "not_due", "deleted": 0}
        except ValueError:
            pass
    result = prune_remote_backups(storage)
    finished_at = now_text()
    for remote_path in result.get("deleted_paths", []):
        db.execute(
            """
            UPDATE pfsense_backups
            SET remote_status='expired', remote_path=NULL, remote_error=NULL
            WHERE remote_path=?
            """,
            (remote_path,),
        )
    db.execute(
        """
        UPDATE pfsense_storage
        SET last_cleanup_at=?, last_cleanup_status=?, last_cleanup_error=?,
            last_cleanup_deleted=?, updated_at=?
        WHERE id=1
        """,
        (
            finished_at, result["status"], result.get("error"),
            result.get("deleted", 0), finished_at,
        ),
    )
    return result


def run_storage_cleanup():
    from db import get_db

    db = get_db()
    try:
        result = cleanup_storage(db, force=False)
        db.commit()
        return result
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
