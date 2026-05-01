# =====================================================
# IMPORTS GENERALES
# =====================================================
import os
import sqlite3
import bcrypt
import zipfile
import tempfile
import shutil
import click
import secrets
from datetime import datetime, timedelta
from io import BytesIO

from dotenv import load_dotenv

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, g, send_file
)

from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.utils import secure_filename

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side


# =====================================================
# CARGA DE VARIABLES DE ENTORNO
# =====================================================
load_dotenv()


# =====================================================
# CONFIGURACIÓN PRINCIPAL DE FLASK
# =====================================================
app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Falta configurar SECRET_KEY en el archivo .env o variables de entorno.")


# =====================================================
# PROTECCIÓN CSRF
# =====================================================
csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("La sesión del formulario expiró o no es válida. Intenta nuevamente.", "warning")
    return redirect(request.referrer or url_for("inicio"))


# =====================================================
# BASE DE DATOS
# =====================================================
database_path = os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "aserve.db"))

if not os.path.isabs(database_path):
    database_path = os.path.join(os.getcwd(), database_path)

app.config["DATABASE"] = database_path


# =====================================================
# SUBIDA DE IMÁGENES
# =====================================================
upload_folder = os.environ.get("UPLOAD_FOLDER", os.path.join("static", "uploads"))
app.config["UPLOAD_FOLDER"] = upload_folder
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "webp"}

# Límite máximo de subida: 2 MB
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


# =====================================================
# SEGURIDAD DE COOKIES
# =====================================================
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"


# =====================================================
# FUNCIONES DE BASE DE DATOS
# =====================================================
def get_db():
    if "db" not in g:
        db_folder = os.path.dirname(app.config["DATABASE"])
        os.makedirs(db_folder, exist_ok=True)

        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


# =====================================================
# FUNCIÓN AUXILIAR: ASEGURAR ESTRUCTURA ADICIONAL
# - Crea audit_logs si no existe
# - Agrega password_temporal si no existe en users
# =====================================================
def ensure_app_schema(db):
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fecha TEXT NOT NULL,
                admin_id INTEGER,
                admin_nombre TEXT,
                accion TEXT NOT NULL,
                detalle TEXT
            )
        """)

        columnas_users = db.execute("PRAGMA table_info(users)").fetchall()
        nombres_columnas = [c["name"] for c in columnas_users]

        if nombres_columnas and "password_temporal" not in nombres_columnas:
            db.execute("ALTER TABLE users ADD COLUMN password_temporal INTEGER DEFAULT 0")

        db.commit()

    except sqlite3.OperationalError as e:
        print("Aviso al verificar estructura:", e)


# =====================================================
# FUNCIÓN AUXILIAR PARA VALIDAR IMÁGENES
# =====================================================
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


# =====================================================
# FUNCIÓN AUXILIAR: NORMALIZAR TEXTO
# =====================================================
def norm_text(value):
    value = (value or "").strip().lower()
    value = value.replace("é", "e")
    return value


# =====================================================
# FUNCIÓN AUXILIAR: VALIDAR CONTRASEÑAS
# =====================================================
def validar_contrasena_segura(password):
    errores = []

    if not password:
        errores.append("La contraseña no puede estar vacía.")
        return errores

    if len(password) < 8:
        errores.append("Debe tener al menos 8 caracteres.")

    if not any(c.isupper() for c in password):
        errores.append("Debe incluir al menos una letra mayúscula.")

    if not any(c.islower() for c in password):
        errores.append("Debe incluir al menos una letra minúscula.")

    if not any(c.isdigit() for c in password):
        errores.append("Debe incluir al menos un número.")

    return errores


# =====================================================
# FUNCIÓN AUXILIAR: REGISTRAR AUDITORÍA
# =====================================================
def registrar_auditoria(accion, detalle="", commit=False):
    try:
        db = get_db()

        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        admin_id = session.get("user_id")
        admin_nombre = session.get("nombre", "Sistema")

        db.execute(
            """
            INSERT INTO audit_logs (fecha, admin_id, admin_nombre, accion, detalle)
            VALUES (?, ?, ?, ?, ?)
            """,
            (fecha, admin_id, admin_nombre, accion, detalle)
        )

        if commit:
            db.commit()

    except Exception as e:
        print("Error registrando auditoría:", e)


# =====================================================
# COMANDO CLI: BACKUP DB
# Comando:
# flask --app app.py backup-db
# =====================================================
@app.cli.command("backup-db")
def backup_db_command():
    backup_folder = os.path.join(os.getcwd(), "backups")
    os.makedirs(backup_folder, exist_ok=True)

    fecha_backup = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_filename = f"respaldo_aserve_{fecha_backup}.zip"
    backup_path = os.path.join(backup_folder, backup_filename)

    with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        db_original_path = app.config["DATABASE"]

        if os.path.exists(db_original_path):
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_db:
                temp_db_path = temp_db.name

            try:
                source = sqlite3.connect(db_original_path)
                destination = sqlite3.connect(temp_db_path)

                with destination:
                    source.backup(destination)

                source.close()
                destination.close()

                zip_file.write(temp_db_path, arcname="database/aserve.db")

            finally:
                if os.path.exists(temp_db_path):
                    os.remove(temp_db_path)

        upload_folder_abs = app.config["UPLOAD_FOLDER"]

        if not os.path.isabs(upload_folder_abs):
            upload_folder_abs = os.path.join(os.getcwd(), upload_folder_abs)

        if os.path.exists(upload_folder_abs):
            for root, dirs, files in os.walk(upload_folder_abs):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, upload_folder_abs)
                    zip_file.write(file_path, arcname=os.path.join("uploads", relative_path))

        info = f"""RESPALDO ASERVE
Fecha de respaldo: {fecha_backup}

Contenido:
- database/aserve.db
- uploads/

Este respaldo fue generado desde comando CLI.
Guardar este archivo en un lugar seguro.
"""
        zip_file.writestr("LEEME_RESPALDO.txt", info)

    print("✅ Respaldo creado correctamente.")
    print(f"Archivo: {backup_path}")


# =====================================================
# COMANDO CLI: RESTAURAR RESPALDO
# Comando:
# flask --app app.py restore-backup "backups/respaldo_aserve_XXXX.zip"
# =====================================================
@app.cli.command("restore-backup")
@click.argument("zip_path")
def restore_backup_command(zip_path):
    if not os.path.exists(zip_path):
        print("❌ El archivo ZIP no existe.")
        print(f"Ruta recibida: {zip_path}")
        return

    if not zipfile.is_zipfile(zip_path):
        print("❌ El archivo indicado no es un ZIP válido.")
        return

    db_path = app.config["DATABASE"]
    db_folder = os.path.dirname(db_path)

    upload_folder_abs = app.config["UPLOAD_FOLDER"]

    if not os.path.isabs(upload_folder_abs):
        upload_folder_abs = os.path.join(os.getcwd(), upload_folder_abs)

    os.makedirs(db_folder, exist_ok=True)
    os.makedirs(upload_folder_abs, exist_ok=True)

    fecha_restore = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    backup_folder = os.path.join(os.getcwd(), "backups")
    os.makedirs(backup_folder, exist_ok=True)

    pre_backup_path = os.path.join(
        backup_folder,
        f"pre_restore_aserve_{fecha_restore}.zip"
    )

    print("🟡 Creando respaldo de emergencia antes de restaurar...")

    with zipfile.ZipFile(pre_backup_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        if os.path.exists(db_path):
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_db:
                temp_db_path = temp_db.name

            try:
                source = sqlite3.connect(db_path)
                destination = sqlite3.connect(temp_db_path)

                with destination:
                    source.backup(destination)

                source.close()
                destination.close()

                zip_file.write(temp_db_path, arcname="database/aserve.db")

            finally:
                if os.path.exists(temp_db_path):
                    os.remove(temp_db_path)

        if os.path.exists(upload_folder_abs):
            for root, dirs, files in os.walk(upload_folder_abs):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, upload_folder_abs)
                    zip_file.write(file_path, arcname=os.path.join("uploads", relative_path))

        info = f"""RESPALDO DE EMERGENCIA ASERVE
Fecha: {fecha_restore}

Este respaldo fue creado automáticamente antes de restaurar otro respaldo.

Contenido:
- database/aserve.db
- uploads/
"""
        zip_file.writestr("LEEME_PRE_RESTORE.txt", info)

    print(f"✅ Respaldo de emergencia creado: {pre_backup_path}")

    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        restored_db = os.path.join(temp_dir, "database", "aserve.db")
        restored_uploads = os.path.join(temp_dir, "uploads")

        if not os.path.exists(restored_db):
            print("❌ El respaldo no contiene database/aserve.db.")
            print("No se restauró nada.")
            print(f"Tu respaldo de emergencia quedó en: {pre_backup_path}")
            return

        print("🟡 Restaurando base de datos...")

        if os.path.exists(db_path):
            os.remove(db_path)

        shutil.copy2(restored_db, db_path)

        print("✅ Base de datos restaurada correctamente.")

        print("🟡 Restaurando imágenes...")

        if os.path.exists(upload_folder_abs):
            shutil.rmtree(upload_folder_abs)

        if os.path.exists(restored_uploads):
            shutil.copytree(restored_uploads, upload_folder_abs)
            print("✅ Imágenes restauradas correctamente.")
        else:
            os.makedirs(upload_folder_abs, exist_ok=True)
            print("⚠️ El respaldo no tenía carpeta uploads. Se creó vacía.")

    print("")
    print("✅ RESTAURACIÓN COMPLETADA CORRECTAMENTE")
    print(f"Respaldo restaurado: {zip_path}")
    print(f"Respaldo de emergencia previo: {pre_backup_path}")
    print("")
    print("Ahora podés iniciar Flask nuevamente con:")
    print("python app.py")


# =====================================================
# COMANDOS DE CONSOLA
# =====================================================
@app.cli.command("init-db")
def init_db_command():
    os.makedirs(app.instance_path, exist_ok=True)

    db = get_db()

    with app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))

    ensure_app_schema(db)

    db.commit()

    print("✅ Base de datos inicializada correctamente.")


@app.cli.command("create-admin")
def create_admin_command():
    db = get_db()
    ensure_app_schema(db)

    nombre = "Administrador"
    usuario = "admin"
    contrasena = "Admin1234"

    existe = db.execute(
        "SELECT id FROM users WHERE usuario = ?",
        (usuario,)
    ).fetchone()

    if existe:
        print("⚠️ El usuario admin ya existe.")
        return

    hash_pw = bcrypt.hashpw(
        contrasena.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    try:
        db.execute(
            """
            INSERT INTO users (nombre, usuario, contrasena_hash, rol, estado, password_temporal)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (nombre, usuario, hash_pw, "admin", "activo")
        )
    except sqlite3.OperationalError:
        db.execute(
            """
            INSERT INTO users (nombre, usuario, contrasena_hash, rol, estado)
            VALUES (?, ?, ?, ?, ?)
            """,
            (nombre, usuario, hash_pw, "admin", "activo")
        )

    db.commit()

    print("✅ Admin creado correctamente.")
    print("Usuario: admin | Contraseña: Admin1234")


# =====================================================
# RUTA PRINCIPAL
# =====================================================
@app.route("/")
def inicio():
    return redirect(url_for("catalogo"))


# =====================================================
# LOGIN
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = (request.form.get("usuario") or "").strip()
        contrasena = (request.form.get("contrasena") or "").strip()

        db = get_db()
        ensure_app_schema(db)

        user = db.execute(
            "SELECT * FROM users WHERE usuario = ?",
            (usuario,)
        ).fetchone()

        if not user:
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("login"))

        if user["estado"] == "bloqueado":
            flash("Usuario bloqueado. Contacte al administrador.", "warning")
            return redirect(url_for("login"))

        if not bcrypt.checkpw(
            contrasena.encode("utf-8"),
            user["contrasena_hash"].encode("utf-8")
        ):
            flash("Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        session["nombre"] = user["nombre"]
        session["rol"] = user["rol"]
        session["password_temporal"] = user["password_temporal"] if "password_temporal" in user.keys() else 0

        if session.get("password_temporal") == 1:
            flash("Debes cambiar tu contraseña temporal antes de continuar.", "warning")
            return redirect(url_for("cambiar_password_temporal"))

        flash(f"Bienvenido/a, {user['nombre']}!", "success")

        if user["rol"] == "admin":
            return redirect(url_for("admin_panel"))

        return redirect(url_for("catalogo"))

    return render_template("login.html")


# =====================================================
# LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))


# =====================================================
# PROTECCIÓN GLOBAL: CONTRASEÑA TEMPORAL
# =====================================================
@app.before_request
def proteger_password_temporal():
    if "user_id" not in session:
        return None

    rutas_permitidas = {
        "cambiar_password_temporal",
        "logout",
        "static"
    }

    if request.endpoint in rutas_permitidas:
        return None

    if session.get("password_temporal") == 1:
        flash("Debes cambiar tu contraseña temporal antes de continuar.", "warning")
        return redirect(url_for("cambiar_password_temporal"))

    return None


# =====================================================
# PERFIL
# =====================================================
@app.route("/perfil", methods=["GET", "POST"])
def perfil():
    if "user_id" not in session:
        flash("Debes iniciar sesión para ver tu perfil.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    user_id = session["user_id"]

    user = db.execute(
        "SELECT id, nombre, usuario, rol, estado FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        session.clear()
        flash("Sesión inválida. Inicia sesión nuevamente.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        actual = (request.form.get("password_actual") or "").strip()
        nueva = (request.form.get("password_nueva") or "").strip()
        confirmar = (request.form.get("password_confirmar") or "").strip()

        if not actual or not nueva or not confirmar:
            flash("Completa todos los campos para cambiar contraseña.", "danger")
            return redirect(url_for("perfil"))

        if nueva != confirmar:
            flash("La nueva contraseña y su confirmación no coinciden.", "danger")
            return redirect(url_for("perfil"))

        errores_password = validar_contrasena_segura(nueva)

        if errores_password:
            flash(" ".join(errores_password), "warning")
            return redirect(url_for("perfil"))

        user_full = db.execute(
            "SELECT contrasena_hash FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user_full or not bcrypt.checkpw(
            actual.encode("utf-8"),
            user_full["contrasena_hash"].encode("utf-8")
        ):
            flash("La contraseña actual no es correcta.", "danger")
            return redirect(url_for("perfil"))

        nuevo_hash = bcrypt.hashpw(
            nueva.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        db.execute(
            "UPDATE users SET contrasena_hash = ? WHERE id = ?",
            (nuevo_hash, user_id)
        )
        db.commit()

        flash("✅ Contraseña actualizada correctamente.", "success")
        return redirect(url_for("perfil"))

    return render_template("perfil.html", user=user)


# =====================================================
# CAMBIO OBLIGATORIO DE CONTRASEÑA TEMPORAL
# =====================================================
@app.route("/cambiar-password-temporal", methods=["GET", "POST"])
def cambiar_password_temporal():
    if "user_id" not in session:
        flash("Debes iniciar sesión.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    ensure_app_schema(db)

    user_id = session["user_id"]

    user = db.execute(
        "SELECT id, nombre, usuario, password_temporal FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        session.clear()
        flash("Sesión inválida. Inicia sesión nuevamente.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        nueva = (request.form.get("password_nueva") or "").strip()
        confirmar = (request.form.get("password_confirmar") or "").strip()

        if not nueva or not confirmar:
            flash("Completa todos los campos.", "danger")
            return redirect(url_for("cambiar_password_temporal"))

        if nueva != confirmar:
            flash("La nueva contraseña y su confirmación no coinciden.", "danger")
            return redirect(url_for("cambiar_password_temporal"))

        errores_password = validar_contrasena_segura(nueva)

        if errores_password:
            flash(" ".join(errores_password), "warning")
            return redirect(url_for("cambiar_password_temporal"))

        nuevo_hash = bcrypt.hashpw(
            nueva.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        db.execute(
            """
            UPDATE users
            SET contrasena_hash = ?, password_temporal = 0
            WHERE id = ?
            """,
            (nuevo_hash, user_id)
        )
        db.commit()

        session["password_temporal"] = 0

        flash("Contraseña actualizada correctamente. Ya puedes usar el sistema.", "success")

        if session.get("rol") == "admin":
            return redirect(url_for("admin_panel"))

        return redirect(url_for("catalogo"))

    return render_template("cambiar_password_temporal.html", user=user)


# =====================================================
# PANEL ADMINISTRADOR
# =====================================================
@app.route("/admin")
def admin_panel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "admin":
        flash("No tienes permisos.", "danger")
        return redirect(url_for("inicio"))

    db = get_db()

    creditos_pendientes = db.execute("""
        SELECT COUNT(*) AS n
        FROM orders
        WHERE replace(lower(trim(tipo_pago)), 'é', 'e') = 'credito'
          AND lower(trim(estado)) = 'pendiente'
    """).fetchone()["n"]

    stock_bajo = db.execute("""
        SELECT COUNT(*) AS n
        FROM products
        WHERE activo = 1
          AND stock_minimo > 0
          AND stock <= stock_minimo
    """).fetchone()["n"]

    usuarios_bloqueados = db.execute("""
        SELECT COUNT(*) AS n
        FROM users
        WHERE estado = 'bloqueado'
    """).fetchone()["n"]

    ordenes_14 = db.execute("""
        SELECT COUNT(*) AS n
        FROM orders
        WHERE date(fecha) >= date('now','-13 day')
          AND date(fecha) <= date('now')
    """).fetchone()["n"]

    return render_template(
        "admin.html",
        kpi_creditos=creditos_pendientes,
        kpi_stock_bajo=stock_bajo,
        kpi_bloqueados=usuarios_bloqueados,
        kpi_ordenes_14=ordenes_14
    )

# =====================================================
# ADMIN: AUDITORÍA
# Ruta: /admin/audit
# - Muestra resumen por tipo de acción
# - Filtra automáticamente últimos 14 días
# - Permite filtrar por acción y fechas
# - Permite ver u ocultar el detalle individual
# =====================================================
@app.route("/admin/audit")
def admin_audit_logs():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
    ensure_app_schema(db)

    accion = (request.args.get("accion") or "").strip()
    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()
    ver_detalle = (request.args.get("ver_detalle") or "").strip() == "1"

    # =====================================================
    # DEFAULT: últimos 14 días
    # Si no se envían fechas desde el filtro, se cargan
    # automáticamente desde hace 13 días hasta hoy.
    # =====================================================
    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    if accion:
        where.append("accion = ?")
        params.append(accion)

    # Siempre se aplica el rango de fechas
    where.append("date(fecha) >= date(?)")
    params.append(start)

    where.append("date(fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    # Lista de acciones disponibles para el filtro
    acciones_disponibles = db.execute(
        """
        SELECT DISTINCT accion
        FROM audit_logs
        ORDER BY accion ASC
        """
    ).fetchall()

    # Resumen agrupado por acción
    resumen_acciones = db.execute(
        f"""
        SELECT
            accion,
            COUNT(*) AS cantidad,
            MAX(fecha) AS ultima_fecha
        FROM audit_logs
        {where_sql}
        GROUP BY accion
        ORDER BY cantidad DESC, accion ASC
        """,
        params
    ).fetchall()

    # Totales generales del rango/filtro
    resumen_general = db.execute(
        f"""
        SELECT
            COUNT(*) AS total_acciones,
            COUNT(DISTINCT accion) AS tipos_acciones,
            MAX(fecha) AS ultima_accion
        FROM audit_logs
        {where_sql}
        """,
        params
    ).fetchone()

    # Detalle individual, solo si se activa
    logs = []

    if ver_detalle or accion:
        logs = db.execute(
            f"""
            SELECT id, fecha, admin_nombre, accion, detalle
            FROM audit_logs
            {where_sql}
            ORDER BY id DESC
            LIMIT 300
            """,
            params
        ).fetchall()

    return render_template(
        "admin_audit_logs.html",
        logs=logs,
        resumen_acciones=resumen_acciones,
        resumen_general=resumen_general,
        acciones_disponibles=acciones_disponibles,
        accion=accion,
        start=start,
        end=end,
        ver_detalle=ver_detalle
    )

# =====================================================
# ADMIN: DESCARGAR RESPALDO
# =====================================================
@app.route("/admin/backup/download")
def admin_backup_download():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    fecha_backup = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"respaldo_aserve_{fecha_backup}.zip"
    zip_buffer = BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        db_original_path = app.config["DATABASE"]

        if os.path.exists(db_original_path):
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_db:
                temp_db_path = temp_db.name

            try:
                source = sqlite3.connect(db_original_path)
                destination = sqlite3.connect(temp_db_path)

                with destination:
                    source.backup(destination)

                source.close()
                destination.close()

                zip_file.write(temp_db_path, arcname="database/aserve.db")

            finally:
                if os.path.exists(temp_db_path):
                    os.remove(temp_db_path)

        upload_folder_abs = app.config["UPLOAD_FOLDER"]

        if not os.path.isabs(upload_folder_abs):
            upload_folder_abs = os.path.join(os.getcwd(), upload_folder_abs)

        if os.path.exists(upload_folder_abs):
            for root, dirs, files in os.walk(upload_folder_abs):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, upload_folder_abs)
                    zip_file.write(file_path, arcname=os.path.join("uploads", relative_path))

        info = f"""RESPALDO ASERVE
Fecha de respaldo: {fecha_backup}

Contenido:
- database/aserve.db
- uploads/

Notas:
Este archivo contiene la base de datos y las imágenes subidas al sistema.
Guardarlo en un lugar seguro.
"""
        zip_file.writestr("LEEME_RESPALDO.txt", info)

    zip_buffer.seek(0)

    registrar_auditoria(
        "Descargar respaldo",
        f"Se generó y descargó el respaldo '{filename}'. Incluye base de datos e imágenes del sistema.",
        commit=True
    )

    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/zip"
    )


# =====================================================
# ADMIN: USUARIOS
# =====================================================
@app.route("/admin/users")
def admin_users():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    usuarios = db.execute("""
        SELECT id, nombre, usuario, rol, estado
        FROM users
        ORDER BY nombre
    """).fetchall()

    return render_template("admin_users.html", usuarios=usuarios)


@app.route("/admin/users/add", methods=["GET", "POST"])
def admin_user_add():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
    ensure_app_schema(db)

    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        usuario = (request.form.get("usuario") or "").strip()
        rol = (request.form.get("rol") or "").strip()
        password = (request.form.get("password") or "").strip()

        if not nombre or not usuario or not password:
            flash("Nombre, usuario y contraseña son obligatorios.", "danger")
            return redirect(url_for("admin_user_add"))

        errores_password = validar_contrasena_segura(password)

        if errores_password:
            flash(" ".join(errores_password), "warning")
            return redirect(url_for("admin_user_add"))

        if rol not in ("admin", "asociado"):
            flash("Rol inválido.", "danger")
            return redirect(url_for("admin_user_add"))

        existe = db.execute(
            "SELECT id FROM users WHERE usuario = ?",
            (usuario,)
        ).fetchone()

        if existe:
            flash("Ese usuario ya existe.", "warning")
            return redirect(url_for("admin_user_add"))

        hash_pw = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        db.execute(
            """
            INSERT INTO users (nombre, usuario, contrasena_hash, rol, estado, password_temporal)
            VALUES (?, ?, ?, ?, 'activo', 1)
            """,
            (nombre, usuario, hash_pw, rol)
        )

        registrar_auditoria(
            "Crear usuario",
            f"Nombre: {nombre}. Usuario: {usuario}. Rol asignado: {rol}. Estado inicial: activo. Contraseña marcada como temporal para cambio obligatorio."
        )

        db.commit()

        flash("Usuario creado correctamente.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_user_add.html")


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def admin_user_edit(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
    ensure_app_schema(db)

    u = db.execute(
        "SELECT id, nombre, usuario, rol, estado FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        usuario = (request.form.get("usuario") or "").strip()
        rol = (request.form.get("rol") or "").strip()
        estado = (request.form.get("estado") or "").strip()
        new_password = (request.form.get("new_password") or "").strip()

        if not nombre or not usuario:
            flash("Nombre y usuario son obligatorios.", "danger")
            return redirect(url_for("admin_user_edit", user_id=user_id))

        if rol not in ("admin", "asociado"):
            flash("Rol inválido.", "danger")
            return redirect(url_for("admin_user_edit", user_id=user_id))

        if estado not in ("activo", "bloqueado"):
            flash("Estado inválido.", "danger")
            return redirect(url_for("admin_user_edit", user_id=user_id))

        existe = db.execute(
            "SELECT id FROM users WHERE usuario = ? AND id <> ?",
            (usuario, user_id)
        ).fetchone()

        if existe:
            flash("Ese usuario ya está en uso por otra cuenta.", "warning")
            return redirect(url_for("admin_user_edit", user_id=user_id))

        db.execute(
            """
            UPDATE users
            SET nombre = ?, usuario = ?, rol = ?, estado = ?
            WHERE id = ?
            """,
            (nombre, usuario, rol, estado, user_id)
        )

        if new_password:
            errores_password = validar_contrasena_segura(new_password)

            if errores_password:
                flash(" ".join(errores_password), "warning")
                return redirect(url_for("admin_user_edit", user_id=user_id))

            hash_pw = bcrypt.hashpw(
                new_password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            db.execute(
                """
                UPDATE users
                SET contrasena_hash = ?, password_temporal = 1
                WHERE id = ?
                """,
                (hash_pw, user_id)
            )

            registrar_auditoria(
                "Reset contraseña",
                f"Usuario ID {user_id}. Nombre: {nombre}. Usuario: {usuario}. Se actualizó la contraseña y quedó marcada como temporal para cambio obligatorio en el próximo inicio de sesión."
            )

        registrar_auditoria(
            "Editar usuario",
            f"Usuario ID {user_id}. Nombre: {nombre}. Usuario: {usuario}. Rol: {rol}. Estado: {estado}."
        )

        db.commit()

        flash("Usuario actualizado correctamente.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_user_edit.html", u=u)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
def admin_user_toggle(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    if session.get("user_id") == user_id:
        flash("No podés bloquear tu propia cuenta.", "warning")
        return redirect(url_for("admin_users"))

    db = get_db()

    u = db.execute(
        "SELECT id, nombre, usuario, estado FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("admin_users"))

    nuevo_estado = "activo" if u["estado"] == "bloqueado" else "bloqueado"

    db.execute(
        "UPDATE users SET estado = ? WHERE id = ?",
        (nuevo_estado, user_id)
    )

    registrar_auditoria(
        "Cambiar estado usuario",
        f"Usuario: {u['nombre']}. Código/usuario: {u['usuario']}. Nuevo estado: {nuevo_estado}."
    )

    db.commit()

    flash(f"Estado actualizado a: {nuevo_estado}", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_user_delete(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    if session.get("user_id") == user_id:
        flash("No podés eliminar tu propia cuenta.", "warning")
        return redirect(url_for("admin_users"))

    db = get_db()

    user = db.execute(
        "SELECT id, nombre, usuario, rol FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("admin_users"))

    compras = db.execute(
        "SELECT COUNT(*) AS total FROM orders WHERE user_id = ?",
        (user_id,)
    ).fetchone()["total"]

    if compras > 0:
        flash(
            "No se puede eliminar este usuario porque tiene compras registradas. "
            "Podés bloquearlo para impedir el acceso y conservar el historial.",
            "warning"
        )
        return redirect(url_for("admin_users"))

    if user["rol"] == "admin":
        admins = db.execute(
            "SELECT COUNT(*) AS total FROM users WHERE rol = 'admin'"
        ).fetchone()["total"]

        if admins <= 1:
            flash("No se puede eliminar el último administrador del sistema.", "warning")
            return redirect(url_for("admin_users"))

    db.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    registrar_auditoria(
        "Eliminar usuario",
        f"Nombre: {user['nombre']}. Usuario: {user['usuario']}. Rol: {user['rol']}. Eliminado porque no tenía compras registradas."
    )

    db.commit()

    flash(f"Usuario '{user['nombre']}' eliminado correctamente.", "success")
    return redirect(url_for("admin_users"))


# =====================================================
# MIS COMPRAS
# =====================================================
@app.route("/mis-compras")
def mis_compras():
    if "user_id" not in session:
        flash("Debes iniciar sesión para ver tu historial.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    db = get_db()

    pago = (request.args.get("pago") or "").strip().lower().replace("é", "e")
    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    where = ["o.user_id = ?"]
    params = [user_id]

    if pago in ("contado", "credito"):
        where.append("replace(lower(trim(o.tipo_pago)), 'é', 'e') = ?")
        params.append(pago)

    if start:
        where.append("date(o.fecha) >= date(?)")
        params.append(start)

    if end:
        where.append("date(o.fecha) <= date(?)")
        params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    orders = db.execute(
        f"""
        SELECT o.id, o.fecha, o.tipo_pago, o.estado, o.total
        FROM orders o
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    total_rango = sum(float(o["total"]) for o in orders) if orders else 0

    return render_template(
        "mis_compras.html",
        orders=orders,
        pago=pago,
        start=start,
        end=end,
        total_rango=total_rango
    )


@app.route("/mis-compras/<int:order_id>")
def mis_compras_detalle(order_id):
    if "user_id" not in session:
        flash("Debes iniciar sesión.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    db = get_db()

    orden = db.execute(
        """
        SELECT id, fecha, tipo_pago, estado, total
        FROM orders
        WHERE id = ? AND user_id = ?
        """,
        (order_id, user_id)
    ).fetchone()

    if not orden:
        flash("Orden no encontrada o sin permisos.", "danger")
        return redirect(url_for("mis_compras"))

    items = db.execute(
        """
        SELECT
            p.nombre,
            oi.cantidad,
            oi.precio_unitario,
            (oi.cantidad * oi.precio_unitario) AS subtotal
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
        """,
        (order_id,)
    ).fetchall()

    return render_template("mis_compras_detalle.html", orden=orden, items=items)


# =====================================================
# ADMIN: HISTORIAL DE ÓRDENES
# =====================================================
@app.route("/admin/orders")
def admin_orders():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    estado = request.args.get("estado", "").strip()
    pago = request.args.get("pago", "").strip()
    q = request.args.get("q", "").strip()

    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    if estado:
        where.append("o.estado = ?")
        params.append(estado)

    if pago:
        where.append("replace(lower(trim(o.tipo_pago)), 'é', 'e') = ?")
        params.append(pago.replace("é", "e"))

    if q:
        where.append("(u.nombre LIKE ? OR o.nombre_no_asociado LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    db = get_db()

    orders = db.execute(
        f"""
        SELECT
            o.*,
            u.nombre AS nombre_usuario
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    return render_template(
        "admin_orders.html",
        orders=orders,
        estado=estado,
        pago=pago,
        q=q,
        start=start,
        end=end
    )


# =====================================================
# ADMIN: EXPORTAR HISTORIAL DE ÓRDENES
# =====================================================
@app.route("/admin/orders/export")
def admin_orders_export():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    estado = (request.args.get("estado") or "").strip().lower()
    pago = (request.args.get("pago") or "").strip().lower().replace("é", "e")
    q = (request.args.get("q") or "").strip()

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    if estado in ("pagada", "pendiente"):
        where.append("lower(trim(o.estado)) = ?")
        params.append(estado)

    if pago in ("contado", "credito"):
        where.append("replace(lower(trim(o.tipo_pago)), 'é', 'e') = ?")
        params.append(pago)

    if q:
        where.append("(u.nombre LIKE ? OR o.nombre_no_asociado LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    db = get_db()

    resumen = db.execute(
        f"""
        SELECT
            COUNT(o.id) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_general,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'contado' THEN o.total
                ELSE 0
            END), 0) AS total_contado,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'credito' THEN o.total
                ELSE 0
            END), 0) AS total_credito
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        {where_sql}
        """,
        params
    ).fetchone()

    orders = db.execute(
        f"""
        SELECT
            o.id,
            o.fecha,
            COALESCE(u.nombre, o.nombre_no_asociado, 'Sin nombre') AS comprador,
            o.tipo_pago,
            o.estado,
            o.total
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    detalle = db.execute(
        f"""
        SELECT
            o.id AS order_id,
            o.fecha,
            COALESCE(u.nombre, o.nombre_no_asociado, 'Sin nombre') AS comprador,
            o.tipo_pago,
            o.estado,
            o.total AS total_orden,
            p.nombre AS producto,
            oi.cantidad,
            oi.precio_unitario,
            (oi.cantidad * oi.precio_unitario) AS subtotal
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        JOIN order_items oi ON oi.order_id = o.id
        JOIN products p ON p.id = oi.product_id
        {where_sql}
        ORDER BY o.id DESC, p.nombre ASC
        """,
        params
    ).fetchall()

    wb = Workbook()

    fill_header = PatternFill("solid", fgColor="1F2328")
    fill_title = PatternFill("solid", fgColor="EAF2F8")
    font_header = Font(color="FFFFFF", bold=True)
    font_title = Font(bold=True, size=14)
    font_bold = Font(bold=True)
    alignment_center = Alignment(horizontal="center", vertical="center")
    alignment_left = Alignment(horizontal="left", vertical="center")

    thin_border = Border(
        left=Side(style="thin", color="D9DEE3"),
        right=Side(style="thin", color="D9DEE3"),
        top=Side(style="thin", color="D9DEE3"),
        bottom=Side(style="thin", color="D9DEE3")
    )

    # Hoja 1
    ws = wb.active
    ws.title = "Órdenes"

    ws.merge_cells("A1:F1")
    ws["A1"] = "Historial de compras - ASERVE"
    ws["A1"].font = font_title
    ws["A1"].fill = fill_title
    ws["A1"].alignment = alignment_left

    ws["A3"] = "Desde"
    ws["B3"] = start
    ws["C3"] = "Hasta"
    ws["D3"] = end
    ws["E3"] = "Pago"
    ws["F3"] = pago if pago else "Todos"

    ws["A4"] = "Estado"
    ws["B4"] = estado if estado else "Todos"
    ws["C4"] = "Búsqueda"
    ws["D4"] = q if q else "Sin búsqueda"

    for row in ws.iter_rows(min_row=3, max_row=4, min_col=1, max_col=6):
        for cell in row:
            cell.border = thin_border
            cell.alignment = alignment_center

    ws["A6"] = "Resumen"
    ws["A6"].font = font_bold
    ws["A6"].fill = fill_title

    ws["A7"] = "Órdenes"
    ws["B7"] = resumen["num_ordenes"]
    ws["A8"] = "Total general"
    ws["B8"] = float(resumen["total_general"])
    ws["A9"] = "Contado"
    ws["B9"] = float(resumen["total_contado"])
    ws["A10"] = "Crédito"
    ws["B10"] = float(resumen["total_credito"])

    for row in ws.iter_rows(min_row=6, max_row=10, min_col=1, max_col=2):
        for cell in row:
            cell.border = thin_border
            cell.alignment = alignment_left

    for row_num in range(7, 11):
        ws.cell(row=row_num, column=1).font = font_bold

    ws["B8"].number_format = '"₡"#,##0.00'
    ws["B9"].number_format = '"₡"#,##0.00'
    ws["B10"].number_format = '"₡"#,##0.00'

    start_row = 12
    headers = ["Orden", "Fecha", "Comprador", "Pago", "Estado", "Total"]

    for col_num, header in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=col_num)
        cell.value = header
        cell.fill = fill_header
        cell.font = font_header
        cell.alignment = alignment_center
        cell.border = thin_border

    current_row = start_row + 1

    for o in orders:
        ws.cell(row=current_row, column=1).value = f"#{o['id']}"
        ws.cell(row=current_row, column=2).value = o["fecha"]
        ws.cell(row=current_row, column=3).value = o["comprador"]
        ws.cell(row=current_row, column=4).value = o["tipo_pago"]
        ws.cell(row=current_row, column=5).value = o["estado"]
        ws.cell(row=current_row, column=6).value = float(o["total"])

        for col in range(1, 7):
            cell = ws.cell(row=current_row, column=col)
            cell.border = thin_border
            cell.alignment = alignment_left

        ws.cell(row=current_row, column=6).number_format = '"₡"#,##0.00'
        current_row += 1

    if not orders:
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=6)
        ws.cell(row=current_row, column=1).value = "Sin datos para los filtros seleccionados."
        ws.cell(row=current_row, column=1).alignment = alignment_center

    ws.column_dimensions["A"].width = 12
    ws.column_dimensions["B"].width = 22
    ws.column_dimensions["C"].width = 35
    ws.column_dimensions["D"].width = 15
    ws.column_dimensions["E"].width = 15
    ws.column_dimensions["F"].width = 16

    ws.freeze_panes = "A13"
    ws.auto_filter.ref = f"A{start_row}:F{max(start_row, current_row - 1)}"

    # Hoja 2
    ws2 = wb.create_sheet("Detalle productos")

    ws2.merge_cells("A1:J1")
    ws2["A1"] = "Detalle de productos por orden - ASERVE"
    ws2["A1"].font = font_title
    ws2["A1"].fill = fill_title
    ws2["A1"].alignment = alignment_left

    headers_detalle = [
        "Orden", "Fecha", "Comprador", "Pago", "Estado",
        "Total orden", "Producto", "Cantidad", "Precio unitario", "Subtotal"
    ]

    start_row_detalle = 3

    for col_num, header in enumerate(headers_detalle, start=1):
        cell = ws2.cell(row=start_row_detalle, column=col_num)
        cell.value = header
        cell.fill = fill_header
        cell.font = font_header
        cell.alignment = alignment_center
        cell.border = thin_border

    current_row = start_row_detalle + 1

    for d in detalle:
        ws2.cell(row=current_row, column=1).value = f"#{d['order_id']}"
        ws2.cell(row=current_row, column=2).value = d["fecha"]
        ws2.cell(row=current_row, column=3).value = d["comprador"]
        ws2.cell(row=current_row, column=4).value = d["tipo_pago"]
        ws2.cell(row=current_row, column=5).value = d["estado"]
        ws2.cell(row=current_row, column=6).value = float(d["total_orden"])
        ws2.cell(row=current_row, column=7).value = d["producto"]
        ws2.cell(row=current_row, column=8).value = int(d["cantidad"])
        ws2.cell(row=current_row, column=9).value = float(d["precio_unitario"])
        ws2.cell(row=current_row, column=10).value = float(d["subtotal"])

        for col in range(1, 11):
            cell = ws2.cell(row=current_row, column=col)
            cell.border = thin_border
            cell.alignment = alignment_left

        ws2.cell(row=current_row, column=6).number_format = '"₡"#,##0.00'
        ws2.cell(row=current_row, column=9).number_format = '"₡"#,##0.00'
        ws2.cell(row=current_row, column=10).number_format = '"₡"#,##0.00'

        current_row += 1

    if not detalle:
        ws2.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=10)
        ws2.cell(row=current_row, column=1).value = "Sin detalle de productos para los filtros seleccionados."
        ws2.cell(row=current_row, column=1).alignment = alignment_center

    widths = {
        "A": 12, "B": 22, "C": 35, "D": 15, "E": 15,
        "F": 16, "G": 35, "H": 12, "I": 18, "J": 16
    }

    for col_letter, width in widths.items():
        ws2.column_dimensions[col_letter].width = width

    ws2.freeze_panes = "A4"
    ws2.auto_filter.ref = f"A{start_row_detalle}:J{max(start_row_detalle, current_row - 1)}"

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    filename = f"historial_compras_{start}_a_{end}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# =====================================================
# ADMIN: DETALLE DE ORDEN
# =====================================================
@app.route("/admin/orders/<int:order_id>")
def admin_order_detail(order_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    orden = db.execute(
        """
        SELECT
            o.*,
            u.nombre AS nombre_usuario
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        WHERE o.id = ?
        """,
        (order_id,)
    ).fetchone()

    if not orden:
        flash("Orden no encontrada.", "danger")
        return redirect(url_for("admin_orders"))

    items = db.execute(
        """
        SELECT
            p.nombre,
            oi.cantidad,
            oi.precio_unitario,
            (oi.cantidad * oi.precio_unitario) AS subtotal
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
        """,
        (order_id,)
    ).fetchall()

    from_page = request.args.get("from_page", "orders")
    back_user_id = request.args.get("user_id", "").strip()

    return render_template(
        "admin_order_detail.html",
        orden=orden,
        items=items,
        from_page=from_page,
        back_user_id=back_user_id
    )


# =====================================================
# ADMIN: COMPRADORES
# =====================================================
@app.route("/admin/buyers")
def admin_buyers():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    registrados = db.execute(
        """
        SELECT
            ('u:' || u.id) AS buyer_key,
            u.nombre AS comprador,
            'registrado' AS tipo,
            COUNT(o.id) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_monto
        FROM orders o
        JOIN users u ON u.id = o.user_id
        GROUP BY u.id, u.nombre
        """
    ).fetchall()

    no_asociados = db.execute(
        """
        SELECT
            ('na:' || o.nombre_no_asociado) AS buyer_key,
            o.nombre_no_asociado AS comprador,
            'no_asociado' AS tipo,
            COUNT(o.id) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_monto
        FROM orders o
        WHERE o.user_id IS NULL
          AND o.nombre_no_asociado IS NOT NULL
          AND TRIM(o.nombre_no_asociado) <> ''
        GROUP BY o.nombre_no_asociado
        """
    ).fetchall()

    buyers = list(registrados) + list(no_asociados)
    buyers.sort(key=lambda x: (-float(x["total_monto"]), x["comprador"]))

    return render_template("admin_buyers.html", buyers=buyers)


@app.route("/admin/buyer")
def admin_buyer_history():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    key = request.args.get("key", "").strip()
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()

    if not key:
        flash("Comprador inválido.", "danger")
        return redirect(url_for("admin_buyers"))

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    db = get_db()

    where = []
    params = []

    comprador_nombre = ""
    comprador_tipo = ""

    if key.startswith("u:"):
        comprador_tipo = "registrado"
        user_id = key.split(":", 1)[1]

        where.append("o.user_id = ?")
        params.append(user_id)

        u = db.execute(
            "SELECT nombre FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        comprador_nombre = u["nombre"] if u else "Usuario"

    elif key.startswith("na:"):
        comprador_tipo = "no_asociado"
        nombre = key.split(":", 1)[1]

        where.append("o.user_id IS NULL")
        where.append("o.nombre_no_asociado = ?")
        params.append(nombre)

        comprador_nombre = nombre

    else:
        flash("Comprador inválido.", "danger")
        return redirect(url_for("admin_buyers"))

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    orders = db.execute(
        f"""
        SELECT
            o.id,
            o.fecha,
            o.tipo_pago,
            o.estado,
            o.total
        FROM orders o
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    total_rango = sum(float(o["total"]) for o in orders) if orders else 0

    return render_template(
        "admin_buyer_history.html",
        key=key,
        comprador_nombre=comprador_nombre,
        comprador_tipo=comprador_tipo,
        orders=orders,
        total_rango=total_rango,
        start=start,
        end=end
    )


@app.route("/admin/buyer/export")
def admin_buyer_history_export():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    key = request.args.get("key", "").strip()
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()

    if not key:
        flash("Comprador inválido para exportar.", "danger")
        return redirect(url_for("admin_buyers"))

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    db = get_db()

    where = []
    params = []

    comprador_nombre = ""
    comprador_tipo = ""

    if key.startswith("u:"):
        comprador_tipo = "registrado"
        user_id = key.split(":", 1)[1]

        where.append("o.user_id = ?")
        params.append(user_id)

        u = db.execute(
            "SELECT nombre FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        comprador_nombre = u["nombre"] if u else "Usuario"

    elif key.startswith("na:"):
        comprador_tipo = "no asociado"
        nombre = key.split(":", 1)[1]

        where.append("o.user_id IS NULL")
        where.append("o.nombre_no_asociado = ?")
        params.append(nombre)

        comprador_nombre = nombre

    else:
        flash("Comprador inválido para exportar.", "danger")
        return redirect(url_for("admin_buyers"))

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    resumen = db.execute(
        f"""
        SELECT
            COUNT(o.id) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_acumulado
        FROM orders o
        {where_sql}
        """,
        params
    ).fetchone()

    rows = db.execute(
        f"""
        SELECT
            o.id AS order_id,
            o.fecha,
            o.tipo_pago,
            o.estado,
            o.total AS total_orden,
            COALESCE(p.nombre, 'Sin producto') AS producto,
            COALESCE(oi.cantidad, 0) AS cantidad,
            COALESCE(oi.precio_unitario, 0) AS precio_unitario,
            COALESCE((oi.cantidad * oi.precio_unitario), 0) AS subtotal
        FROM orders o
        LEFT JOIN order_items oi ON oi.order_id = o.id
        LEFT JOIN products p ON p.id = oi.product_id
        {where_sql}
        ORDER BY o.fecha DESC, o.id DESC, p.nombre ASC
        """,
        params
    ).fetchall()

    wb = Workbook()
    ws = wb.active
    ws.title = "Historial comprador"

    fill_header = PatternFill("solid", fgColor="1F2328")
    fill_title = PatternFill("solid", fgColor="EAF2F8")
    font_header = Font(color="FFFFFF", bold=True)
    font_title = Font(bold=True, size=14)
    font_bold = Font(bold=True)
    alignment_center = Alignment(horizontal="center", vertical="center")
    alignment_left = Alignment(horizontal="left", vertical="center")

    thin_border = Border(
        left=Side(style="thin", color="D9DEE3"),
        right=Side(style="thin", color="D9DEE3"),
        top=Side(style="thin", color="D9DEE3"),
        bottom=Side(style="thin", color="D9DEE3")
    )

    ws.merge_cells("A1:I1")
    ws["A1"] = "Historial de compras por comprador - ASERVE"
    ws["A1"].font = font_title
    ws["A1"].fill = fill_title
    ws["A1"].alignment = alignment_left

    ws["A3"] = "Comprador"
    ws["B3"] = comprador_nombre
    ws["A4"] = "Tipo"
    ws["B4"] = comprador_tipo
    ws["A5"] = "Desde"
    ws["B5"] = start
    ws["A6"] = "Hasta"
    ws["B6"] = end

    ws["A8"] = "Resumen"
    ws["A8"].font = font_bold
    ws["A8"].fill = fill_title

    ws["A9"] = "Órdenes"
    ws["B9"] = resumen["num_ordenes"]

    ws["A10"] = "Total acumulado"
    ws["B10"] = float(resumen["total_acumulado"])
    ws["B10"].number_format = '"₡"#,##0.00'

    for row in ws.iter_rows(min_row=3, max_row=10, min_col=1, max_col=2):
        for cell in row:
            cell.border = thin_border
            cell.alignment = alignment_left

    for row in range(3, 11):
        ws.cell(row=row, column=1).font = font_bold

    start_row = 12

    headers = [
        "Orden", "Fecha", "Tipo de pago", "Estado", "Total orden",
        "Producto", "Cantidad", "Precio unitario", "Subtotal"
    ]

    for col_num, header in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=col_num)
        cell.value = header
        cell.fill = fill_header
        cell.font = font_header
        cell.alignment = alignment_center
        cell.border = thin_border

    current_row = start_row + 1

    for r in rows:
        ws.cell(row=current_row, column=1).value = f"#{r['order_id']}"
        ws.cell(row=current_row, column=2).value = r["fecha"]
        ws.cell(row=current_row, column=3).value = r["tipo_pago"]
        ws.cell(row=current_row, column=4).value = r["estado"]
        ws.cell(row=current_row, column=5).value = float(r["total_orden"])
        ws.cell(row=current_row, column=6).value = r["producto"]
        ws.cell(row=current_row, column=7).value = int(r["cantidad"])
        ws.cell(row=current_row, column=8).value = float(r["precio_unitario"])
        ws.cell(row=current_row, column=9).value = float(r["subtotal"])

        for col in range(1, 10):
            cell = ws.cell(row=current_row, column=col)
            cell.border = thin_border
            cell.alignment = alignment_left

        ws.cell(row=current_row, column=5).number_format = '"₡"#,##0.00'
        ws.cell(row=current_row, column=8).number_format = '"₡"#,##0.00'
        ws.cell(row=current_row, column=9).number_format = '"₡"#,##0.00'

        current_row += 1

    if not rows:
        ws.merge_cells(
            start_row=current_row,
            start_column=1,
            end_row=current_row,
            end_column=9
        )
        ws.cell(row=current_row, column=1).value = "Sin datos para este comprador."
        ws.cell(row=current_row, column=1).alignment = alignment_center
        ws.cell(row=current_row, column=1).border = thin_border

    widths = {
        "A": 12, "B": 22, "C": 16, "D": 14, "E": 16,
        "F": 35, "G": 12, "H": 18, "I": 16
    }

    for col_letter, width in widths.items():
        ws.column_dimensions[col_letter].width = width

    ws.freeze_panes = "A13"
    ws.auto_filter.ref = f"A{start_row}:I{max(start_row, current_row - 1)}"

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    safe_name = secure_filename(comprador_nombre) or "comprador"
    filename = f"historial_comprador_{safe_name}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


# =====================================================
# ADMIN: CRÉDITOS
# =====================================================
@app.route("/admin/credits")
def admin_credits():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    creditos = db.execute(
        """
        SELECT
            u.id AS user_id,
            u.nombre AS comprador,
            COUNT(o.id) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS deuda_total
        FROM orders o
        JOIN users u ON u.id = o.user_id
        WHERE
            replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'credito'
            AND lower(trim(o.estado)) = 'pendiente'
        GROUP BY u.id, u.nombre
        ORDER BY deuda_total DESC, u.nombre ASC
        """
    ).fetchall()

    return render_template("admin_credits.html", creditos=creditos)


@app.route("/admin/credits/user/<int:user_id>")
def admin_credits_user(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    user = db.execute(
        "SELECT id, nombre FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        flash("Colaborador no encontrado.", "danger")
        return redirect(url_for("admin_credits"))

    orders = db.execute(
        """
        SELECT id, fecha, total
        FROM orders
        WHERE user_id = ?
          AND replace(lower(trim(tipo_pago)), 'é', 'e') = 'credito'
          AND lower(trim(estado)) = 'pendiente'
        ORDER BY fecha ASC
        """,
        (user_id,)
    ).fetchall()

    deuda_total = sum(float(o["total"]) for o in orders) if orders else 0

    return render_template(
        "admin_credits_user.html",
        user=user,
        orders=orders,
        deuda_total=deuda_total
    )


@app.route("/admin/credits/user/<int:user_id>/pay-bulk", methods=["POST"])
def admin_credits_pay_bulk(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    order_ids = request.form.getlist("order_ids")

    if not order_ids:
        flash("No seleccionaste ninguna orden.", "warning")
        return redirect(url_for("admin_credits_user", user_id=user_id))

    try:
        order_ids_int = [int(x) for x in order_ids]
    except ValueError:
        flash("Selección inválida.", "danger")
        return redirect(url_for("admin_credits_user", user_id=user_id))

    db = get_db()
    placeholders = ",".join(["?"] * len(order_ids_int))

    cur = db.execute(
        f"""
        UPDATE orders
        SET estado = 'pagada'
        WHERE user_id = ?
          AND replace(lower(trim(tipo_pago)), 'é', 'e') = 'credito'
          AND lower(trim(estado)) = 'pendiente'
          AND id IN ({placeholders})
        """,
        [user_id] + order_ids_int
    )

    comprador = db.execute(
        "SELECT nombre FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    comprador_nombre = comprador["nombre"] if comprador else f"Usuario ID {user_id}"
    ordenes_txt = ", ".join([f"#{oid}" for oid in order_ids_int])

    registrar_auditoria(
        "Pagar créditos en bloque",
        f"Comprador: {comprador_nombre}. Órdenes pagadas: {ordenes_txt}. Total de órdenes actualizadas: {cur.rowcount}."
    )

    db.commit()

    flash(f"Se marcaron como pagadas {cur.rowcount} orden(es).", "success")
    return redirect(url_for("admin_credits_user", user_id=user_id))


@app.route("/admin/credits/pay/<int:order_id>", methods=["POST"])
def admin_credits_pay(order_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    orden = db.execute(
        """
        SELECT
            o.id,
            o.user_id,
            o.total,
            u.nombre AS comprador
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        WHERE o.id = ?
          AND replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'credito'
          AND lower(trim(o.estado)) = 'pendiente'
        """,
        (order_id,)
    ).fetchone()

    if not orden:
        flash("Esa orden no existe o ya fue pagada.", "warning")
        return redirect(url_for("admin_credits"))

    db.execute(
        "UPDATE orders SET estado = 'pagada' WHERE id = ?",
        (order_id,)
    )

    comprador_nombre = orden["comprador"] if orden["comprador"] else f"Usuario ID {orden['user_id']}"

    registrar_auditoria(
        "Pagar crédito",
        f"Orden #{order_id} marcada como pagada. Comprador: {comprador_nombre}. Monto: ₡{float(orden['total']):,.2f}."
    )

    db.commit()

    flash(f"Orden #{order_id} marcada como pagada.", "success")
    return redirect(url_for("admin_credits_user", user_id=orden["user_id"]))


# =====================================================
# ADMIN: STOCK Y PRODUCTOS
# =====================================================
@app.route("/admin/stock")
def admin_stock():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    only_low = (request.args.get("only_low") or "").strip() == "1"

    db = get_db()

    productos = db.execute(
        """
        SELECT id, nombre, stock, stock_minimo, activo
        FROM products
        ORDER BY nombre ASC
        """
    ).fetchall()

    bajos = []

    for p in productos:
        if int(p["activo"]) == 1 and int(p["stock_minimo"]) > 0 and int(p["stock"]) <= int(p["stock_minimo"]):
            bajos.append(p)

    if only_low:
        productos = bajos

    return render_template(
        "admin_stock.html",
        productos=productos,
        bajos_count=len(bajos),
        only_low=only_low
    )


@app.route("/admin/products")
def admin_products():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    productos = db.execute("""
        SELECT id, nombre, precio, stock, stock_minimo, activo, image_filename
        FROM products
        ORDER BY nombre ASC
    """).fetchall()

    bajos = [
        p for p in productos
        if int(p["activo"]) == 1
        and int(p["stock_minimo"] or 0) > 0
        and int(p["stock"] or 0) <= int(p["stock_minimo"] or 0)
    ]

    return render_template("admin_products.html", productos=productos, bajos=bajos)


@app.route("/admin/products/add", methods=["GET", "POST"])
def admin_product_add():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        precio = (request.form.get("precio") or "").strip()
        stock = (request.form.get("stock") or "").strip()
        stock_minimo = (request.form.get("stock_minimo") or "0").strip()
        activo = 1 if request.form.get("activo") == "on" else 0
        imagen = request.files.get("imagen")

        if not nombre or not precio or not stock:
            flash("Nombre, precio y stock son obligatorios.", "danger")
            return redirect(url_for("admin_product_add"))

        try:
            precio_num = float(precio)
            stock_num = int(stock)
            stock_minimo_num = int(stock_minimo)

            if precio_num < 0 or stock_num < 0 or stock_minimo_num < 0:
                flash("Precio/stock no pueden ser negativos.", "danger")
                return redirect(url_for("admin_product_add"))

        except ValueError:
            flash("Precio debe ser número y stock/stock mínimo deben ser enteros.", "danger")
            return redirect(url_for("admin_product_add"))

        image_filename = None

        if imagen and imagen.filename:
            if not allowed_file(imagen.filename):
                flash("Formato de imagen no permitido.", "danger")
                return redirect(url_for("admin_product_add"))

            filename_img = secure_filename(imagen.filename)
            unique_name = f"{int(datetime.now().timestamp())}_{filename_img}"

            upload_folder_abs = app.config["UPLOAD_FOLDER"]
            os.makedirs(upload_folder_abs, exist_ok=True)

            imagen.save(os.path.join(upload_folder_abs, unique_name))
            image_filename = unique_name

        db = get_db()

        db.execute(
            """
            INSERT INTO products (nombre, precio, stock, stock_minimo, activo, image_filename)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (nombre, precio_num, stock_num, stock_minimo_num, activo, image_filename)
        )

        registrar_auditoria(
            "Crear producto",
            f"Producto: {nombre}. Precio: ₡{precio_num:,.2f}. Stock inicial: {stock_num}. Stock mínimo: {stock_minimo_num}. Estado: {'activo' if activo == 1 else 'inactivo'}."
        )

        db.commit()

        flash("✅ Producto agregado.", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin_product_add.html")


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
def admin_product_edit(product_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    p = db.execute(
        """
        SELECT id, nombre, precio, stock, stock_minimo, activo, image_filename
        FROM products
        WHERE id = ?
        """,
        (product_id,)
    ).fetchone()

    if not p:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for("admin_products"))

    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        precio = (request.form.get("precio") or "").strip()
        stock = (request.form.get("stock") or "").strip()
        stock_minimo = (request.form.get("stock_minimo") or "0").strip()
        activo = 1 if request.form.get("activo") == "on" else 0
        imagen = request.files.get("imagen")

        if not nombre or not precio or not stock:
            flash("Nombre, precio y stock son obligatorios.", "danger")
            return redirect(url_for("admin_product_edit", product_id=product_id))

        try:
            precio_num = float(precio)
            stock_num = int(stock)
            stock_minimo_num = int(stock_minimo)

            if precio_num < 0 or stock_num < 0 or stock_minimo_num < 0:
                flash("Precio/stock no pueden ser negativos.", "danger")
                return redirect(url_for("admin_product_edit", product_id=product_id))

        except ValueError:
            flash("Precio debe ser número y stock/stock mínimo deben ser enteros.", "danger")
            return redirect(url_for("admin_product_edit", product_id=product_id))

        image_filename = p["image_filename"]

        if imagen and imagen.filename:
            if not allowed_file(imagen.filename):
                flash("Formato de imagen no permitido.", "danger")
                return redirect(url_for("admin_product_edit", product_id=product_id))

            filename_img = secure_filename(imagen.filename)
            unique_name = f"{int(datetime.now().timestamp())}_{filename_img}"

            upload_folder_abs = app.config["UPLOAD_FOLDER"]
            os.makedirs(upload_folder_abs, exist_ok=True)

            imagen.save(os.path.join(upload_folder_abs, unique_name))
            image_filename = unique_name

        db.execute(
            """
            UPDATE products
            SET nombre = ?, precio = ?, stock = ?, stock_minimo = ?, activo = ?, image_filename = ?
            WHERE id = ?
            """,
            (nombre, precio_num, stock_num, stock_minimo_num, activo, image_filename, product_id)
        )

        registrar_auditoria(
            "Editar producto",
            f"Producto ID {product_id}. Nombre: {nombre}. Precio: ₡{precio_num:,.2f}. Stock: {stock_num}. Stock mínimo: {stock_minimo_num}. Estado: {'activo' if activo == 1 else 'inactivo'}."
        )

        db.commit()

        flash("✅ Producto actualizado.", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin_product_edit.html", p=p)


# =====================================================
# REPORTES
# =====================================================
@app.route("/admin/reports/sales")
def admin_report_sales():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    pago = (request.args.get("pago") or "").strip().lower().replace("é", "e")

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    if pago in ("contado", "credito"):
        where.append("replace(lower(trim(o.tipo_pago)), 'é', 'e') = ?")
        params.append(pago)

    where_sql = "WHERE " + " AND ".join(where)

    db = get_db()

    resumen = db.execute(
        f"""
        SELECT
            COUNT(*) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_general,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'contado' THEN o.total
                ELSE 0
            END), 0) AS total_contado,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'credito' THEN o.total
                ELSE 0
            END), 0) AS total_credito
        FROM orders o
        {where_sql}
        """,
        params
    ).fetchone()

    orders = db.execute(
        f"""
        SELECT
            o.id,
            o.fecha,
            o.tipo_pago,
            o.estado,
            o.total,
            COALESCE(u.nombre, o.nombre_no_asociado, 'Sin nombre') AS comprador
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    return render_template(
        "admin_report_sales.html",
        start=start,
        end=end,
        pago=pago,
        resumen=resumen,
        orders=orders
    )


@app.route("/admin/reports/sales/export")
def admin_report_sales_export():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()
    pago = (request.args.get("pago") or "").strip().lower().replace("é", "e")

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    if pago in ("contado", "credito"):
        where.append("replace(lower(trim(o.tipo_pago)), 'é', 'e') = ?")
        params.append(pago)

    where_sql = "WHERE " + " AND ".join(where)

    db = get_db()

    resumen = db.execute(
        f"""
        SELECT
            COUNT(*) AS num_ordenes,
            COALESCE(SUM(o.total), 0) AS total_general,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'contado' THEN o.total
                ELSE 0
            END), 0) AS total_contado,
            COALESCE(SUM(CASE
                WHEN replace(lower(trim(o.tipo_pago)), 'é', 'e') = 'credito' THEN o.total
                ELSE 0
            END), 0) AS total_credito
        FROM orders o
        {where_sql}
        """,
        params
    ).fetchone()

    orders = db.execute(
        f"""
        SELECT
            o.id,
            o.fecha,
            COALESCE(u.nombre, o.nombre_no_asociado, 'Sin nombre') AS comprador,
            o.tipo_pago,
            o.estado,
            o.total
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        {where_sql}
        ORDER BY o.id DESC
        """,
        params
    ).fetchall()

    wb = Workbook()
    ws = wb.active
    ws.title = "Reporte ventas"

    fill_header = PatternFill("solid", fgColor="1F2328")
    fill_title = PatternFill("solid", fgColor="EAF2F8")
    font_header = Font(color="FFFFFF", bold=True)
    font_title = Font(bold=True, size=14)
    font_bold = Font(bold=True)
    alignment_center = Alignment(horizontal="center", vertical="center")
    alignment_left = Alignment(horizontal="left", vertical="center")

    thin_border = Border(
        left=Side(style="thin", color="D9DEE3"),
        right=Side(style="thin", color="D9DEE3"),
        top=Side(style="thin", color="D9DEE3"),
        bottom=Side(style="thin", color="D9DEE3")
    )

    ws.merge_cells("A1:F1")
    ws["A1"] = "Reporte de ventas - ASERVE"
    ws["A1"].font = font_title
    ws["A1"].fill = fill_title
    ws["A1"].alignment = alignment_left

    ws["A3"] = "Desde"
    ws["B3"] = start
    ws["C3"] = "Hasta"
    ws["D3"] = end
    ws["E3"] = "Tipo de pago"
    ws["F3"] = pago if pago else "Todos"

    for cell in ws[3]:
        cell.border = thin_border
        cell.alignment = alignment_center
        cell.font = font_bold

    ws["A5"] = "Resumen"
    ws["A5"].font = font_bold
    ws["A5"].fill = fill_title
    ws["A5"].alignment = alignment_left

    ws["A6"] = "Órdenes"
    ws["B6"] = resumen["num_ordenes"]

    ws["A7"] = "Total general"
    ws["B7"] = float(resumen["total_general"])

    ws["A8"] = "Contado"
    ws["B8"] = float(resumen["total_contado"])

    ws["A9"] = "Crédito"
    ws["B9"] = float(resumen["total_credito"])

    for row in ws.iter_rows(min_row=5, max_row=9, min_col=1, max_col=2):
        for cell in row:
            cell.border = thin_border
            cell.alignment = alignment_left

    for row_num in range(6, 10):
        ws.cell(row=row_num, column=1).font = font_bold

    ws["B7"].number_format = '"₡"#,##0.00'
    ws["B8"].number_format = '"₡"#,##0.00'
    ws["B9"].number_format = '"₡"#,##0.00'

    start_row = 11
    headers = ["Orden", "Fecha", "Comprador", "Pago", "Estado", "Total"]

    for col_num, header in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=col_num)
        cell.value = header
        cell.fill = fill_header
        cell.font = font_header
        cell.alignment = alignment_center
        cell.border = thin_border

    current_row = start_row + 1

    for o in orders:
        ws.cell(row=current_row, column=1).value = f"#{o['id']}"
        ws.cell(row=current_row, column=2).value = o["fecha"]
        ws.cell(row=current_row, column=3).value = o["comprador"]
        ws.cell(row=current_row, column=4).value = o["tipo_pago"]
        ws.cell(row=current_row, column=5).value = o["estado"]
        ws.cell(row=current_row, column=6).value = float(o["total"])

        for col in range(1, 7):
            cell = ws.cell(row=current_row, column=col)
            cell.border = thin_border
            cell.alignment = alignment_left

        ws.cell(row=current_row, column=6).number_format = '"₡"#,##0.00'
        current_row += 1

    if not orders:
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=6)
        ws.cell(row=current_row, column=1).value = "Sin datos para el filtro seleccionado."
        ws.cell(row=current_row, column=1).alignment = alignment_center

    widths = {
        "A": 12,
        "B": 22,
        "C": 35,
        "D": 15,
        "E": 15,
        "F": 16,
    }

    for col_letter, width in widths.items():
        ws.column_dimensions[col_letter].width = width

    ws.freeze_panes = "A12"

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    filename = f"reporte_ventas_{start}_a_{end}.xlsx"

    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.route("/admin/reports/top-products")
def admin_report_top_products():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)

    if not start:
        start = hace_14.strftime("%Y-%m-%d")

    if not end:
        end = hoy.strftime("%Y-%m-%d")

    where = []
    params = []

    where.append("date(o.fecha) >= date(?)")
    params.append(start)

    where.append("date(o.fecha) <= date(?)")
    params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    db = get_db()

    top = db.execute(
        f"""
        SELECT
            p.id,
            p.nombre,
            SUM(oi.cantidad) AS unidades,
            COALESCE(SUM(oi.cantidad * oi.precio_unitario), 0) AS monto
        FROM order_items oi
        JOIN orders o ON o.id = oi.order_id
        JOIN products p ON p.id = oi.product_id
        {where_sql}
        GROUP BY p.id, p.nombre
        ORDER BY unidades DESC, monto DESC
        LIMIT 20
        """,
        params
    ).fetchall()

    return render_template(
        "admin_report_top_products.html",
        start=start,
        end=end,
        top=top
    )


# =====================================================
# CATÁLOGO
# - Muestra únicamente productos activos y con stock
# - Permite búsqueda por nombre
# - Evita mostrar productos sin disponibilidad
# =====================================================
@app.route("/catalogo")
def catalogo():
    db = get_db()

    q = (request.args.get("q") or "").strip()

    where = [
        "activo = 1",
        "stock > 0"
    ]

    params = []

    if q:
        where.append("nombre LIKE ?")
        params.append(f"%{q}%")

    where_sql = "WHERE " + " AND ".join(where)

    productos = db.execute(
        f"""
        SELECT
            id,
            nombre,
            precio,
            stock,
            stock_minimo,
            activo,
            image_filename
        FROM products
        {where_sql}
        ORDER BY nombre ASC
        """,
        params
    ).fetchall()

    return render_template(
        "catalogo.html",
        productos=productos,
        q=q
    )

# =====================================================
# CARRITO
# =====================================================
def get_cart():
    if "cart" not in session:
        session["cart"] = {}

    return session["cart"]


# =====================================================
# CARRITO: VER CARRITO
# - Limpia productos que ya no existen
# - Quita productos inactivos
# - Quita productos sin stock
# - Ajusta cantidades si superan el stock actual
# =====================================================
@app.route("/carrito")
def ver_carrito():
    cart = get_cart()

    if not cart:
        return render_template("carrito.html", items=[], total=0)

    db = get_db()

    ids = list(cart.keys())
    placeholders = ",".join(["?"] * len(ids))

    productos = db.execute(
        f"""
        SELECT *
        FROM products
        WHERE id IN ({placeholders})
        """,
        ids
    ).fetchall()

    productos_map = {str(p["id"]): p for p in productos}

    items = []
    total = 0
    cart_limpio = {}
    hubo_ajustes = False

    for pid, cantidad_cart in cart.items():
        p = productos_map.get(str(pid))

        # Si el producto ya no existe en base de datos, se elimina del carrito
        if not p:
            hubo_ajustes = True
            continue

        # Validar cantidad del carrito
        try:
            cantidad = int(cantidad_cart)
        except ValueError:
            hubo_ajustes = True
            continue

        # Si la cantidad es inválida, se elimina del carrito
        if cantidad <= 0:
            hubo_ajustes = True
            continue

        # Si el producto está inactivo, se elimina del carrito
        if int(p["activo"]) != 1:
            hubo_ajustes = True
            continue

        stock_disponible = int(p["stock"])

        # Si el producto no tiene stock, se elimina del carrito
        if stock_disponible <= 0:
            hubo_ajustes = True
            continue

        # Si el carrito tiene más cantidad que el stock disponible, se ajusta
        if cantidad > stock_disponible:
            cantidad = stock_disponible
            hubo_ajustes = True

        subtotal = float(p["precio"]) * cantidad
        total += subtotal

        cart_limpio[str(p["id"])] = cantidad

        items.append({
            "id": p["id"],
            "nombre": p["nombre"],
            "precio": float(p["precio"]),
            "stock": stock_disponible,
            "image_filename": p["image_filename"],
            "cantidad": cantidad,
            "subtotal": subtotal
        })

    session["cart"] = cart_limpio

    if hubo_ajustes:
        flash(
            "El carrito fue actualizado porque algunos productos cambiaron de disponibilidad o stock.",
            "warning"
        )

    return render_template("carrito.html", items=items, total=total)


# =====================================================
# CARRITO: AGREGAR PRODUCTO
# =====================================================
@app.route("/carrito/add/<int:product_id>", methods=["POST"])
def carrito_add(product_id):
    db = get_db()

    p = db.execute(
        """
        SELECT *
        FROM products
        WHERE id = ?
          AND activo = 1
        """,
        (product_id,)
    ).fetchone()

    if not p:
        flash("Producto no disponible.", "danger")
        return redirect(url_for("catalogo"))

    if int(p["stock"]) <= 0:
        flash("Este producto no tiene stock disponible.", "warning")
        return redirect(url_for("catalogo"))

    cart = get_cart()
    pid = str(product_id)

    try:
        cantidad_actual = int(cart.get(pid, 0))
    except ValueError:
        cantidad_actual = 0

    if cantidad_actual + 1 > int(p["stock"]):
        flash("No hay suficiente stock para agregar más.", "warning")
        return redirect(url_for("catalogo"))

    cart[pid] = cantidad_actual + 1
    session["cart"] = cart

    flash("Producto agregado al carrito.", "success")
    return redirect(url_for("catalogo"))


# =====================================================
# CARRITO: AUMENTAR CANTIDAD
# =====================================================
@app.route("/carrito/inc/<int:product_id>", methods=["POST"])
def carrito_inc(product_id):
    db = get_db()

    p = db.execute(
        """
        SELECT *
        FROM products
        WHERE id = ?
          AND activo = 1
        """,
        (product_id,)
    ).fetchone()

    if not p:
        flash("Producto no disponible.", "danger")
        return redirect(url_for("ver_carrito"))

    if int(p["stock"]) <= 0:
        flash("Este producto ya no tiene stock disponible.", "warning")
        return redirect(url_for("ver_carrito"))

    cart = get_cart()
    pid = str(product_id)

    try:
        cantidad_actual = int(cart.get(pid, 0))
    except ValueError:
        cantidad_actual = 0

    if cantidad_actual + 1 > int(p["stock"]):
        flash("No hay suficiente stock.", "warning")
        return redirect(url_for("ver_carrito"))

    cart[pid] = cantidad_actual + 1
    session["cart"] = cart

    return redirect(url_for("ver_carrito"))


# =====================================================
# CARRITO: DISMINUIR CANTIDAD
# =====================================================
@app.route("/carrito/dec/<int:product_id>", methods=["POST"])
def carrito_dec(product_id):
    cart = get_cart()
    pid = str(product_id)

    try:
        cantidad_actual = int(cart.get(pid, 0))
    except ValueError:
        cantidad_actual = 0

    if cantidad_actual <= 1:
        cart.pop(pid, None)
    else:
        cart[pid] = cantidad_actual - 1

    session["cart"] = cart

    return redirect(url_for("ver_carrito"))


# =====================================================
# CARRITO: ELIMINAR PRODUCTO
# =====================================================
@app.route("/carrito/remove/<int:product_id>", methods=["POST"])
def carrito_remove(product_id):
    cart = get_cart()
    cart.pop(str(product_id), None)

    session["cart"] = cart

    return redirect(url_for("ver_carrito"))


# =====================================================
# CARRITO: VACIAR CARRITO
# =====================================================
@app.route("/carrito/clear", methods=["POST"])
def carrito_clear():
    session["cart"] = {}
    flash("Carrito vaciado.", "info")

    return redirect(url_for("ver_carrito"))
# =====================================================
# CHECKOUT
# - Valida stock antes de confirmar
# - Evita doble compra con token interno
# - Calcula total siempre desde base de datos
# - Usa bloqueo transaccional para proteger inventario
# =====================================================
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    cart = get_cart()

    if not cart:
        flash("Tu carrito está vacío.", "info")
        return redirect(url_for("catalogo"))

    db = get_db()

    # =====================================================
    # GET: mostrar pantalla de confirmación
    # =====================================================
    if request.method == "GET":
        ids = list(cart.keys())
        placeholders = ",".join(["?"] * len(ids))

        productos = db.execute(
            f"SELECT * FROM products WHERE id IN ({placeholders})",
            ids
        ).fetchall()

        productos_map = {str(p["id"]): p for p in productos}

        items = []
        total = 0

        for pid, cantidad_cart in cart.items():
            p = productos_map.get(str(pid))

            if not p:
                flash("Uno de los productos del carrito ya no existe.", "warning")
                return redirect(url_for("ver_carrito"))

            cantidad = int(cantidad_cart)

            if cantidad <= 0:
                flash("Hay una cantidad inválida en el carrito.", "warning")
                return redirect(url_for("ver_carrito"))

            if int(p["activo"]) != 1:
                flash(f"El producto '{p['nombre']}' ya no está disponible.", "warning")
                return redirect(url_for("ver_carrito"))

            if cantidad > int(p["stock"]):
                flash(f"No hay stock suficiente de '{p['nombre']}'.", "warning")
                return redirect(url_for("ver_carrito"))

            subtotal = float(p["precio"]) * cantidad
            total += subtotal

            items.append({
                "id": p["id"],
                "nombre": p["nombre"],
                "precio": float(p["precio"]),
                "cantidad": cantidad,
                "subtotal": subtotal
            })

        user_id = session.get("user_id")
        rol = session.get("rol")

        es_no_asociado = True if not user_id else False
        can_credit = True if (user_id and rol in ("admin", "asociado")) else False

        # Token interno para evitar doble submit
        checkout_token = secrets.token_urlsafe(24)
        session["checkout_token"] = checkout_token

        return render_template(
            "checkout.html",
            items=items,
            total=total,
            rol=rol,
            es_no_asociado=es_no_asociado,
            can_credit=can_credit,
            checkout_token=checkout_token
        )

    # =====================================================
    # POST: confirmar compra
    # =====================================================
    token_form = (request.form.get("checkout_token") or "").strip()
    token_session = session.get("checkout_token")

    if not token_session or token_form != token_session:
        flash("Esta compra ya fue procesada o el formulario expiró. Revisá tu carrito antes de continuar.", "warning")
        return redirect(url_for("ver_carrito"))

    tipo_pago = norm_text(request.form.get("tipo_pago"))
    nombre_no_asociado = (request.form.get("nombre_no_asociado") or "").strip()

    if tipo_pago not in ("contado", "credito"):
        flash("Tipo de pago inválido.", "danger")
        return redirect(url_for("checkout"))

    user_id = session.get("user_id")
    rol = session.get("rol")
    tipo_usuario = "asociado" if user_id else "no_asociado"

    if tipo_usuario == "no_asociado":
        if tipo_pago != "contado":
            flash("Solo usuarios registrados pueden comprar a crédito.", "danger")
            return redirect(url_for("checkout"))

        if not nombre_no_asociado:
            flash("Debes escribir tu nombre para finalizar la compra.", "danger")
            return redirect(url_for("checkout"))

    if tipo_usuario == "asociado" and tipo_pago == "credito":
        if rol not in ("admin", "asociado"):
            flash("Tu usuario no tiene permiso para comprar a crédito.", "danger")
            return redirect(url_for("checkout"))

    try:
        # Bloqueo de escritura para evitar que dos compras descuenten el mismo stock al mismo tiempo
        db.execute("BEGIN IMMEDIATE")

        ids = list(cart.keys())
        placeholders = ",".join(["?"] * len(ids))

        productos = db.execute(
            f"SELECT * FROM products WHERE id IN ({placeholders})",
            ids
        ).fetchall()

        productos_map = {str(p["id"]): p for p in productos}

        items = []
        total = 0

        for pid, cantidad_cart in cart.items():
            p = productos_map.get(str(pid))

            if not p:
                db.rollback()
                flash("Uno de los productos del carrito ya no existe.", "warning")
                return redirect(url_for("ver_carrito"))

            cantidad = int(cantidad_cart)

            if cantidad <= 0:
                db.rollback()
                flash("Hay una cantidad inválida en el carrito.", "warning")
                return redirect(url_for("ver_carrito"))

            if int(p["activo"]) != 1:
                db.rollback()
                flash(f"El producto '{p['nombre']}' ya no está disponible.", "warning")
                return redirect(url_for("ver_carrito"))

            if cantidad > int(p["stock"]):
                db.rollback()
                flash(f"No hay stock suficiente de '{p['nombre']}'. Stock disponible: {p['stock']}.", "warning")
                return redirect(url_for("ver_carrito"))

            subtotal = float(p["precio"]) * cantidad
            total += subtotal

            items.append({
                "id": p["id"],
                "nombre": p["nombre"],
                "precio": float(p["precio"]),
                "cantidad": cantidad,
                "subtotal": subtotal
            })

        estado = "pagada" if tipo_pago == "contado" else "pendiente"
        fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cur = db.execute(
            """
            INSERT INTO orders (fecha, tipo_usuario, user_id, nombre_no_asociado, tipo_pago, total, estado)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fecha,
                tipo_usuario,
                user_id if tipo_usuario == "asociado" else None,
                nombre_no_asociado if tipo_usuario == "no_asociado" else None,
                tipo_pago,
                float(total),
                estado
            )
        )

        order_id = cur.lastrowid

        for it in items:
            db.execute(
                """
                INSERT INTO order_items (order_id, product_id, cantidad, precio_unitario)
                VALUES (?, ?, ?, ?)
                """,
                (order_id, it["id"], it["cantidad"], float(it["precio"]))
            )

            db.execute(
                """
                UPDATE products
                SET stock = stock - ?
                WHERE id = ?
                """,
                (it["cantidad"], it["id"])
            )

            db.execute(
                """
                INSERT INTO stock_movements (product_id, cambio_stock, motivo, fecha, order_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (it["id"], -it["cantidad"], "Venta", fecha, order_id)
            )

        db.commit()

        # Limpiar carrito y token para que no se pueda reenviar la misma compra
        session["cart"] = {}
        session.pop("checkout_token", None)

        flash(f"✅ Compra realizada. Orden #{order_id} creada.", "success")
        return redirect(url_for("order_success", order_id=order_id))

    except Exception as e:
        db.rollback()
        print("Error en checkout:", e)
        flash("Ocurrió un error al procesar la compra. Intentá nuevamente.", "danger")
        return redirect(url_for("ver_carrito"))

# =====================================================
# ORDEN SUCCESS
# =====================================================
@app.route("/orden/<int:order_id>")
def order_success(order_id):
    db = get_db()

    orden = db.execute(
        """
        SELECT
            o.*,
            u.nombre AS nombre_usuario
        FROM orders o
        LEFT JOIN users u ON u.id = o.user_id
        WHERE o.id = ?
        """,
        (order_id,)
    ).fetchone()

    if not orden:
        flash("Orden no encontrada.", "danger")
        return redirect(url_for("catalogo"))

    comprador = orden["nombre_usuario"] if orden["user_id"] else orden["nombre_no_asociado"]

    items = db.execute(
        """
        SELECT
            p.nombre,
            oi.cantidad,
            oi.precio_unitario,
            (oi.cantidad * oi.precio_unitario) AS subtotal
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
        """,
        (order_id,)
    ).fetchall()

    return render_template(
        "order_success.html",
        orden=orden,
        items=items,
        comprador=comprador
    )


# =====================================================
# EJECUCIÓN LOCAL
# =====================================================
if __name__ == "__main__":
    os.makedirs(app.instance_path, exist_ok=True)

    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"

    app.run(debug=debug_mode)