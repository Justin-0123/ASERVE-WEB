# =====================================================
# IMPORTS GENERALES
# Se importan librerías necesarias para:
# - Flask (rutas, plantillas, sesiones, mensajes flash)
# - Base de datos SQLite
# - Seguridad (bcrypt)
# - Manejo de archivos (imágenes)
# - Fechas para registrar órdenes y nombres únicos de imágenes
# =====================================================
import os
import sqlite3
import bcrypt
from datetime import datetime

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, g
)

from werkzeug.utils import secure_filename


# =====================================================
# CONFIGURACIÓN PRINCIPAL DE FLASK
# =====================================================
app = Flask(__name__)

# Clave para manejar sesiones (en producción debe ser segura)
app.secret_key = "clave_secreta_aserve"

# Ruta de la base de datos SQLite (se guarda en /instance/aserve.db)
app.config["DATABASE"] = os.path.join(app.instance_path, "aserve.db")

# Configuración para subida de imágenes de productos
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "webp"}


# =====================================================
# FUNCIONES DE BASE DE DATOS
# =====================================================
def get_db():
    """
    Devuelve una conexión a la base de datos.
    Usa 'g' para mantener una sola conexión por request.
    """
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """
    Cierra la conexión a la base de datos al finalizar cada request.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


# =====================================================
# FUNCIÓN AUXILIAR PARA VALIDAR IMÁGENES
# =====================================================
def allowed_file(filename):
    """
    Verifica que el archivo tenga una extensión permitida
    para subir como imagen.
    """
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


# =====================================================
# FUNCIÓN AUXILIAR: NORMALIZAR TEXTO (PAGOS / ESTADOS)
# - Quita espacios
# - Pasa a minúsculas
# - Reemplaza "é" por "e" (por si llega "crédito")
# =====================================================
def norm_text(value):
    value = (value or "").strip().lower()
    value = value.replace("é", "e")
    return value


# =====================================================
# COMANDOS DE CONSOLA (FLASK CLI)
# =====================================================
@app.cli.command("init-db")
def init_db_command():
    """
    Inicializa la base de datos ejecutando schema.sql
    """
    os.makedirs(app.instance_path, exist_ok=True)
    db = get_db()
    with app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    db.commit()
    print("✅ Base de datos inicializada correctamente.")


@app.cli.command("create-admin")
def create_admin_command():
    """
    Crea el usuario administrador inicial si no existe
    """
    db = get_db()

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

    db.execute(
        "INSERT INTO users (nombre, usuario, contrasena_hash, rol, estado) VALUES (?, ?, ?, ?, ?)",
        (nombre, usuario, hash_pw, "admin", "activo")
    )
    db.commit()

    print("✅ Admin creado correctamente.")
    print("Usuario: admin | Contraseña: Admin1234")


# =====================================================
# RUTA: /
# Pantalla principal: redirige al catálogo
# =====================================================
@app.route("/")
def inicio():
    return redirect(url_for("catalogo"))


# =====================================================
# LOGIN
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Maneja el inicio de sesión:
    - GET: muestra formulario
    - POST: valida usuario y contraseña
    """
    if request.method == "POST":
        usuario = (request.form.get("usuario") or "").strip()
        contrasena = (request.form.get("contrasena") or "").strip()

        db = get_db()
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

        # Guardar datos en sesión
        session["user_id"] = user["id"]
        session["nombre"] = user["nombre"]
        session["rol"] = user["rol"]

        flash(f"Bienvenido/a, {user['nombre']}!", "success")

        # ✅ Redirección según rol
        if user["rol"] == "admin":
            return redirect(url_for("admin_panel"))

        return redirect(url_for("catalogo"))

    return render_template("login.html")
# =====================================================
# LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    """
    Cierra la sesión del usuario
    """
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))

# =====================================================
# PERFIL (ASOCIADO/ADMIN LOGUEADO)
# Ruta: /perfil
# - Muestra datos del usuario en sesión
# - Permite cambiar contraseña (POST)
# =====================================================
@app.route("/perfil", methods=["GET", "POST"])
def perfil():
    # -----------------------------------------------------
    # Seguridad: requiere sesión
    # (No aplica para "no asociado" porque no tiene cuenta)
    # -----------------------------------------------------
    if "user_id" not in session:
        flash("Debes iniciar sesión para ver tu perfil.", "warning")
        return redirect(url_for("login"))

    db = get_db()

    # -----------------------------------------------------
    # Traer datos actuales del usuario
    # -----------------------------------------------------
    user_id = session["user_id"]
    user = db.execute(
        "SELECT id, nombre, usuario, rol, estado FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        session.clear()
        flash("Sesión inválida. Inicia sesión nuevamente.", "danger")
        return redirect(url_for("login"))

    # -----------------------------------------------------
    # POST: Cambio de contraseña desde perfil
    # -----------------------------------------------------
    if request.method == "POST":
        actual = (request.form.get("password_actual") or "").strip()
        nueva = (request.form.get("password_nueva") or "").strip()
        confirmar = (request.form.get("password_confirmar") or "").strip()

        # Validaciones básicas
        if not actual or not nueva or not confirmar:
            flash("Completa todos los campos para cambiar contraseña.", "danger")
            return redirect(url_for("perfil"))

        if nueva != confirmar:
            flash("La nueva contraseña y su confirmación no coinciden.", "danger")
            return redirect(url_for("perfil"))

        if len(nueva) < 6:
            flash("La nueva contraseña debe tener al menos 6 caracteres.", "warning")
            return redirect(url_for("perfil"))

        # Verificar contraseña actual
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

        # Guardar nueva contraseña (bcrypt)
        nuevo_hash = bcrypt.hashpw(nueva.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db.execute(
            "UPDATE users SET contrasena_hash = ? WHERE id = ?",
            (nuevo_hash, user_id)
        )
        db.commit()

        flash("✅ Contraseña actualizada correctamente.", "success")
        return redirect(url_for("perfil"))

    # GET: mostrar perfil
    return render_template("perfil.html", user=user)
# -----------------------------------------------------
    # POST: ADMIN USERS ESTADOS
    # -----------------------------------------------------
@app.route("/admin/users")
def admin_users():
    # Seguridad: solo admin
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    usuarios = db.execute("""
        SELECT id, nombre, usuario, rol, estado
        FROM users
        ORDER BY nombre
    """).fetchall()

    return render_template("admin_users.html", usuarios=usuarios)
# =====================================================
# MIS COMPRAS (HISTORIAL DEL USUARIO LOGUEADO)
# Ruta: /mis-compras
# - Lista compras del usuario logueado
# - Filtros: tipo_pago (contado/credito) + fechas
# =====================================================
@app.route("/mis-compras")
def mis_compras():
    if "user_id" not in session:
        flash("Debes iniciar sesión para ver tu historial.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    db = get_db()

    # -----------------------------------------------------
    # Filtros desde querystring
    # ?pago=contado|credito&start=YYYY-MM-DD&end=YYYY-MM-DD
    # -----------------------------------------------------
    pago = (request.args.get("pago") or "").strip().lower()
    pago = pago.replace("é", "e")  # por si llega "crédito"

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    where = ["o.user_id = ?"]
    params = [user_id]

    if pago in ("contado", "credito"):
        where.append("lower(trim(o.tipo_pago)) = ?")
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
# =====================================================
# MIS COMPRAS (DETALLE)
# Ruta: /mis-compras/<id>
# - Muestra detalle de orden SOLO si pertenece al usuario
# =====================================================
@app.route("/mis-compras/<int:order_id>")
def mis_compras_detalle(order_id):
    if "user_id" not in session:
        flash("Debes iniciar sesión.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]
    db = get_db()

    # Orden: debe pertenecer al usuario
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

    # Items de la orden
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
# PANEL ADMINISTRADOR
# =====================================================
@app.route("/admin")
def admin_panel():
    # Seguridad
    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("rol") != "admin":
        flash("No tienes permisos.", "danger")
        return redirect(url_for("inicio"))

    db = get_db()

    # =========================
    # CONTADORES (KPIs)
    # =========================

    # 1) Créditos pendientes (robusto por normalización)
    creditos_pendientes = db.execute("""
        SELECT COUNT(*) AS n
        FROM orders
        WHERE lower(trim(tipo_pago)) IN ('credito', 'crédito')
          AND lower(trim(estado)) = 'pendiente'
    """).fetchone()["n"]

    # 2) Productos con stock bajo (<= mínimo) y activos
    stock_bajo = db.execute("""
        SELECT COUNT(*) AS n
        FROM products
        WHERE activo = 1
          AND stock_minimo > 0
          AND stock <= stock_minimo
    """).fetchone()["n"]

    # 3) Usuarios bloqueados
    usuarios_bloqueados = db.execute("""
        SELECT COUNT(*) AS n
        FROM users
        WHERE estado = 'bloqueado'
    """).fetchone()["n"]

    # 4) Órdenes últimos 14 días (incluyendo hoy)
    ordenes_14 = db.execute("""
        SELECT COUNT(*) AS n
        FROM orders
        WHERE date(fecha) >= date('now','-14 day')
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
# ADMIN: USUARIOS (EDITAR)
# Ruta: /admin/users/<id>/edit
# - Permite cambiar nombre, usuario, rol, estado
# - (Opcional) reset password si viene un valor
# =====================================================
@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
def admin_user_edit(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
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

        # Validar usuario único (excepto el mismo)
        existe = db.execute(
            "SELECT id FROM users WHERE usuario = ? AND id <> ?",
            (usuario, user_id)
        ).fetchone()
        if existe:
            flash("Ese usuario ya está en uso por otra cuenta.", "warning")
            return redirect(url_for("admin_user_edit", user_id=user_id))

        # Update básico
        db.execute(
            """
            UPDATE users
            SET nombre = ?, usuario = ?, rol = ?, estado = ?
            WHERE id = ?
            """,
            (nombre, usuario, rol, estado, user_id)
        )

        # Reset password (si viene)
        if new_password:
            hash_pw = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            db.execute(
                "UPDATE users SET contrasena_hash = ? WHERE id = ?",
                (hash_pw, user_id)
            )

        db.commit()
        flash("Usuario actualizado correctamente.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin_user_edit.html", u=u)
# =====================================================
# ADMIN: USUARIOS (BLOQUEAR / DESBLOQUEAR)
# Ruta: POST /admin/users/<id>/toggle
# =====================================================
@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
def admin_user_toggle(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    # Evitar que el admin se bloquee a sí mismo
    if session.get("user_id") == user_id:
        flash("No podés bloquear tu propia cuenta.", "warning")
        return redirect(url_for("admin_users"))

    db = get_db()
    u = db.execute("SELECT id, estado FROM users WHERE id = ?", (user_id,)).fetchone()
    if not u:
        flash("Usuario no encontrado.", "danger")
        return redirect(url_for("admin_users"))

    nuevo_estado = "activo" if u["estado"] == "bloqueado" else "bloqueado"
    db.execute("UPDATE users SET estado = ? WHERE id = ?", (nuevo_estado, user_id))
    db.commit()

    flash(f"Estado actualizado a: {nuevo_estado}", "success")
    return redirect(url_for("admin_users"))
# =====================================================
# ADMIN: HISTORIAL DE ÓRDENES (lista general con filtros)
# =====================================================
from datetime import datetime, timedelta

@app.route("/admin/orders")
def admin_orders():
    # Seguridad: solo admin
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    # Filtros
    estado = request.args.get("estado", "").strip()
    pago = request.args.get("pago", "").strip()
    q = request.args.get("q", "").strip()

    # ✅ NUEVO: fechas (YYYY-MM-DD)
    start = request.args.get("start", "").strip()
    end = request.args.get("end", "").strip()

    # ✅ DEFAULT: últimos 14 días si no mandan fechas
    hoy = datetime.now().date()
    hace_14 = hoy - timedelta(days=13)  # hoy incluido => 14 días (0..13)

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
        where.append("o.tipo_pago = ?")
        params.append(pago)

    if q:
        where.append("(u.nombre LIKE ? OR o.nombre_no_asociado LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])

    # ✅ NUEVO: filtro por rango de fechas (date(o.fecha))
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
        start=start,   # ✅ pasar al template
        end=end        # ✅ pasar al template
    )
# =====================================================
# ADMIN: DETALLE DE ORDEN
# - Incluye "from_page" para volver a credits u orders
# =====================================================
@app.route("/admin/orders/<int:order_id>")
def admin_order_detail(order_id):
    # Seguridad: solo admin
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    # Traer orden y comprador
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

    # Items de la orden
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

    # 🔑 CONTEXTO DE NAVEGACIÓN
    from_page = request.args.get("from_page", "orders")   # orders | credits
    back_user_id = request.args.get("user_id", "").strip() # si viene desde credits/user/<id>

    return render_template(
        "admin_order_detail.html",
        orden=orden,
        items=items,
        from_page=from_page,
        back_user_id=back_user_id
    )
# =====================================================
# ADMIN: LISTA DE COMPRADORES (registrados + no asociados)
# =====================================================
@app.route("/admin/buyers")
def admin_buyers():
    """
    Muestra compradores agrupados:
    - Registrados (users)
    - No asociados (nombre_no_asociado)
    Con cantidad de órdenes y monto total acumulado.
    """
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


# =====================================================
# ADMIN: HISTORIAL POR COMPRADOR (contado + crédito + filtro fechas)
# =====================================================
@app.route("/admin/buyer")
def admin_buyer_history():
    """
    Muestra todas las órdenes de un comprador (contado + crédito)
    Permite filtrar por rango de fechas y calcula total del rango.
    """
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    key = request.args.get("key", "").strip()
    start = request.args.get("start", "").strip()  # YYYY-MM-DD
    end = request.args.get("end", "").strip()      # YYYY-MM-DD

    if not key:
        flash("Comprador inválido.", "danger")
        return redirect(url_for("admin_buyers"))

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

        u = db.execute("SELECT nombre FROM users WHERE id = ?", (user_id,)).fetchone()
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

    if start:
        where.append("date(o.fecha) >= date(?)")
        params.append(start)

    if end:
        where.append("date(o.fecha) <= date(?)")
        params.append(end)

    where_sql = "WHERE " + " AND ".join(where)

    orders = db.execute(
        f"""
        SELECT
            o.id, o.fecha, o.tipo_pago, o.estado, o.total
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
# =====================================================
# ADMIN: CRÉDITOS (RESUMEN POR COLABORADOR)
# Ruta: /admin/credits
# - Agrupa créditos pendientes por usuario
# - Muestra: # de órdenes pendientes y deuda total
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


# =====================================================
# ADMIN: CRÉDITOS POR COLABORADOR (DETALLE)
# Ruta: /admin/credits/user/<user_id>
# - Lista las órdenes a crédito pendientes del colaborador
# - Muestra deuda total (sumatoria)
# =====================================================
@app.route("/admin/credits/user/<int:user_id>")
def admin_credits_user(user_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    user = db.execute("SELECT id, nombre FROM users WHERE id = ?", (user_id,)).fetchone()
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
# =====================================================
# ADMIN: PAGAR CRÉDITOS EN BLOQUE (por colaborador)
# Ruta: POST /admin/credits/user/<user_id>/pay-bulk
# - Recibe lista de order_ids seleccionadas
# - Marca como pagadas solo las que sean crédito pendiente y del mismo user_id
# =====================================================
@app.route("/admin/credits/user/<int:user_id>/pay-bulk", methods=["POST"])
def admin_credits_pay_bulk(user_id):
    # Seguridad: solo admin
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    # Lista de ids seleccionados (checkboxes)
    order_ids = request.form.getlist("order_ids")

    if not order_ids:
        flash("No seleccionaste ninguna orden.", "warning")
        return redirect(url_for("admin_credits_user", user_id=user_id))

    # Convertir a ints de forma segura
    try:
        order_ids_int = [int(x) for x in order_ids]
    except ValueError:
        flash("Selección inválida.", "danger")
        return redirect(url_for("admin_credits_user", user_id=user_id))

    db = get_db()

    # Construir placeholders (?, ?, ?)
    placeholders = ",".join(["?"] * len(order_ids_int))

    # Actualiza SOLO las órdenes que:
    # - pertenezcan al user_id
    # - sean crédito
    # - estén pendientes
    cur = db.execute(
        f"""
        UPDATE orders
        SET estado = 'pagada'
        WHERE user_id = ?
          AND lower(trim(tipo_pago)) IN ('credito', 'crédito')
          AND lower(trim(estado)) = 'pendiente'
          AND id IN ({placeholders})
        """,
        [user_id] + order_ids_int
    )

    db.commit()

    flash(f"Se marcaron como pagadas {cur.rowcount} orden(es).", "success")
    return redirect(url_for("admin_credits_user", user_id=user_id))

# =====================================================
# ADMIN: MARCAR CRÉDITO COMO PAGADO
# Ruta: POST /admin/credits/pay/<order_id>
# - Marca la orden como pagada
# - Redirige de vuelta al detalle del colaborador
# =====================================================
@app.route("/admin/credits/pay/<int:order_id>", methods=["POST"])
def admin_credits_pay(order_id):
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()

    orden = db.execute(
        """
        SELECT id, user_id
        FROM orders
        WHERE id = ?
          AND replace(lower(trim(tipo_pago)), 'é', 'e') = 'credito'
          AND lower(trim(estado)) = 'pendiente'
        """,
        (order_id,)
    ).fetchone()

    if not orden:
        flash("Esa orden no existe o ya fue pagada.", "warning")
        return redirect(url_for("admin_credits"))

    db.execute("UPDATE orders SET estado = 'pagada' WHERE id = ?", (order_id,))
    db.commit()

    flash(f"Orden #{order_id} marcada como pagada.", "success")
    return redirect(url_for("admin_credits_user", user_id=orden["user_id"]))


# =====================================================
# MÓDULO 1: PRODUCTOS – LISTADO
# =====================================================
@app.route("/admin/products")
def admin_products():
    """
    Muestra todos los productos y detecta cuáles están por debajo del stock mínimo.
    """
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
    productos = db.execute("SELECT * FROM products ORDER BY id DESC").fetchall()

    productos_bajos = [
        p for p in productos
        if p["activo"] == 1 and p["stock_minimo"] > 0 and p["stock"] <= p["stock_minimo"]
    ]

    return render_template(
        "admin_products.html",
        productos=productos,
        bajos=productos_bajos
    )


# =====================================================
# MÓDULO 1: PRODUCTOS – AGREGAR
# =====================================================
@app.route("/admin/products/add", methods=["GET", "POST"])
def add_product():
    """
    Permite al administrador agregar un producto con imagen y stock mínimo personalizado.
    """
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":
        nombre = request.form.get("nombre")
        precio = request.form.get("precio")
        stock = request.form.get("stock")
        stock_minimo = request.form.get("stock_minimo", 0)
        imagen = request.files.get("imagen")

        precio = float(precio)
        stock = int(stock)
        stock_minimo = int(stock_minimo)

        image_filename = None

        if imagen and imagen.filename:
            if not allowed_file(imagen.filename):
                flash("Formato de imagen no permitido.", "danger")
                return redirect(url_for("add_product"))

            filename = secure_filename(imagen.filename)
            unique_name = f"{int(datetime.now().timestamp())}_{filename}"

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            imagen.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))
            image_filename = unique_name

        db = get_db()
        db.execute(
            """
            INSERT INTO products (nombre, precio, stock, stock_minimo, image_filename, activo)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (nombre, precio, stock, stock_minimo, image_filename)
        )
        db.commit()

        flash("Producto agregado correctamente.", "success")
        return redirect(url_for("admin_products"))

    return render_template("add_product.html")


# =====================================================
# MÓDULO 1: PRODUCTOS – EDITAR
# =====================================================
@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
def edit_product(product_id):
    """
    Permite al admin editar:
    - nombre, precio, stock, stock_minimo, activo
    - cambiar imagen opcionalmente
    """
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()

    if not p:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for("admin_products"))

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        precio = request.form.get("precio", "").strip()
        stock = request.form.get("stock", "").strip()
        stock_minimo = request.form.get("stock_minimo", "").strip()
        activo = 1 if request.form.get("activo") == "on" else 0
        imagen = request.files.get("imagen")

        if not nombre or not precio or not stock or not stock_minimo:
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("edit_product", product_id=product_id))

        try:
            precio_num = float(precio)
            stock_num = int(stock)
            stock_minimo_num = int(stock_minimo)
            if precio_num < 0 or stock_num < 0 or stock_minimo_num < 0:
                flash("Precio/stock no pueden ser negativos.", "danger")
                return redirect(url_for("edit_product", product_id=product_id))
        except ValueError:
            flash("Precio debe ser número y stock/stock mínimo enteros.", "danger")
            return redirect(url_for("edit_product", product_id=product_id))

        image_filename = p["image_filename"]

        if imagen and imagen.filename:
            if not allowed_file(imagen.filename):
                flash("Formato de imagen no permitido.", "danger")
                return redirect(url_for("edit_product", product_id=product_id))

            safe_name = secure_filename(imagen.filename)
            unique_name = f"{int(datetime.now().timestamp())}_{safe_name}"

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            imagen.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))
            image_filename = unique_name

        db.execute(
            """
            UPDATE products
            SET nombre = ?, precio = ?, stock = ?, stock_minimo = ?, activo = ?, image_filename = ?
            WHERE id = ?
            """,
            (nombre, precio_num, stock_num, stock_minimo_num, activo, image_filename, product_id)
        )
        db.commit()

        flash("Producto actualizado correctamente.", "success")
        return redirect(url_for("admin_products"))

    return render_template("edit_product.html", p=p)
# =====================================================
# ADMIN: STOCK
# Ruta: /admin/stock
# - Lista productos con stock y mínimos
# - Filtro: ?only_low=1 para mostrar solo bajos
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
# =====================================================
# ADMIN: REPORTE VENTAS POR PERIODO
# Ruta: /admin/reports/sales?start=YYYY-MM-DD&end=YYYY-MM-DD
# =====================================================
@app.route("/admin/reports/sales")
def admin_report_sales():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    where = []
    params = []
    if start:
        where.append("date(o.fecha) >= date(?)")
        params.append(start)
    if end:
        where.append("date(o.fecha) <= date(?)")
        params.append(end)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_db()

    # Totales generales
    resumen = db.execute(
        f"""
        SELECT
            COUNT(*) AS num_ordenes,
            COALESCE(SUM(total), 0) AS total_general,
            COALESCE(SUM(CASE WHEN tipo_pago='contado' THEN total ELSE 0 END), 0) AS total_contado,
            COALESCE(SUM(CASE WHEN tipo_pago='credito' THEN total ELSE 0 END), 0) AS total_credito
        FROM orders o
        {where_sql}
        """,
        params
    ).fetchone()

    # Listado de órdenes (para ver detalle rápido)
    orders = db.execute(
        f"""
        SELECT
            o.id, o.fecha, o.tipo_pago, o.estado, o.total,
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
        resumen=resumen,
        orders=orders
    )
# =====================================================
# ADMIN: TOP PRODUCTOS
# Ruta: /admin/reports/top-products?start=YYYY-MM-DD&end=YYYY-MM-DD
# =====================================================
@app.route("/admin/reports/top-products")
def admin_report_top_products():
    if "user_id" not in session or session.get("rol") != "admin":
        return redirect(url_for("login"))

    start = (request.args.get("start") or "").strip()
    end = (request.args.get("end") or "").strip()

    where = []
    params = []
    if start:
        where.append("date(o.fecha) >= date(?)")
        params.append(start)
    if end:
        where.append("date(o.fecha) <= date(?)")
        params.append(end)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

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
# RUTA: /catalogo
# Catálogo visible para compras
# - Solo productos activos con stock > 0
# =====================================================
@app.route("/catalogo")
def catalogo():
    db = get_db()

    # Texto de búsqueda (viene como ?q=...)
    q = (request.args.get("q") or "").strip()

    if q:
        productos = db.execute(
            """
            SELECT * FROM products
            WHERE activo = 1
              AND stock > 0
              AND nombre LIKE ?
            ORDER BY nombre ASC
            """,
            (f"%{q}%",)
        ).fetchall()
    else:
        productos = db.execute(
            """
            SELECT * FROM products
            WHERE activo = 1 AND stock > 0
            ORDER BY nombre ASC
            """
        ).fetchall()

    return render_template("catalogo.html", productos=productos, q=q)
# =====================================================
# HELPER: obtener carrito desde sesión
# Guarda carrito en session["cart"] como dict:
# {"product_id": cantidad, ...}
# =====================================================
def get_cart():
    if "cart" not in session:
        session["cart"] = {}
    return session["cart"]


# =====================================================
# RUTA: /carrito
# Muestra el carrito y total
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
        f"SELECT * FROM products WHERE id IN ({placeholders})",
        ids
    ).fetchall()

    items = []
    total = 0

    for p in productos:
        pid = str(p["id"])
        cantidad = int(cart.get(pid, 0))
        subtotal = float(p["precio"]) * cantidad
        total += subtotal

        items.append({
            "id": p["id"],
            "nombre": p["nombre"],
            "precio": float(p["precio"]),
            "stock": int(p["stock"]),
            "image_filename": p["image_filename"],
            "cantidad": cantidad,
            "subtotal": subtotal
        })

    return render_template("carrito.html", items=items, total=total)


# =====================================================
# RUTA: /carrito/add/<id>
# Agrega 1 unidad al carrito, validando stock
# =====================================================
@app.route("/carrito/add/<int:product_id>", methods=["POST"])
def carrito_add(product_id):
    db = get_db()

    p = db.execute(
        "SELECT * FROM products WHERE id = ? AND activo = 1",
        (product_id,)
    ).fetchone()

    if not p:
        flash("Producto no disponible.", "danger")
        return redirect(url_for("catalogo"))

    cart = get_cart()
    pid = str(product_id)
    cantidad_actual = int(cart.get(pid, 0))

    if cantidad_actual + 1 > int(p["stock"]):
        flash("No hay suficiente stock para agregar más.", "warning")
        return redirect(url_for("catalogo"))

    cart[pid] = cantidad_actual + 1
    session["cart"] = cart
    flash("Producto agregado al carrito.", "success")
    return redirect(url_for("catalogo"))


# =====================================================
# RUTA: /carrito/inc/<id>
# Sube cantidad +1, validando stock
# =====================================================
@app.route("/carrito/inc/<int:product_id>", methods=["POST"])
def carrito_inc(product_id):
    db = get_db()
    p = db.execute(
        "SELECT * FROM products WHERE id = ? AND activo = 1",
        (product_id,)
    ).fetchone()

    if not p:
        flash("Producto no disponible.", "danger")
        return redirect(url_for("ver_carrito"))

    cart = get_cart()
    pid = str(product_id)
    cantidad_actual = int(cart.get(pid, 0))

    if cantidad_actual + 1 > int(p["stock"]):
        flash("No hay suficiente stock.", "warning")
        return redirect(url_for("ver_carrito"))

    cart[pid] = cantidad_actual + 1
    session["cart"] = cart
    return redirect(url_for("ver_carrito"))


# =====================================================
# RUTA: /carrito/dec/<id>
# Baja cantidad -1 y si llega a 0 lo elimina
# =====================================================
@app.route("/carrito/dec/<int:product_id>", methods=["POST"])
def carrito_dec(product_id):
    cart = get_cart()
    pid = str(product_id)
    cantidad_actual = int(cart.get(pid, 0))

    if cantidad_actual <= 1:
        cart.pop(pid, None)
    else:
        cart[pid] = cantidad_actual - 1

    session["cart"] = cart
    return redirect(url_for("ver_carrito"))


# =====================================================
# RUTA: /carrito/remove/<id>
# Elimina un producto del carrito
# =====================================================
@app.route("/carrito/remove/<int:product_id>", methods=["POST"])
def carrito_remove(product_id):
    cart = get_cart()
    cart.pop(str(product_id), None)
    session["cart"] = cart
    return redirect(url_for("ver_carrito"))


# =====================================================
# RUTA: /carrito/clear
# Vacía todo el carrito
# =====================================================
@app.route("/carrito/clear", methods=["POST"])
def carrito_clear():
    session["cart"] = {}
    flash("Carrito vaciado.", "info")
    return redirect(url_for("ver_carrito"))


# =====================================================
# RUTA: /checkout
# - GET: muestra resumen del carrito y formulario de pago
# - POST: crea orden, descuenta stock, registra movimiento y vacía carrito
# Reglas (compatibles con CHECK de SQLite):
#   - tipo_usuario guardado en DB: 'asociado' o 'no_asociado'
#   - Si hay sesión (admin o asociado) => tipo_usuario = 'asociado'
#   - Si NO hay sesión => tipo_usuario = 'no_asociado' (solo contado y nombre obligatorio)
#   - Crédito permitido para admin/asociado (para pruebas)
# =====================================================
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    # -----------------------------------------------------
    # 1) Validar que exista carrito
    # -----------------------------------------------------
    cart = get_cart()
    if not cart:
        flash("Tu carrito está vacío.", "info")
        return redirect(url_for("catalogo"))

    db = get_db()

    # -----------------------------------------------------
    # 2) Traer productos del carrito desde DB
    # -----------------------------------------------------
    ids = list(cart.keys())
    placeholders = ",".join(["?"] * len(ids))

    productos = db.execute(
        f"SELECT * FROM products WHERE id IN ({placeholders})",
        ids
    ).fetchall()

    # -----------------------------------------------------
    # 3) Construir items + total, validando stock/activo
    # -----------------------------------------------------
    items = []
    total = 0

    for p in productos:
        pid = str(p["id"])
        cantidad = int(cart.get(pid, 0))

        if int(p["activo"]) != 1:
            flash(f"El producto '{p['nombre']}' no está disponible.", "danger")
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

    # -----------------------------------------------------
    # 4) Datos de sesión
    # -----------------------------------------------------
    user_id = session.get("user_id")
    rol = session.get("rol")  # admin / asociado / None

    # Para DB (CHECK): asociado o no_asociado
    tipo_usuario = "asociado" if user_id else "no_asociado"

    # -----------------------------------------------------
    # 5) GET: mostrar pantalla de checkout
    # -----------------------------------------------------
    if request.method == "GET":
        es_no_asociado = True if not user_id else False
        can_credit = True if (user_id and rol in ("admin", "asociado")) else False

        return render_template(
            "checkout.html",
            items=items,
            total=total,
            rol=rol,
            es_no_asociado=es_no_asociado,
            can_credit=can_credit
        )

    # -----------------------------------------------------
    # 6) POST: normalizar tipo de pago
    # -----------------------------------------------------
    tipo_pago = norm_text(request.form.get("tipo_pago"))
    if tipo_pago not in ("contado", "credito"):
        flash("Tipo de pago inválido.", "danger")
        return redirect(url_for("checkout"))

    nombre_no_asociado = (request.form.get("nombre_no_asociado") or "").strip()

    # -----------------------------------------------------
    # 7) Reglas de negocio
    # -----------------------------------------------------
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

    # -----------------------------------------------------
    # 8) Estado y fecha
    # -----------------------------------------------------
    estado = "pagada" if tipo_pago == "contado" else "pendiente"
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -----------------------------------------------------
    # 9) Insertar orden
    # -----------------------------------------------------
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

    # -----------------------------------------------------
    # 10) Insertar items + descontar stock + movimiento
    # -----------------------------------------------------
    for it in items:
        db.execute(
            """
            INSERT INTO order_items (order_id, product_id, cantidad, precio_unitario)
            VALUES (?, ?, ?, ?)
            """,
            (order_id, it["id"], it["cantidad"], float(it["precio"]))
        )

        db.execute(
            "UPDATE products SET stock = stock - ? WHERE id = ?",
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

    # Vaciar carrito
    session["cart"] = {}
    flash(f"✅ Compra realizada. Orden #{order_id} creada.", "success")
    return redirect(url_for("order_success", order_id=order_id))


# =====================================================
# RUTA: /orden/<id>
# Página de factura/confirmación
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

    return render_template("order_success.html", orden=orden, items=items, comprador=comprador)


# =====================================================
# EJECUCIÓN DE LA APLICACIÓN
# =====================================================
if __name__ == "__main__":
    os.makedirs(app.instance_path, exist_ok=True)
    app.run(debug=True)

