-- =====================================================
-- ASERVE - ESQUEMA DE BASE DE DATOS (SQLite)
-- Contiene las tablas principales del sistema
-- =====================================================

-- =====================================================
-- LIMPIEZA DE TABLAS
-- IMPORTANTE:
-- Esto elimina datos si se vuelve a ejecutar init-db.
-- Usar solo en desarrollo o cuando se quiera reiniciar la DB.
-- =====================================================
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS stock_movements;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

-- =====================================================
-- TABLA: users
-- Guarda usuarios administradores y asociados.
-- password_temporal:
-- 1 = el usuario debe cambiar la contraseña al iniciar sesión
-- 0 = contraseña definitiva
-- =====================================================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    usuario TEXT NOT NULL UNIQUE,
    contrasena_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('admin', 'asociado')),
    estado TEXT NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo', 'bloqueado')),
    password_temporal INTEGER NOT NULL DEFAULT 0 CHECK (password_temporal IN (0, 1))
);

-- =====================================================
-- TABLA: products
-- Guarda productos, precios, stock, stock mínimo e imagen.
-- image_filename:
-- nombre del archivo guardado en static/uploads
-- activo:
-- 1 = visible/disponible
-- 0 = inactivo/no disponible
-- =====================================================
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    precio REAL NOT NULL CHECK (precio >= 0),
    stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    stock_minimo INTEGER NOT NULL DEFAULT 0 CHECK (stock_minimo >= 0),
    image_filename TEXT,
    activo INTEGER NOT NULL DEFAULT 1 CHECK (activo IN (0, 1))
);

-- =====================================================
-- TABLA: orders
-- Guarda cada compra realizada.
-- tipo_usuario:
-- asociado / no_asociado
-- tipo_pago:
-- contado / credito
-- estado:
-- pagada / pendiente
-- =====================================================
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT NOT NULL,
    tipo_usuario TEXT NOT NULL CHECK (tipo_usuario IN ('asociado', 'no_asociado')),
    user_id INTEGER,
    nombre_no_asociado TEXT,
    tipo_pago TEXT NOT NULL CHECK (tipo_pago IN ('contado', 'credito')),
    total REAL NOT NULL CHECK (total >= 0),
    estado TEXT NOT NULL CHECK (estado IN ('pendiente', 'pagada')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =====================================================
-- TABLA: order_items
-- Detalle de productos comprados en cada orden.
-- =====================================================
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    cantidad INTEGER NOT NULL CHECK (cantidad > 0),
    precio_unitario REAL NOT NULL CHECK (precio_unitario >= 0),
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- =====================================================
-- TABLA: stock_movements
-- Historial de movimientos de stock.
-- Ejemplos:
-- Venta, ajuste manual, reposición, corrección, etc.
-- =====================================================
CREATE TABLE stock_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    cambio_stock INTEGER NOT NULL,
    motivo TEXT NOT NULL,
    fecha TEXT NOT NULL,
    order_id INTEGER,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- =====================================================
-- TABLA: audit_logs
-- Guarda acciones administrativas importantes.
-- Ejemplos:
-- crear usuario, editar usuario, bloquear usuario,
-- crear producto, editar producto, eliminar imagen,
-- pagar crédito, descargar respaldo, etc.
-- =====================================================
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha TEXT NOT NULL,
    admin_id INTEGER,
    admin_nombre TEXT NOT NULL,
    accion TEXT NOT NULL,
    detalle TEXT,
    FOREIGN KEY (admin_id) REFERENCES users(id)
);

-- =====================================================
-- ÍNDICES RECOMENDADOS
-- Mejoran búsquedas, filtros y reportes.
-- =====================================================

-- Usuarios
CREATE INDEX idx_users_usuario ON users(usuario);
CREATE INDEX idx_users_estado ON users(estado);
CREATE INDEX idx_users_rol ON users(rol);

-- Productos
CREATE INDEX idx_products_nombre ON products(nombre);
CREATE INDEX idx_products_activo ON products(activo);
CREATE INDEX idx_products_stock ON products(stock);

-- Órdenes
CREATE INDEX idx_orders_fecha ON orders(fecha);
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_tipo_pago ON orders(tipo_pago);
CREATE INDEX idx_orders_estado ON orders(estado);
CREATE INDEX idx_orders_nombre_no_asociado ON orders(nombre_no_asociado);

-- Detalle de órdenes
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);

-- Movimientos de stock
CREATE INDEX idx_stock_movements_product_id ON stock_movements(product_id);
CREATE INDEX idx_stock_movements_order_id ON stock_movements(order_id);
CREATE INDEX idx_stock_movements_fecha ON stock_movements(fecha);

-- Auditoría
CREATE INDEX idx_audit_logs_fecha ON audit_logs(fecha);
CREATE INDEX idx_audit_logs_accion ON audit_logs(accion);
CREATE INDEX idx_audit_logs_admin_id ON audit_logs(admin_id);