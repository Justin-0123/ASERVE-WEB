-- =====================================================
-- ASERVE - ESQUEMA DE BASE DE DATOS (SQLite)
-- Contiene todas las tablas mínimas del sistema
-- =====================================================

-- =====================================================
-- Limpieza (solo en desarrollo): borra tablas si existen
-- OJO: Esto elimina datos si vuelves a correr init-db
-- =====================================================
DROP TABLE IF EXISTS stock_movements;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users;

-- =====================================================
-- TABLA: users
-- Guarda usuarios admin y asociados
-- =====================================================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    usuario TEXT NOT NULL UNIQUE,
    contrasena_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('admin', 'asociado')),
    estado TEXT NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo', 'bloqueado'))
);

-- =====================================================
-- TABLA: products
-- Guarda productos con stock y umbral de alerta
-- image_filename: nombre del archivo guardado en static/uploads
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
-- Guarda cada compra (asociado o no asociado)
-- tipo_pago: contado o crédito
-- estado: pendiente o pagada (para crédito)
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
-- Detalle de productos comprados por orden
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
-- Historial de cambios de stock (ventas, ajustes, reposición)
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



