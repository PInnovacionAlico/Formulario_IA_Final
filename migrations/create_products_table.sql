-- =====================================================
-- CREAR TABLA DE PRODUCTOS
-- =====================================================

-- Drop table if exists (¡CUIDADO! Esto elimina todos los datos)
DROP TABLE IF EXISTS products CASCADE;

-- Create products table
CREATE TABLE products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  form_type VARCHAR(50) NOT NULL, -- 'termoformado', 'doypack', 'flowpack'
  category VARCHAR(100) NOT NULL,  -- 'estuches', 'base-tapa', 'bandejas', 'domos', etc.
  image_path VARCHAR(500),         -- Ruta en Supabase Storage
  display_order INTEGER DEFAULT 0,
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes
CREATE INDEX idx_products_form_type ON products(form_type);
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_products_active ON products(active);

-- =====================================================
-- INSERTAR PRODUCTOS DE TERMOFORMADO
-- =====================================================

-- ESTUCHES
INSERT INTO products (name, form_type, category, display_order) VALUES
('Estuche Rectangular Pequeño', 'termoformado', 'estuches', 1),
('Estuche Rectangular Mediano', 'termoformado', 'estuches', 2),
('Estuche Rectangular Grande', 'termoformado', 'estuches', 3),
('Estuche Cuadrado Pequeño', 'termoformado', 'estuches', 4),
('Estuche Cuadrado Mediano', 'termoformado', 'estuches', 5),
('Estuche Ovalado', 'termoformado', 'estuches', 6),
('Estuche con Ventana', 'termoformado', 'estuches', 7);

-- BASE Y TAPA
INSERT INTO products (name, form_type, category, display_order) VALUES
('Base y Tapa Rectangular', 'termoformado', 'base-tapa', 1),
('Base y Tapa Cuadrada', 'termoformado', 'base-tapa', 2),
('Base y Tapa Redonda', 'termoformado', 'base-tapa', 3),
('Base y Tapa con Bisagra', 'termoformado', 'base-tapa', 4),
('Base Profunda con Tapa Plana', 'termoformado', 'base-tapa', 5);

-- BANDEJAS
INSERT INTO products (name, form_type, category, display_order) VALUES
('Bandeja Individual', 'termoformado', 'bandejas', 1),
('Bandeja Multi-compartimento', 'termoformado', 'bandejas', 2),
('Bandeja Rectangular', 'termoformado', 'bandejas', 3),
('Bandeja Redonda', 'termoformado', 'bandejas', 4),
('Bandeja con Divisiones', 'termoformado', 'bandejas', 5),
('Bandeja Profunda', 'termoformado', 'bandejas', 6);

-- DOMOS
INSERT INTO products (name, form_type, category, display_order) VALUES
('Domo Bajo', 'termoformado', 'domos', 1),
('Domo Medio', 'termoformado', 'domos', 2),
('Domo Alto', 'termoformado', 'domos', 3),
('Domo Transparente', 'termoformado', 'domos', 4),
('Domo con Ventilación', 'termoformado', 'domos', 5);

-- =====================================================
-- INSERTAR PRODUCTOS DE DOYPACK (Opcional)
-- =====================================================

INSERT INTO products (name, form_type, category, display_order) VALUES
('Doy Pack Estándar', 'doypack', 'standup', 1),
('Doy Pack con Zipper', 'doypack', 'standup', 2),
('Doy Pack con Válvula', 'doypack', 'standup', 3),
('Doy Pack con Pico Vertedor', 'doypack', 'standup', 4),
('Doy Pack Plano', 'doypack', 'flat', 1),
('Doy Pack Transparente', 'doypack', 'transparent', 1);

-- =====================================================
-- INSERTAR PRODUCTOS DE FLOWPACK (Opcional)
-- =====================================================

INSERT INTO products (name, form_type, category, display_order) VALUES
('Flow Pack Horizontal', 'flowpack', 'horizontal', 1),
('Flow Pack Vertical', 'flowpack', 'vertical', 1),
('Flow Pack con Ventana', 'flowpack', 'window', 1),
('Flow Pack Metalizado', 'flowpack', 'metallic', 1);

-- =====================================================
-- VERIFICAR INSERCIÓN
-- =====================================================

-- Contar productos por tipo
SELECT form_type, COUNT(*) as total 
FROM products 
WHERE active = true 
GROUP BY form_type 
ORDER BY form_type;

-- Contar productos de termoformado por categoría
SELECT category, COUNT(*) as total 
FROM products 
WHERE form_type = 'termoformado' AND active = true 
GROUP BY category 
ORDER BY category;
