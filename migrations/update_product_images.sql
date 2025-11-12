-- =====================================================
-- ACTUALIZAR RUTAS DE IMÁGENES DE PRODUCTOS
-- =====================================================
-- NOTA: Las rutas incluyen 'termoformado/' porque así está la estructura en el bucket

-- DOMOS
UPDATE products 
SET image_path = 'termoformado/domos/domo-alto.jpg'
WHERE name = 'Domo Alto' AND form_type = 'termoformado';

-- BASE Y TAPA
UPDATE products 
SET image_path = 'termoformado/base-tapa/base-tapa-estandar.jpg'
WHERE name = 'Base y Tapa Rectangular' AND form_type = 'termoformado';

-- Si tienes más imágenes, puedes agregar más rutas aquí:

-- Ejemplo para otros productos si tienes las imágenes:
-- UPDATE products SET image_path = 'termoformado/domos/domo-bajo.jpg' WHERE name = 'Domo Bajo';
-- UPDATE products SET image_path = 'termoformado/domos/domo-medio.jpg' WHERE name = 'Domo Medio';
-- UPDATE products SET image_path = 'termoformado/domos/domo-transparente.jpg' WHERE name = 'Domo Transparente';
-- UPDATE products SET image_path = 'termoformado/domos/domo-ventilacion.jpg' WHERE name = 'Domo con Ventilación';

-- UPDATE products SET image_path = 'termoformado/base-tapa/base-tapa-cuadrada.jpg' WHERE name = 'Base y Tapa Cuadrada';
-- UPDATE products SET image_path = 'termoformado/base-tapa/base-tapa-redonda.jpg' WHERE name = 'Base y Tapa Redonda';
-- UPDATE products SET image_path = 'termoformado/base-tapa/base-tapa-bisagra.jpg' WHERE name = 'Base y Tapa con Bisagra';
-- UPDATE products SET image_path = 'termoformado/base-tapa/base-profunda.jpg' WHERE name = 'Base Profunda con Tapa Plana';

-- UPDATE products SET image_path = 'termoformado/bandejas/bandeja-individual.jpg' WHERE name = 'Bandeja Individual';
-- UPDATE products SET image_path = 'termoformado/bandejas/bandeja-multi.jpg' WHERE name = 'Bandeja Multi-compartimento';
-- UPDATE products SET image_path = 'termoformado/bandejas/bandeja-rectangular.jpg' WHERE name = 'Bandeja Rectangular';

-- UPDATE products SET image_path = 'termoformado/estuches/estuche-rectangular-pequeno.jpg' WHERE name = 'Estuche Rectangular Pequeño';
-- UPDATE products SET image_path = 'termoformado/estuches/estuche-rectangular-mediano.jpg' WHERE name = 'Estuche Rectangular Mediano';
-- UPDATE products SET image_path = 'termoformado/estuches/estuche-cuadrado.jpg' WHERE name = 'Estuche Cuadrado Pequeño';

-- =====================================================
-- VERIFICAR ACTUALIZACIÓN
-- =====================================================

-- Ver todos los productos de termoformado con sus imágenes
SELECT id, name, category, image_path 
FROM products 
WHERE form_type = 'termoformado' 
ORDER BY category, display_order;

-- Ver solo productos con imágenes asignadas
SELECT category, name, image_path 
FROM products 
WHERE form_type = 'termoformado' AND image_path IS NOT NULL
ORDER BY category, name;
