# Pwnclock

Pwnclock es un panel web que muestra el número de vulnerabilidades CVE
publicadas por mes desde 1999. Los datos proceden de la base de datos del
National Vulnerability Database (NVD).

## Cómo funciona

- `server.py` inicia un servidor HTTP en el puerto `9494`.
- `GET /api/monthly` devuelve el histórico mensual en formato JSON.
- La API incluye una segunda serie con las vulnerabilidades añadidas cada mes
  al catálogo CISA KEV (`dateAdded`).
- Si no existe `monthly-cache.json`, el servidor descarga los feeds anuales
  comprimidos del NVD, cuenta los CVE por mes y guarda el resultado en caché.
- `index.html` presenta los datos en un gráfico adaptable usando `<canvas>`.
- La interfaz usa un único estilo visual de IA genérico y permite alternar
  entre dos pestañas independientes: CVE publicados y CISA KEV.
- El mes actual se excluye porque sus datos todavía están incompletos.

## Ejecución

Requiere Python 3 y acceso a Internet para construir la caché inicial.

```bash
python3 server.py
```

Después, abre <http://localhost:9494> en el navegador.

La primera generación de la caché puede tardar porque descarga un feed anual
por cada año disponible. Las siguientes peticiones usan `monthly-cache.json`.

## Estructura

- `server.py`: servidor HTTP, API y generación de la caché.
- `index.html`: interfaz y gráfico del histórico.
- `monthly-cache.json`: datos mensuales generados desde NVD.
- `kev-monthly-cache.json`: datos mensuales generados desde CISA KEV.

## Fuente de datos

La fuente es NVD. El recuento usa la fecha `published` de cada CVE y no
representa necesariamente el número de vulnerabilidades descubiertas durante
ese mes.
