# 🔐 Escáner de Vulnerabilidades Web

Herramienta en Python para analizar la seguridad básica de sitios web, enfocada en la detección de headers de seguridad faltantes y verificación de HTTPS.

## 🎯 Características

- ✅ Verificación de HTTPS/SSL
- ✅ Análisis de Security Headers (X-Frame-Options, CSP, HSTS, etc.)
- ✅ Reportes detallados en consola
- 🚧 Generación de reportes HTML (próximamente)
- 🚧 Detección de SQL Injection (próximamente)

## 🛠️ Tecnologías

- Python 3.14
- Requests
- BeautifulSoup4
- Jinja2

## 📦 Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/TU_USUARIO/escaner-vulnerabilidades.git
cd escaner-vulnerabilidades
```

2. Instala las dependencias:
```bash
python -m pip install -r requirements.txt
```

## 🚀 Uso
```bash
python src/scanner.py
```

Ingresa la URL que deseas analizar cuando se te solicite.

### Ejemplo:
```bash
Ingresa la URL a escanear: example.com

🔍 Iniciando escaneo de vulnerabilidades...
[✓] HTTPS está habilitado
[✓] Análisis de headers completado
```

## 📊 Ejemplo de Resultados
```
🛡️  SECURITY HEADERS:
   Headers encontrados: 0/5

   [✗] X-Frame-Options
       Protege contra clickjacking
   
   [✗] Content-Security-Policy
       Previene XSS y otros ataques
```

## 🗺️ Roadmap

- [x] Análisis de security headers
- [x] Verificación HTTPS
- [ ] Reportes HTML exportables
- [ ] Detección básica de SQL Injection
- [ ] Detección básica de XSS
- [ ] Escaneo de puertos comunes
- [ ] Interfaz web con Flask

## 🤝 Contribuciones

Este es un proyecto de aprendizaje. Sugerencias y feedback son bienvenidos.

## 📄 Licencia

MIT License - Siéntete libre de usar este código para aprender.

## 👨‍💻 Autor

**Camil Malespina** - [LinkedIn](https://www.linkedin.com/in/camil-malespina-7b9b53217/) | [GitHub](https://github.com/CamilMalespina)

---

⭐ Si te gustó el proyecto, dale una estrella en GitHub