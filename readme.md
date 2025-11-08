# 🔐 Escáner de Vulnerabilidades Web

Herramienta completa en Python para analizar la seguridad de sitios web, enfocada en detección de vulnerabilidades comunes como headers de seguridad faltantes, HTTPS mal configurado y SQL Injection.

![Python](https://img.shields.io/badge/Python-3.14-blue)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 Características

### ✅ Implementadas
- **Verificación HTTPS/SSL:** Detecta si el sitio usa conexión segura
- **Análisis de Security Headers:** Verifica la presencia de headers críticos:
  - X-Frame-Options (protección contra clickjacking)
  - X-Content-Type-Options (previene MIME type sniffing)
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-XSS-Protection
- **Detección de SQL Injection:** Prueba formularios y parámetros URL con payloads comunes
- **Reportes HTML Profesionales:** Genera reportes visuales con resultados detallados
- **Reportes en Consola:** Resumen inmediato en terminal

### 🚧 En Desarrollo
- Detección de XSS (Cross-Site Scripting)
- Escaneo de puertos comunes
- Análisis de cookies inseguras
- Detección de información sensible expuesta
- Interfaz web con Flask

---

## 🛠️ Tecnologías Utilizadas

| Tecnología | Propósito |
|------------|-----------|
| Python 3.14 | Lenguaje principal |
| Requests | Peticiones HTTP |
| BeautifulSoup4 | Parsing de HTML |
| Jinja2 | Generación de reportes |

---

## 📦 Instalación

### Prerrequisitos
- Python 3.8 o superior
- pip (gestor de paquetes de Python)

### Pasos

1. **Clonar el repositorio:**
```bash
git clone https://github.com/CamilMalespina/escaner-vulnerabilidades.git
cd escaner-vulnerabilidades
```

2. **Instalar dependencias:**
```bash
python -m pip install -r requirements.txt
```

3. **Verificar instalación:**
```bash
python src/scanner.py --help
```

---

## 🚀 Uso

### Escaneo Básico

```bash
python src/scanner.py
```

El programa te pedirá la URL a analizar. Ejemplo:

```
Ingresa la URL a escanear (ej: example.com): example.com
```

### Solo SQL Injection

Si quieres probar únicamente la detección de SQLi:

```bash
python src/sql_injection.py
```

---

## 📊 Ejemplo de Salida

### En Consola:

```
🔍 Iniciando escaneo de vulnerabilidades...

[✓] HTTPS está habilitado
[✓] Análisis de headers completado
[+] Iniciando pruebas de SQL Injection...
[⚠] Se encontraron 2 posibles vulnerabilidades SQLi

============================================================
REPORTE DE VULNERABILIDADES - https://example.com
============================================================

🔒 HTTPS:
   El sitio usa HTTPS ✓

🛡️  SECURITY HEADERS:
   Headers encontrados: 2/5

   [✓] Content-Security-Policy
       Previene XSS y otros ataques
   [✗] X-Frame-Options
       Protege contra clickjacking

💉 SQL INJECTION:
   ⚠️  Se encontraron 2 posibles vulnerabilidades
   - Form SQL Injection: formulario
   - URL Parameter SQL Injection: id
```

### Reporte HTML:

El escáner genera automáticamente un archivo HTML en la carpeta `results/` con:
- ✨ Diseño profesional y responsive
- 📊 Resumen visual con métricas clave
- 🎨 Código de colores (verde=seguro, rojo=vulnerable)
- 💡 Recomendaciones específicas para cada vulnerabilidad
- 📅 Fecha y hora del escaneo

---

## 🎓 Conceptos de Ciberseguridad

### ¿Qué es SQL Injection?

**SQL Injection** es una vulnerabilidad donde un atacante puede manipular consultas SQL para:
- Acceder a datos sin autorización
- Modificar o eliminar información
- Ejecutar comandos administrativos

**Ejemplo vulnerable:**
```python
# ❌ MAL - Concatenación directa
query = f"SELECT * FROM users WHERE username = '{user_input}'"
```

**Ejemplo seguro:**
```python
# ✅ BIEN - Prepared statements
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
```

### Security Headers Importantes

| Header | Protege Contra |
|--------|----------------|
| **X-Frame-Options** | Clickjacking (tu sitio dentro de un iframe malicioso) |
| **Content-Security-Policy** | XSS, inyección de scripts, data injection |
| **Strict-Transport-Security** | Man-in-the-middle, downgrade attacks |
| **X-Content-Type-Options** | MIME type sniffing attacks |
| **X-XSS-Protection** | Ataques XSS reflejados |

---

## ⚠️ Advertencias y Ética

### ⚖️ Uso Legal y Ético

**SOLO** usa esta herramienta en:
- ✅ Sitios web propios
- ✅ Proyectos personales
- ✅ Sitios con **permiso explícito por escrito**
- ✅ Plataformas de prueba legales (ver lista abajo)

**NUNCA** escanees:
- ❌ Sitios de terceros sin autorización
- ❌ Sitios gubernamentales
- ❌ Aplicaciones bancarias
- ❌ Redes sociales
- ❌ Tiendas online

> **Nota Legal:** El escaneo no autorizado de sistemas es ilegal en la mayoría de países y puede resultar en cargos criminales.

### 🧪 Plataformas de Práctica Legales

Sitios **legales** para practicar hacking ético:

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Aplicación de entrenamiento
- [Hack The Box](https://www.hackthebox.eu/) - Plataforma de CTF
- [TryHackMe](https://tryhackme.com/) - Laboratorios guiados
- [PentesterLab](https://pentesterlab.com/) - Ejercicios de pentesting
- [http://testphp.vulnweb.com](http://testphp.vulnweb.com) - Sitio de prueba vulnerable

---

## 📁 Estructura del Proyecto

```
escaner-vulnerabilidades/
│
├── src/
│   ├── scanner.py          # Módulo principal del escáner
│   ├── sql_injection.py    # Detector de SQL Injection
│   └── utils.py            # Funciones auxiliares (futuro)
│
├── templates/
│   └── report_template.html # Plantilla HTML para reportes
│
├── results/                 # Reportes generados (no se suben a Git)
│   └── reporte_example.com_2024-11-04_12-30-45.html
│
├── tests/                   # Tests unitarios (futuro)
│   └── test_scanner.py
│
├── requirements.txt         # Dependencias del proyecto
├── README.md               # Este archivo
├── .gitignore              # Archivos ignorados por Git
└── LICENSE                 # Licencia MIT
```

---

## 🗺️ Roadmap

### Versión 1.0 (Actual)
- [x] Análisis de security headers
- [x] Verificación HTTPS
- [x] Detección básica de SQL Injection
- [x] Reportes HTML exportables

### Versión 1.1 (Próximamente)
- [ ] Detección de XSS (Cross-Site Scripting)
- [ ] Análisis de cookies (Secure, HttpOnly, SameSite)
- [ ] Escaneo de subdominios
- [ ] Tests unitarios

### Versión 2.0 (Futuro)
- [ ] Interfaz web con Flask
- [ ] Base de datos para historial de escaneos
- [ ] Escaneo programado (scheduler)
- [ ] API REST para integraciones
- [ ] Alertas por email/Slack
- [ ] Dashboard con métricas temporales

---

## 🤝 Contribuciones

Este es un proyecto de aprendizaje, pero las sugerencias son bienvenidas:

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Agrega nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## 📚 Recursos de Aprendizaje

### Ciberseguridad
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Vulnerabilidades más críticas
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Tutoriales gratuitos
- [HackTricks](https://book.hacktricks.xyz/) - Técnicas de pentesting

### Python
- [Real Python](https://realpython.com/) - Tutoriales Python
- [Python Security Best Practices](https://snyk.io/blog/python-security-best-practices-cheat-sheet/)

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

```
MIT License - Copyright (c) 2024 Camil Malespina

Se permite el uso, copia, modificación y distribución de este software
con fines educativos y comerciales, siempre manteniendo el aviso de copyright.
```

---

## 👨‍💻 Autor

**Camil Malespina**

- 🔗 LinkedIn: [linkedin.com/in/camil-malespina-7b9b53217](https://www.linkedin.com/in/camil-malespina-7b9b53217/)
- 💻 GitHub: [github.com/CamilMalespina](https://github.com/CamilMalespina)
- 📧 Email: camilmalespina@gmail.com

---

## 🙏 Agradecimientos

- [OWASP](https://owasp.org/) por la documentación de seguridad
- [Requests](https://requests.readthedocs.io/) por simplificar HTTP en Python
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) por el parsing HTML
- Comunidad de ciberseguridad por compartir conocimiento

---

## ⭐ ¿Te gustó el proyecto?

Si este proyecto te ayudó a aprender o te resultó útil:
- Dale una ⭐ en GitHub
- Compártelo con otros estudiantes
- Sígueme para más proyectos de ciberseguridad

---

<div align="center">

**Desarrollado con ❤️ para aprender ciberseguridad**

[Reportar Bug](https://github.com/CamilMalespina/escaner-vulnerabilidades/issues) · [Solicitar Feature](https://github.com/CamilMalespina/escaner-vulnerabilidades/issues)

</div>