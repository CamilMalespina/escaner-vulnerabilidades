"""
Escáner de Vulnerabilidades Web - Segunda Versión
Autor: Malespina Camil
Descripción: Analiza sitios web buscando vulnerabilidades básicas
"""

# ============================================
# IMPORTACIONES
# ============================================
# requests: librería para hacer peticiones HTTP (visitar sitios web)
import requests

# Para manejar errores de conexión
from requests.exceptions import RequestException

# Para trabajar con URLs (unir partes, validar, etc.)
from urllib.parse import urlparse

# Para fechas en los reportes
from datetime import datetime


# ============================================
# CLASE PRINCIPAL
# ============================================
class VulnerabilityScanner:
    """
    Esta clase es como una "plantilla" para crear escáneres.
    Contiene todas las funciones para analizar sitios web.
    
    ¿Por qué usar una clase?
    - Organiza el código relacionado
    - Puedes crear múltiples escáneres si se quiere
    """
    
    def __init__(self, url):
        """
        __init__ es el "constructor" - se ejecuta cuando creas un escáner.
        
        Ejemplo de uso:
        scanner = VulnerabilityScanner("https://example.com")
        
        Parámetros:
        - url: el sitio web que vamos a analizar
        """
        self.url = url  # Guardamos la URL para usarla después
        self.results = {}  # Diccionario vacío para guardar resultados
        
        # Validamos que la URL tenga http:// o https://
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'https://' + self.url
    
    
    def check_security_headers(self):
        """
        Verifica si el sitio tiene headers de seguridad importantes.
        
        ¿Qué son los headers?
        Son como "etiquetas" que el servidor web envía junto con la página.
        Algunos headers protegen contra ataques.
        
        Ejemplo de header: "X-Frame-Options: DENY"
        Esto evita que tu sitio se muestre dentro de otro (clickjacking)
        """
        print(f"[+] Analizando headers de seguridad en {self.url}...")
        
        # Headers importantes que deberían existir
        security_headers = {
            'X-Frame-Options': 'Protege contra clickjacking',
            'X-Content-Type-Options': 'Previene MIME type sniffing',
            'Strict-Transport-Security': 'Fuerza HTTPS',
            'Content-Security-Policy': 'Previene XSS y otros ataques',
            'X-XSS-Protection': 'Protección adicional contra XSS'
        }
        
        try:
            # Hacemos una petición GET al sitio (como abrir la página en el navegador)
            response = requests.get(self.url, timeout=10)
            
            # response.headers contiene todos los headers que el servidor envió
            headers_found = {}
            
            # Revisamos cada header de seguridad
            for header, description in security_headers.items():
                if header in response.headers:
                    # ✅ El header existe
                    headers_found[header] = {
                        'present': True,
                        'value': response.headers[header],
                        'description': description
                    }
                else:
                    # ❌ El header NO existe (posible vulnerabilidad)
                    headers_found[header] = {
                        'present': False,
                        'value': None,
                        'description': description
                    }
            
            # Guardamos los resultados
            self.results['security_headers'] = headers_found
            print("[✓] Análisis de headers completado")
            
        except RequestException as e:
            # Si algo salió mal (no hay internet, sitio caído, etc.)
            print(f"[✗] Error al conectar con {self.url}: {e}")
            self.results['security_headers'] = {'error': str(e)}
    
    
    def check_ssl(self):
        """
        Verifica si el sitio usa HTTPS (conexión segura).
        
        ¿Por qué es importante?
        HTTP sin S = datos viajan en texto plano (cualquiera puede leerlos)
        HTTPS = datos encriptados (seguros)
        """
        print("[+] Verificando uso de HTTPS...")
        
        parsed_url = urlparse(self.url)
        
        if parsed_url.scheme == 'https':
            self.results['ssl'] = {
                'enabled': True,
                'message': 'El sitio usa HTTPS ✓'
            }
            print("[✓] HTTPS está habilitado")
        else:
            self.results['ssl'] = {
                'enabled': False,
                'message': '⚠️ El sitio NO usa HTTPS (inseguro)'
            }
            print("[⚠] Advertencia: El sitio no usa HTTPS")
    
    
    def generate_summary(self):
        """
        Genera un resumen de texto con los resultados del escaneo.
        """
        print("\n" + "="*60)
        print(f"REPORTE DE VULNERABILIDADES - {self.url}")
        print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
        
        # Resumen de SSL/HTTPS
        if 'ssl' in self.results:
            print("🔒 HTTPS:")
            print(f"   {self.results['ssl']['message']}\n")
        
        # Resumen de Security Headers
        if 'security_headers' in self.results and 'error' not in self.results['security_headers']:
            print("🛡️  SECURITY HEADERS:")
            
            headers_data = self.results['security_headers']
            present_count = sum(1 for h in headers_data.values() if h.get('present'))
            total_count = len(headers_data)
            
            print(f"   Headers encontrados: {present_count}/{total_count}\n")
            
            for header, data in headers_data.items():
                status = "✓" if data['present'] else "✗"
                print(f"   [{status}] {header}")
                print(f"       {data['description']}")
                if data['present']:
                    print(f"       Valor: {data['value']}")
                print()
        
        print("="*60)
    
    
    def generate_html_report(self):
        """
        Genera un reporte HTML bonito usando Jinja2.
        
        ¿Cómo funciona?
        1. Cargamos la plantilla HTML (el molde)
        2. Le pasamos los datos del escaneo
        3. Jinja2 rellena la plantilla con los datos
        4. Guardamos el resultado en un archivo .html
        """
        from jinja2 import Environment, FileSystemLoader
        import os
        
        print("\n[+] Generando reporte HTML...")
        
        # Configuramos Jinja2 para que busque plantillas en la carpeta 'templates'
        # __file__ es la ruta de este archivo (scanner.py)
        # dirname(__file__) es la carpeta donde está este archivo (src/)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)  # Subimos un nivel (raíz del proyecto)
        templates_dir = os.path.join(parent_dir, 'templates')
        
        # Creamos el "entorno" de Jinja2
        env = Environment(loader=FileSystemLoader(templates_dir))
        
        # Cargamos la plantilla
        template = env.get_template('report_template.html')
        
        # Calculamos estadísticas para el resumen
        headers_data = self.results.get('security_headers', {})
        headers_present = sum(1 for h in headers_data.values() if h.get('present'))
        headers_missing = len(headers_data) - headers_present
        
        # Preparamos los datos para la plantilla
        # Estos son los "espacios en blanco" que rellenaremos
        template_data = {
            'url': self.url,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ssl': self.results.get('ssl', {}),
            'security_headers': headers_data,
            'headers_present': headers_present,
            'headers_missing': headers_missing
        }
        
        # ¡Jinja2 hace la magia! Rellena la plantilla con los datos
        html_content = template.render(**template_data)
        
        # Guardamos el HTML en un archivo
        results_dir = os.path.join(parent_dir, 'results')
        os.makedirs(results_dir, exist_ok=True)  # Crea la carpeta si no existe
        
        # Nombre del archivo: reporte_example.com_2024-01-15_14-30-45.html
        safe_url = self.url.replace('https://', '').replace('http://', '').replace('/', '_')
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f'reporte_{safe_url}_{timestamp}.html'
        filepath = os.path.join(results_dir, filename)
        
        # Escribimos el contenido HTML al archivo
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] Reporte generado: {filepath}")
        return filepath
    
    
    def run_scan(self):
        """
        Ejecuta todos los análisis en orden.
        Esta es la función principal que llamas para escanear.
        """
        print("\n🔍 Iniciando escaneo de vulnerabilidades...\n")
        
        # Ejecutamos cada verificación
        self.check_ssl()
        self.check_security_headers()
        
        # Mostramos el resumen
        self.generate_summary()
        
        # Generamos el reporte HTML
        report_path = self.generate_html_report()
        
        return self.results, report_path


# ============================================
# BLOQUE PRINCIPAL
# ============================================
if __name__ == "__main__":
    """
    Este bloque solo se ejecuta si corres este archivo directamente.
    No se ejecuta si lo importas desde otro archivo.
    
    ¿Por qué es útil?
    - Puedes probar el código fácilmente
    - Puedes importar la clase sin ejecutar el test
    """
    
    print("🔐 Escáner de Vulnerabilidades Web v1.0")
    print("-" * 40)
    
    # Pedimos al usuario la URL a escanear
    target_url = input("\nIngresa la URL a escanear (ej: example.com): ").strip()
    
    # Creamos una instancia del escáner
    scanner = VulnerabilityScanner(target_url)
    
    # Ejecutamos el escaneo
    results = scanner.run_scan()
    
    print("\n✅ Escaneo completado!")
    print("Los resultados están guardados en la variable 'results'")