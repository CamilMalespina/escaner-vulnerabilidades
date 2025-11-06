"""
Detector de SQL Injection - Versión Educativa
Autor: Camil Malespina
Descripción: Detecta posibles vulnerabilidades de SQL Injection en sitios web
⚠️ SOLO PARA FINES EDUCATIVOS Y SITIOS CON PERMISO ⚠️
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time

class SQLInjectionDetector:
    """
    Clase para detectar vulnerabilidades de SQL Injection.
    
    ¿Cómo funciona?
    1. Encuentra formularios y parámetros en URLs
    2. Prueba "payloads" (código malicioso de prueba)
    3. Analiza las respuestas buscando errores de SQL
    """
    
    def __init__(self, url):
        """
        Inicializa el detector.
        
        Parámetros:
        - url: URL del sitio a analizar
        """
        self.url = url
        self.vulnerabilities = []
        
        # Payloads: cadenas de texto que intentan "romper" la consulta SQL
        # Estos son BÁSICOS y SEGUROS para aprendizaje
        self.payloads = [
            "'",           # Comilla simple (lo más básico)
            "' OR '1'='1", # Clásico bypass de autenticación
            "' OR 1=1--",  # Otra variante común
            "1' AND '1'='1", # Test de inyección
            "admin'--",    # Comentario SQL
        ]
        
        # Errores comunes que indican SQL Injection
        # Si vemos estos en la respuesta = probablemente vulnerable
        self.sql_errors = [
            "sql syntax",           # Error de sintaxis SQL
            "mysql_fetch",          # Función PHP de MySQL
            "warning: mysql",       # Advertencia MySQL
            "unclosed quotation",   # Comilla sin cerrar
            "quoted string not properly terminated", # Oracle
            "syntax error",         # Error genérico
            "mysql_num_rows",       # Otra función PHP
            "ORA-",                 # Errores de Oracle
            "PostgreSQL",           # Errores de PostgreSQL
            "Driver",               # ODBC Driver errors
            "Microsoft SQL Native Client", # SQL Server
        ]
    
    
    def find_forms(self):
        """
        Encuentra todos los formularios en la página.
        
        ¿Por qué?
        Los formularios son puntos de entrada comunes para SQLi.
        Ej: login, búsqueda, comentarios, etc.
        
        Returns:
        Lista de diccionarios con información de cada formulario
        """
        print(f"[+] Buscando formularios en {self.url}...")
        
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # BeautifulSoup encuentra todos los <form> en el HTML
            forms = soup.find_all('form')
            
            forms_data = []
            
            for form in forms:
                # Extraemos información del formulario
                form_details = {
                    'action': form.get('action'),      # A dónde envía los datos
                    'method': form.get('method', 'get').lower(), # GET o POST
                    'inputs': []                       # Campos del formulario
                }
                
                # Buscamos todos los inputs (texto, password, email, etc.)
                inputs = form.find_all(['input', 'textarea', 'select'])
                
                for input_tag in inputs:
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    
                    # Solo nos interesan inputs con nombre
                    if input_name:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name
                        })
                
                # Solo guardamos formularios que tengan inputs
                if form_details['inputs']:
                    forms_data.append(form_details)
            
            print(f"[✓] Encontrados {len(forms_data)} formularios")
            return forms_data
            
        except Exception as e:
            print(f"[✗] Error al buscar formularios: {e}")
            return []
    
    
    def test_form(self, form_details):
        """
        Prueba un formulario con payloads de SQL Injection.
        
        ¿Cómo funciona?
        1. Por cada payload, llena el formulario
        2. Envía el formulario
        3. Analiza la respuesta buscando errores SQL
        
        Parámetros:
        - form_details: Diccionario con info del formulario
        """
        print(f"[+] Probando formulario: {form_details['action']}")
        
        # Construimos la URL completa del action
        target_url = urljoin(self.url, form_details['action'])
        
        for payload in self.payloads:
            # Preparamos los datos del formulario
            # Llenamos TODOS los campos con el payload
            data = {}
            for input_field in form_details['inputs']:
                # Skip de campos especiales (submit, button, hidden)
                if input_field['type'] not in ['submit', 'button', 'reset']:
                    data[input_field['name']] = payload
            
            try:
                # Enviamos el formulario
                if form_details['method'] == 'post':
                    response = requests.post(target_url, data=data, timeout=10)
                else:
                    response = requests.get(target_url, params=data, timeout=10)
                
                # Analizamos la respuesta
                if self.check_sql_errors(response.text):
                    vulnerability = {
                        'type': 'Form SQL Injection',
                        'url': target_url,
                        'method': form_details['method'].upper(),
                        'payload': payload,
                        'evidence': 'Errores SQL detectados en la respuesta'
                    }
                    self.vulnerabilities.append(vulnerability)
                    print(f"[!] ¡Posible vulnerabilidad encontrada con payload: {payload}")
                    break  # No seguir probando este formulario
                
                # Pequeña pausa para no saturar el servidor
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[✗] Error al probar formulario: {e}")
    
    
    def test_url_parameters(self):
        """
        Prueba parámetros GET en la URL.
        
        Ejemplo: https://example.com/product?id=5
        Probamos: https://example.com/product?id=5'
        
        Si la URL tiene parámetros (?key=value), los probamos.
        """
        print(f"[+] Analizando parámetros de URL...")
        
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)  # Extrae parámetros GET
        
        # Si no hay parámetros, no hay nada que probar
        if not params:
            print("[i] No se encontraron parámetros en la URL")
            return
        
        print(f"[+] Encontrados {len(params)} parámetros para probar")
        
        for param_name in params.keys():
            for payload in self.payloads:
                # Creamos una copia de los parámetros
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    # Construimos la URL de prueba
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    response = requests.get(test_url, params=test_params, timeout=10)
                    
                    # Verificamos si hay errores SQL
                    if self.check_sql_errors(response.text):
                        vulnerability = {
                            'type': 'URL Parameter SQL Injection',
                            'url': self.url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': 'Errores SQL detectados en la respuesta'
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"[!] ¡Vulnerabilidad en parámetro '{param_name}' con payload: {payload}")
                        break
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"[✗] Error al probar parámetro {param_name}: {e}")
    
    
    def check_sql_errors(self, response_text):
        """
        Verifica si hay errores SQL en el texto de la respuesta.
        
        ¿Por qué funciona?
        Si el sitio es vulnerable, nuestra inyección "rompe" la consulta
        y el servidor devuelve un mensaje de error con detalles SQL.
        
        Parámetros:
        - response_text: HTML de la respuesta
        
        Returns:
        True si encuentra errores SQL, False si no
        """
        response_lower = response_text.lower()
        
        for error in self.sql_errors:
            if error.lower() in response_lower:
                return True
        
        return False
    
    
    def run_scan(self):
        """
        Ejecuta el escaneo completo de SQL Injection.
        
        Pasos:
        1. Busca formularios y los prueba
        2. Busca parámetros en URL y los prueba
        3. Retorna resumen de vulnerabilidades
        """
        print("\n🔍 Iniciando escaneo de SQL Injection...\n")
        print("⚠️  Este escaneo es para fines educativos")
        print("⚠️  Solo escanea sitios con permiso explícito\n")
        
        # Probamos formularios
        forms = self.find_forms()
        for form in forms:
            self.test_form(form)
        
        # Probamos parámetros URL
        self.test_url_parameters()
        
        # Resumen
        print("\n" + "="*60)
        print("RESUMEN DE SQL INJECTION")
        print("="*60)
        
        if self.vulnerabilities:
            print(f"\n⚠️  Se encontraron {len(self.vulnerabilities)} posibles vulnerabilidades:\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln['type']}")
                print(f"   URL: {vuln.get('url', self.url)}")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Evidencia: {vuln['evidence']}\n")
        else:
            print("\n✅ No se detectaron vulnerabilidades de SQL Injection")
            print("   (Esto no garantiza que el sitio sea 100% seguro)\n")
        
        print("="*60)
        
        return self.vulnerabilities


# ============================================
# BLOQUE DE PRUEBAS
# ============================================
if __name__ == "__main__":
    """
    Bloque para probar el detector de forma independiente.
    """
    print("🔐 Detector de SQL Injection v1.0")
    print("-" * 40)
    print("⚠️  ADVERTENCIA: Solo usa en sitios de prueba o con permiso\n")
    
    # Sitio de prueba:
    # http://testphp.vulnweb.com - Sitio INTENCIONALMENTE vulnerable para practicar
    
    target_url = input("Ingresa la URL a escanear: ").strip()
    
    detector = SQLInjectionDetector(target_url)
    vulnerabilities = detector.run_scan()
    
    print(f"\n✅ Escaneo completado. Vulnerabilidades encontradas: {len(vulnerabilities)}")