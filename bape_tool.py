import requests
from bs4 import BeautifulSoup
import re

def analyze_http_headers(url):
    """Analisa cabeçalhos HTTP para identificar SO"""
    response = requests.get(url)
    headers = response.headers
    
    # Detectar SO baseado em header Server
    server = headers.get('Server', '')
    if 'nginx' in server.lower():
        return f"Nginx v{re.search(r'nginx/(\d+\.\d+)', server).group(1)}"
    elif 'apache' in server.lower():
        return f"Apache v{re.search(r'Apache/(\d+\.\d+)', server).group(1)}"
    elif 'iis' in server.lower():
        return f"IIS v{re.search(r'Microsoft-IIS/(\d+\.\d+)', server).group(1)}"
    
    return "SO não identificado"

def check_server_errors(url):
    """Verifica mensagens de erro para deduzir versão"""
    error_patterns = {
        'php': r'<b>Warning</b>:.*?PHP (\d+\.\d+) ',
        'java': r'<b>Version:</b> (\d+\.\d+)'
    }
    
    for pattern in error_patterns.values():
        response = requests.get(f"{url}/nonexistent.php", allow_redirects=False)
        match = re.search(pattern, response.text)
        if match:
            return f"Versão detectada: {match.group(1)}"

def wappalyzer_like_scan(url):
    """Scan de tecnologias com base em padrões"""
    tech_patterns = {
        'WordPress': r'wp-content',
        'Drupal': r'drupal\.org',
        'Joomla': r'joomla\.org'
    }
    
    response = requests.get(url)
    for tech, pattern in tech_patterns.items():
        if re.search(pattern, response.text):
            return f"Detected: {tech}"

def main():
    url = "https://example.com"
    print(analyze_http_headers(url))
    print(check_server_errors(url))
    print(wappalyzer_like_scan(url))

if __name__ == "__main__":
    main()