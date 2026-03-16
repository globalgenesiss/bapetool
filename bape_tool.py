def detect_target_os(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': '*/*',
        'Connection': 'close'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        
        # Identificar SO baseado em headers
        server = response.headers.get('Server', '')
        if 'nginx' in server.lower():
            return f"Target OS: nginx/{server.split('/')[-1]}"
        elif 'apache' in server.lower():
            return f"Target OS: apache/{server.split('/')[-1]}"
        elif 'iis' in server.lower():
            return f"Target OS: IIS/{server.split('/')[-1]}"
            
        # Verificar páginas de erro
        error_response = requests.get(f"{url}/nonexistent.php", 
                                    headers=headers, 
                                    allow_redirects=False,
                                    timeout=5)
        if error_response.status_code == 404:
            if 'php' in error_response.text.lower():
                return "Target OS: PHP-based server"
            if 'asp.net' in error_response.text.lower():
                return "Target OS: Windows/IIS server"
                
        return "Target OS: Unknown"
    except Exception as e:
        return f"Error detecting target OS: {str(e)}"
