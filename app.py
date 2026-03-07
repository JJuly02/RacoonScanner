import os
import secrets
import subprocess
from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')


# --- KONFIGURACJA ŚCIEŻEK ---
PROJECTS_DIR = os.path.join(os.getcwd(), 'projects')
PRIVATE_DIR = os.path.join(os.getcwd(), 'private')
SECRET_KEY_FILE = os.path.join(PRIVATE_DIR, 'secret.key')

os.makedirs(PROJECTS_DIR, exist_ok=True)
os.makedirs(PRIVATE_DIR, exist_ok=True)

# --- ZARZĄDZANIE KLUCZEM (SECRET KEY) ---
if os.path.exists(SECRET_KEY_FILE):
    # Wczytujemy istniejący klucz
    with open(SECRET_KEY_FILE, 'r') as key_file:
        app.secret_key = key_file.read().strip()
else:
    # Generujemy nowy, silny klucz (64 znaki hex)
    new_secret_key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as key_file:
        key_file.write(new_secret_key)
    app.secret_key = new_secret_key
    print("[*] Wygenerowano nowy klucz aplikacji w folderze 'private/'.")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        project_name = request.form.get('project_name')
        target = request.form.get('target')
        tool = request.form.get('tool')

        # Walidacja wejścia
        if not project_name or not target:
            flash("Podaj nazwę projektu i cel!", "error")
            return redirect(url_for('index'))

        # Bezpieczne tworzenie nazwy katalogu
        safe_project_name = "".join([c for c in project_name if c.isalnum() or c == '_']).rstrip()
        project_path = os.path.join(PROJECTS_DIR, safe_project_name)
        os.makedirs(project_path, exist_ok=True)

        output_file = os.path.join(project_path, f"{tool}_result.txt")

        # Przypisywanie komend systemowych (zapobiega shell injection)
        command = []
        if tool == 'ping':
            command = ['ping', '-c', '4', target]
        elif tool == 'nmap_fast':
            command = ['nmap', '-F', target]
        elif tool == 'whatweb':
            command = ['whatweb', '-v', target]
        elif tool == 'dnsrecon':
            command = ['dnsrecon', '-d', target]
        elif tool == 'sqlmap_test':
            command = ['sqlmap', '-u', target, '--batch']
        else:
            flash("Nieznane narzędzie.", "error")
            return redirect(url_for('index'))

        # Uruchamianie procesu i zapis logów do pliku wewnątrz folderu projektu
        try:
            with open(output_file, "w") as outfile:
                subprocess.run(command, stdout=outfile, stderr=subprocess.STDOUT, text=True, timeout=300)
            flash(f"Zakończono! Wyniki zapisano w projekcie: {safe_project_name}.", "success")
        except subprocess.TimeoutExpired:
            flash(f"Przerwano: Narzędzie działało zbyt długo (limit 5 minut).", "error")
        except Exception as e:
            flash(f"Wystąpił błąd podczas uruchamiania narzędzia: {str(e)}", "error")

    # Pobieranie listy projektów do wyświetlenia w interfejsie
    projects = []
    if os.path.exists(PROJECTS_DIR):
        projects = [d for d in os.listdir(PROJECTS_DIR) if os.path.isdir(os.path.join(PROJECTS_DIR, d))]
        
    return render_template('index.html', projects=projects)

@app.route('/project/<project_name>')
def view_project(project_name):
    # Sanityzacja nazwy tak samo jak wcześniej
    safe_project = "".join([c for c in project_name if c.isalnum() or c == '_']).rstrip()
    project_path = os.path.join(PROJECTS_DIR, safe_project)
    
    if not os.path.exists(project_path):
        flash("Taki projekt nie istnieje.", "error")
        return redirect(url_for('index'))
        
    # Pobierz listę plików wewnątrz folderu
    files = [f for f in os.listdir(project_path) if os.path.isfile(os.path.join(project_path, f))]
    
    return render_template('project.html', project_name=safe_project, files=files)

if __name__ == '__main__':
    # Bindowanie na 0.0.0.0, aby Docker udostępnił port na zewnątrz
    app.run(host='0.0.0.0', port=5000, debug=True)