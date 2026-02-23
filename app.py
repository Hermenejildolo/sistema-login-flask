from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os

app = Flask(__name__)
# La clave secreta es obligatoria para usar mensajes flash (para la alerta JS)
app.secret_key = 'clave_secreta_segura_para_el_proyecto'

DB_NAME = 'sistema_login.db'

def init_db():
    """Inicializa la base de datos y crea usuarios por defecto si no existen."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Crear tabla de usuarios
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # Lista de usuarios solicitada
        usuarios_base = [
            ("admin", "1234"),
            ("Pepito", "abcd")
        ]
        
        # Iterar sobre la lista e insertar cada usuario si no existe en la base de datos
        for username, password in usuarios_base:
            cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,))
            if not cursor.fetchone():
                cursor.execute('INSERT INTO usuarios (username, password) VALUES (?, ?)', (username, password))
                
        conn.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    """Maneja la vista de inicio de sesión y la validación de credenciales."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Consultar la base de datos
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE username = ? AND password = ?', (username, password))
            user = cursor.fetchone()

        if user:
            # Si las credenciales son correctas, preparamos el mensaje para la alerta JS
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('welcome'))
        else:
            # Si falla, devolvemos el error sin recargar toda la página de forma brusca
            error = 'Credenciales incorrectas. Por favor, intente de nuevo.'

    return render_template('login.html', error=error)

@app.route('/welcome')
def welcome():
    """Muestra la vista de bienvenida después de un login exitoso."""
    return render_template('welcome.html')

if __name__ == '__main__':
    # Inicializar la base de datos al arrancar el servidor
    init_db()
    # Ejecutar la aplicación en modo desarrollo
    app.run(debug=True)
    