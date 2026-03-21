from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os
import re

app = Flask(__name__)

app.secret_key = 'clave_secreta_segura_para_el_proyecto'

DB_NAME = 'sistema_login.db'

EMAIL_REGEX = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'


def get_table_columns(cursor, table_name):
    """Retorna la lista de columnas de una tabla."""
    cursor.execute(f'PRAGMA table_info({table_name})')
    return [row[1] for row in cursor.fetchall()]

def init_db():
    """Inicializa la base de datos y crea usuarios por defecto si no existen."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        columns = get_table_columns(cursor, 'usuarios')
        if 'email' not in columns:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN email TEXT')
        
        
        usuarios_base = [
            ("admin", "admin@demo.com", "1234"),
            ("Pepito", "pepito@demo.com", "abcd")
        ]
        
        
        for username, email, password in usuarios_base:
            cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,))
            if not cursor.fetchone():
                cursor.execute(
                    'INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)',
                    (username, email, password)
                )
                
        conn.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    """Maneja la vista de inicio de sesión y la validación de credenciales."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE username = ? AND password = ?', (username, password))
            user = cursor.fetchone()

        if user:
            
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('welcome'))
        else:
            
            error = 'Credenciales incorrectas. Por favor, intente de nuevo.'

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Maneja el registro de nuevos usuarios con validaciones de negocio."""
    error = None
    form_data = {
        'username': '',
        'email': ''
    }

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        form_data['username'] = username
        form_data['email'] = email

        if not username or not email or not password or not confirm_password:
            error = 'Todos los campos son obligatorios.'
        elif not re.match(EMAIL_REGEX, email):
            error = 'El correo electrónico no tiene un formato válido.'
        elif len(password) < 6:
            error = 'La contraseña debe tener mínimo 6 caracteres.'
        elif password != confirm_password:
            error = 'La contraseña y su confirmación no coinciden.'
        else:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute('SELECT 1 FROM usuarios WHERE username = ?', (username,))
                if cursor.fetchone():
                    error = 'El nombre de usuario ya existe. Elija otro.'
                else:
                    cursor.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,))
                    if cursor.fetchone():
                        error = 'El correo electrónico ya está registrado.'
                    else:
                        cursor.execute(
                            'INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)',
                            (username, email, password)
                        )
                        conn.commit()
                        flash('Registro exitoso. Ahora puede iniciar sesión.', 'register_success')
                        return redirect(url_for('login'))

    return render_template('register.html', error=error, form_data=form_data)

@app.route('/welcome')
def welcome():
    """Muestra la vista de bienvenida después de un login exitoso."""
    return render_template('welcome.html')

@app.route('/logout')
def logout():
    """Cierra la sesión y redirige al login con mensaje de confirmación."""
    flash('Sesión cerrada exitosamente', 'logout')
    return redirect(url_for('login'))

if __name__ == '__main__':
   
    init_db()
   
    app.run(debug=True)
    