from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
import re
import time
import unicodedata

app = Flask(__name__)

app.secret_key = 'clave_secreta_segura_para_el_proyecto'

DB_NAME = 'sistema_login.db'

EMAIL_REGEX = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
USERNAME_REGEX = r'^[A-Za-z0-9_.-]{3,30}$'

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

# Almacenamiento en memoria para bloqueo temporal por intentos fallidos.
LOGIN_ATTEMPTS = {}


def remove_invisible_and_control_chars(value):
    """Elimina caracteres de control/formato que pueden ser invisibles."""
    if value is None:
        return ''

    return ''.join(
        ch for ch in value
        if unicodedata.category(ch) not in {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}
    )


def normalize_user_text(value):
    """Normaliza texto visible para campos de usuario/correo."""
    cleaned = remove_invisible_and_control_chars(value)
    return cleaned.strip()


def has_forbidden_invisible_chars(value):
    """Indica si el texto contiene caracteres invisibles/control prohibidos."""
    if value is None:
        return False

    for ch in value:
        if unicodedata.category(ch) in {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}:
            return True
    return False


def get_login_attempt_key():
    """Genera una clave estable por IP y usuario para limitar intentos."""
    username = normalize_user_text(request.form.get('username', '')).lower()
    remote_addr = request.remote_addr or 'unknown'
    return f"{remote_addr}:{username}"


def cleanup_expired_attempts(now_ts):
    """Limpia entradas ya desbloqueadas para evitar crecimiento indefinido."""
    expired_keys = []
    for key, state in LOGIN_ATTEMPTS.items():
        lock_until = state.get('lock_until', 0)
        if state.get('count', 0) == 0 and lock_until <= now_ts:
            expired_keys.append(key)

    for key in expired_keys:
        LOGIN_ATTEMPTS.pop(key, None)


def get_lockout_remaining_seconds(key, now_ts):
    """Retorna segundos restantes de bloqueo para la clave dada."""
    state = LOGIN_ATTEMPTS.get(key, {'count': 0, 'lock_until': 0})
    lock_until = state.get('lock_until', 0)
    return max(0, int(lock_until - now_ts))


def register_failed_attempt(key, now_ts):
    """Registra intento fallido y bloquea temporalmente al superar el límite."""
    state = LOGIN_ATTEMPTS.get(key, {'count': 0, 'lock_until': 0})

    if state.get('lock_until', 0) <= now_ts:
        state['lock_until'] = 0

    state['count'] = state.get('count', 0) + 1

    if state['count'] >= MAX_LOGIN_ATTEMPTS:
        state['lock_until'] = now_ts + LOCKOUT_SECONDS

    LOGIN_ATTEMPTS[key] = state
    return state


def clear_login_attempts(key):
    """Limpia contador al autenticar correctamente."""
    LOGIN_ATTEMPTS.pop(key, None)


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
        now_ts = int(time.time())
        cleanup_expired_attempts(now_ts)

        key = get_login_attempt_key()
        remaining_lock = get_lockout_remaining_seconds(key, now_ts)

        if remaining_lock > 0:
            minutes = max(1, (remaining_lock + 59) // 60)
            error = f'Demasiados intentos fallidos. Intente de nuevo en {minutes} minuto(s).'
            return render_template('login.html', error=error)

        username = normalize_user_text(request.form.get('username', ''))
        password = request.form.get('password', '')

        if not username or not password.strip():
            error = 'Debe ingresar usuario y contraseña.'
            return render_template('login.html', error=error)

        if has_forbidden_invisible_chars(request.form.get('username', '')):
            error = 'El usuario contiene caracteres invisibles o no permitidos.'
            return render_template('login.html', error=error)

        if has_forbidden_invisible_chars(password):
            error = 'La contraseña contiene caracteres invisibles o no permitidos.'
            return render_template('login.html', error=error)

        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE username = ? AND password = ?', (username, password))
            user = cursor.fetchone()

        if user:
            clear_login_attempts(key)
            session['logged_in'] = True
            session['username'] = username
            
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('welcome'))
        else:
            state = register_failed_attempt(key, now_ts)
            attempts_left = max(0, MAX_LOGIN_ATTEMPTS - state.get('count', 0))
            if attempts_left > 0:
                error = f'Credenciales incorrectas. Intentos restantes: {attempts_left}.'
            else:
                error = f'Demasiados intentos fallidos. Intente de nuevo en {LOCKOUT_SECONDS // 60} minuto(s).'
            
            

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Maneja el registro de nuevos usuarios con validaciones de negocio."""
    error = None
    empty_fields = []
    form_data = {
        'username': '',
        'email': ''
    }

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_email = request.form.get('email', '')
        username = normalize_user_text(raw_username)
        email = normalize_user_text(raw_email).lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        password_stripped = password.strip()
        confirm_password_stripped = confirm_password.strip()

        form_data['username'] = username
        form_data['email'] = email

        if not username:
            empty_fields.append('username')
        if not email:
            empty_fields.append('email')
        if not password_stripped:
            empty_fields.append('password')
        if not confirm_password_stripped:
            empty_fields.append('confirm_password')

        if empty_fields:
            error = 'Todos los campos son obligatorios.'
        elif has_forbidden_invisible_chars(raw_username):
            error = 'El nombre de usuario contiene caracteres invisibles o no permitidos.'
            empty_fields = ['username']
        elif has_forbidden_invisible_chars(raw_email):
            error = 'El correo contiene caracteres invisibles o no permitidos.'
            empty_fields = ['email']
        elif has_forbidden_invisible_chars(password) or has_forbidden_invisible_chars(confirm_password):
            error = 'La contraseña contiene caracteres invisibles o no permitidos.'
            empty_fields = ['password', 'confirm_password']
        elif not re.match(USERNAME_REGEX, username):
            error = 'El usuario debe tener 3 a 30 caracteres y solo puede usar letras, numeros, punto, guion y guion bajo.'
            empty_fields = ['username']
        elif not re.match(EMAIL_REGEX, email):
            error = 'El correo electrónico no tiene un formato válido.'
            empty_fields = ['email']
        elif len(password_stripped) < 6:
            error = 'La contraseña debe tener mínimo 6 caracteres.'
            empty_fields = ['password']
        elif password != confirm_password:
            error = 'La contraseña y su confirmación no coinciden.'
            empty_fields = ['password', 'confirm_password']
        else:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()

                cursor.execute('SELECT 1 FROM usuarios WHERE username = ?', (username,))
                if cursor.fetchone():
                    error = 'El nombre de usuario ya existe. Elija otro.'
                    empty_fields = ['username']
                else:
                    cursor.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,))
                    if cursor.fetchone():
                        error = 'El correo electrónico ya está registrado.'
                        empty_fields = ['email']
                    else:
                        cursor.execute(
                            'INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)',
                            (username, email, password)
                        )
                        conn.commit()
                        flash('Registro exitoso. Ahora puede iniciar sesión.', 'register_success')
                        return redirect(url_for('login'))

    return render_template('register.html', error=error, form_data=form_data, empty_fields=empty_fields)

@app.route('/welcome')
def welcome():
    """Muestra la vista de bienvenida después de un login exitoso."""
    if not session.get('logged_in'):
        flash('Debe iniciar sesión para acceder.', 'logout')
        return redirect(url_for('login'))

    return render_template('welcome.html')

@app.route('/logout')
def logout():
    """Cierra la sesión y redirige al login con mensaje de confirmación."""
    session.clear()
    flash('Sesión cerrada exitosamente', 'logout')
    return redirect(url_for('login'))

if __name__ == '__main__':
   
    init_db()
   
    app.run(debug=True)
    