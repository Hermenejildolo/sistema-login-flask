from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import sqlite3
import re
import time
import unicodedata
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'clave_secreta_segura_para_el_proyecto'

DB_NAME = 'sistema_login.db'

EMAIL_REGEX = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
USERNAME_REGEX = r'^[A-Za-z0-9_.-]{3,30}$'
VALID_ROLES = {'admin', 'docente', 'estudiante'}
VALID_NOTA_STATES = {'activa', 'bloqueada', 'inactiva'}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
LOGIN_ATTEMPTS = {}


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def remove_invisible_and_control_chars(value):
    if value is None:
        return ''
    return ''.join(
        ch for ch in value
        if unicodedata.category(ch) not in {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}
    )


def normalize_user_text(value):
    cleaned = remove_invisible_and_control_chars(value)
    return cleaned.strip()


def has_forbidden_invisible_chars(value):
    if value is None:
        return False
    for ch in value:
        if unicodedata.category(ch) in {'Cc', 'Cf', 'Cs', 'Co', 'Cn'}:
            return True
    return False


def get_login_attempt_key():
    username = normalize_user_text(request.form.get('username', '')).lower()
    remote_addr = request.remote_addr or 'unknown'
    return f"{remote_addr}:{username}"


def cleanup_expired_attempts(now_ts):
    expired_keys = []
    for key, state in LOGIN_ATTEMPTS.items():
        lock_until = state.get('lock_until', 0)
        if state.get('count', 0) == 0 and lock_until <= now_ts:
            expired_keys.append(key)
    for key in expired_keys:
        LOGIN_ATTEMPTS.pop(key, None)


def get_lockout_remaining_seconds(key, now_ts):
    state = LOGIN_ATTEMPTS.get(key, {'count': 0, 'lock_until': 0})
    lock_until = state.get('lock_until', 0)
    return max(0, int(lock_until - now_ts))


def register_failed_attempt(key, now_ts):
    state = LOGIN_ATTEMPTS.get(key, {'count': 0, 'lock_until': 0})
    if state.get('lock_until', 0) <= now_ts:
        state['lock_until'] = 0
    state['count'] = state.get('count', 0) + 1
    if state['count'] >= MAX_LOGIN_ATTEMPTS:
        state['lock_until'] = now_ts + LOCKOUT_SECONDS
    LOGIN_ATTEMPTS[key] = state
    return state


def clear_login_attempts(key):
    LOGIN_ATTEMPTS.pop(key, None)


def get_table_columns(cursor, table_name):
    cursor.execute(f'PRAGMA table_info({table_name})')
    return [row[1] for row in cursor.fetchall()]


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Debe iniciar sesion para acceder.', 'logout')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Debe iniciar sesion para acceder.', 'logout')
                return redirect(url_for('login'))
            current_role = session.get('role')
            if current_role not in roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password TEXT NOT NULL,
                rol TEXT NOT NULL DEFAULT 'estudiante'
            )
        ''')

        user_columns = get_table_columns(cursor, 'usuarios')
        if 'email' not in user_columns:
            cursor.execute('ALTER TABLE usuarios ADD COLUMN email TEXT')
        if 'rol' not in user_columns:
            cursor.execute("ALTER TABLE usuarios ADD COLUMN rol TEXT NOT NULL DEFAULT 'estudiante'")

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cursos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT UNIQUE NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                estudiante_id INTEGER NOT NULL,
                docente_id INTEGER NOT NULL,
                curso_id INTEGER NOT NULL,
                valor REAL NOT NULL,
                estado TEXT NOT NULL DEFAULT 'activa',
                actualizado_en TEXT NOT NULL,
                FOREIGN KEY (estudiante_id) REFERENCES usuarios(id),
                FOREIGN KEY (docente_id) REFERENCES usuarios(id),
                FOREIGN KEY (curso_id) REFERENCES cursos(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nota_historial (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nota_id INTEGER NOT NULL,
                modificado_por INTEGER NOT NULL,
                fecha TEXT NOT NULL,
                valor_anterior REAL,
                valor_nuevo REAL,
                estado_anterior TEXT,
                estado_nuevo TEXT,
                detalle TEXT,
                FOREIGN KEY (nota_id) REFERENCES notas(id),
                FOREIGN KEY (modificado_por) REFERENCES usuarios(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inasistencias (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                estudiante_id INTEGER NOT NULL,
                docente_id INTEGER NOT NULL,
                curso_id INTEGER NOT NULL,
                fecha TEXT NOT NULL,
                motivo TEXT,
                creado_en TEXT NOT NULL,
                FOREIGN KEY (estudiante_id) REFERENCES usuarios(id),
                FOREIGN KEY (docente_id) REFERENCES usuarios(id),
                FOREIGN KEY (curso_id) REFERENCES cursos(id)
            )
        ''')

        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notas_estudiante ON notas(estudiante_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notas_curso ON notas(curso_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_historial_nota_fecha ON nota_historial(nota_id, fecha)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_inasistencias_estudiante_fecha ON inasistencias(estudiante_id, fecha)')

        cursos_base = ['Matematicas', 'Historia', 'Programacion']
        for curso in cursos_base:
            cursor.execute('INSERT OR IGNORE INTO cursos (nombre) VALUES (?)', (curso,))

        usuarios_base = [
            ('admin', 'admin@demo.com', '1234', 'admin'),
            ('docente1', 'docente1@demo.com', 'abcd1234', 'docente'),
            ('estudiante1', 'estudiante1@demo.com', 'abcd1234', 'estudiante')
        ]

        for username, email, password, rol in usuarios_base:
            cursor.execute('SELECT id FROM usuarios WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row:
                cursor.execute('UPDATE usuarios SET email = ?, rol = ? WHERE username = ?', (email, rol, username))
            else:
                cursor.execute(
                    'INSERT INTO usuarios (username, email, password, rol) VALUES (?, ?, ?, ?)',
                    (username, email, password, rol)
                )

        conn.commit()


def log_nota_change(conn, nota_id, modificado_por, valor_anterior, valor_nuevo, estado_anterior, estado_nuevo, detalle):
    conn.execute(
        '''
        INSERT INTO nota_historial (
            nota_id, modificado_por, fecha, valor_anterior, valor_nuevo,
            estado_anterior, estado_nuevo, detalle
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            nota_id,
            modificado_por,
            datetime.utcnow().isoformat(timespec='seconds'),
            valor_anterior,
            valor_nuevo,
            estado_anterior,
            estado_nuevo,
            detalle
        )
    )


def fetch_dashboard_data(user_id, user_role):
    with get_db_connection() as conn:
        cursos = conn.execute('SELECT id, nombre FROM cursos ORDER BY nombre').fetchall()
        docentes = conn.execute("SELECT id, username FROM usuarios WHERE rol = 'docente' ORDER BY username").fetchall()
        estudiantes = conn.execute("SELECT id, username FROM usuarios WHERE rol = 'estudiante' ORDER BY username").fetchall()

        notas = []
        inasistencias = []
        historial = []

        if user_role == 'estudiante':
            notas = conn.execute(
                '''
                SELECT n.id, c.nombre AS curso, n.valor, n.estado, u.username AS docente, n.actualizado_en
                FROM notas n
                JOIN cursos c ON c.id = n.curso_id
                JOIN usuarios u ON u.id = n.docente_id
                WHERE n.estudiante_id = ?
                ORDER BY n.actualizado_en DESC
                ''',
                (user_id,)
            ).fetchall()

            inasistencias = conn.execute(
                '''
                SELECT i.id, c.nombre AS curso, i.fecha, i.motivo, u.username AS docente
                FROM inasistencias i
                JOIN cursos c ON c.id = i.curso_id
                JOIN usuarios u ON u.id = i.docente_id
                WHERE i.estudiante_id = ?
                ORDER BY i.fecha DESC
                ''',
                (user_id,)
            ).fetchall()

        if user_role == 'docente':
            notas = conn.execute(
                '''
                SELECT n.id, e.username AS estudiante, c.nombre AS curso, n.valor, n.estado, n.actualizado_en
                FROM notas n
                JOIN usuarios e ON e.id = n.estudiante_id
                JOIN cursos c ON c.id = n.curso_id
                WHERE n.docente_id = ?
                ORDER BY n.actualizado_en DESC
                ''',
                (user_id,)
            ).fetchall()

            inasistencias = conn.execute(
                '''
                SELECT i.id, e.username AS estudiante, c.nombre AS curso, i.fecha, i.motivo
                FROM inasistencias i
                JOIN usuarios e ON e.id = i.estudiante_id
                JOIN cursos c ON c.id = i.curso_id
                WHERE i.docente_id = ?
                ORDER BY i.fecha DESC
                ''',
                (user_id,)
            ).fetchall()

        if user_role == 'admin':
            notas = conn.execute(
                '''
                SELECT n.id, e.username AS estudiante, d.username AS docente, c.nombre AS curso,
                       n.valor, n.estado, n.actualizado_en
                FROM notas n
                JOIN usuarios e ON e.id = n.estudiante_id
                JOIN usuarios d ON d.id = n.docente_id
                JOIN cursos c ON c.id = n.curso_id
                ORDER BY n.actualizado_en DESC
                LIMIT 200
                '''
            ).fetchall()

            historial = conn.execute(
                '''
                SELECT h.id, h.nota_id, u.username AS usuario, h.fecha, h.valor_anterior, h.valor_nuevo,
                       h.estado_anterior, h.estado_nuevo, h.detalle
                FROM nota_historial h
                JOIN usuarios u ON u.id = h.modificado_por
                ORDER BY h.fecha DESC
                LIMIT 300
                '''
            ).fetchall()

        return {
            'cursos': cursos,
            'docentes': docentes,
            'estudiantes': estudiantes,
            'notas': notas,
            'inasistencias': inasistencias,
            'historial': historial
        }


@app.route('/', methods=['GET', 'POST'])
def login():
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
            error = 'Debe ingresar usuario y contrasena.'
            return render_template('login.html', error=error)

        if has_forbidden_invisible_chars(request.form.get('username', '')):
            error = 'El usuario contiene caracteres invisibles o no permitidos.'
            return render_template('login.html', error=error)

        if has_forbidden_invisible_chars(password):
            error = 'La contrasena contiene caracteres invisibles o no permitidos.'
            return render_template('login.html', error=error)

        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT id, username, rol FROM usuarios WHERE username = ? AND password = ?',
                (username, password)
            ).fetchone()

        if user:
            clear_login_attempts(key)
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['rol']
            flash('Inicio de sesion exitoso', 'success')
            return redirect(url_for('welcome'))

        state = register_failed_attempt(key, now_ts)
        attempts_left = max(0, MAX_LOGIN_ATTEMPTS - state.get('count', 0))
        if attempts_left > 0:
            error = f'Credenciales incorrectas. Intentos restantes: {attempts_left}.'
        else:
            error = f'Demasiados intentos fallidos. Intente de nuevo en {LOCKOUT_SECONDS // 60} minuto(s).'

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    empty_fields = []
    form_data = {
        'username': '',
        'email': '',
        'role': 'estudiante'
    }

    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_email = request.form.get('email', '')
        username = normalize_user_text(raw_username)
        email = normalize_user_text(raw_email).lower()
        role = normalize_user_text(request.form.get('role', 'estudiante')).lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        password_stripped = password.strip()
        confirm_password_stripped = confirm_password.strip()

        form_data['username'] = username
        form_data['email'] = email
        form_data['role'] = role

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
        elif role not in VALID_ROLES:
            error = 'Rol invalido.'
        elif has_forbidden_invisible_chars(raw_username):
            error = 'El nombre de usuario contiene caracteres invisibles o no permitidos.'
            empty_fields = ['username']
        elif has_forbidden_invisible_chars(raw_email):
            error = 'El correo contiene caracteres invisibles o no permitidos.'
            empty_fields = ['email']
        elif has_forbidden_invisible_chars(password) or has_forbidden_invisible_chars(confirm_password):
            error = 'La contrasena contiene caracteres invisibles o no permitidos.'
            empty_fields = ['password', 'confirm_password']
        elif not re.match(USERNAME_REGEX, username):
            error = 'El usuario debe tener 3 a 30 caracteres y solo puede usar letras, numeros, punto, guion y guion bajo.'
            empty_fields = ['username']
        elif not re.match(EMAIL_REGEX, email):
            error = 'El correo electronico no tiene un formato valido.'
            empty_fields = ['email']
        elif len(password_stripped) < 6:
            error = 'La contrasena debe tener minimo 6 caracteres.'
            empty_fields = ['password']
        elif password != confirm_password:
            error = 'La contrasena y su confirmacion no coinciden.'
            empty_fields = ['password', 'confirm_password']
        else:
            with get_db_connection() as conn:
                existing_user = conn.execute('SELECT 1 FROM usuarios WHERE username = ?', (username,)).fetchone()
                if existing_user:
                    error = 'El nombre de usuario ya existe. Elija otro.'
                    empty_fields = ['username']
                else:
                    existing_email = conn.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,)).fetchone()
                    if existing_email:
                        error = 'El correo electronico ya esta registrado.'
                        empty_fields = ['email']
                    else:
                        conn.execute(
                            'INSERT INTO usuarios (username, email, password, rol) VALUES (?, ?, ?, ?)',
                            (username, email, password, role)
                        )
                        conn.commit()
                        flash('Registro exitoso. Ahora puede iniciar sesion.', 'register_success')
                        return redirect(url_for('login'))

    return render_template('register.html', error=error, form_data=form_data, empty_fields=empty_fields)


@app.route('/welcome')
@login_required
def welcome():
    user_id = session.get('user_id')
    user_role = session.get('role')
    query_start = time.perf_counter()
    data = fetch_dashboard_data(user_id, user_role)
    elapsed_seconds = time.perf_counter() - query_start

    if elapsed_seconds > 2:
        flash(
            f'Aviso RNF: la consulta demoro {elapsed_seconds:.2f}s (objetivo: < 2.00s).',
            'rnf_warn'
        )

    return render_template(
        'welcome.html',
        username=session.get('username'),
        role=user_role,
        cursos=data['cursos'],
        docentes=data['docentes'],
        estudiantes=data['estudiantes'],
        notas=data['notas'],
        inasistencias=data['inasistencias'],
        historial=data['historial']
    )


@app.route('/docente/notas/create', methods=['POST'])
@role_required('docente')
def docente_create_nota():
    docente_id = session['user_id']
    estudiante_id = request.form.get('estudiante_id', type=int)
    curso_id = request.form.get('curso_id', type=int)
    valor = request.form.get('valor', type=float)

    if not estudiante_id or not curso_id or valor is None:
        flash('Datos incompletos para registrar nota.', 'error')
        return redirect(url_for('welcome'))

    with get_db_connection() as conn:
        now_iso = datetime.utcnow().isoformat(timespec='seconds')
        cursor = conn.execute(
            '''
            INSERT INTO notas (estudiante_id, docente_id, curso_id, valor, estado, actualizado_en)
            VALUES (?, ?, ?, ?, 'activa', ?)
            ''',
            (estudiante_id, docente_id, curso_id, valor, now_iso)
        )
        nota_id = cursor.lastrowid
        log_nota_change(conn, nota_id, docente_id, None, valor, None, 'activa', 'Creacion de nota')
        conn.commit()

    flash('Nota registrada correctamente.', 'success')
    return redirect(url_for('welcome'))


@app.route('/docente/notas/<int:nota_id>/edit', methods=['POST'])
@role_required('docente')
def docente_edit_nota(nota_id):
    docente_id = session['user_id']
    nuevo_valor = request.form.get('valor', type=float)

    if nuevo_valor is None:
        flash('Debe ingresar un valor de nota valido.', 'error')
        return redirect(url_for('welcome'))

    with get_db_connection() as conn:
        nota = conn.execute(
            'SELECT id, docente_id, valor, estado FROM notas WHERE id = ?',
            (nota_id,)
        ).fetchone()

        if not nota:
            flash('La nota indicada no existe.', 'error')
            return redirect(url_for('welcome'))

        if nota['docente_id'] != docente_id:
            abort(403)

        if nota['estado'] != 'activa':
            flash('Solo puede editar notas en estado activa.', 'error')
            return redirect(url_for('welcome'))

        now_iso = datetime.utcnow().isoformat(timespec='seconds')
        conn.execute(
            'UPDATE notas SET valor = ?, actualizado_en = ? WHERE id = ?',
            (nuevo_valor, now_iso, nota_id)
        )
        log_nota_change(
            conn,
            nota_id,
            docente_id,
            nota['valor'],
            nuevo_valor,
            nota['estado'],
            nota['estado'],
            'Edicion de nota por docente'
        )
        conn.commit()

    flash('Nota actualizada por docente.', 'success')
    return redirect(url_for('welcome'))


@app.route('/docente/inasistencias/create', methods=['POST'])
@role_required('docente')
def docente_create_inasistencia():
    docente_id = session['user_id']
    estudiante_id = request.form.get('estudiante_id', type=int)
    curso_id = request.form.get('curso_id', type=int)
    fecha = normalize_user_text(request.form.get('fecha', ''))
    motivo = normalize_user_text(request.form.get('motivo', ''))

    if not estudiante_id or not curso_id or not fecha:
        flash('Debe indicar estudiante, curso y fecha de inasistencia.', 'error')
        return redirect(url_for('welcome'))

    try:
        datetime.strptime(fecha, '%Y-%m-%d')
    except ValueError:
        flash('La fecha debe tener formato YYYY-MM-DD.', 'error')
        return redirect(url_for('welcome'))

    with get_db_connection() as conn:
        conn.execute(
            '''
            INSERT INTO inasistencias (estudiante_id, docente_id, curso_id, fecha, motivo, creado_en)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (estudiante_id, docente_id, curso_id, fecha, motivo, datetime.utcnow().isoformat(timespec='seconds'))
        )
        conn.commit()

    flash('Inasistencia registrada correctamente.', 'success')
    return redirect(url_for('welcome'))


@app.route('/admin/notas/<int:nota_id>/edit', methods=['POST'])
@role_required('admin')
def admin_edit_nota(nota_id):
    nuevo_valor = request.form.get('valor', type=float)

    if nuevo_valor is None:
        flash('Debe ingresar un valor de nota valido.', 'error')
        return redirect(url_for('welcome'))

    with get_db_connection() as conn:
        nota = conn.execute('SELECT id, valor, estado FROM notas WHERE id = ?', (nota_id,)).fetchone()
        if not nota:
            flash('La nota indicada no existe.', 'error')
            return redirect(url_for('welcome'))

        if nota['estado'] == 'inactiva':
            flash('No se permite modificar notas inactivas.', 'error')
            return redirect(url_for('welcome'))

        now_iso = datetime.utcnow().isoformat(timespec='seconds')
        conn.execute('UPDATE notas SET valor = ?, actualizado_en = ? WHERE id = ?', (nuevo_valor, now_iso, nota_id))
        log_nota_change(
            conn,
            nota_id,
            session['user_id'],
            nota['valor'],
            nuevo_valor,
            nota['estado'],
            nota['estado'],
            'Edicion de nota por administrador'
        )
        conn.commit()

    flash('Nota actualizada por administrador.', 'success')
    return redirect(url_for('welcome'))


@app.route('/admin/notas/<int:nota_id>/estado', methods=['POST'])
@role_required('admin')
def admin_update_estado_nota(nota_id):
    nuevo_estado = normalize_user_text(request.form.get('estado', '')).lower()

    if nuevo_estado not in VALID_NOTA_STATES:
        flash('Estado invalido.', 'error')
        return redirect(url_for('welcome'))

    with get_db_connection() as conn:
        nota = conn.execute('SELECT id, valor, estado FROM notas WHERE id = ?', (nota_id,)).fetchone()
        if not nota:
            flash('La nota indicada no existe.', 'error')
            return redirect(url_for('welcome'))

        if nota['estado'] == nuevo_estado:
            flash('La nota ya tiene ese estado.', 'info')
            return redirect(url_for('welcome'))

        now_iso = datetime.utcnow().isoformat(timespec='seconds')
        conn.execute(
            'UPDATE notas SET estado = ?, actualizado_en = ? WHERE id = ?',
            (nuevo_estado, now_iso, nota_id)
        )
        log_nota_change(
            conn,
            nota_id,
            session['user_id'],
            nota['valor'],
            nota['valor'],
            nota['estado'],
            nuevo_estado,
            'Cambio de estado de nota'
        )
        conn.commit()

    flash('Estado de nota actualizado.', 'success')
    return redirect(url_for('welcome'))


@app.route('/health')
def health():
    return {'status': 'ok'}, 200


@app.route('/logout')
def logout():
    session.clear()
    flash('Sesion cerrada exitosamente', 'logout')
    return redirect(url_for('login'))


@app.errorhandler(403)
def forbidden(_error):
    flash('No tiene permisos para acceder a esta ruta.', 'error')
    return redirect(url_for('welcome'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
