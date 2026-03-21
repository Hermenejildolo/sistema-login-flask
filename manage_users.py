import argparse
import sqlite3
import sys

DB_NAME = "sistema_login.db"


def list_users(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, COALESCE(email, '') FROM usuarios ORDER BY id ASC")
    rows = cursor.fetchall()

    if not rows:
        print("No hay usuarios registrados.")
        return

    print("ID | Username | Email")
    print("-" * 50)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]}")


def delete_by_id(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM usuarios WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        print(f"No existe usuario con id={user_id}.")
        return

    cursor.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
    conn.commit()
    print(f"Usuario eliminado: {row[0]} (id={user_id})")


def delete_by_username(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM usuarios WHERE username = ?", (username,))
    row = cursor.fetchone()
    if not row:
        print(f"No existe usuario con username='{username}'.")
        return

    cursor.execute("DELETE FROM usuarios WHERE username = ?", (username,))
    conn.commit()
    print(f"Usuario eliminado: {username} (id={row[0]})")


def main():
    parser = argparse.ArgumentParser(description="Gestion basica de usuarios en SQLite")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="Lista todos los usuarios")

    delete_parser = subparsers.add_parser("delete", help="Elimina un usuario")
    group = delete_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", type=int, help="ID del usuario a eliminar")
    group.add_argument("--username", type=str, help="Username del usuario a eliminar")

    if len(sys.argv) == 1:
        with sqlite3.connect(DB_NAME) as conn:
            list_users(conn)
        return

    args = parser.parse_args()

    with sqlite3.connect(DB_NAME) as conn:
        if args.command == "list":
            list_users(conn)
        elif args.command == "delete":
            if args.id is not None:
                delete_by_id(conn, args.id)
            else:
                delete_by_username(conn, args.username)


if __name__ == "__main__":
    main()
