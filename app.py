"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes.
Authentication is implemented with JWTs.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash


load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = "HS256"

print("JWT_SECRET loaded:", JWT_SECRET is not None)
print("JWT_SECRET length:", len(JWT_SECRET) if JWT_SECRET else 0)
print("JWT_ALG:", JWT_ALG)


JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALG = "HS256"

DATABASE = "recipes.db"

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
        "owner_id": row["owner_id"],
    }


def require_auth():
    auth_header = request.headers.get("Authorization")

    if not auth_header:
        return None, (
            jsonify({"error": "Missing Authorization header"}),
            401,
        )

    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, (
            jsonify({"error": "Invalid Authorization header format"}),
            401,
        )

    token = parts[1]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
        )

        print("JWT payload:", payload)

    except jwt.ExpiredSignatureError as e:
        print("JWT ERROR TYPE:", type(e).__name__)
        print("JWT ERROR:", str(e))

        return None, (
            jsonify({"error": "Token expired, please log in again"}),
            401,
        )

    except jwt.InvalidTokenError as e:
        print("JWT ERROR TYPE:", type(e).__name__)
        print("JWT ERROR:", str(e))

        return None, (
            jsonify({"error": "Invalid token"}),
            401,
        )


    user_id = payload.get("sub")

    if not user_id:
        return None, (
            jsonify({"error": "Token missing subject claim"}),
            401,
        )

    g.user_id = int(user_id)
    g.username = payload.get("username")

    return payload, None




@app.get("/")
def hello():
    return jsonify({
        "message": "Recipe Box API",
        "recipes": "/recipes",
    })


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute(
        "SELECT * FROM recipes ORDER BY id"
    ).fetchall()

    return jsonify([
        recipe_to_dict(r)
        for r in rows
    ])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
def create_recipe():
    payload, error = require_auth()

    if error:
        return error

    user_id = g.user_id
    username = g.username

    data = request.get_json(silent=True)

    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({
            "error": "title and ingredients are required"
        }), 400

    db = get_db()

    try:
        cur = db.execute(
            "INSERT INTO recipes "
            "(title, ingredients, instructions, is_public, owner_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,
            ),
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "a recipe with that title already exists"
        }), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (cur.lastrowid,),
    ).fetchone()

    return jsonify({
        **recipe_to_dict(row),
        "created_by": {
            "id": user_id,
            "username": username,
        },
    }), 201


@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    payload, error = require_auth()

    if error:
        return error

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "a JSON body is required"
        }), 400

    db = get_db()

    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404

    if recipe["owner_id"] != g.user_id:
        return jsonify({"error": "forbidden"}), 403

    fields = []
    values = []

    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])

    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)

    if not fields:
        return jsonify({
            "error": "nothing to update"
        }), 400

    values.append(recipe_id)

    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "a recipe with that title already exists"
        }), 409

    if cur.rowcount == 0:
        return jsonify({
            "error": "recipe not found"
        }), 404

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    payload, error = require_auth()

    if error:
        return error

    db = get_db()

    recipe = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()

    if recipe is None:
        return jsonify({"error": "recipe not found"}), 404

    if recipe["owner_id"] != g.user_id:
        return jsonify({"error": "forbidden"}), 403

    cur = db.execute(
        "DELETE FROM recipes WHERE id = ?",
        (recipe_id,),
    )

    db.commit()

    return "", 204


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(email, str)
        or not email.strip()
        or not isinstance(password, str)
        or not password.strip()
    ):
        return jsonify({
            "error": "username, email, and password are required"
        }), 400

    password_hash = generate_password_hash(password)

    db = get_db()

    try:
        cur = db.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "account with that username or email already exists"
        }), 409

    return jsonify({
        "id": cur.lastrowid,
        "username": username,
        "email": email,
    }), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(password, str)
        or not password
    ):
        return jsonify({
            "error": "username and password are required"
        }), 400

    row = get_db().execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    if row is None or not check_password_hash(
        row["password_hash"],
        password,
    ):
        return jsonify({
            "error": "invalid username or password"
        }), 401

    payload = {
        "sub": str(row["id"]),
        "username": row["username"],
        "exp": datetime.now(timezone.utc) + timedelta(seconds=60),
    }


    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALG,
    )

    return jsonify({
        "message": "login successful",
        "token": token,
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
