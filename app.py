"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
import sqlite3

from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

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
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
def create_recipe():
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public)"
            " VALUES (?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Basic validation
    if (
        not isinstance(username, str) or not username.strip() or
        not isinstance(email, str) or not email.strip() or
        not isinstance(password, str) or not password.strip()
    ):
        return jsonify({"error": "username, email, and password are required"}), 400

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
        # assumes UNIQUE(username) or UNIQUE(email) on users table
        return jsonify({"error": "account with that username or email already exists"}), 409

    return jsonify(
        {
            "id": cur.lastrowid,
            "username": username,
            "email": email,
        }
    ), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    if (
        not isinstance(username, str) or not username.strip()
        or not isinstance(password, str) or not password
    ):
        return jsonify({"error": "username and password are required"}), 400

    row = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid username or password"}), 401

    payload = {
        "sub": row["id"],
        "username": row["username"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256",
    )

    return jsonify({
        "message": "login successful",
        "token": token,
    }), 200




if __name__ == "__main__":
    app.run(debug=True)
