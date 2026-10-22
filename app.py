import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-demo-only-change-this-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
csrf = CSRFProtect(app)

BUCKET_NAME = os.environ.get("FINSECURE_S3_BUCKET", "").strip()
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")
DATABASE_PATH = Path(os.environ.get("FINSECURE_DB_PATH", str(Path(__file__).with_name("finsecure.db"))))
logging.basicConfig(level=logging.INFO)
s3 = boto3.client("s3", region_name=AWS_REGION)

ALLOWED_CLIENTS = {"Client A", "Client B", "Accounting Firm"}
ALLOWED_CATEGORIES = {"Financial Report", "Tax Summary", "Audit Report"}
ALLOWED_ROLES = {"Administrator", "Accountant", "Auditor"}

# These accounts are created once in the local SQLite database with password hashes.
# Change these demo passwords after first login; do not use this setup for production.
SEED_USERS = [
    ("FinSecure Administrator", "admin@finsecure.com", "FinSecure123", "Administrator", sorted(ALLOWED_CLIENTS)),
    ("Accountant One", "accountant1@finsecure.com", "FinSecure123", "Accountant", ["Client A"]),
    ("Accountant Two", "accountant2@finsecure.com", "FinSecure123", "Accountant", ["Client B"]),
    ("Auditor One", "auditor1@finsecure.com", "FinSecure123", "Auditor", ["Client A", "Client B"]),
]


def db_connect():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            clients_json TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )""")
        for name, email, password, role, clients in SEED_USERS:
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO users (name,email,password_hash,role,clients_json,active,created_at) VALUES (?,?,?,?,?,?,?)",
                    (name, email, generate_password_hash(password), role, json.dumps(clients), 1,
                     datetime.now(timezone.utc).isoformat()),
                )


def get_user(email):
    with db_connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone()
    if not row:
        return None
    user = dict(row)
    user["clients"] = json.loads(user.pop("clients_json"))
    return user


def login_required():
    return bool(session.get("logged_in"))


def require_bucket():
    if not BUCKET_NAME:
        raise RuntimeError("FINSECURE_S3_BUCKET is not configured.")


def can_access_document(document):
    if not login_required():
        return False
    if session.get("role") == "Administrator":
        return True
    if document.get("owner") not in session.get("clients", []):
        return False
    return session.get("role") in {"Accountant", "Auditor"}


def metadata_key(document_id):
    return f"documents/{document_id}.json"


def pdf_key(document_id):
    return f"documents/{document_id}.pdf"


def get_document(document_id):
    require_bucket()
    try:
        response = s3.get_object(Bucket=BUCKET_NAME, Key=metadata_key(document_id))
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "404", "NotFound"}:
            return None
        raise


def list_documents():
    require_bucket()
    documents = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix="documents/"):
        for item in page.get("Contents", []):
            key = item["Key"]
            if not key.endswith(".json"):
                continue
            response = s3.get_object(Bucket=BUCKET_NAME, Key=key)
            documents.append(json.loads(response["Body"].read().decode("utf-8")))
    documents.sort(key=lambda item: item.get("date", ""), reverse=True)
    return documents


@app.route("/")
def home():
    if login_required():
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = get_user(email)
    if user and user["active"] and check_password_hash(user["password_hash"], password):
        session.clear()
        session["logged_in"] = True
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["name"] = user["name"]
        session["role"] = user["role"]
        session["clients"] = user["clients"]
        app.logger.info("Successful login: user=%s", user["email"])
        return redirect(url_for("dashboard"))
    app.logger.warning("Failed login attempt for email=%s", email[:120])
    return render_template("login.html", error="Invalid email or password. Please try again."), 401


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("home"))
    try:
        documents = [doc for doc in list_documents() if can_access_document(doc)]
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Could not load documents from S3")
        return "Could not load documents from S3. Check bucket, region, credentials, and IAM permissions.", 503
    return render_template("index.html", documents=documents, email=session.get("email"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not login_required():
        return redirect(url_for("home"))
    if session.get("role") not in {"Administrator", "Accountant"}:
        abort(403)
    if request.method == "GET":
        return render_template("upload.html")

    title = request.form.get("title", "").strip()
    client = request.form.get("client", "").strip()
    category = request.form.get("category", "").strip()
    uploaded_file = request.files.get("document")
    if not title or len(title) > 120:
        return render_template("upload.html", error="Enter a title of 1–120 characters."), 400
    if client not in ALLOWED_CLIENTS:
        return render_template("upload.html", error="Select a valid client."), 400
    if session.get("role") != "Administrator" and client not in session.get("clients", []):
        abort(403)
    if category not in ALLOWED_CATEGORIES:
        return render_template("upload.html", error="Select a valid document category."), 400
    if uploaded_file is None or not uploaded_file.filename:
        return render_template("upload.html", error="Please select a PDF file."), 400
    if not secure_filename(uploaded_file.filename).lower().endswith(".pdf"):
        return render_template("upload.html", error="Only PDF files are accepted."), 400
    uploaded_file.stream.seek(0)
    signature = uploaded_file.stream.read(5)
    uploaded_file.stream.seek(0)
    if signature != b"%PDF-":
        return render_template("upload.html", error="The file does not have a valid PDF signature."), 400
    file_bytes = uploaded_file.read()
    if not file_bytes or len(file_bytes) > 10 * 1024 * 1024:
        return render_template("upload.html", error="The PDF must be non-empty and no larger than 10 MB."), 400

    document_id = str(uuid.uuid4())
    object_key = pdf_key(document_id)
    now = datetime.now(timezone.utc)
    size = f"{len(file_bytes) / (1024 * 1024):.2f} MB" if len(file_bytes) >= 1024 * 1024 else f"{len(file_bytes) / 1024:.1f} KB"
    metadata = {
        "id": document_id, "name": f"{title}.pdf", "category": category,
        "owner": client, "date": now.strftime("%Y-%m-%d"), "size": size,
        "status": "Stored in S3", "description": f"{category} for {client}.",
        "uploaded_by": session.get("email", "unknown"), "s3_key": object_key,
    }
    try:
        require_bucket()
        s3.put_object(Bucket=BUCKET_NAME, Key=object_key, Body=BytesIO(file_bytes),
                      ContentType="application/pdf", ServerSideEncryption="AES256")
        s3.put_object(Bucket=BUCKET_NAME, Key=metadata_key(document_id),
                      Body=json.dumps(metadata).encode("utf-8"), ContentType="application/json",
                      ServerSideEncryption="AES256")
        app.logger.info("Document uploaded: id=%s user=%s client=%s", document_id, session.get("email"), client)
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("S3 upload failed")
        return render_template("upload.html", error="Upload failed. Check AWS credentials, region, bucket, and IAM permissions."), 503
    return render_template("upload.html", success="Upload successful. The PDF and metadata were saved to S3.")


@app.route("/documents/<string:document_id>")
def document_details(document_id):
    if not login_required():
        return redirect(url_for("home"))
    try:
        document = get_document(document_id)
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Could not load document metadata")
        return "Could not load document details from S3.", 503
    if document is None:
        abort(404)
    if not can_access_document(document):
        abort(403)
    return render_template("document.html", document=document)


@app.route("/documents/<string:document_id>/download")
def download_document(document_id):
    if not login_required():
        return redirect(url_for("home"))
    try:
        document = get_document(document_id)
        if document is None:
            abort(404)
        if not can_access_document(document):
            abort(403)
        download_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": BUCKET_NAME, "Key": document["s3_key"], "ResponseContentDisposition": "attachment"},
            ExpiresIn=60,
        )
        app.logger.info("Download link generated: id=%s user=%s", document_id, session.get("email"))
        return redirect(download_url)
    except (ClientError, BotoCoreError, RuntimeError):
        app.logger.exception("Could not generate download link")
        return "Could not create a download link.", 503


@app.route("/users", methods=["GET", "POST"])
def users():
    if not login_required():
        return redirect(url_for("home"))
    if session.get("role") != "Administrator":
        abort(403)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()
        clients = request.form.getlist("clients")
        clients = sorted(set(clients))

        if not name or len(name) > 100:
            flash("Enter a name of 1–100 characters.", "error")
        elif "@" not in email or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 12:
            flash("Password must be at least 12 characters long.", "error")
        elif role not in ALLOWED_ROLES:
            flash("Select a valid role.", "error")
        elif any(client not in ALLOWED_CLIENTS for client in clients):
            flash("Select only valid clients.", "error")
        elif role != "Administrator" and not clients:
            flash("Assign at least one client to non-administrator users.", "error")
        else:
            try:
                with db_connect() as conn:
                    conn.execute(
                        "INSERT INTO users (name,email,password_hash,role,clients_json,active,created_at) VALUES (?,?,?,?,?,?,?)",
                        (name, email, generate_password_hash(password), role, json.dumps(clients), 1,
                         datetime.now(timezone.utc).isoformat()),
                    )
                app.logger.info("Admin %s created user %s", session.get("email"), email)
                flash(f"User {email} created successfully.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("A user with that email already exists.", "error")
    with db_connect() as conn:
        rows = conn.execute("SELECT name,email,role,active,clients_json FROM users ORDER BY name").fetchall()
    users_data = []
    for row in rows:
        users_data.append({"name": row["name"], "email": row["email"], "role": row["role"],
                           "status": "Active" if row["active"] else "Disabled",
                           "clients": json.loads(row["clients_json"])})
    return render_template("users.html", users=users_data, email=session.get("email"),
                           allowed_clients=sorted(ALLOWED_CLIENTS), allowed_roles=sorted(ALLOWED_ROLES))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.errorhandler(403)
def forbidden(error):
    return '<h2>Access denied</h2><p>You are not authorized to access this resource.</p><a href="/dashboard">Return to dashboard</a>', 403


@app.errorhandler(404)
def page_not_found(error):
    return '<h2>Page not found</h2><p>The requested page or document does not exist.</p><a href="/dashboard">Return to dashboard</a>', 404


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum upload size is 10 MB.", 413


init_db()

if __name__ == "__main__":
    # Local academic demo only. Use a production WSGI server and HTTPS for deployment.
    app.run(debug=False)
