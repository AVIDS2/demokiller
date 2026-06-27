import os
import subprocess
import pickle
import yaml
import requests
from fastapi import FastAPI, Request
import psycopg2

app = FastAPI()
conn = psycopg2.connect(os.environ["DATABASE_URL"])


@app.get("/users/{user_id}")
def get_user(user_id: str, request: Request):
    # DK-PY-001: SQL injection via f-string
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    user = cursor.fetchone()
    return {"user": user}


@app.post("/run")
def run_command(request: Request):
    # DK-PY-002: Command injection via subprocess
    cmd = request.query_params.get("cmd", "")
    result = subprocess.call(f"echo {cmd}", shell=True)
    os.system(f"echo {cmd}")
    return {"output": result}


@app.post("/load")
def load_data(request: Request):
    # DK-PY-003: Unsafe deserialization
    body = request.body()
    data = pickle.loads(body)
    config = yaml.load(open("config.yaml"))
    code = request.query_params.get("code", "")
    eval(code)
    return {"data": data}


@app.get("/files")
def read_file(request: Request):
    # DK-PY-004: Path traversal
    filename = request.query_params.get("name", "")
    content = open(f"/data/{filename}").read()
    return {"content": content}


@app.get("/fetch")
def fetch_url(request: Request):
    # DK-PY-006: SSRF
    url = request.query_params.get("url", "")
    resp = requests.get(url)
    return {"status": resp.status_code, "body": resp.text[:1000]}
