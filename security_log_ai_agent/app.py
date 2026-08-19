from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import os
import secrets
from dotenv import load_dotenv

load_dotenv()

from core import analyze_log_file
from ai_summary import generate_summary
from reporter import save_txt_report, save_json_report
from notifier import notify_if_needed

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(24)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {".csv", ".log", ".txt"}


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("logfile")

    if not uploaded or not uploaded.filename:
        flash("분석할 로그 파일을 선택해 주세요.")
        return redirect(url_for("index"))

    if not allowed_file(uploaded.filename):
        flash("csv, log, txt 파일만 분석할 수 있습니다.")
        return redirect(url_for("index"))

    safe_name = secure_filename(uploaded.filename)
    if not safe_name:
        safe_name = "uploaded_log.txt"

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    saved_path = UPLOAD_DIR / f"{stamp}_{safe_name}"
    uploaded.save(saved_path)

    try:
        result = analyze_log_file(saved_path)
    except Exception as e:
        flash(f"로그 분석 중 오류가 발생했습니다: {e}")
        return redirect(url_for("index"))

    ai_result = generate_summary(result)
    result["ai_summary"] = ai_result["text"]
    result["ai_mode"] = ai_result["mode"]

    report_base = f"security_report_{stamp}"
    txt_path = REPORT_DIR / f"{report_base}.txt"
    json_path = REPORT_DIR / f"{report_base}.json"

    save_txt_report(result, txt_path)
    save_json_report(result, json_path)

    notification_sent = notify_if_needed(result)
    result["notification_sent"] = notification_sent

    return render_template(
        "result.html",
        result=result,
        txt_name=txt_path.name,
        json_name=json_path.name,
    )


@app.route("/sample/<kind>")
def sample(kind):
    mapping = {
        "attack": BASE_DIR / "sample_attack_logs.csv",
        "normal": BASE_DIR / "sample_normal_logs.csv",
    }
    path = mapping.get(kind)
    if not path:
        return "지원하지 않는 샘플입니다.", 404
    return send_file(path, as_attachment=True)


@app.route("/report/<filename>")
def report(filename):
    safe_name = Path(filename).name
    path = REPORT_DIR / safe_name

    if path.suffix.lower() not in {".txt", ".json"}:
        return "지원하지 않는 보고서입니다.", 404

    if not path.exists():
        return "보고서를 찾을 수 없습니다.", 404

    return send_file(path, as_attachment=True)


@app.errorhandler(413)
def too_large(_):
    flash("파일이 너무 큽니다. 5MB 이하 로그를 사용해 주세요.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
