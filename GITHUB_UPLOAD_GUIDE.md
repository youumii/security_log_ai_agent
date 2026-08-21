# GitHub Upload Guide

이 폴더는 포트폴리오 제출용 GitHub 업로드 최종본입니다.

## 주요 구성
- `app.py` — Flask 실행 및 라우팅
- `core.py` — 로그 파싱, 이상행위 탐지, 위험도 계산
- `ai_summary.py` — 규칙 기반 요약 및 선택적 LLM 연동
- `notifier.py` — 선택적 Webhook 알림
- `reporter.py` — TXT / JSON 보고서 생성
- `templates/` — 웹 화면
- `static/` — CSS
- `tests/` — 자동 테스트
- `sample_*.csv` — 테스트 로그
- `README.md` — 프로젝트 설명
- `PORTFOLIO_GUIDE.md` — 개발 및 문제 해결 기록
- `ARCHITECTURE.md` — 시스템 구조

## 올리지 않는 파일
- `venv/`
- `.env`
- `__pycache__/`
- 실행 중 생성되는 업로드/보고서 파일

## Git 명령어
```bash
git init
git add .
git commit -m "feat: add security log anomaly detection dashboard"
git branch -M main
git remote add origin <YOUR_REPOSITORY_URL>
git push -u origin main
```

## 실행
```bat
run.bat
```

또는:

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

브라우저에서 `http://127.0.0.1:5000` 접속.
