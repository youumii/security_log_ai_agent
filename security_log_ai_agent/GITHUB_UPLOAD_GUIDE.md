# GitHub 업로드 방법

이 폴더는 GitHub 업로드용으로 정리된 프로젝트입니다.

## 업로드하면 되는 파일

프로젝트 폴더 안의 파일과 폴더를 그대로 저장소에 올리면 됩니다.

주요 구성:

- `app.py` — Flask 웹 애플리케이션
- `core.py` — 로그 파싱 및 이상행위 탐지
- `ai_summary.py` — AI/로컬 분석 요약
- `notifier.py` — 선택적 Webhook 알림
- `reporter.py` — TXT/JSON 보고서 생성
- `templates/` — 웹 화면
- `static/` — CSS
- `tests/` — 자동 테스트
- `sample_*.csv` — 테스트용 샘플 로그
- `requirements.txt` — 필요한 Python 패키지
- `README.md` — 프로젝트 설명
- `.env.example` — 환경변수 예시
- `.gitignore` — GitHub에 올리지 않을 파일 설정

## 올리지 않는 파일

`.gitignore`에 의해 다음 항목은 제외됩니다.

- `venv/`
- `.env`
- `__pycache__/`
- 실행 중 생성되는 업로드/보고서 파일
- IDE/OS 임시 파일

특히 실제 API Key가 들어 있는 `.env` 파일은 GitHub에 올리지 마세요.

## Git 명령어로 업로드

GitHub에서 빈 Repository를 만든 뒤 이 프로젝트 폴더에서 실행합니다.

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin <YOUR_REPOSITORY_URL>
git push -u origin main
```

## 실행 방법

Windows:

```bat
run.bat
```

또는 직접 실행:

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

브라우저에서 `http://127.0.0.1:5000`으로 접속합니다.
