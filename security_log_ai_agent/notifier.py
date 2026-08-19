import json
import os
import urllib.request


def notify_if_needed(result):
    """
    WEBHOOK_URL이 설정되어 있고 전체 위험도가 HIGH일 때만 전송합니다.
    보안상 토큰/원문 로그 전체는 전송하지 않고 요약 정보만 보냅니다.
    """

    url = os.getenv("WEBHOOK_URL")

    if not url:
        return False

    if result["overall_risk"]["risk"] != "HIGH":
        return False

    top = result["detections"][0] if result["detections"] else None

    payload = {
        "text": (
            "[Security Log AI Agent]\n"
            f"위험도: {result['overall_risk']['risk']} "
            f"({result['overall_risk']['score']}점)\n"
            f"로그인 실패: {result['event_counts']['login_failed']}건\n"
            f"탐지 이벤트: {len(result['detections'])}건\n"
            f"주요 탐지: {top['reason'] if top else '없음'}"
        )
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False
