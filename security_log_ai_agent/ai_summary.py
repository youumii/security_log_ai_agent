import json
import os
import urllib.request


def local_summary(result):
    detections = result["detections"]

    if not detections:
        text = (
            "현재 설정된 규칙 기준으로 뚜렷한 이상 로그인 패턴은 탐지되지 않았습니다. "
            "다만 규칙 기반 탐지는 모든 보안 사고를 식별할 수 없으므로 운영 환경에서는 "
            "추가 로그와 사용자 행동 정보를 함께 확인해야 합니다."
        )
        return {"mode": "LOCAL_RULE_SUMMARY", "text": text}

    top = detections[0]

    if result["overall_risk"]["risk"] == "HIGH":
        text = (
            f"고위험 수준의 로그 패턴이 탐지되었습니다. 주요 탐지 사유는 "
            f"'{top['reason']}'입니다. 관련 사용자와 IP의 최근 인증 기록을 우선 확인하고, "
            "동일한 접근 패턴이 반복되는지 추가 로그를 점검하는 것이 좋습니다. "
            f"종합 위험도는 {result['overall_risk']['score']}점이며, "
            "본 결과만으로 실제 침해를 확정할 수는 없습니다."
        )
    else:
        text = (
            f"주의가 필요한 인증 패턴이 탐지되었습니다. 주요 탐지 사유는 "
            f"'{top['reason']}'입니다. 해당 사용자와 발신 IP를 중심으로 추가 로그를 "
            "확인하는 것이 좋습니다."
        )

    return {"mode": "LOCAL_RULE_SUMMARY", "text": text}


def generate_summary(result):
    """
    OpenAI-compatible chat completions endpoint 선택 연동.

    환경변수:
    LLM_API_URL
    LLM_API_KEY
    LLM_MODEL

    셋 중 하나라도 없으면 로컬 요약으로 자동 전환합니다.
    """

    api_url = os.getenv("LLM_API_URL")
    api_key = os.getenv("LLM_API_KEY")
    model = os.getenv("LLM_MODEL")

    if not (api_url and api_key and model):
        return local_summary(result)

    compact = {
        "overall_risk": result["overall_risk"],
        "event_counts": result["event_counts"],
        "detections": result["detections"][:10],
    }

    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "당신은 SOC 보안 분석 보조자입니다. 제공된 탐지 결과만 근거로 "
                    "한국어로 4~6문장 분석을 작성하세요. 공격이 확정됐다고 단정하지 말고, "
                    "관찰된 사실, 가능한 위험, 우선 확인할 항목을 구분해 설명하세요."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(compact, ensure_ascii=False),
            },
        ],
        "temperature": 0.2,
    }

    req = urllib.request.Request(
        api_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["choices"][0]["message"]["content"].strip()
            return {"mode": "LLM", "text": text}
    except Exception:
        return local_summary(result)
