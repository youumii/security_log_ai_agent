from pathlib import Path
import json


def save_txt_report(result, filename):
    filename = Path(filename)

    lines = [
        "=" * 72,
        "Security Log AI Agent - 보안 로그 분석 보고서",
        "=" * 72,
        f"분석 파일: {result['source_file']}",
        f"분석 시각: {result['analyzed_at']}",
        f"전체 위험도: {result['overall_risk']['risk']} ({result['overall_risk']['score']}점)",
        f"AI 요약 모드: {result.get('ai_mode', '-')}",
        "",
        "[로그 통계]",
        f"정상 로그: {result['total_valid_logs']}건",
        f"깨진 로그: {result['broken_count']}건",
        f"로그인 성공: {result['event_counts']['login_success']}건",
        f"로그인 실패: {result['event_counts']['login_failed']}건",
        f"로그아웃: {result['event_counts']['logout']}건",
        "",
        "[적용 탐지 규칙]",
    ]

    for key, value in result["rules"].items():
        lines.append(f"- {key}: {value}")

    lines.extend([
        "",
        "[종합 위험도 모델]",
        f"- 공격 강도: {result['overall_risk']['intensity']['score']} / 50",
    ])

    for item in result["overall_risk"]["intensity"]["items"]:
        lines.append(
            f"  · {item['label']}: +{item['score']} / {item['max_score']} | {item['reason']}"
        )

    lines.append(
        f"- 영향도: {result['overall_risk']['impact']['score']} / 50"
    )

    for item in result["overall_risk"]["impact"]["items"]:
        lines.append(
            f"  · {item['label']}: +{item['score']} / {item['max_score']} | {item['reason']}"
        )

    lines.extend([
        f"- 종합: {result['overall_risk']['score']} / 100 ({result['overall_risk']['risk']})",
        "",
        "[AI 분석 요약]",
        result.get("ai_summary", ""),
        "",
        "[탐지 이벤트]",
    ])

    if result["detections"]:
        for i, d in enumerate(result["detections"], start=1):
            lines.extend([
                f"{i}. {d['type']}",
                f"   사용자: {d['user']}",
                f"   IP: {d['ip']}",
                f"   기간: {d['start']} ~ {d['end']}",
                f"   사유: {d['reason']}",
            ])
    else:
        lines.append("- 없음")

    lines.extend(["", "[깨진 로그]"])

    if result["broken_lines"]:
        for b in result["broken_lines"]:
            lines.append(
                f"- {b['line_number']}번째 줄 | {b['line']} | {b['reason']}"
            )
    else:
        lines.append("- 없음")

    filename.write_text("\n".join(lines), encoding="utf-8")
    return filename


def save_json_report(result, filename):
    filename = Path(filename)
    filename.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return filename
