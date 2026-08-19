from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import re

VALID_EVENTS = {"login_failed", "login_success", "logout"}

# 캡스톤 탐지 기준
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

MULTI_ACCOUNT_THRESHOLD = 3
MULTI_ACCOUNT_WINDOW_SECONDS = 300

SUCCESS_AFTER_FAIL_THRESHOLD = 3
SUCCESS_AFTER_FAIL_WINDOW_SECONDS = 600

SSH_FAIL_RE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?P<user>[\w.\-]+) from (?P<ip>[\d.]+)"
)

SSH_SUCCESS_RE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Accepted .* for (?P<user>[\w.\-]+) from (?P<ip>[\d.]+)"
)


def parse_datetime(value):
    value = value.strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if fmt == "%H:%M:%S":
                dt = dt.replace(year=2000, month=1, day=1)
            return dt
        except ValueError:
            pass

    raise ValueError(f"지원하지 않는 시간 형식: {value}")


def parse_line(line):
    line = line.strip()

    if not line:
        raise ValueError("빈 줄")

    # 1) CSV
    parts = [p.strip() for p in line.split(",")]
    if len(parts) == 4:
        time_value, user, event, ip = parts

        if event not in VALID_EVENTS:
            raise ValueError(f"알 수 없는 event: {event}")

        dt = parse_datetime(time_value)

        return {
            "time": time_value,
            "dt": dt,
            "user": user,
            "event": event,
            "ip": ip,
        }

    # 2) SSH 로그인 실패
    m = SSH_FAIL_RE.search(line)
    if m:
        current_year = datetime.now().year
        dt = datetime.strptime(
            f"{current_year} {m.group('month')} {m.group('day')} {m.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
        return {
            "time": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "dt": dt,
            "user": m.group("user"),
            "event": "login_failed",
            "ip": m.group("ip"),
        }

    # 3) SSH 로그인 성공
    m = SSH_SUCCESS_RE.search(line)
    if m:
        current_year = datetime.now().year
        dt = datetime.strptime(
            f"{current_year} {m.group('month')} {m.group('day')} {m.group('time')}",
            "%Y %b %d %H:%M:%S",
        )
        return {
            "time": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "dt": dt,
            "user": m.group("user"),
            "event": "login_success",
            "ip": m.group("ip"),
        }

    raise ValueError("지원하지 않는 로그 형식")


def load_logs(filename):
    logs = []
    broken_lines = []

    with Path(filename).open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            raw = line.strip()

            if not raw:
                continue

            if line_number == 1 and raw.lower().replace(" ", "").startswith("time,user,event,ip"):
                continue

            try:
                item = parse_line(line)
                item["line_number"] = line_number
                logs.append(item)
            except Exception as e:
                broken_lines.append({
                    "line_number": line_number,
                    "line": raw,
                    "reason": str(e),
                })

    logs.sort(key=lambda x: x["dt"])
    return logs, broken_lines


def overall_risk_level(score):
    """프로젝트에서 정의한 종합 위험도 등급."""
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def sliding_windows(items, window_seconds):
    left = 0
    for right in range(len(items)):
        while items[right]["dt"] - items[left]["dt"] > timedelta(seconds=window_seconds):
            left += 1
        yield left, right


def detect_user_bruteforce(logs):
    failed_by_user = defaultdict(list)

    for log in logs:
        if log["event"] == "login_failed":
            failed_by_user[log["user"]].append(log)

    detections = []

    for user, items in failed_by_user.items():
        best = None

        for left, right in sliding_windows(items, BRUTE_FORCE_WINDOW_SECONDS):
            count = right - left + 1
            if count >= BRUTE_FORCE_THRESHOLD:
                window = items[left:right + 1]
                candidate = {
                    "type": "USER_BRUTE_FORCE",
                    "user": user,
                    "ip": ", ".join(sorted({x["ip"] for x in window})),
                    "count": count,
                    "start": window[0]["time"],
                    "end": window[-1]["time"],
                    "reason": (
                        f"{BRUTE_FORCE_WINDOW_SECONDS}초 이내 로그인 실패 "
                        f"{count}회"
                    ),
                }
                if best is None or candidate["count"] > best["count"]:
                    best = candidate

        if best:
            detections.append(best)

    return detections


def detect_ip_multi_account(logs):
    failed_by_ip = defaultdict(list)

    for log in logs:
        if log["event"] == "login_failed":
            failed_by_ip[log["ip"]].append(log)

    detections = []

    for ip, items in failed_by_ip.items():
        best = None

        for left, right in sliding_windows(items, MULTI_ACCOUNT_WINDOW_SECONDS):
            window = items[left:right + 1]
            users = sorted({x["user"] for x in window})

            if len(users) >= MULTI_ACCOUNT_THRESHOLD:
                candidate = {
                    "type": "MULTI_ACCOUNT_ATTACK",
                    "user": ", ".join(users),
                    "user_count": len(users),
                    "ip": ip,
                    "count": len(window),
                    "start": window[0]["time"],
                    "end": window[-1]["time"],
                    "reason": (
                        f"{MULTI_ACCOUNT_WINDOW_SECONDS // 60}분 이내 동일 IP가 "
                        f"{len(users)}개 계정에 로그인 실패"
                    ),
                }
                if best is None or len(users) > len(best["user"].split(", ")):
                    best = candidate

        if best:
            detections.append(best)

    return detections


def detect_success_after_fail(logs):
    by_user = defaultdict(list)

    for log in logs:
        by_user[log["user"]].append(log)

    detections = []

    for user, items in by_user.items():
        for i, log in enumerate(items):
            if log["event"] != "login_success":
                continue

            start_time = log["dt"] - timedelta(seconds=SUCCESS_AFTER_FAIL_WINDOW_SECONDS)
            prior_fails = [
                x for x in items[:i]
                if x["event"] == "login_failed" and x["dt"] >= start_time
            ]

            if len(prior_fails) >= SUCCESS_AFTER_FAIL_THRESHOLD:
                ips = sorted({x["ip"] for x in prior_fails})
                different_ip = log["ip"] not in ips

                detections.append({
                    "type": "SUCCESS_AFTER_FAILURE",
                    "user": user,
                    "ip": log["ip"],
                    "count": len(prior_fails),
                    "different_ip": different_ip,
                    "start": prior_fails[0]["time"],
                    "end": log["time"],
                    "reason": (
                        f"{SUCCESS_AFTER_FAIL_WINDOW_SECONDS // 60}분 이내 "
                        f"로그인 실패 {len(prior_fails)}회 후 로그인 성공"
                    ),
                })

    return detections


def detect_multiple_ips(logs):
    failed_by_user = defaultdict(list)

    for log in logs:
        if log["event"] == "login_failed":
            failed_by_user[log["user"]].append(log)

    detections = []

    for user, items in failed_by_user.items():
        ips = sorted({x["ip"] for x in items})

        if len(ips) >= 3:
            detections.append({
                "type": "MULTIPLE_SOURCE_IPS",
                "user": user,
                "ip": ", ".join(ips),
                "count": len(items),
                "start": items[0]["time"],
                "end": items[-1]["time"],
                "reason": f"동일 계정에 서로 다른 IP {len(ips)}개에서 로그인 실패",
            })

    return detections



def calculate_weighted_overall_risk(detections):
    """
    종합 위험도 = 공격 강도(0~50) + 영향도(0~50)

    공격 강도는 얼마나 빠르고 넓게 시도했는지를,
    영향도는 실제 침해 가능성을 높이는 후속 징후를 평가합니다.
    """

    intensity_items = []

    brute_force_counts = [
        d["count"] for d in detections
        if d["type"] == "USER_BRUTE_FORCE"
    ]
    max_brute_force = max(brute_force_counts, default=0)

    # 60초 내 실패 5회부터 12점, 이후 실패 1회당 +2점, 최대 30점
    if max_brute_force >= 5:
        brute_score = min(30, 12 + (max_brute_force - 5) * 2)
        brute_reason = (
            f"60초 이내 로그인 실패 {max_brute_force}회 "
            f"→ 반복 밀도에 따라 {brute_score}점"
        )
    else:
        brute_score = 0
        brute_reason = "60초 이내 로그인 실패 5회 미만"

    intensity_items.append({
        "label": "로그인 실패 밀도",
        "score": brute_score,
        "max_score": 30,
        "reason": brute_reason,
    })

    multi_account_counts = [
        d.get("user_count", len(d.get("user", "").split(", ")))
        for d in detections
        if d["type"] == "MULTI_ACCOUNT_ATTACK"
    ]
    max_attacked_users = max(multi_account_counts, default=0)

    # 동일 IP가 3개 계정을 공격하면 8점, 이후 계정 1개당 +2점, 최대 20점
    if max_attacked_users >= 3:
        scope_score = min(20, 8 + (max_attacked_users - 3) * 2)
        scope_reason = (
            f"동일 IP가 {max_attacked_users}개 계정에 로그인 실패 "
            f"→ 공격 범위에 따라 {scope_score}점"
        )
    else:
        scope_score = 0
        scope_reason = "동일 IP의 공격 대상 계정 3개 미만"

    intensity_items.append({
        "label": "공격 범위",
        "score": scope_score,
        "max_score": 20,
        "reason": scope_reason,
    })

    intensity_score = min(sum(item["score"] for item in intensity_items), 50)

    impact_items = []
    success_events = [
        d for d in detections
        if d["type"] == "SUCCESS_AFTER_FAILURE"
    ]

    success_score = 20 if success_events else 0
    impact_items.append({
        "label": "반복 실패 후 로그인 성공",
        "score": success_score,
        "max_score": 20,
        "reason": (
            "반복 로그인 실패 이후 성공 기록 존재"
            if success_events else "해당 패턴 없음"
        ),
    })

    different_ip_success = any(d.get("different_ip") for d in success_events)
    different_ip_score = 15 if different_ip_success else 0
    impact_items.append({
        "label": "성공 IP 변화",
        "score": different_ip_score,
        "max_score": 15,
        "reason": (
            "실패 시도에 사용되지 않은 다른 IP에서 로그인 성공"
            if different_ip_success else "해당 패턴 없음"
        ),
    })

    multiple_source = any(
        d["type"] == "MULTIPLE_SOURCE_IPS" for d in detections
    )
    source_score = 10 if multiple_source else 0
    impact_items.append({
        "label": "접근 출처 다양성",
        "score": source_score,
        "max_score": 10,
        "reason": (
            "동일 계정에 3개 이상 서로 다른 IP에서 로그인 실패"
            if multiple_source else "해당 패턴 없음"
        ),
    })

    repeated_success_score = 5 if len(success_events) >= 2 else 0
    impact_items.append({
        "label": "복수 계정 침해 의심",
        "score": repeated_success_score,
        "max_score": 5,
        "reason": (
            f"실패 후 성공 패턴이 {len(success_events)}건 탐지됨"
            if len(success_events) >= 2 else "실패 후 성공 패턴 2건 미만"
        ),
    })

    impact_score = min(sum(item["score"] for item in impact_items), 50)
    total_score = min(intensity_score + impact_score, 100)

    return {
        "score": total_score,
        "risk": overall_risk_level(total_score),
        "intensity": {
            "label": "공격 강도",
            "score": intensity_score,
            "max_score": 50,
            "description": "짧은 시간의 반복 실패와 공격 대상 범위를 평가",
            "items": intensity_items,
        },
        "impact": {
            "label": "영향도",
            "score": impact_score,
            "max_score": 50,
            "description": "실패 후 성공, IP 변화 등 침해 가능성 징후를 평가",
            "items": impact_items,
        },
        "breakdown": intensity_items + impact_items,
    }


def build_user_summary(logs):
    users = defaultdict(lambda: {
        "login_success": 0,
        "login_failed": 0,
        "logout": 0,
        "ips": set(),
    })

    for log in logs:
        u = users[log["user"]]
        u[log["event"]] += 1
        u["ips"].add(log["ip"])

    rows = []
    for user, data in users.items():
        rows.append({
            "user": user,
            "login_success": data["login_success"],
            "login_failed": data["login_failed"],
            "logout": data["logout"],
            "ips": sorted(data["ips"]),
        })

    rows.sort(key=lambda x: x["login_failed"], reverse=True)
    return rows


def build_ip_summary(logs):
    ips = defaultdict(lambda: {
        "login_success": 0,
        "login_failed": 0,
        "users": set(),
    })

    for log in logs:
        i = ips[log["ip"]]
        if log["event"] in {"login_success", "login_failed"}:
            i[log["event"]] += 1
        i["users"].add(log["user"])

    rows = []
    for ip, data in ips.items():
        rows.append({
            "ip": ip,
            "login_success": data["login_success"],
            "login_failed": data["login_failed"],
            "users": sorted(data["users"]),
        })

    rows.sort(key=lambda x: x["login_failed"], reverse=True)
    return rows


def build_timeline(logs):
    buckets = defaultdict(lambda: {
        "login_success": 0,
        "login_failed": 0,
        "logout": 0,
    })

    for log in logs:
        key = log["dt"].strftime("%H:%M")
        buckets[key][log["event"]] += 1

    points = []
    for key in sorted(buckets):
        points.append({
            "label": key,
            **buckets[key],
        })

    max_failed = max((x["login_failed"] for x in points), default=1)

    for p in points:
        p["failed_percent"] = int((p["login_failed"] / max_failed) * 100) if max_failed else 0

    return points


def analyze_log_file(filename):
    logs, broken_lines = load_logs(filename)

    event_counts = Counter(x["event"] for x in logs)

    detections = []
    detections.extend(detect_user_bruteforce(logs))
    detections.extend(detect_ip_multi_account(logs))
    detections.extend(detect_success_after_fail(logs))
    detections.extend(detect_multiple_ips(logs))

    detections.sort(
        key=lambda x: (x["type"], x.get("user", ""), x.get("ip", ""))
    )

    overall = calculate_weighted_overall_risk(detections)

    # JSON 저장을 위해 dt 객체 제거
    serializable_logs = []
    for log in logs:
        serializable_logs.append({
            "time": log["time"],
            "user": log["user"],
            "event": log["event"],
            "ip": log["ip"],
            "line_number": log["line_number"],
        })

    return {
        "source_file": Path(filename).name,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_valid_logs": len(logs),
        "broken_count": len(broken_lines),
        "event_counts": {
            "login_success": event_counts["login_success"],
            "login_failed": event_counts["login_failed"],
            "logout": event_counts["logout"],
        },
        "overall_risk": overall,
        "detections": detections,
        "user_summary": build_user_summary(logs),
        "ip_summary": build_ip_summary(logs),
        "timeline": build_timeline(logs),
        "broken_lines": broken_lines,
        "logs": serializable_logs,
        "rules": {
            "brute_force": f"{BRUTE_FORCE_WINDOW_SECONDS}초 내 실패 {BRUTE_FORCE_THRESHOLD}회",
            "multi_account": f"{MULTI_ACCOUNT_WINDOW_SECONDS // 60}분 내 동일 IP가 {MULTI_ACCOUNT_THRESHOLD}계정 이상 공격",
            "success_after_fail": f"{SUCCESS_AFTER_FAIL_WINDOW_SECONDS // 60}분 내 실패 {SUCCESS_AFTER_FAIL_THRESHOLD}회 이상 후 성공",
        },
    }
