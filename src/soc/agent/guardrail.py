"""가드레일: LLM의 판정을 그대로 믿지 않고 기계적으로 검증합니다. (2일차 1-2, 운전 📘)

01 문서 4장의 '근거 추적'과 01번 정책 PDF 3장의 판정 기준을 코드로 옮긴 것입니다.

    pytest tests/test_guardrail.py -q
"""
from __future__ import annotations


def check_evidence_exists(verdict: dict, seen_event_ids: list[str], alert: dict) -> list[str]:
    """판정이 인용한 event_id가 도구로 실제 조회한 기록 안에 있는지 확인합니다.

    알림 자체의 event_ids(탐지 룰이 붙인 근거)도 확인된 기록으로 칩니다.
    돌려주는 것: 문제 설명 목록 (문제가 없으면 빈 목록)
    """
    # 정책 PDF 3장 "조회하지 않은 이벤트를 근거로 쓰는 것은 금지": 도구 결과와 알림에 없는 id는 지어낸 근거로 본다
    known = set(seen_event_ids) | set(alert.get("event_ids") or [])
    unseen = [i for i in verdict.get("evidence_event_ids") or [] if i not in known]
    # 같은 id를 여러 번 인용해도 한 번만 알린다. 이 문구는 다시 조사할 때 LLM에게 그대로 전달된다
    return [f"조회하지 않은 근거: {i}" for i in dict.fromkeys(unseen)]


def check_cites_evidence(verdict: dict) -> list[str]:
    """판정은 종류와 상관없이 근거 event_id를 하나 이상 인용해야 합니다. (01번 정책 PDF 3장)"""
    # 정책 3장 "모든 판정과 보고서는 근거 이벤트 ID를 인용해야": 정상, 의심 판정도 근거가 비면 추적할 수 없다
    if not verdict.get("evidence_event_ids"):
        return ["근거 event_id가 하나도 없습니다"]
    return []


def check_malicious_needs_two(verdict: dict) -> list[str]:
    """악성 판정에는 서로 다른 근거가 2개 이상 있어야 합니다. (01번 정책 PDF 3장 판정 기준)

    정책의 '서로 독립적인 근거'(공격 단계가 다른 근거)인지는 코드로 판단하지 않습니다. 여기서는 서로 다른 id
    개수만 세고, 독립성은 판정 프롬프트의 기준과 사람 검토에 맡깁니다. 같은 비컨의 반복 연결 2건처럼 단계가
    같은 근거도 이 검사는 통과합니다.
    """
    if verdict.get("verdict") != "malicious":
        return []
    # 같은 id를 두 번 적어도 근거는 하나이므로, 서로 다른 id 개수로 센다
    distinct = set(verdict.get("evidence_event_ids") or [])
    if len(distinct) < 2:
        return [f"악성 판정에는 서로 다른 근거가 2개 이상 필요합니다 (지금 {len(distinct)}개)"]
    return []


def check(verdict: dict, seen_event_ids: list[str], alert: dict) -> dict:
    problems = (check_cites_evidence(verdict) + check_evidence_exists(verdict, seen_event_ids, alert)
                + check_malicious_needs_two(verdict))
    return {"ok": not problems, "problems": problems}
