"""📘 가드레일 경계 사례 테스트 (2일차 1-2, TODO[G-1], [G-2]).

tests/test_guardrail.py의 기본 사례 외에, 실제 판정에서 나올 수 있는 모양을 확인합니다.
기준: 01번 정책 PDF 3장 "악성 판정에는 서로 독립적인 근거 이벤트가 두 개 이상",
"조회하지 않은 이벤트를 근거로 쓰는 것은 금지".

    pytest tests/test_guardrail_edges.py -q
"""
from soc.agent import guardrail

ALERT = {"alert_id": "al-edge", "host": "WS-007", "event_ids": ["evt-00000023"]}


def test_g1_message_names_the_unseen_id():
    # 다시 조사할 때 LLM에게 이 문구가 그대로 전달되므로, 어떤 id가 문제인지 들어 있어야 한다
    v = {"verdict": "suspicious", "evidence_event_ids": ["evt-77777777"]}
    assert guardrail.check_evidence_exists(v, [], ALERT) == ["조회하지 않은 근거: evt-77777777"]


def test_g1_same_unseen_id_reported_once_in_order():
    v = {"verdict": "malicious", "evidence_event_ids": ["evt-2", "evt-1", "evt-2"]}
    assert guardrail.check_evidence_exists(v, [], ALERT) == ["조회하지 않은 근거: evt-2", "조회하지 않은 근거: evt-1"]


def test_g1_missing_fields_do_not_crash():
    # 판정에 근거 칸이 없거나 알림에 event_ids가 없어도 검사가 죽지 않는다
    assert guardrail.check_evidence_exists({"verdict": "benign"}, [], {"alert_id": "x"}) == []
    v = {"verdict": "suspicious", "evidence_event_ids": ["evt-5"]}
    assert guardrail.check_evidence_exists(v, ["evt-5"], {"alert_id": "x"}) == []


def test_g2_malicious_without_evidence_field_is_caught():
    assert guardrail.check_malicious_needs_two({"verdict": "malicious"})


def test_g2_benign_and_suspicious_are_not_checked():
    assert guardrail.check_malicious_needs_two({"verdict": "benign", "evidence_event_ids": []}) == []
    assert guardrail.check_malicious_needs_two({"verdict": "suspicious", "evidence_event_ids": []}) == []


def test_check_combines_both_rules():
    # 지어낸 근거 1개 + 실제 근거 1개인 악성 판정: G-2는 통과(서로 다른 id 2개)하지만 G-1이 잡는다
    v = {"verdict": "malicious", "evidence_event_ids": ["evt-00000023", "evt-99999999"]}
    out = guardrail.check(v, [], ALERT)
    assert out["ok"] is False
    assert out["problems"] == ["조회하지 않은 근거: evt-99999999"]
    # 실제 근거 1개뿐인 악성 판정: G-2가 잡는다
    out = guardrail.check({"verdict": "malicious", "evidence_event_ids": ["evt-00000023"]}, [], ALERT)
    assert out["ok"] is False and len(out["problems"]) == 1
