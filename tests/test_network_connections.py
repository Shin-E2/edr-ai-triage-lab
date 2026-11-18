"""📘 → 🔍 교차 작업: get_network_connections 테스트 (2일차 3).

    pytest tests/test_network_connections.py -q

OpenSearch가 켜져 있으면 진짜 OpenSearch(템플릿 strict 매핑 포함), 꺼져 있으면 메모리 흉내로 돈다 (conftest).
시나리오: WS-007의 powershell.exe가 C2(198.51.100.23:443)에 30초 간격으로 6번 통신한다 (simulator의
phishing_macro_powershell 비컨과 같은 모양). 사내 IP 통신, 다른 PC의 같은 통신, 시간 밖 통신을 함께 넣어
걸러지는지 본다.
"""
from datetime import datetime, timedelta, timezone

import pytest

from soc import mocks
from soc.agent import nodes
from soc.config import settings
from soc.osclient import get_client
from soc.telemetry import tools
from soc.telemetry.index_template import apply_template, index_events

C2 = "198.51.100.23"
T0 = datetime(2026, 11, 16, 9, 30, tzinfo=timezone.utc)
PS = {"pid": 5100, "ppid": 5000, "name": "powershell.exe", "cmdline": "powershell.exe -nop -w hidden -enc ...",
      "parent_name": "cmd.exe", "signed": True, "user": "kim"}

UPD = {"pid": 6200, "ppid": 5000, "name": "updater.exe", "cmdline": "C:\\Users\\Public\\updater.exe",
       "parent_name": "explorer.exe", "signed": False, "user": "kim"}


def _iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def net(eid, t, dst_ip, port=443, host="WS-007", bytes_out=300, proc=PS):
    return {"event_id": eid, "ts": _iso(t), "host": host, "type": "network", "process": dict(proc),
            "network": {"dst_ip": dst_ip, "dst_port": port, "proto": "tcp", "bytes_out": bytes_out}}


EVENTS = (
    [net(f"evt-net-c2-{i}", T0 + timedelta(seconds=30 * i), C2) for i in range(6)]          # 비컨 6번, 30초 간격
    + [net("evt-net-saas", T0 + timedelta(seconds=45), "203.0.113.10", bytes_out=6000)]     # 외부 1번
    + [net("evt-net-int-1", T0 + timedelta(seconds=10), "10.0.2.10", port=445),             # 사내 서버: 빼야 함
       net("evt-net-int-2", T0 + timedelta(seconds=20), "192.168.0.5", port=445)]
    + [net("evt-net-other-host", T0 + timedelta(seconds=5), C2, host="WS-099")]             # 다른 PC: 섞이면 안 됨
    + [net("evt-net-old", T0 - timedelta(hours=2), C2)]                                      # 시간 밖: 빼야 함
    + [net("evt-net-upd", T0 + timedelta(seconds=100), C2, port=8443, proc=UPD)]           # 같은 C2, 다른 프로세스
)


@pytest.fixture(scope="module", autouse=True)
def loaded():
    client = get_client()
    client.indices.delete(index=f"{settings.index_events}-*", params={"ignore_unavailable": "true"})
    apply_template(client)
    index_events(EVENTS, client)   # 진짜 OpenSearch에서는 strict 매핑에 맞지 않으면 여기서 거절된다
    yield
    client.indices.delete(index=f"{settings.index_events}-*", params={"ignore_unavailable": "true"})


def _call(minutes=10, around=T0):
    return tools.get_network_connections("WS-007", minutes=minutes, around_ts=_iso(around))


def test_beacon_is_grouped_with_count_and_interval():
    r = _call()
    c2 = _c2(r)
    assert c2["count"] == 6 and c2["pid"] == 5100 and c2["name"] == "powershell.exe"
    assert c2["ports"] == [443]
    assert c2["interval_sec"] == {"avg": 30.0, "min": 30.0, "max": 30.0}
    assert c2["bytes_out"] == 1800
    assert c2["first_ts"].startswith("2026-11-16T09:30:00") and c2["last_ts"].startswith("2026-11-16T09:32:30")
    assert [e["event_id"] for e in c2["events"]] == [f"evt-net-c2-{i}" for i in range(6)]


def _c2(r, pid=5100):
    return next(c for c in r["connections"] if c["dst_ip"] == C2 and c["pid"] == pid)


def test_same_ip_from_other_process_is_a_separate_group():
    # 프로세스를 섞어 묶으면 30초 비컨 사이에 다른 프로그램의 연결이 끼어 간격이 불규칙해 보인다
    # (로컬 시뮬레이터 WS-010에서 powershell 443 비컨과 updater.exe 8443이 섞여 최대 간격 142.5초로 나왔음)
    r = _call()
    upd = _c2(r, pid=6200)
    assert upd["count"] == 1 and upd["ports"] == [8443] and upd["name"] == "updater.exe"
    assert _c2(r)["interval_sec"]["max"] == 30.0


def test_internal_ips_are_excluded():
    ips = {c["dst_ip"] for c in _call()["connections"]}
    assert ips == {C2, "203.0.113.10"}


def test_other_host_and_out_of_window_are_excluded():
    ids = {e["event_id"] for c in _call()["connections"] for e in c["events"]}
    assert "evt-net-other-host" not in ids and "evt-net-old" not in ids


def test_sorted_by_count_and_single_connection_has_no_interval():
    r = _call()
    assert [(c["dst_ip"], c["pid"]) for c in r["connections"]] == [(C2, 5100), (C2, 6200), ("203.0.113.10", 5100)]
    assert r["connections"][1]["interval_sec"] is None


def test_window_fields_and_truncated():
    r = _call(minutes=10)
    assert r["host"] == "WS-007"
    assert r["from"] == "2026-11-16T09:20:00Z" and r["to"] == "2026-11-16T09:40:00Z"
    assert r["truncated"] is False


def test_every_event_has_event_id_that_guardrail_can_see():
    # 계약: 모든 기록에 event_id. run_tools는 nodes._ids로 이 값을 '실제로 조회한 기록'에 넣는다
    r = _call()
    listed = [e["event_id"] for c in r["connections"] for e in c["events"]]
    assert listed and all(listed)
    assert set(nodes._ids(r)) == set(listed)


def test_no_network_returns_empty_list():
    r = tools.get_network_connections("WS-001", minutes=10, around_ts=_iso(T0))
    assert r["connections"] == [] and r["truncated"] is False


def test_bad_input_raises():
    with pytest.raises(ValueError):
        tools.get_network_connections("WS-007", minutes=-1, around_ts=_iso(T0))
    with pytest.raises(ValueError):
        tools.get_network_connections("WS-007", minutes=10, around_ts="2026-11-16T09:30:00")


def test_events_per_destination_are_capped_but_count_is_full(monkeypatch):
    monkeypatch.setattr(tools, "NET_EVENTS_PER_DEST", 3)
    c2 = _c2(_call())
    assert c2["count"] == 6 and len(c2["events"]) == 3


def test_truncated_when_more_than_limit(monkeypatch):
    monkeypatch.setattr(tools, "NET_LIMIT", 4)
    assert _call()["truncated"] is True


def test_truncated_when_more_groups_than_limit(monkeypatch):
    monkeypatch.setattr(tools, "NET_MAX_DESTS", 1)
    r = _call()
    assert r["truncated"] is True and len(r["connections"]) == 1 and r["connections"][0]["count"] == 6


def test_default_window_ends_now():
    # around_ts를 주지 않으면 지금 시각 기준. 실시간 생성기(--loop, --inject)로 들어온 기록을 볼 때 쓴다
    now = datetime.now(timezone.utc).replace(microsecond=0)
    index_events([net("evt-net-now", now - timedelta(minutes=1), C2)], get_client())
    r = tools.get_network_connections("WS-007", minutes=5)
    assert [e["event_id"] for c in r["connections"] for e in c["events"]] == ["evt-net-now"]


def test_registered_as_tool_and_mock_has_same_shape():
    assert "get_network_connections" in [t.name for t in tools.TELEMETRY_TOOLS]
    assert "get_network_connections" in [t.name for t in mocks.TELEMETRY_TOOLS]
    real, fake = _call(), mocks.get_network_connections("WS-007", minutes=10, around_ts=_iso(T0))
    assert set(fake) == set(real)
    assert set(fake["connections"][0]) == set(real["connections"][0])
    assert all(e["event_id"] for c in fake["connections"] for e in c["events"])
