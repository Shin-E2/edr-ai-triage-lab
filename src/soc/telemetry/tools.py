"""🔍 조사 도구: 에이전트가 PC 기록을 조사할 때 부르는 함수들.

도구 계약 (docs/CONTRACT.md)
- 모든 결과의 기록 하나하나에 `event_id`가 있다 → 가드레일이 판정 근거를 검증하는 데 씀
- 명령줄은 앞부분만 (요약) → LLM에게 넘기는 글자 수가 곧 비용과 속도

함수의 설명(docstring)은 LLM이 '어떤 도구를 부를지' 고를 때 읽는 글입니다. 신경 써서 쓰세요.

    pytest tests/test_telemetry_tools.py -q
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address, ip_address, ip_network

from langchain_core.tools import tool

from ..config import settings
from ..osclient import get_client

EVENTS = f"{settings.index_events}-*"
CMD_MAX = 120           # 명령줄 요약 길이
MAX_ANCESTORS = 5
MAX_CHILDREN = 5
ACTIVITY_LIMIT = 50
TIMELINE_LIMIT = 100
NET_LIMIT = 500             # 네트워크 기록을 최대 몇 건까지 읽어 묶을지
NET_MAX_DESTS = 20          # 돌려줄 묶음(외부 IP와 프로세스) 개수 상한 (연결 횟수가 많은 순)
NET_EVENTS_PER_DEST = 10    # 묶음마다 함께 넘길 기록(event_id) 수
INTERNAL_NETS = [ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                         "127.0.0.0/8", "169.254.0.0/16",
                                         "::1/128", "fe80::/10", "fc00::/7")]   # IPv6 루프백, 링크 로컬, 사설


def _search(body: dict) -> list[dict]:
    res = get_client().search(index=EVENTS, body=body)
    return [h["_source"] for h in res["hits"]["hits"]]


def summarize(e: dict) -> dict:
    """기록 하나를 LLM에게 넘길 모양으로 줄입니다. (이미 만들어 둔 도우미)"""
    p = e.get("process", {})
    out = {"event_id": e["event_id"], "ts": e["ts"], "type": e["type"],
           "pid": p.get("pid"), "ppid": p.get("ppid"), "name": p.get("name"),
           "cmdline": (p.get("cmdline") or "")[:CMD_MAX], "user": p.get("user"), "signed": p.get("signed")}
    if e.get("network"):
        n = e["network"]
        out["detail"] = f"{n['dst_ip']}:{n['dst_port']} ({n.get('bytes_out', 0)} bytes)"
    elif e.get("file"):
        f = e["file"]
        out["detail"] = f"{f['action']} {f['path']}" + (f" → {f['new_path']}" if f.get("new_path") else "")
    elif e.get("registry"):
        out["detail"] = f"{e['registry']['key']} = {e['registry']['value']}"
    elif e.get("script_text"):
        out["detail"] = e["script_text"][:200]
    return out


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def _find_process(host: str, pid: int, before: str | None = None) -> dict | None:
    """host에서 pid를 가진 가장 최근 프로세스 생성 기록 (before가 있으면 그 시각 이전)."""
    filters = [{"term": {"host": host}}, {"term": {"type": "process"}}, {"term": {"process.pid": pid}}]
    if before is not None:
        filters.append({"range": {"ts": {"lte": before}}})
    rows = _search({"size": 1, "sort": [{"ts": "desc"}], "query": {"bool": {"filter": filters}}})
    return rows[0] if rows else None


def get_process_tree(host: str, pid: int) -> dict:
    """프로세스의 족보를 봅니다: 누가 이 프로세스를 실행했는지(부모, 조부모 …)와 이 프로세스가 실행한 자식들.
    '누가 실행했나', '정상 프로그램이 띄운 것인가'를 확인할 때 씁니다.

    Args:
        host: PC 이름 (예: WS-007)
        pid: 프로세스 번호 (알림의 pid)
    """
    process = _find_process(host, pid)
    result = {"host": host, "pid": pid, "process": summarize(process) if process else None,
              "ancestors": [], "children": []}
    if process is None:
        result["note"] = f"프로세스(pid {pid})의 생성 기록이 없습니다."
        return result

    current = process
    visited = {pid}
    for _ in range(MAX_ANCESTORS):
        parent_pid = current["process"].get("ppid")
        if not parent_pid:
            break
        if parent_pid in visited:
            result["note"] = f"부모 PID {parent_pid}가 반복되어 탐색을 중단했습니다."
            break
        visited.add(parent_pid)
        parent = _find_process(host, parent_pid, before=current["ts"])
        if parent is None:
            result["note"] = f"부모 프로세스(pid {parent_pid})의 생성 기록이 없습니다."
            break
        result["ancestors"].append(summarize(parent))
        current = parent

    children = _search({"size": MAX_CHILDREN, "sort": [{"ts": "asc"}], "query": {"bool": {"filter": [
        {"term": {"host": host}}, {"term": {"type": "process"}}, {"term": {"process.ppid": pid}},
        {"range": {"ts": {"gte": process["ts"]}}}]}}})
    result["children"] = [summarize(child) for child in children]
    return result


def get_process_activity(host: str, pid: int) -> dict:
    """한 프로세스가 한 일을 시간순으로 봅니다: 네트워크 연결, 파일 생성·변경, 레지스트리 변경, 실행한 스크립트.
    '이 프로세스가 무엇을 남겼나(파일, 통신)'를 확인할 때 씁니다.

    Args:
        host: PC 이름 (예: WS-007)
        pid: 프로세스 번호
    """
    events = _search({"size": ACTIVITY_LIMIT, "sort": [{"ts": "asc"}], "query": {"bool": {"filter": [
        {"term": {"host": host}}, {"term": {"process.pid": pid}},
        {"terms": {"type": ["network", "file", "registry", "script"]}}]}}})
    return {"host": host, "pid": pid, "events": [summarize(event) for event in events]}


def get_host_timeline(host: str, around_ts: str, minutes: int = 10) -> dict:
    """특정 시각 앞뒤로 그 PC에서 일어난 모든 일을 시간순으로 봅니다.
    알림 직전·직후에 다른 수상한 활동(다른 프로그램, 다른 통신)이 있었는지 넓게 볼 때 씁니다.

    Args:
        host: PC 이름 (예: WS-007)
        around_ts: 기준 시각 (ISO 형식, 예: 2026-11-16T09:12:02Z). 보통 알림 시각
        minutes: 기준 시각 앞뒤로 몇 분까지 볼지 (기본 10)
    """
    if minutes < 0:
        raise ValueError("minutes는 0 이상이어야 합니다")
    center = _parse_ts(around_ts)
    if center.utcoffset() is None:
        raise ValueError("around_ts에는 시간대가 필요합니다 (예: Z 또는 +09:00)")
    start, end = _iso(center - timedelta(minutes=minutes)), _iso(center + timedelta(minutes=minutes))
    events = _search({"size": TIMELINE_LIMIT + 1, "sort": [{"ts": "asc"}], "query": {"bool": {"filter": [
        {"term": {"host": host}}, {"range": {"ts": {"gte": start, "lte": end}}}]}}})
    return {"host": host, "from": start, "to": end,
            "events": [summarize(event) for event in events[:TIMELINE_LIMIT]],
            "truncated": len(events) > TIMELINE_LIMIT}


def _is_internal(ip: str) -> bool:
    """사내망, 루프백, 링크 로컬 주소인지. ipaddress의 is_private는 문서용 대역(198.51.100.0/24 등)도
    사설로 보므로 쓰지 않는다. 실습 데이터의 외부 IP가 바로 그 문서용 대역이기 때문이다."""
    addr = ip_address(ip)
    # ::ffff:10.0.0.1처럼 IPv4를 IPv6 모양으로 적은 주소는 안쪽 IPv4로 판단한다
    if isinstance(addr, IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in INTERNAL_NETS)


def get_network_connections(host: str, minutes: int = 30, around_ts: str | None = None) -> dict:
    """그 PC가 외부 IP와 통신한 기록을 IP와 프로세스별로 묶어 봅니다: 연결 횟수, 포트, 보낸 바이트, 연결 사이 간격(초).
    악성코드가 C2 서버에 일정한 간격으로 신호를 보내는 '비컨' 통신처럼, 주기적인 외부 통신이 의심될 때 씁니다.
    간격의 최소, 최대가 평균과 거의 같고 횟수가 많으면 사람이 아닌 프로그램이 규칙적으로 보낸 통신일 가능성이 큽니다.
    사내 IP(10.x, 172.16~31.x, 192.168.x와 IPv6 사설, 루프백, 링크 로컬) 통신은 빼고 봅니다.

    Args:
        host: PC 이름 (예: WS-007)
        minutes: 기준 시각 앞뒤로 몇 분까지 볼지 (기본 30)
        around_ts: 기준 시각 (ISO 형식, 예: 2026-11-16T09:12:02Z). 보통 알림 시각. 비우면 지금 시각
    """
    if minutes < 0:
        raise ValueError("minutes는 0 이상이어야 합니다")
    center = _parse_ts(around_ts) if around_ts else datetime.now(timezone.utc)
    if center.utcoffset() is None:
        raise ValueError("around_ts에는 시간대가 필요합니다 (예: Z 또는 +09:00)")
    start, end = _iso(center - timedelta(minutes=minutes)), _iso(center + timedelta(minutes=minutes))
    rows = _search({"size": NET_LIMIT + 1, "sort": [{"ts": "asc"}], "query": {"bool": {"filter": [
        {"term": {"host": host}}, {"term": {"type": "network"}}, {"range": {"ts": {"gte": start, "lte": end}}}]}}})
    truncated = len(rows) > NET_LIMIT

    # 외부 IP와 프로세스 쌍으로 묶는다. IP로만 묶으면 같은 서버에 붙은 다른 프로그램의 연결이 끼어
    # 규칙적인 비컨도 간격이 들쭉날쭉해 보인다. 시간순으로 받았으므로 묶인 목록도 시간순이다
    groups: dict[tuple, list[dict]] = {}
    for e in rows[:NET_LIMIT]:
        ip, p = e["network"]["dst_ip"], e.get("process", {})
        if not _is_internal(ip):
            groups.setdefault((ip, p.get("pid"), p.get("name")), []).append(e)

    connections = []
    for (ip, pid, name), evs in groups.items():
        times = [_parse_ts(e["ts"]) for e in evs]
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        connections.append({
            "dst_ip": ip, "pid": pid, "name": name,
            "ports": sorted({e["network"]["dst_port"] for e in evs}),
            "count": len(evs),
            "bytes_out": sum(e["network"].get("bytes_out", 0) for e in evs),
            "first_ts": evs[0]["ts"], "last_ts": evs[-1]["ts"],
            # 연결이 1번뿐이면 간격이 없다. 평균만 주면 들쭉날쭉한 통신도 규칙적으로 보이므로 최소, 최대를 함께 준다
            "interval_sec": {"avg": round(sum(gaps) / len(gaps), 1), "min": round(min(gaps), 1),
                             "max": round(max(gaps), 1)} if gaps else None,
            # 가드레일이 근거로 인정하려면 기록마다 event_id가 있어야 한다. 비용을 줄이려고 앞의 몇 개만 넘긴다
            "events": [{"event_id": e["event_id"], "ts": e["ts"]} for e in evs[:NET_EVENTS_PER_DEST]],
        })
    connections.sort(key=lambda c: (-c["count"], c["dst_ip"], c["pid"] or 0))
    return {"host": host, "from": start, "to": end, "connections": connections[:NET_MAX_DESTS],
            "truncated": truncated or len(connections) > NET_MAX_DESTS}


TELEMETRY_TOOLS = [tool(get_process_tree), tool(get_process_activity), tool(get_host_timeline),
                   tool(get_network_connections)]
