import pytest

from soc.kb import search as kb_search


@pytest.mark.parametrize("kwargs, expected_k", [({"k": 7}, 5), ({"k": 3}, 3), ({"k": 0}, 1), ({}, 3)])
def test_search_playbook_clamps_k_and_preserves_contract(monkeypatch, kwargs, expected_k):
    # 실제 검색 없이 전달된 k와 도구 계약에 맞는 결과만 확인합니다.
    calls = []

    def fake_search(query, k):
        # 요청 개수만큼 가짜 결과를 만들어 상한과 하한 적용을 확인합니다.
        calls.append((query, k))
        return [{"source": "playbook.pdf", "page": i + 1, "category": "response",
                 "text": f"hit {i}", "score": 1.0, "id": f"hit-{i}"} for i in range(k)]

    monkeypatch.setattr(kb_search, "search", fake_search)

    result = kb_search.search_playbook("격리 승인", **kwargs)

    assert calls == [("격리 승인", expected_k)]
    assert len(result) == expected_k
    assert all(set(hit) == {"source", "page", "category", "text", "score"} for hit in result)
