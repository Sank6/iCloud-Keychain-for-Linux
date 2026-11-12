from icp.auth import apple_tls


def test_request_once_uses_and_closes_an_isolated_session(monkeypatch):
    events = []

    class Response:
        content = b"response"

    class Session:
        def mount(self, prefix, adapter):
            events.append(("mount", prefix, adapter))

        def request(self, method, url, **kwargs):
            events.append(("request", method, url, kwargs))
            return Response()

        def close(self):
            events.append(("close",))

    monkeypatch.setattr(apple_tls.requests, "Session", Session)
    monkeypatch.setattr(apple_tls, "_build_context", object)

    response = apple_tls.request_once("POST", "https://example.invalid", timeout=10)

    assert response.content == b"response"
    assert events[0][0:2] == ("mount", "https://")
    assert events[1] == (
        "request", "POST", "https://example.invalid", {"timeout": 10},
    )
    assert events[2] == ("close",)
