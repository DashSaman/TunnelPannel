def test_reality_sni_can_differ_from_local_cover_dial_address():
    from plan_executor.executor import generate_xray_reality
    class Remote:
        def run(self, *args, **kwargs):
            return {"stdout": "PrivateKey: private-test-value\nPassword: public-test-value\n"}
    server, client = generate_xray_reality(Remote(), "127.0.0.1:21018", "1234567890abcdef", "cover.test")
    assert server["target"] == "127.0.0.1:21018"
    assert server["serverNames"] == ["cover.test"]
    assert client["serverName"] == "cover.test"
