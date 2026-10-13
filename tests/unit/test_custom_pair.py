def test_hedioum_pair_config_is_scoped_and_uses_real_tun_mode():
    from engines.custom_pair import hedioum_configs
    server, hub = hedioum_configs("198.51.100.5", 21021, 21022, "test-auth-key", "hdt123", True)
    assert server["http_decoy_port"] == -1
    assert server["mimics"] == [{"type": "tls", "port": 21021, "server_name": "hedioum.test"}]
    assert hub["foreign_nodes"][0]["target_ip"] == "198.51.100.5"
    assert hub["foreign_nodes"][0]["tun_enabled"]
    assert hub["foreign_nodes"][0]["tun_name"] == "hdt123"
    assert hub["foreign_nodes"][0]["local_socks_port"] == 21022

