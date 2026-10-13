def test_full_hajsaman_uses_marked_xray_over_wg_over_sit():
    from engines.hajsaman_pair import full_xray_config
    config = full_xray_config(21001, 34567)
    assert config['inbounds'][0]['protocol'] == 'socks'
    assert config['outbounds'][0]['streamSettings']['sockopt']['mark'] == 34567
    assert config['outbounds'][0]['protocol'] == 'freedom'
