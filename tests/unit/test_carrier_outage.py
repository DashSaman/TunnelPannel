def test_carrier_probe_targets_underlay_not_overlay_interface():
    from orchestrator.pair_runtime import carrier_details
    artifact = {'components': [
        {'method': 'SECURE_GOST_TUN_CARRIER', 'interfaces_a': ['ngc_underlay'], 'services_a': ['own-gost-client']},
        {'method': 'SIT_6IN4', 'interface_name': 'nsi_overlay', 'systemd_unit': 'own-sit'}]}
    assert carrier_details(artifact) == ('ngc_underlay', ['own-gost-client'])
