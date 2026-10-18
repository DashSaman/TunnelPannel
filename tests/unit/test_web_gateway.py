"""The website host forwards requests; it never runs application/queue workers."""
import pytest
from scripts import web_gateway


def test_two_distinct_ports_skip_foreign_listeners_and_operator_reservations():
    report={'complete':True,'errors':[],'listeners':[{'proto':'TCP','port':21000}],
            'reserved_ranges':{'TCP':[[21001,21005]]}}
    ports=web_gateway.select_ports(report)
    assert len(set(ports)) == 2
    assert all(port > 21005 for port in ports)
    with pytest.raises(RuntimeError):
        web_gateway.select_ports(report,21000,21010)
    with pytest.raises(RuntimeError):
        web_gateway.select_ports({'complete':False},21010,21011)
    with pytest.raises(ValueError):
        web_gateway.select_ports(report,21010,21010)


def test_gateway_has_no_api_database_or_queue_process_and_pins_ssh():
    config=web_gateway.settings('192.0.2.10','tp-web-gateway',22,8080,21010,21011)
    units=web_gateway.units(config)
    ssh=units['tunnelpannel-web-transport.service']
    http=units['tunnelpannel-web-http.service']
    assert 'StrictHostKeyChecking=yes' in ssh and 'BatchMode=yes' in ssh
    assert '127.0.0.1:21011:127.0.0.1:8080' in ssh
    assert 'MemoryMax=64M' in ssh and 'CPUQuota=10%' in ssh
    assert 'nginx' in http and 'User=tp-web-gateway' in http
    assert 'MemoryMax=96M' in http
    assert all(word not in ssh+http for word in ('uvicorn','alembic','sqlite','celery','rq worker'))
    nginx=web_gateway.nginx_config(config)
    assert 'listen 127.0.0.1:21010;' in nginx
    assert 'proxy_pass http://127.0.0.1:21011;' in nginx
    assert 'proxy_request_buffering off;' in nginx
    assert 'proxy_buffering off;' in nginx and 'access_log off;' in nginx


@pytest.mark.parametrize('host,user', [('a;touch /tmp/x','user'),('192.0.2.10','root\nExecStart=/bin/x'),('user@host','u')])
def test_config_rejects_systemd_and_shell_injection(host,user):
    with pytest.raises(ValueError):
        web_gateway.settings(host,user,22,8080,21010,21011)
