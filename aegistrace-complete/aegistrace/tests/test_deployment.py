from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]

def test_network_separation_and_egress():
    config=yaml.safe_load((ROOT/'compose.yaml').read_text())
    services=config['services'];agent=services['agent_service'];audit=services['audit_service'];recon=services['reconstruction_service']
    assert not set(agent['networks']) & set(recon['networks'])
    assert 'volumes' not in agent and 'ports' not in agent and 'ports' not in audit
    assert all(config['networks'][name].get('internal') for name in agent['networks'])
    assert recon['volumes']==['audit_data:/data:ro', 'anchor_data:/anchor_data:ro']
    assert 'anchor_data:/anchor_data:ro' in recon['volumes']
    assert 'anchor_net' not in agent['networks']
    assert 'anchor_data' not in str(agent.get('volumes', []))
    assert 'anchor_data' not in str(audit.get('volumes', []))
    assert 'anchor_net' in config['networks']
    assert config['networks']['anchor_net'].get('internal') is True
    assert set(services['anchor_service']['networks']) == {'anchor_net'}
    assert services['anchor_service']['volumes'] == ['anchor_data:/anchor_data']
    assert recon['environment']['DEMO_MODE']=='false'
    assert services['groq_proxy']['networks'].keys() >= {'internet','groq_egress'}
    for name,service in services.items():
        if name!='groq_proxy': assert 'internet' not in service['networks']
    nginx=(ROOT/'deploy/nginx.conf').read_text()
    for address in agent['networks'].values(): assert 'deny '+address['ipv4_address']+';' in nginx
    squid=(ROOT/'deploy/squid.conf').read_text()
    assert 'acl groq dstdomain api.groq.com' in squid
    assert 'http_access allow agent CONNECT TLS_port groq' in squid
    assert 'http_access deny all' in squid

def test_demo_override_is_explicit():
    override=yaml.safe_load((ROOT/'compose.demo.yaml').read_text())
    recon=override['services']['reconstruction_service']
    assert recon['environment']['DEMO_MODE']=='true'
    assert recon['volumes']==['audit_data:/data:rw']
