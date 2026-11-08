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

def test_gateway_limits_and_port_wiring():
    config=yaml.safe_load((ROOT/'compose.yaml').read_text())
    services=config['services'];frontend=services['frontend'];agent=services['agent_service']
    assert frontend['ports']==['${BIND_HOST:-127.0.0.1}:${FRONTEND_PORT:-3000}:3000']
    assert frontend['environment']['LLM_RATE_LIMIT_PER_MINUTE']=='${LLM_RATE_LIMIT_PER_MINUTE:-10}'
    assert frontend['environment']['MAX_REQUEST_BODY_BYTES']=='${MAX_REQUEST_BODY_BYTES:-131072}'
    assert frontend['environment']['TRUSTED_PROXY_CIDR']=='${TRUSTED_PROXY_CIDR:-}'
    assert 'ALLOWED_ORIGINS' in frontend['environment']
    assert agent['environment']['MAX_PROMPT_CHARS']=='${MAX_PROMPT_CHARS:-4000}'
    assert agent['environment']['LLM_TIMEOUT_SECONDS']=='${LLM_TIMEOUT_SECONDS:-20}'
    assert agent['environment']['AGENT_MAX_SESSIONS']=='${AGENT_MAX_SESSIONS:-256}'
    nginx=(ROOT/'deploy/nginx.conf').read_text()
    for fragment in ('rate=${LLM_RATE_LIMIT_PER_MINUTE}r/m','client_max_body_size ${MAX_REQUEST_BODY_BYTES}',
                     'limit_req_status 429','include /tmp/realip.conf','include /tmp/corsmap.conf',
                     'error_page 413 = @payload_too_large','error_page 429 = @rate_limited'):
        assert fragment in nginx
    entrypoint=(ROOT/'frontend/entrypoint.sh').read_text()
    for fragment in ('set_real_ip_from','real_ip_header X-Forwarded-For','real_ip_recursive on'):
        assert fragment in entrypoint
    dockerfile=(ROOT/'frontend/Dockerfile').read_text()
    assert 'nginx.conf.template' in dockerfile and 'frontend-entrypoint.sh' in dockerfile


def test_demo_override_is_explicit():
    override=yaml.safe_load((ROOT/'compose.demo.yaml').read_text())
    recon=override['services']['reconstruction_service']
    assert recon['environment']['DEMO_MODE']=='true'
    assert recon['volumes']==['audit_data:/data:rw']
