"""The adapter boundary: every x_* field, utm_token and anything pass / psk /
secret / key / token is dropped — at any depth — and key material in a value
is dropped whatever its field. The fields the adapter needs survive."""
from __future__ import annotations

from apps.octo.adapters.unifi import sanitize


def test_secret_fields_are_dropped_at_any_depth():
    raw = {
        "name": "Office",
        "x_passphrase": "fixture-1",
        "X_Wireguard_Private_Key": "fixture-2",
        "utm_token": "fixture-3",
        "wpa_psk": "fixture-4",
        "radius_secret": "fixture-5",
        "nested": {"apiKey": "fixture-6", "authToken": "fixture-7", "ok": 1,
                   "deeper": [{"x_ssh_password": "fixture-8", "keep": "yes"}]},
        "credentials": {"user": "fixture-9"},
        "private_note": "fixture-10",
        "certificate_pem": "fixture-11",
        "auth_method": "fixture-12",
    }
    clean = sanitize.strip(raw)
    assert clean == {"name": "Office", "nested": {"ok": 1, "deeper": [{"keep": "yes"}]}}
    assert sanitize.find_secret_keys(clean) == []
    assert len(sanitize.find_secret_keys(raw)) == 12


def test_key_material_in_a_value_is_dropped_whatever_its_field():
    pem = "-----BEGIN OPENVPN STATIC KEY V1-----\nfixture\n-----END OPENVPN STATIC KEY V1-----"
    wg = "fixtureFIXTUREfixtureFIXTUREfixture0000000="
    clean = sanitize.strip({"config": pem, "peer": wg, "list": ["ok", pem], "note": "fine"})
    assert clean == {"list": ["ok"], "note": "fine"}


def test_needed_fields_survive():
    """What the adapter reads must never be caught by the over-broad rule."""
    needed = {
        "id": "F1X7A0000000000000000000000000000000000000000000000000A001:100000001",
        "hostId": "F1X7A0000000000000000000000000000000000000000000000000A001:100000001",
        "siteId": "f1x7517e0000000000000001",
        "meta": {"name": "default", "desc": "Acme Corp", "timezone": "America/Chicago",
                 "gatewayMac": "00:00:5e:00:53:02"},
        "statistics": {"counts": {"offlineGatewayDevice": 0},
                       "ispInfo": {"asn": 64500, "name": "Example ISP", "organization": "x"},
                       "wans": {"WAN": {"externalIp": "203.0.113.129", "portUp": True}}},
        "reportedState": {"hostname": "acme-udm", "state": "connected",
                          "location": {"lat": 1.0, "long": 2.0, "radius": 3, "text": "x"}},
        "macAddress": "00:00:5e:00:53:37", "ipAddress": "192.0.2.37",
        "connectedAt": "2026-10-01T09:00:00Z", "uplinkDeviceId": "sw-1",
        "access": {"type": "DEFAULT"}, "type": "WIRED", "totalCount": 3,
        "category": "SECURITY", "subcategory": "SECURITY_INTRUSION_PREVENTION",
        "event": "THREAT_BLOCKED", "severity": "HIGH", "timestamp": 1790769600000,
        "title_raw": "Threat {SIGNATURE}", "message_raw": "{CLIENT} matched",
        "parameters": {"CLIENT": {"id": "00:00:5e:00:53:37", "ip": "192.0.2.37"},
                       "SIGNATURE": {"id": "2030001", "name": "ET MALWARE"},
                       "DST_IP": {"id": "203.0.113.66"}},
        "page_number": 0, "total_element_count": 1, "total_page_count": 1,
        "nextToken": "500",
        "_id": "net-1", "ip_subnet": "192.0.2.1/24", "dhcpd_dns_1": "192.0.2.1",
        "purpose": "guest", "vlan": 30,
    }
    assert sanitize.strip(needed) == needed


def test_bounded():
    deep: dict = {}
    cur = deep
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    assert sanitize.strip(deep) is not None
    assert len(sanitize.strip({"s": "x" * 10_000})["s"]) == sanitize.MAX_STRING
    assert len(sanitize.strip(list(range(10_000)))) == sanitize.MAX_LIST
    assert sanitize.strip({"o": object()}) == {"o": None}
