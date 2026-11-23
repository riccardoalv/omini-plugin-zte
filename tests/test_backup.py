import json

from omini_zte.backup import backup
from tests.conftest import BASE


def test_backup_is_sorted_json_of_the_settings(zte, cfg):
    (b,) = backup(cfg)
    assert (b.device, b.format) == (BASE, "json")
    data = json.loads(b.content)
    assert data["wifi_networks"]["OBJ_WLANAP_ID"][0]["ESSID"] == "ZTE_2.4G_Home"
    assert data["dmz"]["OBJ_FWDMZ_ID"][0]["Enable"] == "0"
    # Only the radios' settings, not the country channel table.
    assert list(data["wifi_radios"]) == ["OBJ_WLANSETTING_ID"]
    assert zte.logouts == 1


def test_backup_has_no_secrets_nor_status(zte, cfg):
    content = backup(cfg)[0].content
    data = json.loads(content)
    assert "KeyPassphrase" not in content and "OBJ_WLANPSK_ID" not in content
    # Encrypted fields (the device lists them) are left out.
    assert "Password" not in json.dumps(data["ddns"])
    assert "CurrentLocalTime" not in json.dumps(data["ntp"])
    assert "Status" not in json.dumps(data["ddns"])


def test_two_backups_of_the_same_settings_are_equal(zte, cfg):
    first = backup(cfg)[0].content
    # Live values move between runs; the backup does not.
    zte.rows("statusMgr", "devmgr_statusmgr_lua", "OBJ_POWERONTIME_ID")[0]["PowerOnTime"] = "9"
    assert backup(cfg)[0].content == first
