import custom_components.unifi_gateway_refactored as gw_init
from custom_components.unifi_gateway_refactored.const import (
    CONF_SPEEDTEST_INTERVAL,
    DEFAULT_SPEEDTEST_INTERVAL,
    DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
    LEGACY_CONF_SPEEDTEST_INTERVAL_MIN,
)
from custom_components.unifi_gateway_refactored.utils import (
    build_speedtest_button_unique_id,
)
from custom_components.unifi_gateway_refactored.monitor import SpeedtestRunner


def test_normalize_speedtest_entity_ids_from_string():
    raw = " sensor.one ,sensor.two\n,sensor.one,,"
    result = gw_init._normalize_speedtest_entity_ids(raw)
    assert result == ["sensor.one", "sensor.two"]


def test_normalize_speedtest_entity_ids_from_iterable():
    raw = ["sensor.one", "  sensor.two  ", "sensor.one", "sensor.three", None, ""]
    result = gw_init._normalize_speedtest_entity_ids(raw)
    assert result == ["sensor.one", "sensor.two", "sensor.three"]


def test_normalize_speedtest_entity_ids_fallback():
    result = gw_init._normalize_speedtest_entity_ids(object())
    assert result == list(gw_init._DEFAULT_SPEEDTEST_ENTITY_IDS)


def test_build_speedtest_button_unique_id_namespaced():
    assert build_speedtest_button_unique_id("entry123") == "entry123_run_speedtest"


def test_speedtest_runner_normalizes_entity_ids():
    source = ["sensor.one", " sensor.one ", "sensor.two", "", None, "sensor.two"]
    assert SpeedtestRunner._normalize_entity_ids(source) == [
        "sensor.one",
        "sensor.two",
    ]


def test_resolve_speedtest_interval_prefers_legacy_minutes_when_custom():
    options = {LEGACY_CONF_SPEEDTEST_INTERVAL_MIN: 15}
    data = {CONF_SPEEDTEST_INTERVAL: DEFAULT_SPEEDTEST_INTERVAL}

    assert (
        gw_init._resolve_speedtest_interval_seconds(options, data)
        == 15 * 60
    )


def test_resolve_speedtest_interval_uses_seconds_when_minutes_default():
    options = {CONF_SPEEDTEST_INTERVAL: 1800}
    data = {LEGACY_CONF_SPEEDTEST_INTERVAL_MIN: DEFAULT_SPEEDTEST_INTERVAL_MINUTES}

    assert gw_init._resolve_speedtest_interval_seconds(options, data) == 1800


def test_resolve_speedtest_interval_defaults_when_missing():
    options = {}
    data = {}

    assert (
        gw_init._resolve_speedtest_interval_seconds(options, data)
        == DEFAULT_SPEEDTEST_INTERVAL
    )
