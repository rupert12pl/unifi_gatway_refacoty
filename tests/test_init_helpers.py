import custom_components.unifi_gateway_refactored as gw_init
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
