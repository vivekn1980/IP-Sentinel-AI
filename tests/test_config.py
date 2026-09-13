"""Unit tests for ConfigManager and SecretStore framework."""

import os
from pathlib import Path
from ip_sentinel.core.config import ConfigManager, EnvironmentSecretStore


def test_config_defaults(clean_config_mgr):
    settings = clean_config_mgr.get_settings()
    assert settings.config_version == "1.0"
    assert settings.theme == "dark"
    assert "mock" in settings.providers
    assert settings.providers["mock"]["enabled"] is True


def test_config_update_and_persist(clean_config_mgr, tmp_config_file):
    clean_config_mgr.update_settings(theme="light", dns_timeout=5.0)
    
    # Reload from file
    ConfigManager._instance = None
    new_mgr = ConfigManager(config_path=tmp_config_file)
    reloaded = new_mgr.get_settings()
    
    assert reloaded.theme == "light"
    assert reloaded.dns_timeout == 5.0


def test_environment_secret_store():
    store = EnvironmentSecretStore()
    os.environ["IPSENTINEL_KEY_ABUSEIPDB"] = "test_secret_key_123"
    
    val = store.get_secret("abuseipdb")
    assert val == "test_secret_key_123"
    
    store.delete_secret("abuseipdb")
    assert store.get_secret("abuseipdb") is None


def test_local_secret_store(clean_config_mgr):
    store = clean_config_mgr.secret_store
    store.set_secret("virustotal", "vt_mock_api_key_456")
    
    assert store.get_secret("virustotal") == "vt_mock_api_key_456"
    store.delete_secret("virustotal")
    assert store.get_secret("virustotal") is None
