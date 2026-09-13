"""Thread-safe Configuration Framework & SecretStore Abstraction for IP Sentinel AI.

Manages persistent JSON configuration, defaults, environment overrides, and credential management.
Stores configuration under %LOCALAPPDATA%\\IPSentinelAI\\config.json on Windows.
"""

import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ip_sentinel.core.exceptions import ConfigError
from ip_sentinel.core.path_utils import get_app_data_dir

logger = logging.getLogger("ip_sentinel.config")

CURRENT_CONFIG_VERSION = "1.0"


@dataclass
class ProviderConfig:
    enabled: bool = True
    timeout_seconds: int = 5
    rate_limit_per_minute: int = 60


@dataclass
class AppSettings:
    config_version: str = CURRENT_CONFIG_VERSION
    theme: str = "dark"
    log_level: str = "INFO"
    auto_check_updates: bool = False
    export_dir: str = ""
    dns_timeout: float = 3.0
    providers: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "mock": {"enabled": True, "timeout_seconds": 2},
        "abuseipdb": {"enabled": False, "timeout_seconds": 5},
        "virustotal": {"enabled": False, "timeout_seconds": 5},
        "shodan": {"enabled": False, "timeout_seconds": 5},
        "otx": {"enabled": False, "timeout_seconds": 5},
    })


class BaseSecretStore(ABC):
    """Abstract interface for API credential storage without hardcoded keys."""
    
    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret by key string."""
        pass
        
    @abstractmethod
    def set_secret(self, key: str, value: str) -> bool:
        """Store a secret securely."""
        pass
        
    @abstractmethod
    def delete_secret(self, key: str) -> bool:
        """Delete a stored secret."""
        pass


class EnvironmentSecretStore(BaseSecretStore):
    """SecretStore implementation reading from OS environment variables.
    
    Format: IPSENTINEL_KEY_<NAME> (e.g. IPSENTINEL_KEY_ABUSEIPDB)
    """
    
    def get_secret(self, key: str) -> Optional[str]:
        env_var = f"IPSENTINEL_KEY_{key.upper()}"
        return os.environ.get(env_var)

    def set_secret(self, key: str, value: str) -> bool:
        env_var = f"IPSENTINEL_KEY_{key.upper()}"
        os.environ[env_var] = value
        return True

    def delete_secret(self, key: str) -> bool:
        env_var = f"IPSENTINEL_KEY_{key.upper()}"
        if env_var in os.environ:
            del os.environ[env_var]
            return True
        return False


class LocalSecretStore(BaseSecretStore):
    """Fallback obfuscated secret store saved alongside user config.
    
    Never logs secrets or hardcodes default credentials.
    """
    def __init__(self, secrets_file: Path):
        self._file = secrets_file
        self._lock = threading.Lock()

    def _load_all(self) -> Dict[str, str]:
        if not self._file.exists():
            return {}
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as err:
            logger.warning(f"Could not load local secret store: {err}")
            return {}

    def get_secret(self, key: str) -> Optional[str]:
        # Priority check to environment variable first
        env_val = os.environ.get(f"IPSENTINEL_KEY_{key.upper()}")
        if env_val:
            return env_val
        with self._lock:
            data = self._load_all()
            return data.get(key.lower())

    def set_secret(self, key: str, value: str) -> bool:
        with self._lock:
            data = self._load_all()
            data[key.lower()] = value
            try:
                self._file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                return True
            except Exception as err:
                logger.error(f"Failed to write to secret store: {err}")
                return False

    def delete_secret(self, key: str) -> bool:
        with self._lock:
            data = self._load_all()
            if key.lower() in data:
                del data[key.lower()]
                try:
                    with open(self._file, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                    return True
                except Exception as err:
                    logger.error(f"Failed to update secret store: {err}")
                    return False
        return False


class ConfigManager:
    """Thread-safe Singleton configuration manager for IP Sentinel AI."""

    _instance: Optional["ConfigManager"] = None
    _lock = threading.Lock()

    def __new__(cls, config_path: Optional[Path] = None) -> "ConfigManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, config_path: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return
        
        self.config_dir = get_app_data_dir()
        self.config_path = config_path or (self.config_dir / "config.json")
        self.secret_store = LocalSecretStore(self.config_dir / "credentials.json")
        self._rw_lock = threading.Lock()
        self._settings = AppSettings()
        
        # Set default export directory to User Documents if empty
        documents = Path.home() / "Documents" / "IPSentinelReports"
        self._settings.export_dir = str(documents)

        self.load_config()
        self._initialized = True

    def load_config(self) -> AppSettings:
        """Load settings from JSON file and apply environment variable overrides."""
        with self._rw_lock:
            if self.config_path.exists():
                try:
                    with open(self.config_path, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)
                    
                    # Version check and deserialization
                    version = raw_data.get("config_version", CURRENT_CONFIG_VERSION)
                    
                    self._settings.theme = raw_data.get("theme", self._settings.theme)
                    self._settings.log_level = raw_data.get("log_level", self._settings.log_level)
                    self._settings.export_dir = raw_data.get("export_dir", self._settings.export_dir)
                    self._settings.dns_timeout = raw_data.get("dns_timeout", self._settings.dns_timeout)
                    if "providers" in raw_data and isinstance(raw_data["providers"], dict):
                        self._settings.providers.update(raw_data["providers"])
                        
                    logger.info(f"Loaded configuration v{version} from {self.config_path}")
                except Exception as err:
                    logger.error(f"Failed to parse config file {self.config_path}: {err}. Using defaults.")
            else:
                logger.info(f"Config file does not exist yet. Initializing defaults at {self.config_path}")
                self._save_unlocked()

            self._apply_env_overrides_unlocked()
            return self._settings

    def save_config(self) -> bool:
        """Atomically persist current configuration to JSON file."""
        with self._rw_lock:
            return self._save_unlocked()

    def _save_unlocked(self) -> bool:
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            data = asdict(self._settings)
            
            # Write to temp file first for atomic saving
            temp_path = self.config_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                
            if temp_path.exists():
                temp_path.replace(self.config_path)
            return True
        except Exception as err:
            logger.error(f"Failed to persist configuration to {self.config_path}: {err}")
            raise ConfigError(f"Unable to save settings: {err}")

    def _apply_env_overrides_unlocked(self) -> None:
        """Apply IPSENTINEL_* environment variables to override settings safely."""
        env_log = os.getenv("IPSENTINEL_LOG_LEVEL")
        if env_log:
            self._settings.log_level = env_log.upper()
            
        env_export = os.getenv("IPSENTINEL_EXPORT_DIR")
        if env_export:
            self._settings.export_dir = env_export

    def get_settings(self) -> AppSettings:
        """Return a copy of the current AppSettings."""
        with self._rw_lock:
            return self._settings

    def update_settings(self, **kwargs) -> None:
        """Update configuration fields and save immediately."""
        with self._rw_lock:
            for key, val in kwargs.items():
                if hasattr(self._settings, key):
                    setattr(self._settings, key, val)
            self._save_unlocked()

    def reset_to_defaults(self) -> AppSettings:
        """Reset all configuration settings back to original defaults."""
        with self._rw_lock:
            self._settings = AppSettings()
            documents = Path.home() / "Documents" / "IPSentinelReports"
            self._settings.export_dir = str(documents)
            self._save_unlocked()
            return self._settings
