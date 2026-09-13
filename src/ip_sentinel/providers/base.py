"""Abstract Base Class definition for Threat Intelligence Providers."""

from abc import ABC, abstractmethod
from typing import Optional

from ip_sentinel.models.threat_intel import ProviderResult


class BaseIntelProvider(ABC):
    """Abstract interface enforcing single contract across all threat intel sources."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the unique canonical name of the provider (e.g. 'mock', 'abuseipdb')."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if credentials and prerequisites are present."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Perform lightweight health check on provider API service."""
        pass

    @abstractmethod
    def query_ip(self, target_ip: str) -> ProviderResult:
        """Perform threat intelligence query for the given IP address.
        
        Args:
            target_ip: Validated IP address string.
            
        Returns:
            Normalized ProviderResult DTO payload.
        """
        pass
