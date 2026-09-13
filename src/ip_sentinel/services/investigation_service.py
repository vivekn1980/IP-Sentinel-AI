"""InvestigationService orchestrating IP threat intelligence gathering workflows."""

import datetime
import logging
import uuid
from typing import Callable, List, Optional

import dns.resolver
import dns.reversename

from ip_sentinel.core.exceptions import ValidationError
from ip_sentinel.core.ip_utils import validate_and_classify_ip
from ip_sentinel.models.threat_intel import (
    DNSData,
    DataStatus,
    EvidenceItem,
    GeoIPData,
    IPIntelResult,
    ProviderResult,
    ThreatLevel,
    ThreatScore,
)
from ip_sentinel.providers.base import BaseIntelProvider
from ip_sentinel.providers.mock_provider import MockIntelProvider

logger = logging.getLogger("ip_sentinel.investigation")


class InvestigationService:
    """Orchestrates IP validation, DNS lookup, provider queries, and threat aggregation."""

    def __init__(self, providers: Optional[List[BaseIntelProvider]] = None):
        self.providers = providers if providers is not None else [MockIntelProvider()]

    def register_provider(self, provider: BaseIntelProvider) -> None:
        """Dynamically add an intelligence provider."""
        self.providers.append(provider)

    def resolve_dns_records(self, ip_str: str, timeout: float = 2.0) -> DNSData:
        """Perform reverse DNS PTR lookup and related record queries safely."""
        ptr_list: List[str] = []
        mx_list: List[str] = []
        txt_list: List[str] = []
        primary_host: Optional[str] = None

        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout

        try:
            rev_name = dns.reversename.from_address(ip_str)
            answers = resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                host_str = str(rdata.target).rstrip(".")
                ptr_list.append(host_str)
            if ptr_list:
                primary_host = ptr_list[0]
        except Exception as err:
            logger.debug(f"Reverse PTR lookup failed for {ip_str}: {err}")

        status = DataStatus.AVAILABLE if (ptr_list or primary_host) else DataStatus.UNAVAILABLE
        return DNSData(
            status=status,
            hostname=primary_host,
            ptr_records=ptr_list,
            mx_records=mx_list,
            txt_records=txt_list,
            error_message=None if status == DataStatus.AVAILABLE else "No PTR DNS records resolved.",
        )

    def investigate(
        self,
        target_ip: str,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> IPIntelResult:
        """Perform complete threat intelligence investigation for target IP.
        
        Args:
            target_ip: Input IP string to investigate.
            progress_callback: Optional callback receiving (percentage, message).
            
        Returns:
            Normalized IPIntelResult container.
            
        Raises:
            ValidationError: If IP format is invalid.
        """
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        logger.info(f"Starting investigation {inv_id} for target IP: '{target_ip}'")
        if progress_callback:
            progress_callback(10, "Validating target IP address...")

        classification = validate_and_classify_ip(target_ip)
        if not classification.is_valid:
            logger.error(f"IP validation failed for input '{target_ip}': {classification.error_message}")
            raise ValidationError(classification.error_message or "Invalid IP address format.")

        norm_ip = classification.normalized_ip

        if progress_callback:
            progress_callback(30, "Performing local network & DNS resolution...")

        # Reverse DNS Resolution
        dns_data = self.resolve_dns_records(norm_ip)

        # Basic GeoIP/ASN classification for mock/local fallback
        geoip_data = GeoIPData(
            status=DataStatus.AVAILABLE,
            country_code="US" if not classification.is_private else "LOCAL",
            country_name="United States" if not classification.is_private else "Private Network Range",
            city="Ashburn" if not classification.is_private else "Internal Network",
            asn=13335 if not classification.is_private else 0,
            asn_org="Cloudflare / Mock Autonomous System" if not classification.is_private else "RFC 1918 Private Net",
            isp="Mock Telecom Infrastructure",
        )

        if progress_callback:
            progress_callback(50, "Querying threat intelligence providers...")

        provider_results = {}
        aggregated_evidence: List[EvidenceItem] = []
        scores: List[int] = []
        is_mock_run = False

        total_providers = len(self.providers)
        for idx, provider in enumerate(self.providers, start=1):
            if progress_callback and total_providers > 0:
                pct = 50 + int((idx / total_providers) * 40)
                progress_callback(pct, f"Querying {provider.provider_name}...")

            if provider.provider_name == "mock":
                is_mock_run = True

            try:
                if not provider.is_configured():
                    logger.info(f"Provider '{provider.provider_name}' is not configured. Skipping.")
                    provider_results[provider.provider_name] = ProviderResult(
                        provider_name=provider.provider_name,
                        status=DataStatus.NOT_CONFIGURED,
                        error_message="API key or credentials not configured.",
                    )
                    continue

                res = provider.query_ip(norm_ip)
                provider_results[provider.provider_name] = res

                if res.status == DataStatus.AVAILABLE:
                    if res.threat_score:
                        scores.append(res.threat_score.score)
                    if res.evidence:
                        aggregated_evidence.extend(res.evidence)

            except Exception as err:
                logger.error(f"Provider '{provider.provider_name}' raised unexpected error: {err}")
                provider_results[provider.provider_name] = ProviderResult(
                    provider_name=provider.provider_name,
                    status=DataStatus.ERROR,
                    error_message=f"Provider query exception: {err}",
                )

        if progress_callback:
            progress_callback(95, "Aggregating threat scores and finalizing report...")

        # Threat Score Aggregation
        if scores:
            avg_score = int(sum(scores) / len(scores))
        else:
            avg_score = 0

        if avg_score >= 80:
            level = ThreatLevel.MALICIOUS
        elif avg_score >= 40:
            level = ThreatLevel.SUSPICIOUS
        elif avg_score > 0:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.CLEAN

        overall_score = ThreatScore(
            score=avg_score,
            level=level,
            confidence=95 if scores else 0,
            status=DataStatus.AVAILABLE if scores else DataStatus.UNAVAILABLE,
        )

        result = IPIntelResult(
            investigation_id=inv_id,
            target_ip=norm_ip,
            timestamp=now_str,
            is_mock=is_mock_run,
            overall_threat_score=overall_score,
            geoip=geoip_data,
            dns=dns_data,
            provider_results=provider_results,
            aggregated_evidence=aggregated_evidence,
            is_private_ip=classification.is_private,
            is_loopback_ip=classification.is_loopback,
            summary_notes="Mock investigation completed." if is_mock_run else "Investigation completed.",
        )

        if progress_callback:
            progress_callback(100, "Investigation completed.")

        logger.info(f"Investigation {inv_id} finished. Final Threat Level: {level.value} (Score: {avg_score})")
        return result
