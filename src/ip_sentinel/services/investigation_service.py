"""InvestigationService orchestrating real passive IP intelligence, threat providers, evidence correlation, and risk calculation."""

import datetime
import logging
import uuid
from typing import Callable, List, Optional

from ip_sentinel.core.exceptions import ValidationError
from ip_sentinel.core.ip_utils import validate_and_classify_ip
from ip_sentinel.models.threat_intel import (
    ASNData,
    DNSData,
    DataStatus,
    EvidenceItem,
    EvidenceSummary,
    GeoIPData,
    IPIntelResult,
    ProviderResult,
    RDAPData,
    ThreatScore,
    WAFContext,
)
from ip_sentinel.providers.abuseipdb_provider import AbuseIPDBProvider
from ip_sentinel.providers.base import BaseIntelProvider
from ip_sentinel.providers.geoip_provider import GeoIPProvider
from ip_sentinel.providers.mock_provider import MockIntelProvider
from ip_sentinel.providers.rdap_provider import RDAPProvider
from ip_sentinel.providers.virustotal_provider import VirusTotalProvider
from ip_sentinel.services.dns_service import DNSService
from ip_sentinel.services.evidence_aggregator import EvidenceAggregator
from ip_sentinel.services.risk_engine import RiskEngine

logger = logging.getLogger("ip_sentinel.investigation")


class InvestigationService:
    """Orchestrates network intelligence, live threat providers, evidence correlation, and risk evaluation."""

    def __init__(self, providers: Optional[List[BaseIntelProvider]] = None):
        if providers is not None:
            self.providers = providers
        else:
            self.providers = [
                MockIntelProvider(),
                AbuseIPDBProvider(),
                VirusTotalProvider(),
            ]

        self.rdap_provider = RDAPProvider()
        self.geoip_provider = GeoIPProvider()
        self.dns_service = DNSService()
        self.evidence_aggregator = EvidenceAggregator()
        self.risk_engine = RiskEngine()

    def register_provider(self, provider: BaseIntelProvider) -> None:
        """Dynamically register a threat intelligence provider."""
        self.providers.append(provider)

    def investigate(
        self,
        target_ip: str,
        waf_context: Optional[WAFContext] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> IPIntelResult:
        """Execute complete passive network investigation and threat correlation for target IP.
        
        Args:
            target_ip: Input IP string to investigate.
            waf_context: Optional WAFContext containing attack telemetry.
            progress_callback: Optional callback receiving (percentage, status_message).
            
        Returns:
            Normalized IPIntelResult payload.
            
        Raises:
            ValidationError: If target IP format is invalid.
        """
        inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        logger.info(f"Starting Phase 3 investigation {inv_id} for target IP: '{target_ip}'")

        # Step 1: Validating IP
        if progress_callback:
            progress_callback(10, "Validating IP")

        classification = validate_and_classify_ip(target_ip)
        if not classification.is_valid:
            logger.error(f"IP validation failed for input '{target_ip}': {classification.error_message}")
            raise ValidationError(classification.error_message or "Invalid IP address format.")

        norm_ip = classification.normalized_ip

        # Step 2: Retrieving RDAP
        if progress_callback:
            progress_callback(20, "Retrieving RDAP")

        rdap_data = RDAPData(status=DataStatus.UNAVAILABLE, ip_address=norm_ip, lookup_timestamp=now_str)
        if not classification.is_private and not classification.is_loopback:
            try:
                rdap_data = self.rdap_provider.query_rdap(norm_ip)
            except Exception as err:
                logger.error(f"RDAP provider exception for {norm_ip}: {err}")
                rdap_data = RDAPData(status=DataStatus.ERROR, ip_address=norm_ip, error_message=f"RDAP Error: {err}")
        else:
            rdap_data = RDAPData(
                status=DataStatus.UNAVAILABLE,
                ip_address=norm_ip,
                network_name="Private/Internal Network",
                error_message="RDAP lookup not applicable for private/loopback IP.",
            )

        # Step 3 & 4: Retrieving network information & GeoIP
        if progress_callback:
            progress_callback(35, "Retrieving network information")
        if progress_callback:
            progress_callback(50, "Retrieving GeoIP")

        geoip_data = GeoIPData(status=DataStatus.UNAVAILABLE)
        asn_data = ASNData(status=DataStatus.UNAVAILABLE, timestamp=now_str)

        if not classification.is_private and not classification.is_loopback:
            try:
                geoip_data, asn_data = self.geoip_provider.query_geoip_and_asn(norm_ip)
            except Exception as err:
                logger.error(f"GeoIP/ASN exception for {norm_ip}: {err}")
                geoip_data = GeoIPData(status=DataStatus.ERROR, error_message=f"GeoIP Error: {err}")
                asn_data = ASNData(status=DataStatus.ERROR, timestamp=now_str, error_message=f"ASN Error: {err}")
        else:
            geoip_data = GeoIPData(
                status=DataStatus.AVAILABLE,
                country_code="LOCAL",
                country_name="Private / Local Network",
                city="Internal Network",
                asn_org="RFC 1918 Private Range",
            )
            asn_data = ASNData(
                status=DataStatus.AVAILABLE,
                asn=0,
                asn_org="RFC 1918 Private Range",
                timestamp=now_str,
            )

        # Step 5 & 6: Performing reverse DNS & DNS lookups
        if progress_callback:
            progress_callback(65, "Performing reverse DNS")
        if progress_callback:
            progress_callback(75, "Performing DNS lookups")

        dns_data = DNSData(status=DataStatus.UNAVAILABLE)
        try:
            dns_data = self.dns_service.resolve_all_records(norm_ip)
        except Exception as err:
            logger.error(f"DNS Service exception for {norm_ip}: {err}")
            dns_data = DNSData(status=DataStatus.ERROR, error_message=f"DNS Error: {err}")

        # Step 7: Query registered threat intelligence providers
        if progress_callback:
            progress_callback(85, "Querying live threat intelligence providers...")

        provider_results = {}
        is_mock_run = False

        for provider in self.providers:
            if provider.provider_name == "mock":
                is_mock_run = True

            try:
                if not provider.is_configured():
                    provider_results[provider.provider_name] = ProviderResult(
                        provider_name=provider.provider_name,
                        status=DataStatus.NOT_CONFIGURED,
                        error_message="Provider API key not configured.",
                    )
                    continue

                res = provider.query_ip(norm_ip)
                provider_results[provider.provider_name] = res

            except Exception as err:
                logger.error(f"Provider '{provider.provider_name}' query error: {err}")
                provider_results[provider.provider_name] = ProviderResult(
                    provider_name=provider.provider_name,
                    status=DataStatus.ERROR,
                    error_message=f"Provider query exception: {err}",
                )

        # Step 8: Evidence Aggregation & Correlation
        if progress_callback:
            progress_callback(92, "Aggregating evidence & analyzing threat indicators...")

        evidence_list, evidence_summary, has_conflict, conflict_notes = self.evidence_aggregator.aggregate_evidence(
            rdap=rdap_data,
            asn_data=asn_data,
            geoip=geoip_data,
            dns=dns_data,
            provider_results=provider_results,
            waf_context=waf_context,
        )

        # Step 9: Risk Evaluation
        if progress_callback:
            progress_callback(98, "Calculating risk score & evaluating confidence...")

        overall_threat_score = self.risk_engine.evaluate_risk(
            evidence_list=evidence_list,
            evidence_summary=evidence_summary,
            provider_results=provider_results,
            rdap=rdap_data,
            asn_data=asn_data,
            waf_context=waf_context,
            has_conflicting_evidence=has_conflict,
            conflict_explanation=conflict_notes,
        )

        result = IPIntelResult(
            investigation_id=inv_id,
            target_ip=norm_ip,
            timestamp=now_str,
            is_mock=is_mock_run,
            overall_threat_score=overall_threat_score,
            rdap=rdap_data,
            asn_data=asn_data,
            geoip=geoip_data,
            dns=dns_data,
            waf_context=waf_context,
            provider_results=provider_results,
            aggregated_evidence=evidence_list,
            evidence_summary=evidence_summary,
            has_conflicting_evidence=has_conflict,
            conflict_explanation=conflict_notes,
            is_private_ip=classification.is_private,
            is_loopback_ip=classification.is_loopback,
            summary_notes="Passive network intelligence & evidence correlation completed successfully.",
        )

        if progress_callback:
            progress_callback(100, "Ready")

        logger.info(f"Phase 3 investigation {inv_id} completed. Threat Level: {overall_threat_score.level.value} (Score: {overall_threat_score.score})")
        return result
