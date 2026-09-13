"""Abstract Base Class for Forensic Report Generators."""

from abc import ABC, abstractmethod
from pathlib import Path

from ip_sentinel.models.report_model import ReportData


class BaseReportGenerator(ABC):
    """Abstract contract for rendering investigation report artifacts."""

    @abstractmethod
    def generate_report(self, data: ReportData, output_path: Path) -> Path:
        """Render investigation dataset into an output file.
        
        Args:
            data: ReportData containing investigation results and metadata.
            output_path: Target destination Path for generated file.
            
        Returns:
            Path to created report file.
            
        Raises:
            ReportError: If template rendering or file writing fails.
        """
        pass
