"""CSV WAF Log Parser."""

import csv
import io
import logging
from typing import List

from ip_sentinel.models.waf_event import WAFEvent
from ip_sentinel.parsers.base import BaseWAFParser

logger = logging.getLogger("ip_sentinel.parsers.csv")


class CSVWAFParser(BaseWAFParser):
    """Parses WAF events from CSV formatted files or string buffers."""

    def parse_file(self, file_path: str) -> List[WAFEvent]:
        """Parse WAF events from a CSV file path."""
        try:
            with open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
                return self.parse_content(f.read())
        except Exception as e:
            logger.error("Failed to read CSV WAF file '%s': %s", file_path, e)
            return []

    def parse_content(self, content_str: str) -> List[WAFEvent]:
        """Parse WAF events from CSV formatted string content."""
        events: List[WAFEvent] = []
        if not content_str or not content_str.strip():
            return events

        buffer = io.StringIO(content_str)
        try:
            reader = csv.DictReader(buffer)
            for line_no, row in enumerate(reader, start=2):
                if not row:
                    continue
                try:
                    event = self._normalize_dict(row)
                    events.append(event)
                except Exception as row_err:
                    logger.warning("Error parsing CSV row at line %d: %s", line_no, row_err)
        except Exception as err:
            logger.error("Error reading CSV content: %s", err)

        return events
