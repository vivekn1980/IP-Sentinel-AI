"""JSON and NDJSON WAF Log Parser."""

import json
import logging
from typing import Any, Dict, List

from ip_sentinel.models.waf_event import WAFEvent
from ip_sentinel.parsers.base import BaseWAFParser

logger = logging.getLogger("ip_sentinel.parsers.json")


class JSONWAFParser(BaseWAFParser):
    """Parses WAF events from JSON array files, JSONL/NDJSON lines, or JSON string buffers."""

    def parse_file(self, file_path: str) -> List[WAFEvent]:
        """Parse WAF events from a JSON file on disk."""
        try:
            with open(file_path, mode="r", encoding="utf-8", errors="replace") as f:
                return self.parse_content(f.read())
        except Exception as e:
            logger.error("Failed to read JSON WAF file '%s': %s", file_path, e)
            return []

    def parse_content(self, content_str: str) -> List[WAFEvent]:
        """Parse WAF events from JSON or NDJSON content string."""
        events: List[WAFEvent] = []
        if not content_str or not content_str.strip():
            return events

        stripped = content_str.strip()

        # Try parsing as a standard JSON array or document
        try:
            parsed: Any = json.loads(stripped)
            if isinstance(parsed, list):
                for idx, item in enumerate(parsed):
                    if isinstance(item, dict):
                        events.append(self._normalize_dict(item))
                return events
            elif isinstance(parsed, dict):
                # Single event dictionary or wrapped dict e.g. {"events": [...]}
                if "events" in parsed and isinstance(parsed["events"], list):
                    for item in parsed["events"]:
                        if isinstance(item, dict):
                            events.append(self._normalize_dict(item))
                    return events
                elif "logs" in parsed and isinstance(parsed["logs"], list):
                    for item in parsed["logs"]:
                        if isinstance(item, dict):
                            events.append(self._normalize_dict(item))
                    return events
                else:
                    events.append(self._normalize_dict(parsed))
                    return events
        except Exception:
            # Fall back to line-by-line NDJSON / JSONL parsing
            pass

        # NDJSON line-by-line parsing
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            line_clean = line.strip()
            if not line_clean:
                continue
            try:
                item_dict = json.loads(line_clean)
                if isinstance(item_dict, dict):
                    events.append(self._normalize_dict(item_dict))
            except Exception as line_err:
                logger.warning("Error parsing JSON line %d: %s", line_no, line_err)

        return events
