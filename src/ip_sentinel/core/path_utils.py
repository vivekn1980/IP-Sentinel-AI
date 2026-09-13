"""Centralized path and resource resolution utilities for IP Sentinel AI.

Handles path resolution both when running from raw source and when packaged
as a PyInstaller single-file portable Windows executable (via sys._MEIPASS).
"""

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """Return True if application is running in a PyInstaller frozen bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def get_base_dir() -> Path:
    """Get root base directory of application or PyInstaller extraction directory."""
    if is_frozen():
        return Path(getattr(sys, "_MEIPASS"))
    # Resolves to project root directory when running from source
    return Path(__file__).resolve().parent.parent.parent.parent


def get_resource_path(relative_path: str) -> Path:
    """Resolve absolute path to a bundled resource asset.
    
    Args:
        relative_path: Relative path string from resources directory or base dir.
        
    Returns:
        Absolute pathlib.Path object.
    """
    base = get_base_dir()
    
    # Try resolving relative to resources folder first if relative_path starts with resources
    target = base / relative_path
    if target.exists():
        return target
        
    # Fallback search under resources/ if relative path doesn't include it
    target_in_resources = base / "resources" / relative_path
    if target_in_resources.exists():
        return target_in_resources

    return target


def get_app_data_dir() -> Path:
    """Get platform-specific user application data directory.
    
    On Windows: %LOCALAPPDATA%\\IPSentinelAI
    Fallback: ~/.ipsentinelai
    """
    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        app_dir = Path(local_app_data) / "IPSentinelAI"
    else:
        app_dir = Path.home() / ".ipsentinelai"
        
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir
