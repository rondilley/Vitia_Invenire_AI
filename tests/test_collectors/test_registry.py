"""Tests for the Windows registry collector."""

from __future__ import annotations

import sys

import pytest

from vitia_invenire.collectors.registry import (
    enumerate_subkeys,
    platform_available,
    read_key,
    read_value,
)


class TestRegistryPlatform:
    def test_platform_available_on_linux(self):
        if sys.platform != "win32":
            assert platform_available() is False

    def test_read_key_on_non_windows(self):
        if sys.platform != "win32":
            result = read_key(0x80000002, "SOFTWARE\\Microsoft")
            assert result == []

    def test_read_value_on_non_windows(self):
        if sys.platform != "win32":
            result = read_value(0x80000002, "SOFTWARE\\Microsoft", "test")
            assert result is None

    def test_enumerate_subkeys_on_non_windows(self):
        if sys.platform != "win32":
            result = enumerate_subkeys(0x80000002, "SOFTWARE")
            assert result == []


@pytest.mark.skipif(sys.platform != "win32", reason="Test requires Windows")
class TestRegistryWindows:
    def test_read_known_key(self):
        # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion should exist on all Windows
        result = read_key(0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_read_nonexistent_key(self):
        result = read_key(0x80000002, "SOFTWARE\\NonExistentKey12345")
        assert result == []
