# tests/unit/tools/test_custom.py
import pytest
from autored.tools.custom import CustomResult


def test_custom_result_model():
    r = CustomResult(
        command="whoami",
        stdout="root\n",
        stderr="",
        returncode=0,
        success=True,
    )
    assert r.success is True
    assert r.stdout == "root\n"
