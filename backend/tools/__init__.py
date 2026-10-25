"""Módulo de Registro de Herramientas y Detección de Stack (F14)."""

from tools.base import BaseTool
from tools.stack_detector import detect_stack_v2
from tools.coverage import build_coverage_block
from tools.registry import ToolRegistry, get_tool_registry

__all__ = [
    "BaseTool",
    "detect_stack_v2",
    "build_coverage_block",
    "ToolRegistry",
    "get_tool_registry",
]
