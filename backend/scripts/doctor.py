#!/usr/bin/env python3
"""Comando CLI 'secai doctor' (F14).

Verifica el entorno de ejecución, detecta herramientas de seguridad instaladas,
versiones disponibles y reporta qué binarios faltan con su indicación de instalación.
"""

import sys
from pathlib import Path

# Agregar backend al path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.registry import get_tool_registry


def run_doctor():
    registry = get_tool_registry()
    tools_info = registry.get_installed_tools_status()

    print("==================================================================")
    print("  SECAI DOCTOR — Diagnóstico de Herramientas del Security Control Center")
    print("==================================================================")
    print(f"Total de herramientas en catálogo: {len(tools_info)}\n")

    installed_count = 0
    missing_count = 0

    categories = {}
    for t in tools_info:
        cat = t["category"]
        categories.setdefault(cat, []).append(t)

    for cat, list_tools in sorted(categories.items()):
        print(f"\n[ Categoría: {cat.upper()} ]")
        for t in list_tools:
            if t["installed"]:
                installed_count += 1
                status_icon = "✓"
                status_text = f"OK ({t['version']})"
                color = "\033[92m"  # verde
            else:
                missing_count += 1
                status_icon = "✗"
                status_text = f"FALTA — {t['install_hint']}"
                color = "\033[93m"  # amarillo

            reset = "\033[0m"
            offline_badge = "[offline]" if t["works_offline"] else "[red-req]"
            print(f"  {color}{status_icon} {t['id']:<14}{reset} | {status_text:<38} | {offline_badge}")

    print("\n------------------------------------------------------------------")
    print(f"Resumen: {installed_count} instaladas | {missing_count} no disponibles en el host")
    print("------------------------------------------------------------------")
    if missing_count > 0:
        print("💡 Nota: Las herramientas ausentes se omitirán limpiamente o activarán")
        print("   el estado 'completed_with_gaps' y la sugerencia de revisión con IA.")
    print("==================================================================")


if __name__ == "__main__":
    run_doctor()
