"""Revisión por control con IA (inventario de controles v1.0).

Módulos:
- spec_loader: carga y valida las 35 especificaciones YAML (controls/specs/).
- evidence_builder: arma el paquete de evidencia de forma determinista.
- reviewer_agent: agente que solo lee; devuelve JSON validado con verificación
  de líneas citadas; descarta respuestas que citen líneas inexistentes.
- review_service: orquesta la revisión, el gating de C10-C13 (SDK de LLM),
  la evaluación endpoint-por-endpoint de RBAC/IDOR y el cruce con scanners.
"""
