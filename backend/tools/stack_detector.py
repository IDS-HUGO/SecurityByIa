"""Detector de stack avanzado (detect_stack v2) para repositorios políglotas (F14).

Analiza la estructura del proyecto sin ejecutar jamás su contenido:
1. Conteo de archivos y volumen en bytes por lenguaje.
2. Exclusión estricta de carpetas vendorizadas o compiladas.
3. Detección de manifiestos y lockfiles para SCA.
4. Identificación de frameworks web comunes.
5. Detección de monorepos y subproyectos independientes.
6. Mantenimiento del 100% de compatibilidad con detect_stack v1.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

_PRUNE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "vendor",
    "target", ".gradle", "pods", "dist", "build", "bin", "obj", ".idea", ".vscode"
}

_LANG_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "java": {".java"},
    "kotlin": {".kt", ".kts"},
    "ruby": {".rb"},
    "php": {".php"},
    "rust": {".rs"},
    "csharp": {".cs"},
    "cpp": {".cpp", ".cc", ".cxx", ".hpp", ".h"},
    "c": {".c"},
    "dart": {".dart"},
    "elixir": {".ex", ".exs"},
    "swift": {".swift"},
    "solidity": {".sol"},
}

_MAX_LISTED_FILES = 50
_MAX_YAML_SNIFFED = 200


def detect_stack_v2(root: str) -> Dict[str, Any]:
    """Detecta stack tecnológico, lenguajes, lockfiles, monorepos y frameworks."""
    # Estructura compatible con v1 + extensiones v2
    stack: Dict[str, Any] = {
        # Claves v1
        "languages": [],
        "dependency_files": [],
        "package_managers": [],
        "requirements_files": [],
        "package_lock": False,
        "terraform": [],
        "cloudformation": [],
        "dockerfiles": [],
        "github_workflows": [],
        "dependabot": False,
        "has_python": False,
        "has_node": False,
        # Claves v2 enriquecidas
        "languages_stats": {},  # { "python": {"files": 12, "bytes": 45000}, ... }
        "frameworks": [],
        "monorepo_roots": [],
        "subprojects": [],
        "iac_types": [],
        "ci_systems": [],
    }

    lang_counts: Dict[str, Dict[str, int]] = {lang: {"files": 0, "bytes": 0} for lang in _LANG_EXTENSIONS}
    detected_languages: Set[str] = set()
    detected_managers: Set[str] = set()
    dep_files: List[str] = []
    req_files: List[str] = []
    subprojects: Set[str] = set()
    frameworks: Set[str] = set()
    yaml_sniffed = 0

    root_abs = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root_abs):
        # Excluir carpetas vendorizadas
        dirnames[:] = sorted(d for d in dirnames if d.lower() not in _PRUNE_DIRS)
        rel_dir = os.path.relpath(dirpath, root_abs).replace("\\", "/")

        # Detección de subproyectos (monorepos)
        if rel_dir != ".":
            for f in filenames:
                fl = f.lower()
                if fl in ("package.json", "pom.xml", "build.gradle", "go.mod", "cargo.toml", "requirements.txt"):
                    subprojects.add(rel_dir)
                    break

        for name in sorted(filenames):
            lower = name.lower()
            rel = f"{rel_dir}/{name}" if rel_dir != "." else name
            ext = os.path.splitext(lower)[1]
            file_abs = os.path.join(dirpath, name)

            try:
                file_size = os.path.getsize(file_abs)
            except OSError:
                file_size = 0

            # 1. Conteo por extensión
            for lang, exts in _LANG_EXTENSIONS.items():
                if ext in exts:
                    lang_counts[lang]["files"] += 1
                    lang_counts[lang]["bytes"] += file_size
                    detected_languages.add(lang)
                    if lang == "python":
                        stack["has_python"] = True
                    if lang in ("javascript", "typescript"):
                        stack["has_node"] = True

            # 2. CI/CD
            if rel.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
                stack["github_workflows"].append(rel)
                stack["ci_systems"].append("github-actions")
            if lower == ".gitlab-ci.yml":
                stack["ci_systems"].append("gitlab-ci")
            if lower == "jenkinsfile":
                stack["ci_systems"].append("jenkins")
            if lower in ("dependabot.yml", "dependabot.yaml") and rel.startswith(".github/"):
                stack["dependabot"] = True

            # 3. IaC
            if lower.endswith((".tf", ".tfvars")):
                stack["terraform"].append(rel)
                if "terraform" not in stack["iac_types"]:
                    stack["iac_types"].append("terraform")
            if lower.endswith((".yaml", ".yml")) and "k8s" in rel.lower():
                if "kubernetes" not in stack["iac_types"]:
                    stack["iac_types"].append("kubernetes")
            if lower == "chart.yaml":
                if "helm" not in stack["iac_types"]:
                    stack["iac_types"].append("helm")

            # 4. Contenedores
            if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
                stack["dockerfiles"].append(rel)

            # 5. Dependencias y lockfiles por ecosistema
            if lower.endswith(".txt") and lower.startswith("requirements"):
                req_files.append(rel)
                dep_files.append(rel)
                detected_languages.add("python")
                stack["has_python"] = True
            if lower in ("pyproject.toml", "setup.py", "setup.cfg", "pipfile"):
                detected_languages.add("python")
                stack["has_python"] = True
                dep_files.append(rel)
                if lower == "pipfile":
                    detected_managers.add("pipenv")
            if lower == "poetry.lock":
                detected_languages.add("python")
                detected_managers.add("poetry")
                dep_files.append(rel)

            if lower == "package.json":
                detected_languages.add("node")
                stack["has_node"] = True
                dep_files.append(rel)
            if lower == "package-lock.json":
                stack["package_lock"] = True
                detected_languages.add("node")
                detected_managers.add("npm")
                dep_files.append(rel)
            if lower in ("yarn.lock", "pnpm-lock.yaml"):
                detected_languages.add("node")
                detected_managers.add("yarn" if lower == "yarn.lock" else "pnpm")
                dep_files.append(rel)

            if lower == "pom.xml":
                detected_languages.add("java")
                detected_managers.add("maven")
                dep_files.append(rel)
            if lower in ("build.gradle", "build.gradle.kts"):
                detected_languages.add("java")
                detected_managers.add("gradle")
                dep_files.append(rel)
            if lower == "go.mod":
                detected_languages.add("go")
                detected_managers.add("go")
                dep_files.append(rel)
            if lower in ("gemfile", "gemfile.lock"):
                detected_languages.add("ruby")
                detected_managers.add("bundler")
                dep_files.append(rel)
            if lower in ("cargo.toml", "cargo.lock"):
                detected_languages.add("rust")
                detected_managers.add("cargo")
                dep_files.append(rel)
            if lower in ("composer.json", "composer.lock"):
                detected_languages.add("php")
                detected_managers.add("composer")
                dep_files.append(rel)
            if lower.endswith(".csproj") or lower in ("packages.lock.json", "packages.config"):
                detected_languages.add("dotnet")
                detected_managers.add("nuget")
                dep_files.append(rel)
            if lower in ("pubspec.yaml", "pubspec.lock"):
                detected_languages.add("dart")
                detected_managers.add("pub")
                dep_files.append(rel)
            if lower == "mix.exs":
                detected_languages.add("elixir")
                detected_managers.add("mix")
                dep_files.append(rel)

            # 6. Detección de frameworks por archivos característicos
            if lower == "manage.py":
                frameworks.add("django")
            if lower in ("artisan", "server.php"):
                frameworks.add("laravel")
            if lower == "routes.rb":
                frameworks.add("rails")

            # 7. CloudFormation YAML sniff acotado
            if (lower.endswith((".yaml", ".yml")) and not rel.startswith(".github/")
                    and yaml_sniffed < _MAX_YAML_SNIFFED):
                yaml_sniffed += 1
                try:
                    with open(file_abs, "r", encoding="utf-8", errors="replace") as handle:
                        head = handle.read(2048)
                    if "AWSTemplateFormatVersion" in head:
                        stack["cloudformation"].append(rel)
                        if "cloudformation" not in stack["iac_types"]:
                            stack["iac_types"].append("cloudformation")
                except OSError:
                    pass

    # Filtrar lenguajes activos con al menos 1 archivo
    active_langs = {k: v for k, v in lang_counts.items() if v["files"] > 0}
    stack["languages_stats"] = active_langs
    # Sincronizar languages con los detectados
    for l in active_langs:
        detected_languages.add(l)

    stack["languages"] = sorted(detected_languages)
    stack["package_managers"] = sorted(detected_managers)
    stack["dependency_files"] = dep_files[:_MAX_LISTED_FILES]
    stack["requirements_files"] = req_files[:_MAX_LISTED_FILES]
    stack["frameworks"] = sorted(frameworks)
    stack["subprojects"] = sorted(subprojects)
    stack["monorepo_roots"] = sorted(subprojects)

    for key in ("terraform", "cloudformation", "dockerfiles", "github_workflows"):
        stack[key] = stack[key][:_MAX_LISTED_FILES]

    return stack
