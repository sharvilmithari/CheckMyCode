"""Project Profiling Module for OpenGuard.

Inspects extracted project archives to detect programming languages,
frameworks, dependency manifests, configuration files, and project entry points
without executing any untrusted code.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

# Standard directory exclusions to avoid scanning vendored or cache artifacts
IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".next",
    "target",
}

# Known file extensions for language mapping
LANGUAGE_EXTENSIONS = {
    "Python": {".py", ".pyw"},
    "JavaScript": {".js", ".jsx", ".mjs", ".cjs"},
    "TypeScript": {".ts", ".tsx"},
    "Go": {".go"},
    "Java": {".java"},
    "Kotlin": {".kt"},
    "Shell": {".sh", ".bash", ".zsh"},
    "HTML/CSS": {".html", ".htm", ".css", ".scss"},
    "SQL": {".sql"},
    "YAML/JSON": {".yaml", ".yml", ".json"},
}

MANIFEST_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "pom.xml",
    "Gemfile",
}

CONFIG_FILENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.example",
    ".env.template",
    ".env.local",
    ".gitignore",
    "tsconfig.json",
    "Procfile",
    "vercel.json",
    "netlify.toml",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyd", ".class",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".pdf", ".mp4", ".mp3",
    ".woff", ".woff2", ".ttf", ".eot",
}


def is_binary_file(file_path: Path) -> bool:
    """Check if file is binary by extension or null byte inspection."""
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        return True
    return False


def detect_frameworks(root_dir: Path, manifests: List[str]) -> List[str]:
    """Identify recognizable application frameworks from dependency manifests without code execution."""
    frameworks: Set[str] = set()

    for rel_manifest in manifests:
        manifest_path = root_dir / rel_manifest
        if not manifest_path.exists():
            continue

        try:
            # Check requirements.txt / pyproject.toml
            if manifest_path.name in ["requirements.txt", "Pipfile"]:
                text = manifest_path.read_text(encoding="utf-8", errors="ignore").lower()
                if "fastapi" in text:
                    frameworks.add("FastAPI")
                if "flask" in text:
                    frameworks.add("Flask")
                if "django" in text:
                    frameworks.add("Django")
                if "streamlit" in text:
                    frameworks.add("Streamlit")
                if "celery" in text:
                    frameworks.add("Celery")
                if "tornado" in text:
                    frameworks.add("Tornado")

            elif manifest_path.name == "package.json":
                data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))
                dep_keys = {k.lower() for k in deps.keys()}

                if "react" in dep_keys:
                    frameworks.add("React")
                if "next" in dep_keys:
                    frameworks.add("Next.js")
                if "express" in dep_keys:
                    frameworks.add("Express")
                if "vue" in dep_keys or "nuxt" in dep_keys:
                    frameworks.add("Vue/Nuxt")
                if "nestjs" in dep_keys or "@nestjs/core" in dep_keys:
                    frameworks.add("NestJS")
                if "fastify" in dep_keys:
                    frameworks.add("Fastify")

        except Exception as e:
            logger.debug("Error checking framework in manifest %s: %s", rel_manifest, e)

    return sorted(list(frameworks))


def profile_project(root_dir: Path) -> Dict[str, Any]:
    """Analyze the structure, languages, manifests, and file counts of an extracted project."""
    root = Path(root_dir).resolve()
    if not root.exists():
        return {
            "project_name": "Unknown",
            "total_files": 0,
            "inspected_files": 0,
            "languages": [],
            "frameworks": [],
            "manifests": [],
            "configs": [],
            "approx_loc": 0,
            "files_by_language": {},
            "inspected_file_paths": [],
        }

    detected_languages: Dict[str, int] = {}
    manifests: List[str] = []
    configs: List[str] = []
    inspected_paths: List[str] = []
    total_files = 0
    approx_loc = 0

    for current_dir, dirs, files in os.walk(root):
        # Prune ignored directory trees in place
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            total_files += 1
            full_path = Path(current_dir) / file
            rel_path = str(full_path.relative_to(root)).replace("\\", "/")

            # Check manifests
            if file in MANIFEST_FILENAMES or file.startswith("requirements"):
                manifests.append(rel_path)

            # Check configs
            if file in CONFIG_FILENAMES or ".env" in file or file.endswith(".config.js") or file.endswith(".config.ts"):
                configs.append(rel_path)

            # Check if binary
            if is_binary_file(full_path):
                continue

            # Classify language
            ext = full_path.suffix.lower()
            classified = False
            for lang, exts in LANGUAGE_EXTENSIONS.items():
                if ext in exts:
                    detected_languages[lang] = detected_languages.get(lang, 0) + 1
                    classified = True
                    break

            # Count lines of code for source files
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = sum(1 for line in f if line.strip())
                    approx_loc += lines
                inspected_paths.append(rel_path)
            except Exception:
                pass

    # Sort languages by prevalence
    sorted_langs = sorted(detected_languages.keys(), key=lambda l: detected_languages[l], reverse=True)
    frameworks = detect_frameworks(root, manifests)

    # Derive reasonable project name from root directory or package.json
    project_name = root.name
    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            p_data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            if p_data.get("name"):
                project_name = p_data["name"]
        except Exception:
            pass

    return {
        "project_name": project_name,
        "total_files": total_files,
        "inspected_files": len(inspected_paths),
        "languages": sorted_langs,
        "frameworks": frameworks,
        "manifests": manifests,
        "configs": configs,
        "approx_loc": approx_loc,
        "files_by_language": detected_languages,
        "inspected_file_paths": inspected_paths,
    }
