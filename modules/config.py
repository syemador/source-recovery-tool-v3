"""
Configuration management.

Loads settings from (in order of priority):
  1. Environment variables
  2. config.json in project root
  3. Hard-coded defaults
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_FILE = Path(__file__).parent.parent / "config.json"


@dataclass
class Config:
    ghidra_home: str = ""
    project_dir: str = ""
    github_token: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o"
    llm_base_url: str = "https://api.openai.com/v1"
    max_candidates: int = 50

    @classmethod
    def load(cls) -> "Config":
        """Load configuration from file and environment variables.

        Environment variables take precedence over config.json.
        When both LLM_API_KEY and OPENAI_API_KEY are set, OPENAI_API_KEY
        wins (it is applied last in the env_map iteration order).
        """
        cfg = cls()

        # Load from config.json
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                for key, value in data.items():
                    if hasattr(cfg, key):
                        setattr(cfg, key, value)
            except (json.JSONDecodeError, OSError) as e:
                print(f"[WARN] Could not parse {CONFIG_FILE}: {e}")

        # Environment overrides (applied in insertion order;
        # later entries override earlier ones for the same attribute)
        env_map = {
            "GHIDRA_HOME": "ghidra_home",
            "GHIDRA_PROJECT_DIR": "project_dir",
            "GITHUB_TOKEN": "github_token",
            "LLM_API_KEY": "llm_api_key",
            "OPENAI_API_KEY": "llm_api_key",  # takes precedence over LLM_API_KEY
            "LLM_MODEL": "llm_model",
            "LLM_BASE_URL": "llm_base_url",
        }
        for env_var, attr in env_map.items():
            val = os.environ.get(env_var)
            if val:
                setattr(cfg, attr, val)

        # Default project dir
        if not cfg.project_dir:
            cfg.project_dir = str(Path(__file__).parent.parent / "ghidra_projects")

        return cfg

    def save(self, path: str | None = None):
        """Save current config to JSON."""
        target = Path(path) if path else CONFIG_FILE
        data = {
            "ghidra_home": self.ghidra_home,
            "project_dir": self.project_dir,
            "github_token": self.github_token,
            "llm_api_key": self.llm_api_key,
            "llm_model": self.llm_model,
            "llm_base_url": self.llm_base_url,
            "max_candidates": self.max_candidates,
        }
        with open(target, "w") as f:
            json.dump(data, f, indent=2)
