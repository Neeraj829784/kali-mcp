"""Tests for centralized data directory (KALI_MCP_DATA_DIR)."""
import os
import subprocess
import sys
import tempfile

import config
import cred_vault
import engagement
import scope


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_default_data_dir_is_base_dir():
    """Backward compatibility: with no env var, DATA_DIR == BASE_DIR."""
    # In the test environment KALI_MCP_DATA_DIR is not set.
    assert config.DATA_DIR == config.BASE_DIR


def test_all_writable_paths_under_data_dir():
    paths = [
        config.JOBS_DB_PATH, config.ARTIFACTS_DIR, config.AUDIT_LOG_PATH,
        config.SCOPE_FILE, config.PROGRAMS_DB_PATH, config.ENGAGEMENT_DB_PATH,
        config.VAULT_DB_PATH, config.VAULT_KEY_FILE, config.SSH_KNOWN_HOSTS,
    ]
    for p in paths:
        assert p.startswith(config.DATA_DIR), f"{p} not under DATA_DIR"


def test_modules_use_config_paths():
    """The out-of-config modules must resolve to the config paths."""
    assert engagement.ENGAGEMENT_DB == config.ENGAGEMENT_DB_PATH
    assert cred_vault.VAULT_DB == config.VAULT_DB_PATH
    assert cred_vault.KEY_FILE == config.VAULT_KEY_FILE
    assert scope.SCOPE_FILE == config.SCOPE_FILE


def test_env_override_relocates_all_state(tmp_path):
    """Setting KALI_MCP_DATA_DIR relocates every writable path and creates the dir."""
    data_dir = str(tmp_path / "custom-data")
    code = (
        "import config, engagement, cred_vault, scope, os, json;"
        "paths=[config.JOBS_DB_PATH, config.ARTIFACTS_DIR, config.AUDIT_LOG_PATH,"
        "config.SCOPE_FILE, config.PROGRAMS_DB_PATH, config.ENGAGEMENT_DB_PATH,"
        "config.VAULT_DB_PATH, config.VAULT_KEY_FILE, config.SSH_KNOWN_HOSTS,"
        "engagement.ENGAGEMENT_DB, cred_vault.VAULT_DB, cred_vault.KEY_FILE, scope.SCOPE_FILE];"
        "print(json.dumps({'data_dir': config.DATA_DIR, 'paths': paths,"
        "'created': os.path.isdir(config.DATA_DIR)}))"
    )
    env = dict(os.environ, KALI_MCP_DATA_DIR=data_dir)
    out = subprocess.check_output([sys.executable, "-c", code], cwd=PROJECT_ROOT, env=env)
    import json
    result = json.loads(out.decode().strip().splitlines()[-1])
    assert result["data_dir"] == data_dir
    assert result["created"] is True
    for p in result["paths"]:
        assert p.startswith(data_dir), f"{p} not relocated under {data_dir}"


def test_data_dir_created_with_restricted_perms(tmp_path):
    """The data dir is created 0700 (owner-only) for engagement/credential privacy."""
    data_dir = str(tmp_path / "perm-data")
    code = "import config, os; print(oct(os.stat(config.DATA_DIR).st_mode & 0o777))"
    env = dict(os.environ, KALI_MCP_DATA_DIR=data_dir)
    out = subprocess.check_output([sys.executable, "-c", code], cwd=PROJECT_ROOT, env=env)
    assert "0o700" in out.decode()
