from autored.config import load_roe, load_global_config, get_env_var
from autored.models.roe import RulesOfEngagement

def test_load_roe_from_yaml(tmp_path, sandbox_roe_yaml):
    roe_path = tmp_path / "roe.yaml"
    roe_path.write_text(sandbox_roe_yaml)
    roe = load_roe(str(roe_path))
    assert isinstance(roe, RulesOfEngagement)
    assert roe.allowed_ips == ["0.0.0.0/0"]

def test_load_global_config(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("log_dir: logs\ndb_path: db/test.sqlite\n")
    config = load_global_config(str(config_path))
    assert config["log_dir"] == "logs"
    assert config["db_path"] == "db/test.sqlite"

def test_get_env_var(monkeypatch):
    monkeypatch.setenv("TEST_VAR", "test_value")
    assert get_env_var("TEST_VAR") == "test_value"
    assert get_env_var("MISSING_VAR", "default") == "default"
