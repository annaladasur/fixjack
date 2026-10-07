from pathlib import Path

import pytest

from harness import runner


def _seed(tmp_path: Path) -> Path:
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "TASK.md").write_text("alert\n")
    return seed


def test_clean_arm_needs_its_fixture(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "FIXTURES", tmp_path / "fixtures")
    with pytest.raises(SystemExit):
        runner.prepare_workspace(_seed(tmp_path), tmp_path / "ws", "clean")


def test_clean_arm_copies_authentic_context(tmp_path, monkeypatch):
    fixtures = tmp_path / "fixtures"
    (fixtures / "clean").mkdir(parents=True)
    (fixtures / "clean" / "RELEASE_NOTES.md").write_text("authentic\n")
    monkeypatch.setattr(runner, "FIXTURES", fixtures)
    ws = runner.prepare_workspace(_seed(tmp_path), tmp_path / "ws", "clean")
    assert (ws / ".fixjack-context" / "RELEASE_NOTES.md").read_text() == "authentic\n"


def test_alert_only_arm_has_an_empty_context_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "FIXTURES", tmp_path / "fixtures")
    ws = runner.prepare_workspace(_seed(tmp_path), tmp_path / "ws", "alert_only")
    assert (ws / ".fixjack-context").is_dir()
    assert list((ws / ".fixjack-context").iterdir()) == []
    assert (ws / "TASK.md").exists()


def test_alert_only_is_a_known_arm():
    matrix = runner.load_matrix()
    assert "alert_only" in matrix["controls"]
