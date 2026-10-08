"""Author classification for the non-human dependency change share (review finding R1-04)."""
import re
import subprocess

from worksheet.baseline import AGENT_PATTERNS, BOT_PATTERNS, classify, coauthor_trailers, lockfile_commits

BOT = re.compile("|".join(BOT_PATTERNS), re.I)
AGENT = re.compile("|".join(AGENT_PATTERNS), re.I)


def test_bot_accounts():
    assert classify("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com", BOT, AGENT) == "bot"
    assert classify("renovate[bot]", "bot@renovateapp.com", BOT, AGENT) == "bot"


def test_agent_by_name():
    assert classify("Copilot", "198982749+Copilot@users.noreply.github.com", BOT, AGENT) == "agent"


def test_agent_substring_no_longer_matches():
    # "agent" inside an unrelated name used to be classified as an agent.
    assert classify("Reagent Labs", "ops@reagent-labs.example", BOT, AGENT) == "human"
    assert classify("Travel Agency CI", "ci@agency.example", BOT, AGENT) == "human"


def test_agent_detected_through_coauthor_trailer():
    # An agent committing under the developer's identity is visible only in the trailer.
    assert classify("Dana Dev", "dana@example.com", BOT, AGENT, ["Claude <noreply@anthropic.com>"]) == "agent"
    assert classify("Dana Dev", "dana@example.com", BOT, AGENT, ["Sam Pair <sam@example.com>"]) == "human"


def _git(repo, *args, env=None):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)


def test_end_to_end_on_a_temp_repo(tmp_path):
    import os
    env = {**os.environ, "GIT_AUTHOR_NAME": "Dana Dev", "GIT_AUTHOR_EMAIL": "dana@example.com",
           "GIT_COMMITTER_NAME": "Dana Dev", "GIT_COMMITTER_EMAIL": "dana@example.com"}
    _git(tmp_path, "init", "-q", env=env)
    (tmp_path / "package-lock.json").write_text("{}\n")
    _git(tmp_path, "add", ".", env=env)
    _git(tmp_path, "commit", "-q", "-m", "bump deps\n\nCo-authored-by: Copilot <copilot@example.com>", env=env)
    (tmp_path / "README.md").write_text("docs\n")
    _git(tmp_path, "add", ".", env=env)
    _git(tmp_path, "commit", "-q", "-m", "docs", env=env)

    commits = lockfile_commits(tmp_path, 30)
    assert len(commits) == 1 and commits[0]["files"] == ["package-lock.json"]
    trailers = coauthor_trailers(tmp_path, 30)
    assert trailers[commits[0]["sha"]] == ["Copilot <copilot@example.com>"]
    assert classify(commits[0]["author"], commits[0]["email"], BOT, AGENT, trailers[commits[0]["sha"]]) == "agent"
