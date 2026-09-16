import subprocess
import sys


def test_cli_rejects_action_and_prints_investigation(alert_file, tmp_path):
    # Run from a temporary cwd only to ensure audit state is isolated.
    result = subprocess.run(
        [sys.executable, "-m", "app.investigate", str(alert_file)],
        input="n\n",
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env={"PATH": __import__("os").environ["PATH"], "PYTHONPATH": str(__import__("pathlib").Path.cwd())},
    )
    assert result.returncode == 0
    assert "credential compromise" in result.stdout
    assert "Action rejected safely" in result.stdout


def test_cli_dry_run_does_not_prompt(alert_file, tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "app.investigate", "--dry-run", str(alert_file)],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env={"PATH": __import__("os").environ["PATH"], "PYTHONPATH": str(__import__("pathlib").Path.cwd())},
    )
    assert result.returncode == 0
    assert "Recommendations:" in result.stdout
    assert "Approve one high-impact action" not in result.stdout


def test_cli_approve_action_requires_exact_recommendation(alert_file, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.investigate",
            "--approve-action",
            "not-a-tool",
            str(alert_file),
        ],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env={"PATH": __import__("os").environ["PATH"], "PYTHONPATH": str(__import__("pathlib").Path.cwd())},
    )
    assert result.returncode == 0
    assert "Action rejected safely" in result.stdout
    audit = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert "not-a-tool" in audit
