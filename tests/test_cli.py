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
