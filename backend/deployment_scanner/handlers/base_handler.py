import json
import subprocess
from pathlib import Path


class BaseHandler:
    def __init__(self, proj_path: str):
        self.proj_path = Path(proj_path)

    def run_cmd(self, cmd: list[str]) -> tuple[int, str, str]:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        out, err = proc.communicate()
        return proc.returncode, out, err

    def parse_json(self, text: str):
        try:
            return json.loads(text)
        except Exception:
            return None
