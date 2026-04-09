from __future__ import annotations

import shutil
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class StageWheelSourcesHook(BuildHookInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._staged_paths: list[Path] = []

    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        src_root = Path(self.root) / "src" / "impacket"
        if src_root.exists():
            return

        source_root = Path(self.root).resolve().parents[1] / "impacket"
        if not source_root.is_dir():
            raise OSError(f"Unable to stage impacket sources from {source_root}")

        src_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_root, src_root, dirs_exist_ok=True)
        self._staged_paths.append(src_root.parent)

    def finalize(self, version: str, build_data: dict[str, object], artifact_path: str) -> None:
        while self._staged_paths:
            staged_path = self._staged_paths.pop()
            if staged_path.exists():
                shutil.rmtree(staged_path)


def get_build_hook():
    return StageWheelSourcesHook


build_hook = StageWheelSourcesHook
