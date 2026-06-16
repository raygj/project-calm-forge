"""GitOps artifact emitter — write governed deployment artifacts to a target location.

Two implementations:
  FilesystemEmitter  — writes to a local directory tree; fully testable, no git required.
  GitBranchEmitter   — writes to a git worktree branch and commits; degrades gracefully
                       when the path is not a git repo.

Both satisfy the GitOpsEmitter protocol.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class GitOpsEmitter(Protocol):
    """Protocol for writing governed deployment artifacts to a GitOps target."""

    def emit(self, workload_slug: str, attestation_sha: str, files: dict[str, str]) -> dict[str, Any]:
        """Write artifacts and return an emission result dict.

        Args:
            workload_slug:   URL-safe workload identifier (e.g. "fraud-v1")
            attestation_sha: SHA-256 hex digest of the combined artifact content
            files:           dict of filename → file content strings

        Returns:
            dict with keys:
              target_path   str   absolute path where artifacts were written
              target_branch str   git branch name, or None for FilesystemEmitter
              artifact_paths list[str]  paths of individual written files
              emitter_type  str   "filesystem" | "git-branch"
        """
        ...


class FilesystemEmitter:
    """Write artifacts under <target_dir>/<workload_slug>/<sha8>/.

    Fully testable without git. The resulting directory tree mirrors what a
    GitBranchEmitter would write to a worktree, making it a safe stand-in for
    local development and CI.
    """

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir)

    def emit(self, workload_slug: str, attestation_sha: str, files: dict[str, str]) -> dict[str, Any]:
        sha8 = attestation_sha[:8]
        dest = self.target_dir / workload_slug / sha8
        dest.mkdir(parents=True, exist_ok=True)

        artifact_paths: list[str] = []
        for filename, content in files.items():
            path = dest / filename
            path.write_text(content)
            artifact_paths.append(str(path))

        # Write a manifest so the deployment observer can verify completeness
        manifest = {
            "workload_slug": workload_slug,
            "attestation_sha": attestation_sha,
            "files": list(files.keys()),
        }
        manifest_path = dest / "_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        artifact_paths.append(str(manifest_path))

        return {
            "target_path": str(dest),
            "target_branch": None,
            "artifact_paths": artifact_paths,
            "emitter_type": "filesystem",
        }


class GitBranchEmitter:
    """Write artifacts to a git branch under <repo_path>.

    Creates a branch named `calm-forge/<workload_slug>/<sha8>`, writes files,
    and commits. Optionally pushes when push=True. Degrades gracefully when
    repo_path is not a git repository: falls back to FilesystemEmitter behaviour
    and logs a warning in the result.
    """

    def __init__(self, repo_path: Path, base_branch: str = "main", push: bool = False):
        self.repo_path = Path(repo_path)
        self.base_branch = base_branch
        self.push = push

    def emit(self, workload_slug: str, attestation_sha: str, files: dict[str, str]) -> dict[str, Any]:
        sha8 = attestation_sha[:8]
        branch = f"calm-forge/{workload_slug}/{sha8}"
        dest = self.repo_path / workload_slug / sha8

        try:
            self._run(["git", "rev-parse", "--is-inside-work-tree"])
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Not a git repo — fall back to plain filesystem write
            fs = FilesystemEmitter(self.repo_path)
            result = fs.emit(workload_slug, attestation_sha, files)
            result["emitter_type"] = "git-branch-degraded"
            result["warning"] = f"{self.repo_path} is not a git repository; wrote files without git"
            return result

        # Create branch from base
        try:
            self._run(["git", "checkout", "-b", branch, self.base_branch])
        except subprocess.CalledProcessError:
            # Branch may already exist — check it out
            self._run(["git", "checkout", branch])

        dest.mkdir(parents=True, exist_ok=True)
        artifact_paths: list[str] = []
        for filename, content in files.items():
            path = dest / filename
            path.write_text(content)
            artifact_paths.append(str(path))

        manifest = {
            "workload_slug": workload_slug,
            "attestation_sha": attestation_sha,
            "files": list(files.keys()),
        }
        manifest_path = dest / "_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        artifact_paths.append(str(manifest_path))

        self._run(["git", "add", str(dest)])
        self._run(["git", "commit", "-m",
                   f"feat(calm-forge): deploy {workload_slug} @ {sha8}"])

        if self.push:
            self._run(["git", "push", "--set-upstream", "origin", branch])

        return {
            "target_path": str(dest),
            "target_branch": branch,
            "artifact_paths": artifact_paths,
            "emitter_type": "git-branch",
        }

    def _run(self, cmd: list[str]) -> None:
        subprocess.run(cmd, cwd=self.repo_path, check=True, capture_output=True)
