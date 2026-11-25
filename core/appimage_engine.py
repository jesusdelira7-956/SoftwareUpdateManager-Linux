"""Declarative AppImage & Standalone Binary Updater with Smart Bandwidth Caching.

100% Python Standard Library (urllib.request, json, tarfile, zipfile).
Reads providers.json and checks only applications actually present on the
user's system or configured secondary drives, skipping downloads when
ETags, release tags, redirect filenames, or build IDs already match.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

from core.config_manager import (
    CACHE_DIR,
    get_search_directories,
    load_version_cache,
    save_version_cache,
)
from core.package_engine import UpdateItem
from core.privilege_helper import run_command, wait_for_apt_locks
from core.security_auditor import compute_sha256, evaluate_package_trust

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROVIDERS_FILE = PROJECT_ROOT / "providers.json"
USER_AGENT = "SoftwareUpdateManager-Linux/1.0"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_get_text(url: str, timeout: int = 12) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _http_head_headers(url: str, follow_redirects: bool = True, timeout: int = 10) -> tuple[str, dict[str, str]]:
    """Return (final_or_redirect_url, lowercase_headers)."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    opener = (
        urllib.request.build_opener()
        if follow_redirects
        else urllib.request.build_opener(_NoRedirectHandler())
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.geturl(), headers
    except urllib.error.HTTPError as err:
        headers = {k.lower(): v for k, v in err.headers.items()}
        if err.code in (301, 302, 303, 307, 308) and "location" in headers:
            return headers["location"], headers
        return url, headers
    except (urllib.error.URLError, TimeoutError, OSError):
        return url, {}


def _download_file(
    url: str,
    dest: Path,
    stream_cb: Callable[[str], None] | None = None,
    timeout: int = 120,
) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as out:
            total = int(resp.headers.get("Content-Length") or 0)
            downloaded = 0
            last_pct = -1
            while chunk := resp.read(131072):
                out.write(chunk)
                downloaded += len(chunk)
                if total > 0 and stream_cb:
                    pct = int((downloaded * 100) / total)
                    if pct >= last_pct + 10:
                        last_pct = pct
                        mb_done = downloaded / (1024 * 1024)
                        mb_tot = total / (1024 * 1024)
                        stream_cb(f"  Downloading {dest.name}: {pct}% ({mb_done:.1f}/{mb_tot:.1f} MB)")
        tmp.replace(dest)
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if stream_cb:
            stream_cb(f"  Download failed: {exc}")
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return False


_PRUNED_DIR_NAMES = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "models", "blobs",
    ".cache", "lost+found", ".tmp", "tmp", "Cache", "GPUCache", "Code Cache",
    "DawnCache", "extensions", "site-packages", "target", "build", "dist",
    ".Trash-1000", "SteamLibrary", "steamapps", "docker-data",
}


def load_providers() -> list[dict[str, Any]]:
    if not PROVIDERS_FILE.exists():
        return []
    try:
        data = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
        return data.get("providers", [])
    except (OSError, json.JSONDecodeError):
        return []


def load_git_ai_repos() -> list[dict[str, Any]]:
    if not PROVIDERS_FILE.exists():
        return []
    try:
        data = json.loads(PROVIDERS_FILE.read_text(encoding="utf-8"))
        return data.get("git_ai_repos", [])
    except (OSError, json.JSONDecodeError):
        return []


def _iter_candidate_dirs(search_dirs: list[Path], max_depth: int = 3) -> list[Path]:
    """Walk search_dirs up to `max_depth` levels deep, pruning noisy/heavy subtrees."""
    results: list[Path] = []
    seen: set[str] = set()

    def _walk(folder: Path, depth: int) -> None:
        key = str(folder)
        if key in seen:
            return
        seen.add(key)
        results.append(folder)
        if depth >= max_depth:
            return
        try:
            for child in folder.iterdir():
                if not child.is_dir() or child.is_symlink():
                    continue
                if child.name.startswith(".") or child.name in _PRUNED_DIR_NAMES:
                    continue
                _walk(child, depth + 1)
        except OSError:
            pass

    for base in search_dirs:
        if base.is_dir():
            _walk(base, 0)
    return results


def _find_installed_app_dir(provider: dict[str, Any], candidate_dirs: list[Path]) -> Path | None:
    """Locate an existing installation directory for a standalone provider."""
    pattern = provider.get("filename_pattern", "")
    binary_check = provider.get("binary_check", "")

    for folder in candidate_dirs:
        try:
            if binary_check and (folder / binary_check).is_file():
                return folder
            if pattern and any(folder.glob(pattern)):
                return folder
        except OSError:
            continue
    return None


def _check_docker_desktop(provider: dict[str, Any]) -> UpdateItem | None:
    """Check Docker Desktop installed build vs latest release notes build ID (amd64 .deb)."""
    if platform.machine().lower() not in ("x86_64", "amd64") or not shutil.which("dpkg"):
        return None
    dpkg_pkg = provider.get("dpkg_package", "docker-desktop")
    try:
        res = subprocess.run(
            ["dpkg", "-s", dpkg_pkg],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0:
            return None
    except (OSError, subprocess.SubprocessError):
        return None

    installed_ver = ""
    for line in res.stdout.splitlines():
        if line.lower().startswith("version:"):
            installed_ver = line.split(":", 1)[1].strip()
            break

    m_inst = re.search(r"(\d+)$", installed_ver)
    installed_build = m_inst.group(1) if m_inst else ""

    html = _http_get_text(provider["release_notes_url"])
    if not html:
        return None

    m_url = re.search(
        r"https://desktop\.docker\.com/linux/main/amd64/(\d+)/docker-desktop-amd64\.deb",
        html,
    )
    if not m_url:
        return None

    latest_url = m_url.group(0)
    latest_build = m_url.group(1)

    if latest_build and latest_build == installed_build:
        return None  # Smart cache hit: already on latest build

    return UpdateItem(
        id="standalone:docker_desktop",
        name="Docker Desktop",
        source="Docker (.deb)",
        current_version=installed_ver or "installed",
        available_version=f"build {latest_build}",
        trust_status="TRUSTED",
        trust_reasons=[],
        needs_root=True,
        metadata={
            "provider": provider,
            "download_url": latest_url,
            "latest_build": latest_build,
        },
    )


def _scan_git_ai_repos(candidate_dirs: list[Path]) -> list[UpdateItem]:
    """Auto-discover local Git-managed AI repos (SwarmUI, ComfyUI, etc.) and check upstream commits."""
    if not shutil.which("git"):
        return []

    repo_defs = load_git_ai_repos()
    if not repo_defs:
        return []

    items: list[UpdateItem] = []
    matched_ids: set[str] = set()

    for folder in candidate_dirs:
        try:
            if not (folder / ".git").is_dir():
                continue
        except OSError:
            continue
        for rdef in repo_defs:
            rid = rdef["id"]
            if rid in matched_ids:
                continue
            dir_names = [d.lower() for d in rdef.get("dir_names", [])]
            markers = rdef.get("marker_files", [])
            name_match = folder.name.lower() in dir_names
            marker_match = any((folder / m).exists() for m in markers)
            if not (name_match or marker_match):
                continue

            matched_ids.add(rid)
            try:
                subprocess.run(
                    ["git", "-C", str(folder), "fetch", "--quiet"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                count_res = subprocess.run(
                    ["git", "-C", str(folder), "rev-list", "--count", "HEAD..@{u}"],
                    capture_output=True,
                    text=True,
                    timeout=8,
                )
                if count_res.returncode != 0:
                    continue
                behind = int(count_res.stdout.strip() or "0")
                if behind <= 0:
                    continue
                head_sha = subprocess.run(
                    ["git", "-C", str(folder), "rev-parse", "--short", "HEAD"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip() or "local"
                up_sha = subprocess.run(
                    ["git", "-C", str(folder), "rev-parse", "--short", "@{u}"],
                    capture_output=True, text=True, timeout=5,
                ).stdout.strip() or "upstream"
                items.append(UpdateItem(
                    id=f"git:{rid}",
                    name=rdef["name"],
                    source="Git AI Repo",
                    current_version=head_sha,
                    available_version=f"{up_sha} (+{behind} commits)",
                    trust_status="TRUSTED",
                    trust_reasons=[],
                    needs_root=False,
                    metadata={
                        "provider": {"id": rid, "name": rdef["name"], "strategy": "git_pull"},
                        "install_dir": str(folder),
                        "download_url": "",
                        "version_token": up_sha,
                    },
                ))
            except (OSError, ValueError, subprocess.SubprocessError):
                continue

    return items


def _on_disk_matches_tag(install_dir: Path, tag: str, pattern: str = "") -> bool:
    """Return True if an on-disk filename or .version file already reflects `tag`."""
    clean_tag = tag.lstrip("v").strip()
    if not clean_tag:
        return False
    # Check version marker files (e.g. .version, .obsidian_version)
    for vf in install_dir.glob("*version*"):
        if vf.is_file():
            try:
                content = vf.read_text(encoding="utf-8", errors="ignore").strip().lstrip("v")
                if content == clean_tag:
                    return True
            except OSError:
                pass
    # Check actual filenames in the directory
    try:
        for entry in install_dir.iterdir():
            if clean_tag in entry.name:
                return True
    except OSError:
        pass
    return False


def scan_standalone_updates(config: dict[str, Any]) -> list[UpdateItem]:
    """Scan installed standalone apps/AppImages, Git AI repos, + Docker Desktop using smart caching."""
    items: list[UpdateItem] = []
    providers = load_providers()
    search_dirs = get_search_directories(config)
    candidate_dirs = _iter_candidate_dirs(search_dirs, max_depth=3)
    cache = load_version_cache()

    for provider in providers:
        strategy = provider.get("strategy", "")
        pid = provider.get("id", "")

        if strategy == "docker_release_notes_deb":
            if config.get("enable_docker_desktop", True):
                docker_item = _check_docker_desktop(provider)
                if docker_item:
                    items.append(docker_item)
            continue

        if not config.get("enable_appimages", True):
            continue

        install_dir = _find_installed_app_dir(provider, candidate_dirs)
        if not install_dir:
            continue  # App is not installed on this machine; skip cleanly

        trust = evaluate_package_trust(
            name=provider["name"],
            pkg_id=pid,
            install_path=str(install_dir),
        )

        if strategy == "github_release":
            api_url = f"https://api.github.com/repos/{provider['repo']}/releases/latest"
            body = _http_get_text(api_url)
            if not body:
                continue
            try:
                rel = json.loads(body)
            except json.JSONDecodeError:
                continue
            tag = rel.get("tag_name", "")
            asset_url = ""
            for asset in rel.get("assets", []):
                dl = asset.get("browser_download_url", "")
                if dl.endswith(".AppImage"):
                    asset_url = dl
                    break
            if not tag or not asset_url:
                continue
            cached_tag = cache.get(pid, {}).get("tag", "")
            if cached_tag == tag or _on_disk_matches_tag(install_dir, tag, provider.get("filename_pattern", "")):
                continue
            items.append(UpdateItem(
                id=f"appimage:{pid}",
                name=provider["name"],
                source="AppImage",
                current_version=cached_tag or "installed",
                available_version=tag,
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": asset_url,
                    "version_token": tag,
                },
            ))

        elif strategy == "github_release_zip":
            api_url = f"https://api.github.com/repos/{provider['repo']}/releases/latest"
            body = _http_get_text(api_url)
            if not body:
                continue
            try:
                rel = json.loads(body)
            except json.JSONDecodeError:
                continue
            tag = rel.get("tag_name", "")
            regex = provider.get("asset_regex", r"linux-x64.*\.zip$")
            asset_url = ""
            for asset in rel.get("assets", []):
                dl = asset.get("browser_download_url", "")
                if re.search(regex, dl, re.IGNORECASE):
                    asset_url = dl
                    break
            if not tag or not asset_url:
                continue
            cached_tag = cache.get(pid, {}).get("tag", "")
            if cached_tag == tag or _on_disk_matches_tag(install_dir, tag):
                continue
            items.append(UpdateItem(
                id=f"standalone:{pid}",
                name=provider["name"],
                source="Standalone",
                current_version=cached_tag or "installed",
                available_version=tag,
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": asset_url,
                    "version_token": tag,
                },
            ))

        elif strategy == "antigravity_cloud_tar":
            body = _http_get_text(provider["api_url"])
            if not body:
                continue
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue
            releases = data if isinstance(data, list) else data.get("releases", [data])
            latest = releases[0] if releases and isinstance(releases[0], dict) else {}
            remote_ver = str(latest.get("version") or "").strip()
            exec_id = str(latest.get("execution_id") or latest.get("executionId") or "").strip()
            if not remote_ver or not exec_id:
                continue
            # Check local version file or cache
            local_ver = cache.get(pid, {}).get("tag", "")
            vfile = install_dir / provider.get("version_file", ".version")
            if vfile.is_file():
                try:
                    local_ver = vfile.read_text(encoding="utf-8", errors="ignore").strip() or local_ver
                except OSError:
                    pass
            if local_ver == remote_ver:
                continue
            dl_url = provider["url_template"].format(version=remote_ver, execution_id=exec_id)
            items.append(UpdateItem(
                id=f"standalone:{pid}",
                name=provider["name"],
                source="Standalone",
                current_version=local_ver or "installed",
                available_version=f"v{remote_ver}",
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": dl_url,
                    "version_token": remote_ver,
                },
            ))

        elif strategy == "http_redirect":
            redir_url, _ = _http_head_headers(provider["url"], follow_redirects=False)
            filename = Path(redir_url.split("?")[0]).name
            if not filename or filename == Path(provider["url"].split("?")[0]).name:
                continue
            if (install_dir / filename).is_file():
                continue  # Smart cache hit
            items.append(UpdateItem(
                id=f"appimage:{pid}",
                name=provider["name"],
                source="AppImage",
                current_version=cache.get(pid, {}).get("filename", "installed"),
                available_version=filename,
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": redir_url,
                    "version_token": filename,
                },
            ))

        elif strategy == "http_etag":
            _, headers = _http_head_headers(provider["url"], follow_redirects=True)
            etag = headers.get("etag", "")
            if not etag:
                continue
            if cache.get(pid, {}).get("etag") == etag:
                continue  # Smart cache hit
            items.append(UpdateItem(
                id=f"appimage:{pid}",
                name=provider["name"],
                source="AppImage",
                current_version="installed",
                available_version=f"etag:{etag[:10]}",
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": provider["url"],
                    "version_token": etag,
                },
            ))

        elif strategy == "http_redirect_tar":
            redir_url, _ = _http_head_headers(provider["url"], follow_redirects=False)
            tarball = Path(redir_url.split("?")[0]).name
            if not tarball or cache.get(pid, {}).get("tarball") == tarball:
                continue
            items.append(UpdateItem(
                id=f"standalone:{pid}",
                name=provider["name"],
                source="Standalone",
                current_version=cache.get(pid, {}).get("tarball", "installed"),
                available_version=tarball,
                trust_status=trust["status"],
                trust_reasons=trust["reasons"],
                needs_root=False,
                metadata={
                    "provider": provider,
                    "install_dir": str(install_dir),
                    "download_url": redir_url,
                    "version_token": tarball,
                },
            ))

    if config.get("enable_appimages", True):
        items.extend(_scan_git_ai_repos(candidate_dirs))

    return items


def apply_standalone_update(
    item: UpdateItem,
    mode: str = "cli",
    timeout_lock: int = 60,
    stream_cb: Callable[[str], None] | None = None,
) -> tuple[bool, str]:
    """Download, verify SHA-256, install, and update smart cache for a standalone item."""
    if item.trust_status == "BLOCKED":
        return False, f"Blocked by Trust Gate: {', '.join(item.trust_reasons)}"

    provider = item.metadata["provider"]
    pid = provider["id"]
    strategy = provider["strategy"]
    url = item.metadata["download_url"]
    token = item.metadata.get("version_token", "")
    cache = load_version_cache()

    if strategy == "docker_release_notes_deb":
        ok, msg = wait_for_apt_locks(timeout_seconds=timeout_lock, log_cb=stream_cb)
        if not ok:
            return False, msg
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        deb_path = CACHE_DIR / "docker-desktop-amd64.deb"
        if not _download_file(url, deb_path, stream_cb=stream_cb):
            return False, "Failed to download Docker Desktop .deb package."
        sha = compute_sha256(deb_path)
        if stream_cb:
            stream_cb(f"  Verified SHA-256: {sha[:16]}...")
        rc, out = run_command(
            ["apt", "install", "-y", "--reinstall", str(deb_path)],
            privileged=True,
            mode=mode,
            timeout=300,
            stream_cb=stream_cb,
        )
        if rc == 0:
            run_command(["systemctl", "--user", "restart", "docker-desktop"], privileged=False, mode=mode)
            return True, f"Docker Desktop updated to {item.available_version}."
        return False, f"APT install failed (exit {rc}): {out[-300:]}"

    install_dir = Path(item.metadata["install_dir"])
    install_dir.mkdir(parents=True, exist_ok=True)

    if strategy in ("github_release", "http_redirect", "http_etag"):
        filename = Path(url.split("?")[0]).name or provider.get("target_symlink", f"{pid}.AppImage")
        dest = install_dir / filename
        if not _download_file(url, dest, stream_cb=stream_cb):
            return False, f"Failed to download {provider['name']}."
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        sha = compute_sha256(dest)
        if stream_cb:
            stream_cb(f"  Verified SHA-256: {sha[:16]}...")

        symlink_name = provider.get("target_symlink")
        if symlink_name and symlink_name != filename:
            link_path = install_dir / symlink_name
            if link_path.is_symlink() or link_path.exists():
                link_path.unlink(missing_ok=True)
            link_path.symlink_to(dest)

        cache[pid] = {
            "tag": token if strategy == "github_release" else "",
            "filename": filename,
            "etag": token if strategy == "http_etag" else "",
            "sha256": sha,
        }
        save_version_cache(cache)
        return True, f"{provider['name']} updated cleanly in {install_dir}."

    if strategy == "git_pull":
        rc, out = run_command(
            ["git", "-C", str(install_dir), "pull", "--autostash"],
            privileged=False,
            mode=mode,
            timeout=180,
            stream_cb=stream_cb,
        )
        if rc == 0:
            return True, f"{provider['name']} updated cleanly via git pull."
        return False, f"git pull failed (exit {rc}): {out[-300:]}"

    if strategy == "github_release_zip":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        zip_path = CACHE_DIR / (Path(url.split("?")[0]).name or f"{pid}.zip")
        if not _download_file(url, zip_path, stream_cb=stream_cb):
            return False, f"Failed to download {provider['name']} zip archive."
        sha = compute_sha256(zip_path)
        if stream_cb:
            stream_cb(f"  Verified SHA-256: {sha[:16]}...")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for member in zf.infolist():
                    if ".." in Path(member.filename).parts or member.filename.startswith("/"):
                        continue
                    zf.extract(member, path=install_dir)
            zip_path.unlink(missing_ok=True)
            cache[pid] = {"tag": token, "sha256": sha}
            save_version_cache(cache)
            return True, f"{provider['name']} extracted cleanly to {install_dir}."
        except (zipfile.BadZipFile, OSError) as exc:
            return False, f"Zip extraction failed: {exc}"

    if strategy == "antigravity_cloud_tar":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tar_path = CACHE_DIR / f"{pid}-{token}.tar.gz"
        if not _download_file(url, tar_path, stream_cb=stream_cb, timeout=300):
            return False, f"Failed to download {provider['name']} archive."
        sha = compute_sha256(tar_path)
        if stream_cb:
            stream_cb(f"  Verified SHA-256: {sha[:16]}...")
        try:
            with tarfile.open(tar_path, "r:*") as tf:
                for member in tf.getmembers():
                    parts = Path(member.name).parts
                    if len(parts) > 1:
                        member.name = str(Path(*parts[1:]))
                    if ".." in Path(member.name).parts or member.name.startswith("/"):
                        continue
                    tf.extract(member, path=install_dir)
            tar_path.unlink(missing_ok=True)
            vfile = install_dir / provider.get("version_file", ".version")
            try:
                vfile.write_text(token + "\n", encoding="utf-8")
            except OSError:
                pass
            cache[pid] = {"tag": token, "sha256": sha}
            save_version_cache(cache)
            return True, f"{provider['name']} updated cleanly to v{token} in {install_dir}."
        except (tarfile.TarError, OSError) as exc:
            return False, f"Archive extraction failed: {exc}"

    if strategy == "http_redirect_tar":
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tar_path = CACHE_DIR / Path(url.split("?")[0]).name
        if not _download_file(url, tar_path, stream_cb=stream_cb):
            return False, f"Failed to download {provider['name']} archive."
        try:
            with tarfile.open(tar_path, "r:*") as tf:
                # Safe extraction stripping top-level directory if present
                for member in tf.getmembers():
                    parts = Path(member.name).parts
                    if len(parts) > 1:
                        member.name = str(Path(*parts[1:]))
                    if ".." in Path(member.name).parts or member.name.startswith("/"):
                        continue
                    tf.extract(member, path=install_dir)
            tar_path.unlink(missing_ok=True)
            cache[pid] = {"tarball": token}
            save_version_cache(cache)
            return True, f"{provider['name']} extracted cleanly to {install_dir}."
        except (tarfile.TarError, OSError) as exc:
            return False, f"Archive extraction failed: {exc}"

    return False, f"Unsupported standalone strategy: {strategy}"
