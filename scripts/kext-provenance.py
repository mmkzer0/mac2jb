#!/usr/bin/env python3
"""mac2jb kext provenance and comparison tool.

Subcommands:
  record: records toolchain, host, git, source tree, and kext artifact provenance.
  report: prints deterministic Markdown comparing a built kext against shipped.
"""

import argparse
import datetime
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Union

REPO_ROOT = Path(__file__).resolve().parent.parent


def to_repo_rel(path_input: Union[str, Path], repo_root: Path) -> str:
    """Resolve path relative to repository root for deterministic output."""
    path = Path(path_input).resolve()
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return path.name


def strip_abs_paths(text: str, repo_root: Path) -> str:
    """Strip repository root or user home directory from tool output strings."""
    repo_str = str(repo_root)
    text = text.replace(repo_str + "/", "").replace(repo_str, ".")
    try:
        home_str = str(Path.home())
        if home_str and home_str != "/":
            text = text.replace(home_str + "/", "~/")
            text = text.replace(home_str, "~")
    except Exception:
        pass
    return text


def ensure_tools(tools: list[str]) -> None:
    """Verify all required CLI tools exist on PATH."""
    for tool in tools:
        if shutil.which(tool) is None:
            sys.stderr.write(f"error: required tool '{tool}' not found\n")
            sys.exit(1)


def get_codesign_state(bundle_path: Path, repo_root: Optional[Path] = None) -> str:
    """Return 'unsigned' when codesign -dv fails, otherwise the first line of output."""
    res = subprocess.run(
        ["codesign", "-dv", str(bundle_path)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        return "unsigned"

    # codesign -dv typically outputs to stderr on macOS
    combined = (res.stderr or "") + "\n" + (res.stdout or "")
    for line in combined.splitlines():
        line = line.strip()
        if line:
            if repo_root:
                line = strip_abs_paths(line, repo_root)
            return line
    return "unsigned"


def get_executable_arch(exec_path: Path) -> str:
    """Determine executable architecture using lipo, file, or Mach-O header."""
    if shutil.which("lipo"):
        res = subprocess.run(
            ["lipo", "-archs", str(exec_path)],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()

    if shutil.which("file"):
        res = subprocess.run(
            ["file", "-b", str(exec_path)],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            out = res.stdout.strip()
            for arch in ("arm64e", "arm64", "x86_64", "armv7"):
                if arch in out:
                    return arch
            parts = out.split()
            if parts:
                return parts[-1]

    # Mach-O header inspection fallback
    try:
        header = exec_path.read_bytes()[:12]
        if len(header) >= 12:
            cputype = int.from_bytes(header[4:8], byteorder=sys.byteorder)
            cpusubtype = int.from_bytes(header[8:12], byteorder=sys.byteorder)
            # CPU_TYPE_ARM64 = 0x0100000C
            if cputype == 0x0100000C:
                return "arm64e" if (cpusubtype & 0xFF) == 2 else "arm64"
            if cputype == 0x01000007:
                return "x86_64"
    except Exception:
        pass

    return "unknown"


def find_bundle_components(bundle_path: Path) -> tuple[Path, Path, str, str]:
    """Validate bundle and return (info_plist_path, exec_path, bundle_id, exec_name)."""
    bundle_path = bundle_path.resolve()
    if not bundle_path.is_dir():
        sys.stderr.write(f"error: bundle directory not found: {bundle_path}\n")
        sys.exit(1)

    info_plist_path = bundle_path / "Contents" / "Info.plist"
    if not info_plist_path.is_file():
        info_plist_path = bundle_path / "Info.plist"
        if not info_plist_path.is_file():
            sys.stderr.write(f"error: Info.plist not found in bundle: {bundle_path}\n")
            sys.exit(1)

    try:
        plist_data = plistlib.loads(info_plist_path.read_bytes())
        bundle_id = plist_data.get("CFBundleIdentifier", "")
        exec_name = plist_data.get("CFBundleExecutable", "")
    except Exception as err:
        sys.stderr.write(f"error: failed to parse Info.plist in {bundle_path}: {err}\n")
        sys.exit(1)

    exec_path = None
    if exec_name:
        candidate = bundle_path / "Contents" / "MacOS" / exec_name
        if candidate.is_file():
            exec_path = candidate
        else:
            candidate = bundle_path / "MacOS" / exec_name
            if candidate.is_file():
                exec_path = candidate

    if not exec_path:
        macos_dir = bundle_path / "Contents" / "MacOS"
        if not macos_dir.is_dir():
            macos_dir = bundle_path / "MacOS"
        if macos_dir.is_dir():
            for entry in sorted(macos_dir.iterdir()):
                if entry.is_file():
                    exec_path = entry
                    if not exec_name:
                        exec_name = entry.name
                    break

    if not exec_path or not exec_path.is_file():
        sys.stderr.write(f"error: executable not found in bundle: {bundle_path}\n")
        sys.exit(1)

    return info_plist_path, exec_path, bundle_id, exec_name


def collect_git_info(repo_root: Path) -> dict:
    """Collect git commit, branch, and dirty status ignoring build/."""
    try:
        res_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        commit = res_commit.stdout.strip()

        res_branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        branch = res_branch.stdout.strip()

        res_status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        dirty = False
        for line in res_status.stdout.splitlines():
            if not line:
                continue
            entry = line[3:].strip()
            if entry.startswith('"') and entry.endswith('"'):
                entry = entry[1:-1]
            if " -> " in entry:
                entry = entry.split(" -> ", 1)[1]
            if entry == "build" or entry.startswith("build/"):
                continue
            dirty = True
            break

        return {
            "branch": branch,
            "commit": commit,
            "dirty": dirty,
        }
    except Exception as err:
        sys.stderr.write(f"error: failed to read git repository state: {err}\n")
        sys.exit(1)


def collect_host_info() -> dict:
    """Collect host product, version, and build using sw_vers."""
    try:
        res = subprocess.run(["sw_vers"], capture_output=True, text=True, check=True)
        product = "macOS"
        version = ""
        build = ""
        for line in res.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k_norm = k.strip().lower()
                v_norm = v.strip()
                if "productname" in k_norm:
                    product = v_norm
                elif "productversion" in k_norm:
                    version = v_norm
                elif "buildversion" in k_norm:
                    build = v_norm
        return {
            "build": build,
            "product": product,
            "version": version,
        }
    except Exception as err:
        sys.stderr.write(f"error: failed to execute sw_vers: {err}\n")
        sys.exit(1)


def collect_toolchain_info() -> dict:
    """Collect toolchain version data."""
    try:
        res_xcode = subprocess.run(
            ["xcodebuild", "-version"],
            capture_output=True,
            text=True,
            check=True,
        )
        xcode_ver = ""
        xcode_build = ""
        for line in res_xcode.stdout.splitlines():
            line = line.strip()
            if line.startswith("Xcode"):
                xcode_ver = line.removeprefix("Xcode").strip()
            elif line.startswith("Build version"):
                xcode_build = line.removeprefix("Build version").strip()
            elif not xcode_ver:
                xcode_ver = line
            elif not xcode_build:
                xcode_build = line

        res_sdk_ver = subprocess.run(
            ["xcrun", "--sdk", "macosx", "--show-sdk-version"],
            capture_output=True,
            text=True,
            check=True,
        )
        sdk_version = res_sdk_ver.stdout.strip()

        res_sdk_path = subprocess.run(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"],
            capture_output=True,
            text=True,
            check=True,
        )
        sdk_path = res_sdk_path.stdout.strip()
        sdk_name = Path(sdk_path).name

        res_clang = subprocess.run(
            ["xcrun", "clang", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        clang_lines = [l.strip() for l in res_clang.stdout.splitlines() if l.strip()]
        clang_version = clang_lines[0] if clang_lines else ""

        return {
            "clang": clang_version,
            "sdk": {
                "name": sdk_name,
                "path": sdk_path,
                "version": sdk_version,
            },
            "xcode": xcode_ver,
            "xcode_build": xcode_build,
        }
    except Exception as err:
        sys.stderr.write(f"error: failed to collect toolchain info: {err}\n")
        sys.exit(1)


def collect_source_info(source_dir: Path, repo_root: Path) -> dict:
    """Collect source files and compute tree_sha256."""
    source_dir = source_dir.resolve()
    if not source_dir.is_dir():
        sys.stderr.write(f"error: source directory not found: {source_dir}\n")
        sys.exit(1)

    source_rel_path = to_repo_rel(source_dir, repo_root)

    files = []
    for root, _, filenames in os.walk(source_dir):
        for name in filenames:
            f = Path(root) / name
            if not f.is_file():
                continue
            rel_path = str(f.relative_to(source_dir).as_posix())
            content = f.read_bytes()
            files.append({
                "path": rel_path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            })

    files.sort(key=lambda x: x["path"])

    # tree_sha256 = sha256 over the UTF-8 text of sorted lines '<relative path>\0<sha256>\n'
    tree_text = "".join(f"{f['path']}\0{f['sha256']}\n" for f in files)
    tree_sha256 = hashlib.sha256(tree_text.encode("utf-8")).hexdigest()

    return {
        "files": files,
        "path": source_rel_path,
        "tree_sha256": tree_sha256,
    }


def collect_artifact_info(bundle_path: Path, repo_root: Path) -> dict:
    """Collect artifact bundle metadata, files, executable, and signing state."""
    bundle_path = bundle_path.resolve()
    info_plist_path, exec_path, bundle_id, _ = find_bundle_components(bundle_path)

    artifact_rel_path = to_repo_rel(bundle_path, repo_root)
    info_plist_bytes = info_plist_path.read_bytes()
    info_plist_sha256 = hashlib.sha256(info_plist_bytes).hexdigest()

    exec_bytes = exec_path.read_bytes()
    exec_sha256 = hashlib.sha256(exec_bytes).hexdigest()
    exec_size = len(exec_bytes)
    exec_rel_path = str(exec_path.relative_to(bundle_path).as_posix())
    exec_arch = get_executable_arch(exec_path)

    files = []
    for root, _, filenames in os.walk(bundle_path):
        for name in filenames:
            f = Path(root) / name
            if not f.is_file():
                continue
            rel_file = str(f.relative_to(bundle_path).as_posix())
            content = f.read_bytes()
            files.append({
                "path": rel_file,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            })
    files.sort(key=lambda x: x["path"])

    codesign_state = get_codesign_state(bundle_path, repo_root)

    return {
        "bundle_id": bundle_id,
        "codesign": codesign_state,
        "executable": {
            "arch": exec_arch,
            "path": exec_rel_path,
            "sha256": exec_sha256,
            "size": exec_size,
        },
        "files": files,
        "info_plist_sha256": info_plist_sha256,
        "path": artifact_rel_path,
    }


def cmd_record(args: argparse.Namespace) -> None:
    """Execute record subcommand."""
    ensure_tools(["git", "sw_vers", "xcodebuild", "xcrun", "codesign"])

    artifact_path = Path(args.artifact)
    source_path = Path(args.source)
    output_path = Path(args.output).resolve()

    git_info = collect_git_info(REPO_ROOT)
    host_info = collect_host_info()
    toolchain_info = collect_toolchain_info()
    source_info = collect_source_info(source_path, REPO_ROOT)
    artifact_info = collect_artifact_info(artifact_path, REPO_ROOT)

    created_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    record_data = {
        "artifact": artifact_info,
        "created": created_iso,
        "format": "mac2jb-kext-provenance-v1",
        "git": git_info,
        "host": host_info,
        "source": source_info,
        "toolchain": toolchain_info,
    }

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(record_data, f, indent=2, sort_keys=True)
            f.write("\n")
    except Exception as err:
        sys.stderr.write(f"error: failed to write output file: {err}\n")
        sys.exit(1)


def parse_otool_sections(output: str) -> dict[tuple[str, str], int]:
    """Parse 'otool -l' output for segname/sectname/size."""
    sections: dict[tuple[str, str], int] = {}
    current_sectname: Optional[str] = None
    current_segname: Optional[str] = None
    current_size: Optional[int] = None
    in_section = False

    def save_current():
        nonlocal current_sectname, current_segname, current_size
        if current_sectname and current_segname and current_size is not None:
            sections[(current_segname, current_sectname)] = current_size
        current_sectname = None
        current_segname = None
        current_size = None

    for line in output.splitlines():
        line = line.strip()
        if line == "Section":
            if in_section:
                save_current()
            in_section = True
            continue

        if in_section:
            if line.startswith("Load command") or line.startswith("cmd "):
                save_current()
                in_section = False
                continue

            parts = line.split()
            if len(parts) >= 2:
                key = parts[0]
                val = parts[1]
                if key == "sectname":
                    current_sectname = val
                elif key == "segname":
                    current_segname = val
                elif key == "size":
                    try:
                        current_size = int(val, 0)
                    except ValueError:
                        pass

    if in_section:
        save_current()

    return sections


def parse_undefined_symbols(output: str) -> set[str]:
    """Parse 'nm -u' output to extract undefined symbols."""
    symbols = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        sym = parts[-1]
        if sym.endswith(":") or sym.startswith("Archive:"):
            continue
        symbols.add(sym)
    return symbols


def parse_defined_symbols(output: str) -> set[str]:
    """Parse 'nm -m' output to extract defined symbols only."""
    symbols = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.endswith(":") or line.startswith("Archive:"):
            continue
        if "undefined" in line.lower():
            continue
        parts = line.split()
        if not parts:
            continue
        sym = parts[-1]
        if sym.endswith(":"):
            continue
        symbols.add(sym)
    return symbols

def collect_strings(output: str) -> list[str]:
    """Return sorted unique non-empty lines from 'strings -a'."""
    unique_strings = set()
    for line in output.splitlines():
        line = line.strip()
        if line:
            unique_strings.add(line)
    return sorted(unique_strings)


def cmd_report(args: argparse.Namespace) -> None:
    """Execute report subcommand."""
    ensure_tools(["codesign", "file", "nm", "otool", "strings"])

    artifact_bundle = Path(args.artifact).resolve()
    shipped_bundle = Path(args.shipped).resolve()
    source_dir = Path(args.source).resolve()

    if not source_dir.is_dir():
        sys.stderr.write(f"error: source directory not found: {source_dir}\n")
        sys.exit(1)

    built_plist, built_exec, _, _ = find_bundle_components(artifact_bundle)
    shipped_plist, shipped_exec, _, _ = find_bundle_components(shipped_bundle)

    # 1. Artifacts
    built_total_size = sum(f.stat().st_size for f in artifact_bundle.rglob("*") if f.is_file())
    shipped_total_size = sum(f.stat().st_size for f in shipped_bundle.rglob("*") if f.is_file())

    built_exec_bytes = built_exec.read_bytes()
    shipped_exec_bytes = shipped_exec.read_bytes()
    built_exec_size = len(built_exec_bytes)
    shipped_exec_size = len(shipped_exec_bytes)
    built_exec_sha = hashlib.sha256(built_exec_bytes).hexdigest()
    shipped_exec_sha = hashlib.sha256(shipped_exec_bytes).hexdigest()

    built_plist_bytes = built_plist.read_bytes()
    shipped_plist_bytes = shipped_plist.read_bytes()
    built_plist_size = len(built_plist_bytes)
    shipped_plist_size = len(shipped_plist_bytes)
    built_plist_sha = hashlib.sha256(built_plist_bytes).hexdigest()
    shipped_plist_sha = hashlib.sha256(shipped_plist_bytes).hexdigest()

    built_bundle_rel = to_repo_rel(artifact_bundle, REPO_ROOT)
    shipped_bundle_rel = to_repo_rel(shipped_bundle, REPO_ROOT)
    built_exec_rel = str(built_exec.relative_to(artifact_bundle).as_posix())
    shipped_exec_rel = str(shipped_exec.relative_to(shipped_bundle).as_posix())
    built_plist_rel = str(built_plist.relative_to(artifact_bundle).as_posix())
    shipped_plist_rel = str(shipped_plist.relative_to(shipped_bundle).as_posix())

    # 2. Signing
    built_codesign = get_codesign_state(artifact_bundle, REPO_ROOT)
    shipped_codesign = get_codesign_state(shipped_bundle, REPO_ROOT)

    # 3. Mach-O
    built_arch = get_executable_arch(built_exec)
    shipped_arch = get_executable_arch(shipped_exec)

    built_file_res = subprocess.run(
        ["file", to_repo_rel(built_exec, REPO_ROOT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    shipped_file_res = subprocess.run(
        ["file", to_repo_rel(shipped_exec, REPO_ROOT)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    built_file_out = strip_abs_paths(built_file_res.stdout.strip(), REPO_ROOT)
    shipped_file_out = strip_abs_paths(shipped_file_res.stdout.strip(), REPO_ROOT)

    # 4. Undefined symbols
    built_nm_res = subprocess.run(
        ["nm", "-u", str(built_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    shipped_nm_res = subprocess.run(
        ["nm", "-u", str(shipped_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    built_syms = parse_undefined_symbols(built_nm_res.stdout)
    shipped_syms = parse_undefined_symbols(shipped_nm_res.stdout)
    syms_added = sorted(built_syms - shipped_syms)
    syms_removed = sorted(shipped_syms - built_syms)

    # 5. Sections
    built_otool_res = subprocess.run(
        ["otool", "-l", str(built_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    shipped_otool_res = subprocess.run(
        ["otool", "-l", str(shipped_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    built_sects = parse_otool_sections(built_otool_res.stdout)
    shipped_sects = parse_otool_sections(shipped_otool_res.stdout)
    sects_added = sorted(set(built_sects.keys()) - set(shipped_sects.keys()))
    sects_removed = sorted(set(shipped_sects.keys()) - set(built_sects.keys()))
    sects_common = sorted(set(built_sects.keys()) & set(shipped_sects.keys()))
    sects_changed = [k for k in sects_common if built_sects[k] != shipped_sects[k]]

    # 6. Defined symbols
    built_nm_m_res = subprocess.run(
        ["nm", "-m", str(built_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    shipped_nm_m_res = subprocess.run(
        ["nm", "-m", str(shipped_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    built_defined = parse_defined_symbols(built_nm_m_res.stdout)
    shipped_defined = parse_defined_symbols(shipped_nm_m_res.stdout)
    defined_added = sorted(built_defined - shipped_defined)
    defined_removed = sorted(shipped_defined - built_defined)

    # 7. Strings
    built_str_res = subprocess.run(
        ["strings", "-a", "-n", "8", str(built_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    shipped_str_res = subprocess.run(
        ["strings", "-a", "-n", "8", str(shipped_exec)],
        capture_output=True,
        text=True,
        check=True,
    )
    built_str = collect_strings(built_str_res.stdout)
    shipped_str = collect_strings(shipped_str_res.stdout)
    built_str_set = set(built_str)
    shipped_str_set = set(shipped_str)
    str_added = sorted(built_str_set - shipped_str_set)
    str_removed = sorted(shipped_str_set - built_str_set)

    # Assemble report
    out: list[str] = []

    out.append("## Artifacts\n")
    out.append(f"- Built: `{built_bundle_rel}`")
    out.append(f"  - Total size: {built_total_size} bytes")
    out.append(f"  - Executable: `{built_exec_rel}` ({built_exec_size} bytes)")
    out.append(f"    - SHA256: `{built_exec_sha}`")
    out.append(f"  - Info.plist: `{built_plist_rel}` ({built_plist_size} bytes)")
    out.append(f"    - SHA256: `{built_plist_sha}`")
    out.append(f"- Shipped: `{shipped_bundle_rel}`")
    out.append(f"  - Total size: {shipped_total_size} bytes")
    out.append(f"  - Executable: `{shipped_exec_rel}` ({shipped_exec_size} bytes)")
    out.append(f"    - SHA256: `{shipped_exec_sha}`")
    out.append(f"  - Info.plist: `{shipped_plist_rel}` ({shipped_plist_size} bytes)")
    out.append(f"    - SHA256: `{shipped_plist_sha}`")

    out.append("\n## Signing\n")
    out.append(f"- Built: `{built_codesign}`")
    out.append(f"- Shipped: `{shipped_codesign}`")

    out.append("\n## Mach-O\n")
    out.append(f"- Built: {built_file_out} (arch: `{built_arch}`)")
    out.append(f"- Shipped: {shipped_file_out} (arch: `{shipped_arch}`)")

    out.append("\n## Undefined symbols\n")
    out.append(
        f"- Counts: built has {len(built_syms)} undefined symbols, shipped has {len(shipped_syms)} undefined symbols."
    )
    out.append(f"- Added in built ({len(syms_added)}):")
    if syms_added:
        for s in syms_added[:20]:
            out.append(f"  - `{s}`")
        if len(syms_added) > 20:
            out.append(f"  - ... ({len(syms_added) - 20} more)")
    else:
        out.append("  - none")

    out.append(f"- Removed in built ({len(syms_removed)}):")
    if syms_removed:
        for s in syms_removed[:20]:
            out.append(f"  - `{s}`")
        if len(syms_removed) > 20:
            out.append(f"  - ... ({len(syms_removed) - 20} more)")
    else:
        out.append("  - none")

    out.append("\n## Sections\n")
    out.append(f"- Counts: built has {len(built_sects)} sections, shipped has {len(shipped_sects)} sections.")
    out.append(f"- Added sections ({len(sects_added)}):")
    if sects_added:
        for seg, sect in sects_added:
            out.append(f"  - `{seg},{sect}` (size: {built_sects[(seg, sect)]} bytes)")
    else:
        out.append("  - none")

    out.append(f"- Removed sections ({len(sects_removed)}):")
    if sects_removed:
        for seg, sect in sects_removed:
            out.append(f"  - `{seg},{sect}` (size: {shipped_sects[(seg, sect)]} bytes)")
    else:
        out.append("  - none")

    out.append(f"- Changed sections ({len(sects_changed)}):")
    if sects_changed:
        for seg, sect in sects_changed:
            bsize = built_sects[(seg, sect)]
            ssize = shipped_sects[(seg, sect)]
            diff = bsize - ssize
            diff_str = f"+{diff}" if diff > 0 else f"{diff}"
            out.append(
                f"  - `{seg},{sect}`: built {bsize} bytes, shipped {ssize} bytes ({diff_str} bytes)"
            )
    else:
        out.append("  - none")

    out.append("\n## Defined symbols\n")
    out.append(
        f"- Counts: built has {len(built_defined)} defined symbols, shipped has {len(shipped_defined)} defined symbols."
    )
    out.append(f"- Added in built ({len(defined_added)}):")
    if defined_added:
        for s in defined_added[:20]:
            out.append(f"  - `{s}`")
        if len(defined_added) > 20:
            out.append(f"  - ... ({len(defined_added) - 20} more)")
    else:
        out.append("  - none")

    out.append(f"- Removed in built ({len(defined_removed)}):")
    if defined_removed:
        for s in defined_removed[:20]:
            out.append(f"  - `{s}`")
        if len(defined_removed) > 20:
            out.append(f"  - ... ({len(defined_removed) - 20} more)")
    else:
        out.append("  - none")

    out.append("\n## Strings (-n 8)\n")
    out.append(
        f"- Unique strings (-a -n 8, minimum length 8): built has {len(built_str_set)}, shipped has {len(shipped_str_set)}."
    )
    out.append(f"- Added in built ({len(str_added)}):")
    if str_added:
        for s in str_added[:20]:
            out.append(f"  - `{s}`")
        if len(str_added) > 20:
            out.append(f"  - ... ({len(str_added) - 20} more)")
    else:
        out.append("  - none")

    out.append(f"- Removed in built ({len(str_removed)}):")
    if str_removed:
        for s in str_removed[:20]:
            out.append(f"  - `{s}`")
        if len(str_removed) > 20:
            out.append(f"  - ... ({len(str_removed) - 20} more)")
    else:
        out.append("  - none")

    out.append("\nThese artifacts were built with different Xcode/SDK versions; byte-identical reproduction is not claimed.")

    report_markdown = "\n".join(out)
    report_markdown = strip_abs_paths(report_markdown, REPO_ROOT)
    print(report_markdown)


def main() -> None:
    """Parse arguments and dispatch to subcommand."""
    parser = argparse.ArgumentParser(
        description="mac2jb kext provenance and comparison tool"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    record_parser = subparsers.add_parser(
        "record",
        help="Record provenance metadata for a built kext",
    )
    record_parser.add_argument(
        "--artifact",
        required=True,
        help="Path to built kext bundle",
    )
    record_parser.add_argument(
        "--source",
        required=True,
        help="Path to kext source directory",
    )
    record_parser.add_argument(
        "--output",
        required=True,
        help="Path to output JSON file",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Report comparison between built and shipped kext",
    )
    report_parser.add_argument(
        "--artifact",
        required=True,
        help="Path to built kext bundle",
    )
    report_parser.add_argument(
        "--shipped",
        required=True,
        help="Path to shipped kext bundle",
    )
    report_parser.add_argument(
        "--source",
        required=True,
        help="Path to kext source directory",
    )

    args = parser.parse_args()
    if args.subcommand == "record":
        cmd_record(args)
    elif args.subcommand == "report":
        cmd_report(args)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
