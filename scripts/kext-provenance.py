#!/usr/bin/env python3
"""mac2jb kext provenance and comparison tool.

Subcommands:
  record: written by scripts/build-kext.sh right after a build; binds the
    artifact to the digest of the compiled source copy, the toolchain actually
    used, the build script and the matching KDK.
  verify: fails when the artifact, the git-tracked source digest or the build
    script no longer match the record, or when the build inputs are dirty.
  verify-bundle: fails unless the bundled driver (drivers/usbgadget.kext) is
    byte-identical to the built artifact and drivers/SHA256SUMS and
    drivers/PROVENANCE describe it, the record and each other exactly.
  bundle: writes a verified artifact, SHA256SUMS and PROVENANCE into a
    destination directory (the bundled driver); refuses unless verify passes.
  kdk-check: validates the contents of the KDK matching a host version/build.
  export-checkout: copies the build inputs of the working tree into a fresh git
    repository at another path (path-independence checks).
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


class ProvenanceError(Exception):
    """A provenance input is missing, inconsistent, or unreadable."""


SOURCE_REL = "vendor/macos_usb_gadget_poc/usbgadget"
BUILD_SCRIPT_REL = "scripts/build-kext.sh"
# Paths whose working-tree state decides whether a build is "dirty": the kext
# source and the script that fixes every compiler and linker flag.
BUILD_INPUTS = [SOURCE_REL, BUILD_SCRIPT_REL]
EXPORT_INPUTS = BUILD_INPUTS + ["scripts/kext-provenance.py", ".gitignore"]
RECORD_FORMAT = "mac2jb-kext-provenance-v2"
DEFAULT_RECORD = "build/kext/provenance.json"
DEFAULT_ARTIFACT = "build/kext/usbgadget.kext"
DEFAULT_BUNDLE_DIR = "drivers"
BUNDLE_NAME = "usbgadget.kext"
BUNDLE_FORMAT = "mac2jb-bundled-kext-v1"
BUNDLE_KEYS = (
    "format",
    "bundle_identifier",
    "executable_sha256",
    "info_plist_sha256",
    "lc_uuid",
    "source_tree_sha256",
    "source_commit",
    "xcode_build",
    "sdk_build",
)
BUNDLE_DIRS = ("Contents", "Contents/MacOS")
BUNDLE_FILES = ("Contents/Info.plist", "Contents/MacOS/usbgadget")
DEFAULT_KDK_ROOT = "/Library/Developer/KDKs"
BUILD_SETTING_KEYS = (
    "DEVELOPER_DIR",
    "MACOSX_DEPLOYMENT_TARGET",
    "PLATFORM_PRODUCT_BUILD_VERSION",
    "SDKROOT",
    "SDK_NAME",
    "SDK_PRODUCT_BUILD_VERSION",
    "SDK_VERSION",
    "SDK_VERSION_ACTUAL",
    "XCODE_PRODUCT_BUILD_VERSION",
    "XCODE_VERSION_ACTUAL",
)


def git_output(repo_root: Path, args: list) -> bytes:
    """Run git in repo_root and return stdout; raise ProvenanceError on failure."""
    res = subprocess.run(["git"] + args, cwd=str(repo_root), capture_output=True)
    if res.returncode != 0:
        detail = res.stderr.decode("utf-8", "replace").strip()
        raise ProvenanceError(f"git {' '.join(args)} failed: {detail}")
    return res.stdout


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_git_info(repo_root: Path) -> dict:
    """Collect commit, branch, and dirty state of the build inputs only.

    Dirty means: a tracked or untracked-but-not-ignored change under the kext
    source directory or the build script. Ignored files never count.
    """
    commit = git_output(repo_root, ["rev-parse", "HEAD"]).decode().strip()
    branch = git_output(repo_root, ["rev-parse", "--abbrev-ref", "HEAD"]).decode().strip()
    status = git_output(
        repo_root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--"] + BUILD_INPUTS,
    )
    entries = [e for e in status.split(b"\0") if e]
    dirty_paths = [
        e[3:].decode("utf-8", "replace") for e in entries if len(e) > 3 and e[2:3] == b" "
    ]
    return {
        "branch": branch,
        "commit": commit,
        "dirty": bool(entries),
        "dirty_paths": dirty_paths[:20],
    }


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


def parse_build_settings(path: Path) -> dict:
    """Extract the pinned keys from 'xcodebuild -showBuildSettings' output."""
    settings = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.strip().partition(" = ")
        if sep and key in BUILD_SETTING_KEYS:
            settings[key] = strip_abs_paths(value.strip(), REPO_ROOT)
    missing = [k for k in BUILD_SETTING_KEYS if k not in settings]
    if missing:
        raise ProvenanceError(f"build settings are missing {', '.join(missing)}: {path}")
    return settings


def collect_toolchain_info(build_settings_path: Optional[Path]) -> dict:
    """Collect the toolchain the build actually used.

    The caller runs this under the same sanitized environment as xcodebuild,
    so xcodebuild/xcrun resolve the same Xcode. When a showBuildSettings dump is
    supplied its pinned keys (SDK, Xcode build) are recorded verbatim.
    """
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

        def xcrun(flag: str) -> str:
            res = subprocess.run(
                ["xcrun", "--sdk", "macosx", flag],
                capture_output=True,
                text=True,
                check=True,
            )
            return res.stdout.strip()

        sdk_path = xcrun("--show-sdk-path")

        res_clang = subprocess.run(
            ["xcrun", "clang", "--version"],
            capture_output=True,
            text=True,
            check=True,
        )
        clang_lines = [l.strip() for l in res_clang.stdout.splitlines() if l.strip()]

        info = {
            "clang": clang_lines[0] if clang_lines else "",
            "developer_dir_override": os.environ.get("DEVELOPER_DIR"),
            "sdk": {
                "build": xcrun("--show-sdk-build-version"),
                "name": Path(sdk_path).name,
                "path": strip_abs_paths(sdk_path, REPO_ROOT),
                "version": xcrun("--show-sdk-version"),
            },
            "xcode": xcode_ver,
            "xcode_build": xcode_build,
        }
        if build_settings_path is not None:
            info["build_settings"] = parse_build_settings(build_settings_path)
        return info
    except ProvenanceError:
        raise
    except Exception as err:
        raise ProvenanceError(f"failed to collect toolchain info: {err}")


def macho_header(path: Path) -> tuple:
    """Return (magic, cputype) of a thin 64-bit Mach-O, or the raw magic for others."""
    with open(path, "rb") as handle:
        head = handle.read(8)
    if len(head) < 8:
        return (b"", 0)
    return (head[:4], int.from_bytes(head[4:8], "little"))


def inspect_kdk(kdk_path: Path, version: str, build: str) -> tuple:
    """Validate KDK contents against a host version/build; return (info, problems)."""
    problems = []
    info = {"name": kdk_path.name, "path": str(kdk_path)}
    if not kdk_path.is_dir():
        return info, [f"KDK directory is missing: {kdk_path}"]

    plist_path = kdk_path / "System" / "Library" / "CoreServices" / "SystemVersion.plist"
    if not plist_path.is_file():
        problems.append("KDK has no System/Library/CoreServices/SystemVersion.plist")
    else:
        try:
            data = plistlib.loads(plist_path.read_bytes())
        except Exception as err:
            data = {}
            problems.append(f"KDK SystemVersion.plist is unreadable: {err}")
        info["product_version"] = data.get("ProductVersion")
        info["product_build"] = data.get("ProductBuildVersion")
        info["system_version_sha256"] = sha256_file(plist_path)
        if data.get("ProductVersion") != version:
            problems.append(
                f"KDK ProductVersion is {data.get('ProductVersion')!r}, host is {version!r}"
            )
        if data.get("ProductBuildVersion") != build:
            problems.append(
                f"KDK ProductBuildVersion is {data.get('ProductBuildVersion')!r}, host is {build!r}"
            )

    kernels = kdk_path / "System" / "Library" / "Kernels"
    kernel = kernels / "kernel"
    if not kernel.is_file() or kernel.stat().st_size == 0:
        problems.append("KDK has no System/Library/Kernels/kernel")
    elif macho_header(kernel)[0] not in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        problems.append("KDK System/Library/Kernels/kernel is not a Mach-O file")

    arm_kernels = []
    if kernels.is_dir():
        for candidate in sorted(kernels.glob("kernel.release.*")):
            if candidate.is_file():
                magic, cputype = macho_header(candidate)
                if magic == b"\xcf\xfa\xed\xfe" and cputype == 0x0100000C:
                    arm_kernels.append(candidate.name)
    info["arm64_release_kernels"] = arm_kernels
    if not arm_kernels:
        problems.append("KDK has no arm64 System/Library/Kernels/kernel.release.* Mach-O kernel")

    if not (kdk_path / "System" / "Library" / "Extensions").is_dir():
        problems.append("KDK has no System/Library/Extensions")
    return info, problems


def collect_kdk_info(host: dict, kdk_root: Path) -> dict:
    """Record the KDK matching the host build; absence is recorded, not fatal."""
    name = f"KDK_{host['version']}_{host['build']}.kdk"
    info, problems = inspect_kdk(kdk_root / name, host["version"], host["build"])
    info["problems"] = problems
    info["valid"] = not problems
    return info


def file_digests(paths: list, base: Path) -> list:
    files = []
    for rel in sorted(paths):
        content = (base / rel).read_bytes()
        files.append({
            "path": rel,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        })
    return files


def tree_digest(files: list) -> str:
    # sha256 over the UTF-8 text of sorted lines '<relative path>\0<sha256>\n'
    tree_text = "".join(f"{f['path']}\0{f['sha256']}\n" for f in files)
    return hashlib.sha256(tree_text.encode("utf-8")).hexdigest()


def collect_source_info(source_dir: Path, repo_root: Path) -> dict:
    """Digest the git-tracked files of source_dir as they are in the working tree.

    Ignored and untracked files (.DS_Store, xcuserdata, scratch files) are not
    part of the digest; untracked-but-not-ignored files make the tree dirty
    instead (see collect_git_info).
    """
    source_dir = source_dir.resolve()
    try:
        source_rel = source_dir.relative_to(repo_root).as_posix()
    except ValueError:
        raise ProvenanceError(f"source directory is outside the repository: {source_dir}")
    listing = git_output(repo_root, ["ls-files", "-z", "--", source_rel])
    names = [n.decode("utf-8") for n in listing.split(b"\0") if n]
    if not names:
        raise ProvenanceError(f"no tracked files under {source_rel}")
    prefix = source_rel + "/"
    rels = []
    for name in names:
        if not (repo_root / name).is_file():
            raise ProvenanceError(f"tracked source file is missing or not a file: {name}")
        rels.append(name[len(prefix):])
    files = file_digests(rels, source_dir)
    return {
        "files": files,
        "path": source_rel,
        "tree_sha256": tree_digest(files),
    }


def collect_dir_info(directory: Path) -> dict:
    """Digest every regular file under directory with the same scheme."""
    directory = directory.resolve()
    if not directory.is_dir():
        raise ProvenanceError(f"directory not found: {directory}")
    rels = []
    for root, _, filenames in os.walk(directory):
        for name in filenames:
            f = Path(root) / name
            if f.is_file():
                rels.append(f.relative_to(directory).as_posix())
    files = file_digests(rels, directory)
    return {"files": files, "tree_sha256": tree_digest(files)}


def collect_artifact_info(bundle_path: Path, repo_root: Path) -> dict:
    """Collect artifact bundle metadata, files, executable, and signing state."""
    bundle_path = bundle_path.resolve()
    info_plist_path, exec_path, bundle_id, _ = find_bundle_components(bundle_path)

    artifact_rel_path = to_repo_rel(bundle_path, repo_root)
    info_plist_sha256 = sha256_file(info_plist_path)

    exec_bytes = exec_path.read_bytes()
    exec_sha256 = hashlib.sha256(exec_bytes).hexdigest()
    exec_size = len(exec_bytes)
    exec_rel_path = str(exec_path.relative_to(bundle_path).as_posix())
    exec_arch = get_executable_arch(exec_path)

    rels = []
    for root, _, filenames in os.walk(bundle_path):
        for name in filenames:
            f = Path(root) / name
            if f.is_file():
                rels.append(f.relative_to(bundle_path).as_posix())
    files = file_digests(rels, bundle_path)

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
    """Record provenance for a build that was just produced from build/kext/src.

    The record binds the artifact to the digest of the compiled source copy. It
    refuses to be written when the working-tree source no longer equals that
    copy, so an edit made after the build cannot yield a record.
    """
    ensure_tools(["git", "sw_vers", "xcodebuild", "xcrun", "codesign"])

    output_path = Path(args.output).resolve()
    script_path = Path(args.build_script).resolve()

    git_info = collect_git_info(REPO_ROOT)
    host_info = collect_host_info()
    toolchain_info = collect_toolchain_info(Path(args.build_settings))
    kdk_info = collect_kdk_info(host_info, Path(args.kdk_root))
    source_info = collect_source_info(Path(args.source), REPO_ROOT)
    built_info = collect_dir_info(Path(args.built_source))
    if built_info["tree_sha256"] != source_info["tree_sha256"]:
        raise ProvenanceError(
            "the source tree no longer matches the copy that was compiled "
            f"(working tree {source_info['tree_sha256']}, compiled {built_info['tree_sha256']})"
        )
    artifact_info = collect_artifact_info(Path(args.artifact), REPO_ROOT)

    created_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    record_data = {
        "artifact": artifact_info,
        "build": {
            "arguments": list(args.build_arg),
            "script": to_repo_rel(script_path, REPO_ROOT),
            "script_sha256": sha256_file(script_path),
        },
        "created": created_iso,
        "format": RECORD_FORMAT,
        "git": git_info,
        "host": host_info,
        "kdk": kdk_info,
        "source": source_info,
        "toolchain": toolchain_info,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(record_data, f, indent=2, sort_keys=True)
        f.write("\n")


RECORD_SECTIONS = ("artifact", "build", "git", "host", "kdk", "source", "toolchain")
RECORD_FIELDS = (
    ("artifact", "executable", "sha256"),
    ("artifact", "files"),
    ("build", "script_sha256"),
    ("git", "commit"),
    ("git", "dirty"),
    ("source", "tree_sha256"),
    ("toolchain", "xcode_build"),
    ("toolchain", "sdk", "build"),
)


def read_record(path: Path) -> tuple[Optional[dict], list[str]]:
    """Read a v2 record; return (record, problem details).

    The record is only returned when every section and field that the verify
    and bundle checks rely on is present, so a malformed record cannot be
    mistaken for a passing check.
    """
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        return None, [f"cannot read {path}: {err}"]
    if not isinstance(record, dict):
        return None, [f"{path} does not contain a JSON object"]
    if record.get("format") != RECORD_FORMAT:
        return None, [f"unexpected record format {record.get('format')!r}"]
    problems = []
    for section in RECORD_SECTIONS:
        if not isinstance(record.get(section), dict):
            problems.append(f"record has no {section!r} object")
    for field_path in RECORD_FIELDS:
        value = record
        for key in field_path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                problems.append("record has no " + ".".join(field_path))
                break
    return (None if problems else record), problems


def artifact_differences(record: dict, current_artifact: dict) -> list[tuple[str, str]]:
    """Return (problem code, detail) pairs for artifact deviations from the record."""
    recorded = record["artifact"]
    differences = []
    if current_artifact["executable"]["sha256"] != recorded["executable"]["sha256"]:
        differences.append((
            "artifact-hash",
            f"executable is {current_artifact['executable']['sha256']}, record has "
            f"{recorded['executable']['sha256']}",
        ))
    now = {f["path"]: f["sha256"] for f in current_artifact["files"]}
    then = {f["path"]: f["sha256"] for f in recorded["files"]}
    if now != then:
        changed = sorted(p for p in set(now) | set(then) if now.get(p) != then.get(p))
        differences.append((
            "artifact-files",
            "bundle files differ from the record: " + ", ".join(changed),
        ))
    return differences


def macho_uuid(path: Path) -> str:
    """Return the LC_UUID of a thin 64-bit Mach-O as uppercase 8-4-4-4-12.

    A FAT container or a file without LC_UUID is rejected: the bundled driver
    is a single arm64e executable and its load-command UUID identifies the
    loaded kext in kmutil output.
    """
    try:
        data = Path(path).read_bytes()
    except OSError as err:
        raise ProvenanceError(f"cannot read {path}: {err}")
    if len(data) < 32:
        raise ProvenanceError(f"{path} is too short to be a 64-bit Mach-O")
    magic = int.from_bytes(data[0:4], "little")
    if magic in (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA):
        raise ProvenanceError(f"{path} is a FAT Mach-O; a thin 64-bit executable is required")
    if magic != 0xFEEDFACF:
        raise ProvenanceError(f"{path} is not a thin 64-bit Mach-O")
    ncmds = int.from_bytes(data[16:20], "little")
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > len(data):
            raise ProvenanceError(f"{path} has a truncated load command")
        cmd = int.from_bytes(data[offset:offset + 4], "little")
        cmdsize = int.from_bytes(data[offset + 4:offset + 8], "little")
        if cmdsize < 8 or offset + cmdsize > len(data):
            raise ProvenanceError(f"{path} has an invalid load command size")
        if cmd == 0x1B:
            if cmdsize < 24:
                raise ProvenanceError(f"{path} has a truncated LC_UUID")
            raw = data[offset + 8:offset + 24]
            return "-".join((
                raw[0:4].hex().upper(),
                raw[4:6].hex().upper(),
                raw[6:8].hex().upper(),
                raw[8:10].hex().upper(),
                raw[10:16].hex().upper(),
            ))
        offset += cmdsize
    raise ProvenanceError(f"{path} has no LC_UUID load command")


def bundle_identifier(info_plist_path: Path) -> Optional[str]:
    """Return CFBundleIdentifier of an Info.plist, or None when unreadable."""
    try:
        data = plistlib.loads(Path(info_plist_path).read_bytes())
    except Exception:
        return None
    value = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def parse_bundle_provenance(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    """Parse a bundled PROVENANCE file; return (entries, structural problems).

    Values are everything after the first '='. The file must be UTF-8 with LF
    endings and exactly the contract keys, in order, each once.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as err:
        return [], [f"cannot read {path}: {err}"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as err:
        return [], [f"{path} is not UTF-8: {err}"]
    problems = []
    if "\r" in text:
        problems.append(f"{path} uses CRLF line endings instead of LF")
    if text and not text.endswith("\n"):
        problems.append(f"{path} does not end with a newline")
    entries = []
    seen = set()
    for number, line in enumerate(text.splitlines(), 1):
        key, separator, value = line.partition("=")
        if not separator or not key:
            problems.append(f"line {number} is not key=value: {line!r}")
            continue
        if key in seen:
            problems.append(f"key {key!r} appears more than once")
            continue
        if not value:
            problems.append(f"key {key!r} has an empty value")
        seen.add(key)
        entries.append((key, value))
    keys = [key for key, _ in entries]
    if keys != list(BUNDLE_KEYS):
        problems.append(f"keys are {keys}, expected {list(BUNDLE_KEYS)}")
    return entries, problems


def sums_problems(sums_path: Path, digests: dict[str, str]) -> list[str]:
    """Return deviations of SHA256SUMS from the two contract lines."""
    expected = [
        f"{digests['Contents/Info.plist']}  Contents/Info.plist",
        f"{digests['Contents/MacOS/usbgadget']}  Contents/MacOS/usbgadget",
    ]
    try:
        text = sums_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        return [f"cannot read {sums_path}: {err}"]
    problems = []
    if "\r" in text:
        problems.append(f"{sums_path} uses CRLF line endings instead of LF")
    lines = text.splitlines()
    if len(lines) != len(expected):
        problems.append(f"{sums_path} has {len(lines)} lines, expected {len(expected)}")
    for number, line in enumerate(expected, 1):
        actual = lines[number - 1] if number <= len(lines) else "<missing>"
        if actual != line:
            problems.append(f"{sums_path} line {number} is {actual!r}, expected {line!r}")
    if not problems and text != "\n".join(expected) + "\n":
        problems.append(f"{sums_path} is not exactly the two contract lines")
    return problems


def bundle_layout_problems(bundle_path: Path) -> list[str]:
    """Return deviations from the frozen two-file, two-directory bundle shape."""
    if bundle_path.is_symlink() or not bundle_path.is_dir():
        return [f"{bundle_path} is missing or not a plain directory"]
    problems = []
    seen = set()

    def walk(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
        except OSError as err:
            problems.append(f"cannot list {directory}: {err}")
            return
        for entry in entries:
            relative = prefix + entry.name
            seen.add(relative)
            if entry.is_symlink():
                problems.append(f"symlink: {relative}")
            elif entry.is_dir():
                if relative not in BUNDLE_DIRS:
                    problems.append(f"unexpected directory: {relative}")
                walk(entry, relative + "/")
            elif not entry.is_file():
                problems.append(f"not a regular file: {relative}")
            elif relative not in BUNDLE_FILES:
                problems.append(f"unexpected file: {relative}")

    walk(bundle_path, "")
    for relative in BUNDLE_DIRS + BUNDLE_FILES:
        if relative not in seen:
            problems.append(f"missing: {relative}")
    return problems


def replaceable_bundle_problems(bundle_path: Path) -> list[str]:
    """Return entries that make an existing bundle path unsafe to overwrite."""
    if bundle_path.is_symlink():
        return [f"{bundle_path} is a symlink"]
    if not bundle_path.exists():
        return []
    if not bundle_path.is_dir():
        return [f"{bundle_path} exists and is not a directory"]
    problems = []
    for root, dirnames, filenames in os.walk(bundle_path):
        relative_root = Path(root).relative_to(bundle_path).as_posix()
        prefix = "" if relative_root == "." else relative_root + "/"
        for name in sorted(dirnames + filenames):
            entry = Path(root) / name
            relative = prefix + name
            if entry.is_symlink():
                problems.append(f"unexpected symlink: {relative}")
            elif relative not in (BUNDLE_DIRS if entry.is_dir() else BUNDLE_FILES):
                problems.append(f"unexpected entry: {relative}")
            elif not entry.is_dir() and not entry.is_file():
                problems.append(f"not a regular file: {relative}")
        dirnames[:] = [name for name in dirnames if not (Path(root) / name).is_symlink()]
    return problems


def destination_problems(dest_dir: Path) -> list[str]:
    """Return entries under a --dest-dir that make writing the bundle unsafe."""
    if dest_dir.is_symlink() and not dest_dir.exists():
        return [f"{dest_dir} is a broken symlink"]
    if dest_dir.exists() and not dest_dir.is_dir():
        return [f"{dest_dir} exists and is not a directory"]
    problems = replaceable_bundle_problems(dest_dir / BUNDLE_NAME)
    for name in ("SHA256SUMS", "PROVENANCE"):
        target = dest_dir / name
        if target.is_symlink():
            problems.append(f"unexpected symlink: {target}")
        elif target.exists() and not target.is_file():
            problems.append(f"not a regular file: {target}")
    return problems


def verify_state(record_path: Path, artifact_path: Path, source_path: Path,
                 build_script_path: Path, allow_dirty: bool) -> tuple[Optional[dict], str, list[str], list[str]]:
    """Check artifact, source and build script against the record.

    Returns (record, summary, notes, problems); notes and problems already
    carry their 'note: ' or 'problem: <code>: ' prefix.
    """
    ensure_tools(["git", "codesign"])
    problems = []
    notes = []

    def problem(code: str, detail: str, dirty_class: bool = False) -> None:
        line = f"problem: {code}: {detail}"
        if dirty_class and allow_dirty:
            notes.append("note: " + line)
        else:
            problems.append(line)

    record, record_problems = read_record(record_path)
    for detail in record_problems:
        problem("record", detail)

    commit = dirty = source_sha = exec_sha = "unknown"
    try:
        git_info = collect_git_info(REPO_ROOT)
        commit = git_info["commit"]
        dirty = "true" if git_info["dirty"] else "false"
        if git_info["dirty"]:
            problem("dirty", "build inputs have uncommitted changes: "
                    + ", ".join(git_info["dirty_paths"]), True)
    except ProvenanceError as err:
        problem("dirty", f"cannot determine git state: {err}")

    current_source = None
    try:
        current_source = collect_source_info(source_path, REPO_ROOT)
        source_sha = current_source["tree_sha256"]
    except ProvenanceError as err:
        problem("source-digest", str(err))

    current_artifact = None
    try:
        current_artifact = collect_artifact_info(artifact_path, REPO_ROOT)
        exec_sha = current_artifact["executable"]["sha256"]
    except (ProvenanceError, SystemExit):
        problem("artifact-files", f"cannot read the artifact bundle: {artifact_path}")

    if record is not None:
        if record["git"]["dirty"]:
            problem("record-dirty",
                    "the artifact was built from a dirty tree: "
                    + ", ".join(record["git"].get("dirty_paths", [])), True)
        if current_source is not None and current_source["tree_sha256"] != record["source"]["tree_sha256"]:
            problem("source-digest",
                    f"source tree is {current_source['tree_sha256']}, record has "
                    f"{record['source']['tree_sha256']}")
        if not build_script_path.is_file() or sha256_file(build_script_path) != record["build"]["script_sha256"]:
            problem("build-script", f"{BUILD_SCRIPT_REL} differs from the script that built the artifact")
        if current_artifact is not None:
            for code, detail in artifact_differences(record, current_artifact):
                problem(code, detail)

    summary = (f"provenance: commit={commit} dirty={dirty} source_sha256={source_sha} "
               f"executable_sha256={exec_sha}")
    return record, summary, notes, problems


def cmd_verify(args: argparse.Namespace) -> None:
    """Fail unless the artifact, source and build script still match the record.

    Problem codes (one 'problem: <code>: <detail>' line each):
      record, record-dirty, dirty, artifact-files, artifact-hash,
      source-digest, build-script.
    """
    _record, summary, notes, problems = verify_state(
        Path(args.record), Path(args.artifact), Path(args.source),
        Path(args.build_script), args.allow_dirty)
    print(summary)
    for line in notes + problems:
        print(line)
    sys.exit(1 if problems else 0)


def cmd_verify_bundle(args: argparse.Namespace) -> None:
    """Fail unless the bundled driver and its metadata match this build exactly.

    Problem codes (one 'problem: <code>: <detail>' line each):
      record, artifact, bundle-files, bundle-bytes, sums, provenance.
    """
    ensure_tools(["codesign"])
    record_path = Path(args.record)
    artifact_path = Path(args.artifact)
    bundle_dir = Path(args.bundle_dir)
    bundle_path = bundle_dir / BUNDLE_NAME
    problems = []

    def problem(code: str, detail: str) -> None:
        problems.append(f"problem: {code}: {detail}")

    record, record_problems = read_record(record_path)
    for detail in record_problems:
        problem("record", detail)
    if record is not None and record["git"]["dirty"]:
        problem("record", "the artifact was built from a dirty tree: "
                + ", ".join(record["git"].get("dirty_paths", [])))

    current_artifact = None
    try:
        current_artifact = collect_artifact_info(artifact_path, REPO_ROOT)
    except (ProvenanceError, SystemExit, OSError):
        problem("artifact", f"cannot read the artifact bundle: {artifact_path}")
    if record is not None and current_artifact is not None:
        for _code, detail in artifact_differences(record, current_artifact):
            problem("artifact", detail)

    for detail in bundle_layout_problems(bundle_path):
        problem("bundle-files", detail)

    bundle_digests = {}
    for relative in BUNDLE_FILES:
        candidate = bundle_path / relative
        if candidate.is_file() and not candidate.is_symlink():
            try:
                bundle_digests[relative] = sha256_file(candidate)
            except OSError:
                continue

    for relative in BUNDLE_FILES:
        artifact_file = artifact_path / relative
        bundle_file = bundle_path / relative
        if not artifact_file.is_file():
            problem("bundle-bytes", f"artifact has no {relative}")
        elif not bundle_file.is_file() or bundle_file.is_symlink():
            problem("bundle-bytes", f"bundled copy has no regular file {relative}")
        else:
            try:
                identical = artifact_file.read_bytes() == bundle_file.read_bytes()
            except OSError as err:
                problem("bundle-bytes", f"cannot read {relative}: {err}")
                continue
            if not identical:
                problem("bundle-bytes", f"{relative} differs from the artifact")

    if len(bundle_digests) == len(BUNDLE_FILES):
        for detail in sums_problems(bundle_dir / "SHA256SUMS", bundle_digests):
            problem("sums", detail)
    else:
        problem("sums", "cannot hash every bundled file")

    expected_uuid = None
    executable = bundle_path / BUNDLE_FILES[1]
    try:
        expected_uuid = macho_uuid(executable)
    except ProvenanceError as err:
        problem("provenance", str(err))

    entries, provenance_problems = parse_bundle_provenance(bundle_dir / "PROVENANCE")
    for detail in provenance_problems:
        problem("provenance", detail)
    if not provenance_problems:
        values = dict(entries)
        identifier = bundle_identifier(bundle_path / BUNDLE_FILES[0])
        if identifier is None:
            problem("provenance", f"cannot read CFBundleIdentifier from {BUNDLE_FILES[0]}")
        elif values["bundle_identifier"] != identifier:
            problem("provenance", f"bundle_identifier={values['bundle_identifier']} "
                    f"does not match Info.plist CFBundleIdentifier={identifier}")
        if values["format"] != BUNDLE_FORMAT:
            problem("provenance", f"format={values['format']} is not {BUNDLE_FORMAT}")
        for key, relative in (("info_plist_sha256", "Contents/Info.plist"),
                              ("executable_sha256", "Contents/MacOS/usbgadget")):
            actual = bundle_digests.get(relative)
            if actual is not None and values[key] != actual:
                problem("provenance", f"{key}={values[key]} does not match {relative} ({actual})")
        if not re.fullmatch(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                            values["lc_uuid"]):
            problem("provenance", f"lc_uuid={values['lc_uuid']} is not uppercase 8-4-4-4-12")
        if expected_uuid is not None and values["lc_uuid"] != expected_uuid:
            problem("provenance", f"lc_uuid={values['lc_uuid']} does not match "
                    f"the executable's LC_UUID {expected_uuid}")
        if record is not None:
            if values["source_tree_sha256"] != record["source"]["tree_sha256"]:
                problem("provenance", f"source_tree_sha256={values['source_tree_sha256']} "
                        f"does not match the record's {record['source']['tree_sha256']}")
            if values["xcode_build"] != record["toolchain"]["xcode_build"]:
                problem("provenance", f"xcode_build={values['xcode_build']} "
                        f"does not match the record's {record['toolchain']['xcode_build']}")
            if values["sdk_build"] != record["toolchain"]["sdk"]["build"]:
                problem("provenance", f"sdk_build={values['sdk_build']} "
                        f"does not match the record's {record['toolchain']['sdk']['build']}")
        if not re.fullmatch(r"[0-9a-f]{40}", values["source_commit"]):
            problem("provenance", f"source_commit={values['source_commit']} is not 40 lowercase hex characters")

    source_tree = record["source"]["tree_sha256"] if record is not None else "unknown"
    print(f"bundle: executable_sha256={bundle_digests.get('Contents/MacOS/usbgadget', 'unknown')} "
          f"lc_uuid={expected_uuid or 'unknown'} source_tree_sha256={source_tree}")
    for line in problems:
        print(line)
    sys.exit(1 if problems else 0)


def cmd_bundle(args: argparse.Namespace) -> None:
    """Write a verified artifact as a bundled driver with its metadata.

    Refuses unless record, source, build script and artifact pass the same
    checks as `verify`. Nothing is removed: a destination bundle holding
    entries outside the frozen two-file layout is rejected.
    """
    record_path = Path(args.record)
    artifact_path = Path(args.artifact)
    dest_dir = Path(args.dest_dir)

    record, _summary, _notes, problems = verify_state(
        record_path, artifact_path, Path(args.source), Path(args.build_script),
        allow_dirty=False)
    if problems:
        for line in problems:
            print(line)
        sys.exit(1)

    unexpected = destination_problems(dest_dir)
    if unexpected:
        for detail in unexpected:
            print(f"problem: bundle-files: {detail}")
        sys.exit(1)

    artifact_plist = artifact_path / BUNDLE_FILES[0]
    artifact_executable = artifact_path / BUNDLE_FILES[1]
    identifier = bundle_identifier(artifact_plist)
    if identifier is None:
        raise ProvenanceError(f"cannot read CFBundleIdentifier from {artifact_plist}")
    lc_uuid = macho_uuid(artifact_executable)

    bundle_path = dest_dir / BUNDLE_NAME
    (bundle_path / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(artifact_plist, bundle_path / "Contents" / "Info.plist")
    shutil.copyfile(artifact_executable, bundle_path / "Contents" / "MacOS" / "usbgadget")

    digests = {relative: sha256_file(bundle_path / relative) for relative in BUNDLE_FILES}
    sums_text = (
        f"{digests['Contents/Info.plist']}  Contents/Info.plist\n"
        f"{digests['Contents/MacOS/usbgadget']}  Contents/MacOS/usbgadget\n"
    )
    (dest_dir / "SHA256SUMS").write_bytes(sums_text.encode("utf-8"))

    entries = (
        ("format", BUNDLE_FORMAT),
        ("bundle_identifier", identifier),
        ("executable_sha256", digests["Contents/MacOS/usbgadget"]),
        ("info_plist_sha256", digests["Contents/Info.plist"]),
        ("lc_uuid", lc_uuid),
        ("source_tree_sha256", record["source"]["tree_sha256"]),
        ("source_commit", record["git"]["commit"]),
        ("xcode_build", record["toolchain"]["xcode_build"]),
        ("sdk_build", record["toolchain"]["sdk"]["build"]),
    )
    (dest_dir / "PROVENANCE").write_bytes(
        "".join(f"{key}={value}\n" for key, value in entries).encode("utf-8"))
    print(f"bundle: {to_repo_rel(dest_dir, REPO_ROOT)}")


def cmd_kdk_check(args: argparse.Namespace) -> None:
    """Validate the KDK matching a host version/build under --kdk-root."""
    version = args.product_version
    build = args.product_build
    if not version or not build:
        host = collect_host_info()
        version = version or host["version"]
        build = build or host["build"]
    name = f"KDK_{version}_{build}.kdk"
    info, problems = inspect_kdk(Path(args.kdk_root) / name, version, build)
    if problems:
        for line in problems:
            print(f"problem: {line}")
        sys.exit(1)
    print(f"kdk: {name} ProductVersion={info['product_version']} "
          f"ProductBuildVersion={info['product_build']} "
          f"arm64_release_kernels={len(info['arm64_release_kernels'])}")


def cmd_export_checkout(args: argparse.Namespace) -> None:
    """Copy the build inputs of the working tree into a fresh one-commit git repo.

    The copy mirrors the working tree (including uncommitted edits) at another
    path, so a build there shows path independence without touching this repo.
    """
    dest = Path(args.dest).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise ProvenanceError(f"destination is not empty: {dest}")
    listing = git_output(
        REPO_ROOT,
        ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--"] + EXPORT_INPUTS,
    )
    for raw in listing.split(b"\0"):
        if not raw:
            continue
        name = raw.decode("utf-8")
        src = REPO_ROOT / name
        if not src.is_file():
            continue
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)

    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
    identity = ["-c", "user.name=kext-export", "-c", "user.email=kext-export@localhost",
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]
    for git_args in (
        ["-c", "init.defaultBranch=main", "init", "-q"],
        ["add", "-A"],
        identity + ["commit", "-q", "--no-verify", "-m", "Export kext build inputs"],
    ):
        res = subprocess.run(["git"] + git_args, cwd=str(dest), env=env,
                             capture_output=True, text=True)
        if res.returncode != 0:
            raise ProvenanceError(f"git {git_args[-1]} failed in {dest}: {res.stderr.strip()}")
    print(str(dest))


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
        help="Record provenance for a kext just built by scripts/build-kext.sh",
    )
    record_parser.add_argument("--artifact", required=True, help="Path to built kext bundle")
    record_parser.add_argument("--source", required=True, help="Path to kext source directory")
    record_parser.add_argument(
        "--built-source", required=True,
        help="Copy of the source tree that was compiled (must digest equal to --source)",
    )
    record_parser.add_argument("--build-script", required=True, help="Path to the build script")
    record_parser.add_argument(
        "--build-settings", required=True,
        help="Output of xcodebuild -showBuildSettings for the build",
    )
    record_parser.add_argument(
        "--build-arg", action="append", default=[],
        help="Non-path xcodebuild argument to record (repeatable)",
    )
    record_parser.add_argument(
        "--kdk-root", default=DEFAULT_KDK_ROOT, help="Directory holding KDK_*.kdk"
    )
    record_parser.add_argument("--output", required=True, help="Path to output JSON file")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Fail unless artifact, source digest and build script match the record",
    )
    verify_parser.add_argument("--record", default=str(REPO_ROOT / DEFAULT_RECORD))
    verify_parser.add_argument("--artifact", default=str(REPO_ROOT / DEFAULT_ARTIFACT))
    verify_parser.add_argument("--source", default=str(REPO_ROOT / SOURCE_REL))
    verify_parser.add_argument("--build-script", default=str(REPO_ROOT / BUILD_SCRIPT_REL))
    verify_parser.add_argument(
        "--allow-dirty", action="store_true",
        help="Report a dirty tree as a note instead of a failure (iteration builds)",
    )

    verify_bundle_parser = subparsers.add_parser(
        "verify-bundle",
        help="Fail unless drivers/ is byte-identical to this build with matching metadata",
    )
    verify_bundle_parser.add_argument("--record", default=str(REPO_ROOT / DEFAULT_RECORD))
    verify_bundle_parser.add_argument("--artifact", default=str(REPO_ROOT / DEFAULT_ARTIFACT))
    verify_bundle_parser.add_argument("--bundle-dir", default=str(REPO_ROOT / DEFAULT_BUNDLE_DIR))

    bundle_parser = subparsers.add_parser(
        "bundle",
        help="Write usbgadget.kext, SHA256SUMS and PROVENANCE from a verified build",
    )
    bundle_parser.add_argument("--dest-dir", required=True)
    bundle_parser.add_argument("--record", default=str(REPO_ROOT / DEFAULT_RECORD))
    bundle_parser.add_argument("--artifact", default=str(REPO_ROOT / DEFAULT_ARTIFACT))
    bundle_parser.add_argument("--source", default=str(REPO_ROOT / SOURCE_REL))
    bundle_parser.add_argument("--build-script", default=str(REPO_ROOT / BUILD_SCRIPT_REL))

    kdk_parser = subparsers.add_parser(
        "kdk-check",
        help="Validate the KDK matching the host (or given) macOS version/build",
    )
    kdk_parser.add_argument("--kdk-root", default=DEFAULT_KDK_ROOT)
    kdk_parser.add_argument("--product-version", default="")
    kdk_parser.add_argument("--product-build", default="")

    export_parser = subparsers.add_parser(
        "export-checkout",
        help="Copy the build inputs into a fresh git repository at --dest",
    )
    export_parser.add_argument("--dest", required=True)

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
    handlers = {
        "record": cmd_record,
        "verify": cmd_verify,
        "verify-bundle": cmd_verify_bundle,
        "bundle": cmd_bundle,
        "kdk-check": cmd_kdk_check,
        "export-checkout": cmd_export_checkout,
        "report": cmd_report,
    }
    try:
        handlers[args.subcommand](args)
    except ProvenanceError as err:
        sys.stderr.write(f"error: {err}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
