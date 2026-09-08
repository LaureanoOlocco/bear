"""Bounded native analysis and PE resource APIs.

Integration: ``app.include_router(bear.analysis.router)``. Resource extraction
calls ``bear.artifacts.store_file(path) -> dict`` synchronously before deleting
its temporary file; artifact sources use ``artifact_path(artifact_id)``.
Batch submission returns the envelope from
``bear.server.submit_task(operation, label) -> {task_id, status, ...}``.
The zero-argument operation calls ``check_task_cancelled()`` on its owning task
thread and ``update_task_progress(progress_percent=..., completed_items=...,
total_items=..., partial_results=[...])``. Cancellation exceptions propagate.

POST /api/tools/pe/resources: binary OR artifact_id; optional resource_type,
resource_id, language (integer IDs or exact names); offset=0, limit=100 (<=200).
POST /api/tools/pe/resources/extract: same source; resource_type=10 (RCDATA),
required resource_id, optional language (required if ambiguous), max_bytes=64MiB
(<=256MiB). Returns resource metadata and an artifact, never inline payloads.
POST /api/tools/pe/resources/batch: same source/optional filters; operation is
extract or sha256; offset=0, limit=100 (<=500), concurrency=2 (<=4), max_bytes as
above, max_total_bytes=256MiB (<=1GiB), result_offset=0, result_limit=100 (<=200).
Returns an async task_id. Progress partial_results and final results contain
only the requested result page, in resource order; completed_items counts all
finished items, including failures. Final matched_total/next_offset page the
resource selection. If the result page omits items, results_artifact contains the
complete JSON results list (read using the parent's paged artifact API).
A directory exceeding metadata limits is rejected rather
than reported as an empty or complete listing.

Strings offset/length are absolute file-byte windows, intersected with PE
code/initialized-data sections (excluding .rsrc and the resource directory).
include_resources includes resource sections; full_scan scans the raw window,
including overlays/resources, without the 16MiB input cap. Output remains bounded
and carries truncation/skip warnings. compute_hash independently opts into a
streamed whole-file SHA256; full_scan does not implicitly enable hashing.
"""

from concurrent.futures import FIRST_COMPLETED, CancelledError, ThreadPoolExecutor, wait
from contextlib import contextmanager
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import tempfile
import threading
from typing import Callable, Literal

from fastapi import APIRouter, HTTPException
import pefile
from pydantic import BaseModel, Field, model_validator

SCAN_LIMIT = 16 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
MAX_STRING_LENGTH = 4096
MAX_OUTPUT_CHARS = 1024 * 1024
MAX_HEADER_BYTES = 1024 * 1024
MAX_RESOURCE_ENTRIES = 30000
MAX_RESOURCE_ITEMS = 10000
MAX_RESOURCE_BYTES = 256 * 1024 * 1024
router = APIRouter()


class _MetadataMap(mmap.mmap):
    def __getitem__(self, key):
        if isinstance(key, slice) and len(range(*key.indices(len(self)))) > MAX_HEADER_BYTES:
            raise ValueError("PE metadata read exceeds the 1MiB safety limit")
        return super().__getitem__(key)


def file_size(path: str | Path) -> int:
    try:
        info = os.stat(path)
    except OSError as exc:
        raise ValueError(f"Cannot access file: {path}: {exc.strerror}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Analysis requires a regular file")
    return info.st_size


def detect_format(path: str | Path) -> str:
    """Read at most 68 bytes, including a bounded seek to the PE signature."""
    size = file_size(path)
    with open(path, "rb") as source:
        header = source.read(64)
        if header[:4] == b"\x7fELF":
            return "ELF"
        if header[:4] in {
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
            b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
        }:
            return "MachO"
        if header[:2] == b"MZ" and len(header) == 64:
            offset = struct.unpack_from("<I", header, 0x3C)[0]
            if 64 <= offset <= size - 24:
                source.seek(offset)
                if source.read(4) == b"PE\0\0":
                    return "PE"
    return "unknown"


@contextmanager
def open_pe(path: str | Path):
    """Use mmap/fast_load, guarding pefile's otherwise unbounded header copy."""
    if detect_format(path) != "PE":
        raise ValueError("Expected a PE file")
    with open(path, "rb") as source, _MetadataMap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        count = struct.unpack_from("<H", data, nt + 6)[0]
        optional_size = struct.unpack_from("<H", data, nt + 20)[0]
        sections = nt + 24 + optional_size
        if count > 96 or sections + count * 40 > min(len(data), MAX_HEADER_BYTES):
            raise ValueError("PE header exceeds bounds (1MiB headers, 96 sections)")
        pointers = [struct.unpack_from("<I", data, sections + i * 40 + 20)[0]
                    for i in range(count)]
        if min((pointer for pointer in pointers if pointer), default=0) > MAX_HEADER_BYTES:
            raise ValueError("PE header padding exceeds the 1MiB safety limit")
        try:
            with pefile.PE(data=data, fast_load=True) as pe:
                if pe.PE_TYPE not in (0x10B, 0x20B):
                    raise ValueError("Unsupported PE optional header")
                yield pe, data
        except pefile.PEFormatError as exc:
            raise ValueError(f"Malformed PE: {exc}") from exc


def rva_offset(pe, rva: int, size: int, file_bytes: int) -> int:
    """Reject virtual padding, ambiguous sections, overflow and out-of-file data."""
    if rva < 0 or size < 0 or rva + size > 1 << 32:
        raise ValueError("Invalid RVA/size")
    candidates = []
    if rva < pe.OPTIONAL_HEADER.SizeOfHeaders and rva + size <= pe.OPTIONAL_HEADER.SizeOfHeaders:
        candidates.append(rva)
    for section in pe.sections:
        delta = rva - section.VirtualAddress
        if 0 <= delta < section.SizeOfRawData and delta + size <= section.SizeOfRawData:
            candidates.append(section.PointerToRawData + delta)
    if len(candidates) != 1 or candidates[0] + size > file_bytes:
        raise ValueError(f"RVA 0x{rva:x} size {size} is not uniquely file-backed")
    return candidates[0]


def pe_metadata(path: str | Path) -> dict:
    with open_pe(path) as (pe, data):
        optional = pe.OPTIONAL_HEADER
        flags = optional.DllCharacteristics
        directories = optional.DATA_DIRECTORY
        certificate = directories[4] if len(directories) > 4 else None
        certificate_present = bool(certificate and certificate.VirtualAddress and certificate.Size)
        certificate_valid = bool(certificate_present and certificate.VirtualAddress + certificate.Size <= len(data))
        return {
            "success": True, "status": "completed", "format": "PE", "backend": "native",
            "machine": pe.FILE_HEADER.Machine,
            "machine_name": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "unknown"),
            "bits": 64 if pe.PE_TYPE == 0x20B else 32,
            "entry_point_rva": optional.AddressOfEntryPoint,
            "image_base": optional.ImageBase, "subsystem": optional.Subsystem,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": pe.FILE_HEADER.Characteristics,
            "dll_characteristics": flags,
            "security": {
                "aslr": bool(flags & 0x40), "high_entropy_va": bool(flags & 0x20),
                "nx_compat": bool(flags & 0x100), "no_seh": bool(flags & 0x400),
                "guard_cf": bool(flags & 0x4000), "force_integrity": bool(flags & 0x80),
                "app_container": bool(flags & 0x1000),
                "relocations_stripped": bool(pe.FILE_HEADER.Characteristics & 1),
                "certificate_table_present": certificate_present,
                "certificate_table_in_bounds": certificate_valid,
                "signature_verified": None, "safe_seh": None, "stack_cookie": None,
            },
            "sections": [{
                "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
                "rva": section.VirtualAddress, "virtual_size": section.Misc_VirtualSize,
                "offset": section.PointerToRawData, "size_bytes": section.SizeOfRawData,
                "characteristics": section.Characteristics,
            } for section in pe.sections],
            "warnings": ["Security values are header declarations, not runtime guarantees; "
                         "signature, SafeSEH and stack-cookie verification were not performed."] + pe.get_warnings()[:20],
        }


def scan_strings(path: str | Path, *, min_len: int = 4, encoding: str = "",
                 additional_args: str = "", offset: int = 0, length: int | None = None,
                 max_scan_bytes: int = SCAN_LIMIT, max_strings: int = 1000,
                 include_resources: bool = False, full_scan: bool = False,
                 check_cancelled: Callable = lambda: None) -> dict:
    """Bound both input and output; never hand an unbounded file to strings(1)."""
    if additional_args:
        raise ValueError("Native bounded strings does not accept additional_args; use the explicit scan fields")
    if not 1 <= min_len <= MAX_STRING_LENGTH or not 1 <= max_strings <= 10000:
        raise ValueError("Invalid strings length/result limit")
    if offset < 0 or (length is not None and length < 0) or not 1 <= max_scan_bytes <= SCAN_LIMIT:
        raise ValueError("Invalid strings scan window/budget")
    if encoding not in ("", "s", "S", "b", "l", "B", "L"):
        raise ValueError("Unsupported strings encoding")
    size = file_size(path)
    format_name = detect_format(path)
    end = size if length is None else min(size, offset + length)
    ranges = [(min(offset, size), max(min(offset, size), end))]
    warnings = []
    if full_scan:
        warnings.append("full_scan opted into potentially expensive scanning of the raw window, including resources/overlays")
    elif format_name == "PE":
        ranges = []
        with open_pe(path) as (pe, _):
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            resource = directory[2] if len(directory) > 2 else None
            for section in pe.sections:
                is_resource = section.Name.rstrip(b"\0") == b".rsrc" or bool(
                    resource and resource.VirtualAddress
                    and section.VirtualAddress <= resource.VirtualAddress
                    < section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData))
                if is_resource and not include_resources:
                    continue
                if not section.Characteristics & 0x60 and not (is_resource and include_resources):
                    continue
                start = max(offset, section.PointerToRawData)
                stop = min(end, section.PointerToRawData + section.SizeOfRawData)
                if start < stop:
                    ranges.append((start, stop))
        warnings.append("PE scan is limited to code/initialized-data sections; headers, overlays and unselected sections are skipped")
        if not include_resources:
            warnings.append("PE resources are excluded; use include_resources or full_scan to opt in")
    merged = []
    for start, stop in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(stop, merged[-1][1]))
        else:
            merged.append((start, stop))
    eligible = sum(stop - start for start, stop in merged)
    budget = eligible if full_scan else min(eligible, max_scan_bytes)
    # GNU strings encodings: s=7-bit, S=8-bit, b/l=16-bit, B/L=32-bit.
    width = 2 if encoding in ("b", "l") else 4 if encoding in ("B", "L") else 1
    printable = b"[\x09\x20-\x7e\x80-\xff]" if encoding == "S" else b"[\x09\x20-\x7e]"
    unit = printable + b"\x00" * (width - 1) if encoding in ("l", "L") else b"\x00" * (width - 1) + printable
    pattern = re.compile(b"(?:" + unit + b")+")
    prefixes = [
        re.compile(printable + b"\x00" * (count - 1) if encoding in ("l", "L") else b"\x00" * count)
        for count in range(1, width)
    ]
    codec = {"b": "utf-16-be", "l": "utf-16-le", "B": "utf-32-be", "L": "utf-32-le"}.get(encoding, "latin-1")
    items = []
    scanned = output_chars = 0
    output_limited = False
    long_string = False
    with open(path, "rb") as source:
        for start, stop in merged:
            position = start
            carry = b""
            carry_offset = start
            carry_truncated = False
            while position < stop and scanned < budget and not output_limited:
                check_cancelled()
                source.seek(position)
                chunk = source.read(min(CHUNK_SIZE, stop - position, budget - scanned))
                if not chunk:
                    raise ValueError("File changed during strings scan")
                base = position - len(carry)
                block = carry + chunk
                previous_offset = carry_offset
                previous_truncated = carry_truncated
                position += len(chunk)
                scanned += len(chunk)
                carry = b""
                carry_truncated = False
                more = position < stop and scanned < budget
                for match in pattern.finditer(block):
                    raw = match.group()
                    origin = previous_offset if match.start() == 0 else base + match.start()
                    truncated = len(raw) > MAX_STRING_LENGTH * width or (match.start() == 0 and previous_truncated)
                    suffix = block[match.end():] if len(block) - match.end() < width else None
                    if more and suffix is not None and (not suffix or prefixes[len(suffix) - 1].fullmatch(suffix)):
                        carry = raw[:MAX_STRING_LENGTH * width] + suffix
                        carry_offset = origin
                        carry_truncated = truncated
                        break
                    if len(raw) < min_len * width:
                        continue
                    long_string |= truncated
                    text = raw[:MAX_STRING_LENGTH * width].decode(codec)
                    if len(items) >= max_strings or output_chars + len(text) > MAX_OUTPUT_CHARS:
                        output_limited = True
                        break
                    items.append({"offset": origin, "text": text, "truncated": truncated})
                    output_chars += len(text)
                    if len(items) >= max_strings:
                        output_limited = True
                        break
                if more and not carry and width > 1:
                    for count in range(min(len(block), width - 1), 0, -1):
                        if prefixes[count - 1].fullmatch(block[-count:]):
                            carry = block[-count:]
                            carry_offset = position - count
                            break
                if not carry:
                    carry_offset = position
            if output_limited or scanned >= budget:
                break
    if scanned < eligible:
        warnings.append("Scan stopped before all eligible bytes were examined")
    if output_limited:
        warnings.append("String count/output limit reached; more strings may exist")
    if long_string:
        warnings.append("Long strings were truncated to 4096 characters")
    return {
        "success": True, "status": "completed", "format": format_name,
        "backend": "native", "strings": items,
        "stdout": "\n".join(item["text"] for item in items), "stderr": "", "return_code": 0,
        "scan": {"file_size_bytes": size, "offset": offset, "length": length,
                 "bytes_scanned": scanned, "eligible_bytes": eligible,
                 "max_scan_bytes": None if full_scan else max_scan_bytes,
                 "full_scan": full_scan, "include_resources": include_resources,
                 "skipped_bytes": size - scanned, "output_limited": output_limited,
                 "truncated": scanned < eligible or output_limited or long_string},
        "warnings": warnings,
    }


def skipped(reason: str) -> dict:
    return {"success": False, "status": "skipped", "reason": reason}


def triage(params: dict, execute_command: Callable, check_cancelled: Callable = lambda: None) -> dict:
    check_cancelled()
    path = params["binary"]
    size = file_size(path)
    format_name = detect_format(path)
    checks = {"file": {"success": True, "status": "completed", "backend": "native",
                       "stdout": format_name, "size_bytes": size}}
    warnings = []
    if params.get("full_scan", False):
        warnings.append("full_scan opted into potentially expensive whole-file analysis")
    if params.get("compute_hash", False):
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
                check_cancelled()
                digest.update(chunk)
        checks["sha256"] = {"success": True, "status": "completed", "sha256": digest.hexdigest(), "stdout": digest.hexdigest()}
        warnings.append("compute_hash opted into reading the entire file")
    else:
        checks["sha256"] = skipped("Whole-file hashing is opt-in: set compute_hash=true")
    if format_name == "PE":
        try:
            checks["pe"] = pe_metadata(path)
            checks["checksec"] = {"success": True, "status": "completed", "backend": "native",
                                  "security": checks["pe"]["security"], "warnings": checks["pe"]["warnings"]}
        except ValueError as exc:
            checks["pe"] = checks["checksec"] = {"success": False, "status": "failed", "error": str(exc)}
    elif format_name == "ELF" and (size <= SCAN_LIMIT or params.get("full_scan", False)):
        for name, command in {
            "checksec": f"checksec --file={shlex.quote(path)}",
            "elf_header": f"readelf -h -- {shlex.quote(path)}",
            "dynamic_symbols": f"readelf -Ws -- {shlex.quote(path)}",
        }.items():
            checks[name] = execute_command(command, use_cache=params.get("use_cache", True), cache_params=params)
    else:
        checks["checksec"] = skipped("ELF analysis exceeds the default size limit; set full_scan=true" if format_name == "ELF" else f"No native security analyzer for {format_name}")
    for name in ("elf_header", "dynamic_symbols"):
        if name not in checks:
            checks[name] = skipped("ELF-only check" if format_name != "ELF" else "Large-file ELF analysis requires full_scan=true")
    if params.get("strings_limit", 40):
        try:
            checks["strings"] = scan_strings(path, max_strings=params.get("strings_limit", 40), check_cancelled=check_cancelled, **{
                key: params[key] for key in ("offset", "length", "max_scan_bytes", "include_resources", "full_scan") if key in params})
        except ValueError as exc:
            checks["strings"] = {"success": False, "status": "failed", "error": str(exc)}
    else:
        checks["strings"] = skipped("strings_limit=0")
    return {"success": all(item.get("success") or item.get("status") == "skipped" for item in checks.values()),
            "binary": path, "format": format_name, "size_bytes": size, "checks": checks,
            "partial": any(item.get("status") == "skipped" for item in checks.values()) or checks.get("strings", {}).get("scan", {}).get("truncated", False),
            "warnings": warnings,
            "summary": {"file": format_name, "sha256": checks["sha256"].get("sha256"),
                        "checksec_available": checks["checksec"].get("success", False)}}


class ResourceSource(BaseModel):
    model_config = {"extra": "forbid"}
    binary: str | None = Field(default=None, min_length=1)
    artifact_id: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def one_source(self):
        if bool(self.binary) == bool(self.artifact_id):
            raise ValueError("Provide exactly one of binary or artifact_id")
        return self

    def source_path(self) -> str:
        if self.binary is not None:
            return self.binary
        from bear.artifacts import artifact_path
        return str(artifact_path(self.artifact_id))


class ResourceFilter(ResourceSource):
    resource_type: int | str | None = None
    resource_id: int | str | None = None
    language: int | str | None = None


class ResourcesRequest(ResourceFilter):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=200)


class ResourceExtractRequest(ResourceSource):
    resource_type: int | str = 10
    resource_id: int | str
    language: int | str | None = None
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=0, le=MAX_RESOURCE_BYTES)


class ResourceBatchRequest(ResourceFilter):
    operation: Literal["extract", "sha256"]
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    concurrency: int = Field(default=2, ge=1, le=4)
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=0, le=MAX_RESOURCE_BYTES)
    max_total_bytes: int = Field(default=256 * 1024 * 1024, ge=0, le=1024 * 1024 * 1024)
    result_offset: int = Field(default=0, ge=0)
    result_limit: int = Field(default=100, ge=1, le=200)


def resource_catalog(path: str, check_cancelled: Callable = lambda: None) -> list[dict]:
    """Walk metadata only: pefile's resource parser eagerly decodes some payloads."""
    with open_pe(path) as (pe, data):
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= 2 or not (directories[2].VirtualAddress or directories[2].Size):
            return []
        directory = directories[2]
        if not directory.VirtualAddress or directory.Size < 16:
            raise ValueError("Invalid resource directory RVA/size")
        root = rva_offset(pe, directory.VirtualAddress, directory.Size, len(data))
        entries_seen = 0
        visited = set()
        resources = []

        def read(relative: int, size: int) -> bytes:
            if relative < 0 or relative + size > directory.Size:
                raise ValueError("Resource directory pointer is out of bounds")
            return data[root + relative:root + relative + size]

        def walk(relative: int, keys: tuple):
            nonlocal entries_seen
            check_cancelled()
            if relative in visited:
                raise ValueError("Resource directory is cyclic or aliased")
            visited.add(relative)
            header = read(relative, 16)
            named, ids = struct.unpack_from("<HH", header, 12)
            count = named + ids
            entries_seen += count
            if entries_seen > MAX_RESOURCE_ENTRIES:
                raise ValueError("Resource directory entry limit exceeded")
            for index in range(count):
                check_cancelled()
                name, target = struct.unpack("<II", read(relative + 16 + index * 8, 8))
                if name & 0x80000000:
                    name_offset = name & 0x7FFFFFFF
                    chars = struct.unpack("<H", read(name_offset, 2))[0]
                    if chars > 256:
                        raise ValueError("Resource name exceeds 256 characters")
                    key = read(name_offset + 2, chars * 2).decode("utf-16-le", "replace")
                else:
                    key = name
                child_keys = keys + (key,)
                if target & 0x80000000:
                    if len(child_keys) >= 3:
                        raise ValueError("Resource directory exceeds type/id/language depth")
                    walk(target & 0x7FFFFFFF, child_keys)
                else:
                    if len(child_keys) != 3:
                        raise ValueError("Resource data must have type/id/language keys")
                    rva, size, codepage, _ = struct.unpack("<IIII", read(target, 16))
                    item = {"type": child_keys[0], "id": child_keys[1], "language": child_keys[2],
                            "rva": rva, "size_bytes": size, "codepage": codepage}
                    try:
                        item["offset"] = rva_offset(pe, rva, size, len(data))
                        item["valid"] = True
                    except ValueError as exc:
                        item.update(valid=False, error=str(exc))
                    resources.append(item)
                    if len(resources) > MAX_RESOURCE_ITEMS:
                        raise ValueError("Resource item limit exceeded")

        walk(0, ())
        return sorted(resources, key=lambda item: tuple(
            (0, item[key]) if isinstance(item[key], int) else (1, item[key]) for key in ("type", "id", "language")))


def filter_resources(items: list[dict], params) -> list[dict]:
    return [item for item in items if all(value is None or item[key] == value for key, value in (
        ("type", params.resource_type), ("id", params.resource_id), ("language", params.language)))]


def process_resource(path: str, item: dict, operation: str, max_bytes: int,
                     store_file: Callable | None = None, cancelled: threading.Event | None = None) -> dict:
    if not item["valid"]:
        raise ValueError(item["error"])
    if item["size_bytes"] > max_bytes:
        raise ValueError("Resource exceeds max_bytes")
    digest = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="bear-resource-") as directory:
        output_path = Path(directory) / "resource.bin"
        with open(path, "rb") as source:
            if item["offset"] + item["size_bytes"] > os.fstat(source.fileno()).st_size:
                raise ValueError("Resource extends beyond file")
            source.seek(item["offset"])
            output = open(output_path, "wb") if operation == "extract" else None
            try:
                remaining = item["size_bytes"]
                while remaining:
                    if cancelled is not None and cancelled.is_set():
                        raise CancelledError()
                    chunk = source.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("File changed during resource operation")
                    if output is not None:
                        output.write(chunk)
                    else:
                        digest.update(chunk)
                    remaining -= len(chunk)
            finally:
                if output is not None:
                    output.close()
        if cancelled is not None and cancelled.is_set():
            raise CancelledError()
        result = {"success": True, "resource": item}
        if operation == "extract":
            if store_file is None:
                from bear.artifacts import store_file
            result["artifact"] = store_file(output_path)
        else:
            result["sha256"] = digest.hexdigest()
        return result


@router.post("/api/tools/pe/resources")
def list_resources(params: ResourcesRequest):
    items = filter_resources(resource_catalog(params.source_path()), params)
    end = min(len(items), params.offset + params.limit)
    return {"success": True, "resources": items[params.offset:end], "total": len(items),
            "offset": params.offset, "limit": params.limit, "next_offset": end if end < len(items) else None,
            "invalid_items": sum(not item["valid"] for item in items)}


@router.post("/api/tools/pe/resources/extract")
def extract_resource(params: ResourceExtractRequest):
    path = params.source_path()
    items = filter_resources(resource_catalog(path), params)
    if not items:
        raise HTTPException(404, "Resource not found")
    if len(items) != 1:
        raise HTTPException(409, "Resource selection is ambiguous; specify language/type/id")
    return process_resource(path, items[0], "extract", params.max_bytes)


def run_resource_batch(params: ResourceBatchRequest, *, update_progress: Callable,
                       check_cancelled: Callable, store_file: Callable | None = None,
                       store_bytes: Callable | None = None) -> dict:
    check_cancelled()
    path = params.source_path()
    matches = filter_resources(resource_catalog(path, check_cancelled), params)
    items = matches[params.offset:params.offset + params.limit]
    total = len(items)
    results = {}
    completed = 0
    cancelled = threading.Event()
    accepted_bytes = 0

    def page():
        return [results[index] for index in range(params.result_offset, min(total, params.result_offset + params.result_limit)) if index in results]

    def progress():
        update_progress(progress_percent=100 * completed / total if total else 100,
                        completed_items=completed, total_items=total, partial_results=page())

    progress()
    pool = ThreadPoolExecutor(max_workers=params.concurrency, thread_name_prefix="bear-resource")
    pending = {}
    next_item = 0
    try:
        while next_item < total or pending:
            check_cancelled()
            while next_item < total and len(pending) < params.concurrency:
                check_cancelled()
                index = next_item
                next_item += 1
                item = items[index]
                error = item.get("error") if not item["valid"] else None
                if item["size_bytes"] > params.max_bytes:
                    error = "Resource exceeds max_bytes"
                elif accepted_bytes + item["size_bytes"] > params.max_total_bytes:
                    error = "Batch exceeds max_total_bytes"
                if error:
                    results[index] = {"success": False, "resource": item, "error": error}
                    completed += 1
                    progress()
                    continue
                accepted_bytes += item["size_bytes"]
                pending[pool.submit(process_resource, path, item, params.operation,
                                    params.max_bytes, store_file, cancelled)] = index
            done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
            for future in done:
                index = pending.pop(future)
                try:
                    results[index] = future.result()
                except (OSError, ValueError) as exc:
                    results[index] = {"success": False, "resource": items[index], "error": str(exc)}
                completed += 1
                progress()
        check_cancelled()
    finally:
        cancelled.set()
        pool.shutdown(wait=True, cancel_futures=True)
    end = min(len(matches), params.offset + params.limit)
    result_end = min(total, params.result_offset + params.result_limit)
    result = {"success": all(item["success"] for item in results.values()),
              "operation": params.operation, "completed_items": completed, "total_items": total,
              "matched_total": len(matches), "next_offset": end if end < len(matches) else None,
              "results": page(), "result_offset": params.result_offset,
              "next_result_offset": result_end if result_end < total else None,
              "failed_items": sum(not item["success"] for item in results.values())}
    if len(result["results"]) < total:
        check_cancelled()
        if store_bytes is None:
            from bear.artifacts import store_bytes
        result["results_artifact"] = store_bytes(json.dumps([results[index] for index in range(total)]).encode("utf-8"))
    return result


@router.post("/api/tools/pe/resources/batch")
def batch_resources(params: ResourceBatchRequest):
    from bear.server import check_task_cancelled, submit_task, update_task_progress

    return submit_task(lambda: run_resource_batch(
        params, update_progress=update_task_progress, check_cancelled=check_task_cancelled),
        label=f"PE resources {params.operation}")
