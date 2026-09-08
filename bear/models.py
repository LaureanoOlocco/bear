#!/usr/bin/env python3
"""Pydantic request models for the BEAR API."""

from typing import Literal

from pydantic import BaseModel, Field


class BearBaseModel(BaseModel):
    """Base model that preserves BEAR's permissive request behavior."""

    model_config = {"extra": "forbid"}


class GenericCommandRequest(BearBaseModel):
    command: str = Field(min_length=1)
    use_cache: bool = True
    timeout: int = Field(default=300, ge=1, le=86400)
    async_mode: bool = False


class FileCreateRequest(BearBaseModel):
    filename: str = Field(min_length=1)
    content: str = ""
    binary: bool = False


class FileModifyRequest(BearBaseModel):
    filename: str = Field(min_length=1)
    content: str = ""
    append: bool = False


class FileDeleteRequest(BearBaseModel):
    filename: str = Field(min_length=1)


class PayloadGenerateRequest(BearBaseModel):
    type: str = "buffer"
    size: int = Field(default=1024, ge=0)
    pattern: str = "A"
    filename: str = ""


class PythonInstallRequest(BearBaseModel):
    package: str = Field(min_length=1)
    env_name: str = "default"


class PythonExecuteRequest(BearBaseModel):
    script: str = Field(min_length=1)
    env_name: str = "default"
    filename: str = ""
    timeout: int = Field(default=300, ge=1, le=86400)
    async_mode: bool = False


class ChecksecRequest(BearBaseModel):
    binary: str = Field(min_length=1)


class StringsRequest(BearBaseModel):
    file_path: str = Field(min_length=1)
    min_len: int = Field(default=4, ge=1, le=4096)
    encoding: Literal["", "s", "S", "b", "l", "B", "L"] = ""
    additional_args: str = ""
    offset: int = Field(default=0, ge=0)
    length: int | None = Field(default=None, ge=0)
    max_scan_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_strings: int = Field(default=1000, ge=1, le=10000)
    include_resources: bool = False
    full_scan: bool = False
    async_mode: bool = False


class ObjdumpRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    disassemble: bool = True
    section: str = ""
    additional_args: str = ""


class ReadelfRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    headers: bool = True
    symbols: bool = False
    sections: bool = False
    all_info: bool = False
    additional_args: str = ""


class XxdRequest(BearBaseModel):
    file_path: str = Field(min_length=1)
    offset: str = "0"
    length: str = ""
    cols: int = 16
    reverse: bool = False
    additional_args: str = ""


class HexdumpRequest(BearBaseModel):
    file_path: str = Field(min_length=1)
    format_type: str = "canonical"
    offset: str = "0"
    length: str = ""
    additional_args: str = ""


class BinwalkRequest(BearBaseModel):
    file_path: str = Field(min_length=1)
    extract: bool = False
    signature: bool = False
    entropy: bool = False
    additional_args: str = ""


class RopgadgetRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    gadget_type: str = ""
    rop_chain: bool = False
    depth: int = 10
    additional_args: str = ""


class RopperRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    gadget_type: Literal["rop", "jop", "sys", "all"] = "rop"
    quality: int = 1
    arch: str = ""
    search_string: str = ""
    additional_args: str = ""


class OneGadgetRequest(BearBaseModel):
    libc_path: str = Field(min_length=1)
    level: int = 1
    additional_args: str = ""


class GdbRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    commands: str = ""
    script_file: str = ""
    additional_args: str = ""


class GdbEnhancedRequest(BearBaseModel):
    binary: str = ""
    commands: str = ""
    attach_pid: int = 0
    core_file: str = ""
    additional_args: str = ""


class Radare2Request(BearBaseModel):
    binary: str = Field(min_length=1)
    commands: str = ""
    additional_args: str = ""


class TriageRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    strings_limit: int = Field(default=40, ge=0, le=1000)
    use_cache: bool = True
    offset: int = Field(default=0, ge=0)
    length: int | None = Field(default=None, ge=0)
    max_scan_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    include_resources: bool = False
    full_scan: bool = False
    compute_hash: bool = False
    async_mode: bool = False


class GhidraRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    function: str = "all"
    timeout: int = Field(default=300, ge=1)
    async_mode: bool = False


class GhidraFunctionsRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    timeout: int = Field(default=300, ge=1)
    async_mode: bool = False


class GhidraXrefsRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    target: str = Field(min_length=1)
    direction: Literal["to", "from", "both"] = "both"
    target_type: Literal["auto", "function", "address", "string", "symbol"] = "auto"
    timeout: int = Field(default=300, ge=1)
    async_mode: bool = False


class GhidraCallgraphRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    function: str = "all"
    direction: Literal["out", "in", "both"] = "out"
    depth: int = Field(default=2, ge=1, le=10)
    timeout: int = Field(default=300, ge=1)
    async_mode: bool = False


class PwntoolsRequest(BearBaseModel):
    script_content: str = ""
    target_binary: str = ""
    target_host: str = ""
    target_port: int = 0
    exploit_type: str = "local"
    additional_args: str = ""


class LibcDatabaseRequest(BearBaseModel):
    action: Literal["find", "dump", "download"] = "find"
    symbols: str = ""
    libc_id: str = ""
    additional_args: str = ""


class PwninitRequest(BearBaseModel):
    binary: str = Field(min_length=1)
    libc: str = ""
    ld: str = ""
    template_type: str = "python"
    additional_args: str = ""
