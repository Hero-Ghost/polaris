"""
Polaris - Windows Minidump & Kernel Crash Dump Binary Parser
Pure Python implementation (zero-dependency, standard library struct & os).
Parses standard user/kernel minidumps (MDMP), 64-bit & 32-bit Kernel dumps (PAGEDU64 / PAGEDUMP),
and extracts BugCheck codes, parameters, exception addresses, and maps them to loaded driver modules.
"""

import os
import sys
import struct
import datetime
import subprocess
from typing import Dict, List, Any, Optional, Tuple

# Constants for Minidump Stream Types
STREAM_UNUSED = 0
STREAM_RESERVED0 = 1
STREAM_RESERVED1 = 2
STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_MEMORY_LIST = 5
STREAM_EXCEPTION = 6
STREAM_SYSTEM_INFO = 7
STREAM_THREAD_EX_LIST = 8
STREAM_MEMORY_64_LIST = 9
STREAM_COMMENT_A = 10
STREAM_COMMENT_W = 11
STREAM_HANDLE_DATA = 12
STREAM_FUNCTION_TABLE = 13
STREAM_UNLOADED_MODULE_LIST = 14
STREAM_MISC_INFO = 15
STREAM_MEMORY_INFO_LIST = 16
STREAM_THREAD_INFO_LIST = 17
STREAM_HANDLE_OPERATION_LIST = 18
STREAM_TOKEN = 19
STREAM_JAVASCRIPT_DATA = 20
STREAM_SYSTEM_MEMORY_INFO = 21
STREAM_PROCESS_VM_COUNTERS = 22
STREAM_THREAD_NAMES = 24
STREAM_BUGCHECK = 0x20000

ARCH_NAMES = {
    0: "x86 (32-bit)",
    5: "ARM",
    6: "Itanium",
    9: "x64 (AMD64)",
    12: "ARM64"
}

MACHINE_IMAGE_TYPES = {
    0x014c: "x86 (32-bit)",
    0x8664: "x64 (AMD64)",
    0xaa64: "ARM64"
}


class MinidumpParser:
    """
    Parses Windows Minidump (.dmp) and Kernel Dump binary files without requiring WinDbg.
    Extracts BugCheck codes, 4 parameters, faulting instruction addresses, OS build info,
    and all loaded driver modules with base memory addresses.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.raw_data: bytes = b""
        self.file_size = 0
        self.is_valid = False
        self.format_type = "UNKNOWN"
        self.bugcheck_code = 0
        self.bugcheck_params: List[int] = [0, 0, 0, 0]
        self.exception_code = 0
        self.exception_address = 0
        self.context_rip = 0
        self.context_rsp = 0
        self.os_version = ""
        self.os_build = 0
        self.architecture = "Unknown"
        self.crash_time: Optional[str] = None
        self.modules: List[Dict[str, Any]] = []
        self.unloaded_modules: List[Dict[str, Any]] = []
        self.streams: Dict[int, Dict[str, int]] = {}
        self.culprit_driver: Optional[Dict[str, Any]] = None
        self.debug_output: List[str] = []

    def parse(self) -> Dict[str, Any]:
        """
        Reads and parses the dump file. Returns structured metadata dictionary.
        """
        if not os.path.exists(self.file_path):
            return {
                "success": False,
                "error": f"File not found: {self.file_path}",
                "file_path": self.file_path
            }

        try:
            self.file_size = os.path.getsize(self.file_path)
            if self.file_size < 32:
                return {
                    "success": False,
                    "error": "File too small to be a valid dump file",
                    "file_path": self.file_path
                }

            with open(self.file_path, "rb") as f:
                # Read header
                header_bytes = f.read(min(8192, self.file_size))

            # Detect format by magic bytes
            if header_bytes.startswith(b"MDMP"):
                self.format_type = "MDMP"
                self._parse_mdmp()
            elif header_bytes.startswith(b"PAGEDU64") or header_bytes.startswith(b"PAGE64") or header_bytes.startswith(b"DU64"):
                self.format_type = "KERNEL_DUMP64"
                self._parse_kernel_dump64(header_bytes)
            elif header_bytes.startswith(b"PAGEDUMP") or header_bytes.startswith(b"PAGE"):
                self.format_type = "KERNEL_DUMP32"
                self._parse_kernel_dump32(header_bytes)
            else:
                # Scan for MDMP signature in case of wrapping headers
                offset = header_bytes.find(b"MDMP")
                if offset != -1:
                    self.format_type = "MDMP"
                    self._parse_mdmp(start_offset=offset)
                else:
                    return {
                        "success": False,
                        "error": "Unrecognized dump signature (not MDMP or PAGEDUMP)",
                        "file_path": self.file_path,
                        "file_size": self.file_size
                    }

            # Map the faulting address to the loaded driver modules
            self._resolve_culprit_module()

            return self.to_dict()

        except Exception as e:
            return {
                "success": False,
                "error": f"Error parsing dump file: {str(e)}",
                "file_path": self.file_path,
                "file_size": self.file_size
            }

    def _parse_mdmp(self, start_offset: int = 0):
        """
        Parses standard MDMP minidump file.
        """
        with open(self.file_path, "rb") as f:
            f.seek(start_offset)
            hdr_data = f.read(32)
            if len(hdr_data) < 32:
                return

            sig, version, num_streams, stream_dir_rva, checksum, time_stamp, flags = struct.unpack(
                "<4sIIIIIQ", hdr_data
            )

            if sig != b"MDMP":
                return

            self.is_valid = True
            if time_stamp > 0:
                try:
                    self.crash_time = datetime.datetime.fromtimestamp(
                        time_stamp, tz=datetime.timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    pass

            # Read Stream Directory
            f.seek(start_offset + stream_dir_rva)
            dir_data = f.read(num_streams * 12)

            for i in range(num_streams):
                if (i + 1) * 12 > len(dir_data):
                    break
                stream_type, data_size, rva = struct.unpack(
                    "<III", dir_data[i * 12 : (i + 1) * 12]
                )
                self.streams[stream_type] = {"size": data_size, "rva": rva}

            # 1. Parse System Info Stream
            if STREAM_SYSTEM_INFO in self.streams:
                sys_entry = self.streams[STREAM_SYSTEM_INFO]
                f.seek(start_offset + sys_entry["rva"])
                sys_data = f.read(min(sys_entry["size"], 56))
                if len(sys_data) >= 24:
                    arch, level, rev, num_cpus, prod_type, maj, min_, build, plat, csd_rva = struct.unpack(
                        "<HHHBBIIIII", sys_data[:28] if len(sys_data) >= 28 else sys_data[:24] + b"\x00"*4
                    )
                    self.architecture = ARCH_NAMES.get(arch, f"Arch({arch})")
                    self.os_build = build
                    self.os_version = f"Windows {maj}.{min_} (Build {build})"

            # 2. Parse Exception Stream
            if STREAM_EXCEPTION in self.streams:
                exc_entry = self.streams[STREAM_EXCEPTION]
                f.seek(start_offset + exc_entry["rva"])
                exc_data = f.read(exc_entry["size"])
                if len(exc_data) >= 32:
                    # ThreadId (4), align (4), ExceptionCode (4), ExceptionFlags (4), Record (8), Address (8)
                    thread_id, _, exc_code, exc_flags, exc_record, exc_addr = struct.unpack(
                        "<IIIIQQ", exc_data[:32]
                    )
                    self.exception_code = exc_code
                    self.exception_address = exc_addr
                    if self.bugcheck_code == 0 and exc_code != 0:
                        self.bugcheck_code = exc_code

                    # If bugcheck parameters exist inside ExceptionInformation array (up to 15 QWORDs)
                    if len(exc_data) >= 40:
                        num_params = struct.unpack("<I", exc_data[32:36])[0]
                        num_params = min(num_params, 4)
                        if len(exc_data) >= 40 + num_params * 8:
                            for p_idx in range(num_params):
                                param_val = struct.unpack("<Q", exc_data[40 + p_idx * 8 : 48 + p_idx * 8])[0]
                                self.bugcheck_params[p_idx] = param_val

                    # Read Context Record (contains RIP/EIP register)
                    if len(exc_data) >= 168:
                        context_size, context_rva = struct.unpack("<II", exc_data[160:168])
                        if context_rva > 0 and context_size > 0:
                            f.seek(start_offset + context_rva)
                            ctx_data = f.read(min(context_size, 1200))
                            # x64 context: RIP is at offset 0xF8 (248)
                            if len(ctx_data) >= 256:
                                self.context_rip = struct.unpack("<Q", ctx_data[248:256])[0]
                                self.context_rsp = struct.unpack("<Q", ctx_data[152:160])[0]

            # 3. Parse Module List Stream
            if STREAM_MODULE_LIST in self.streams:
                mod_entry = self.streams[STREAM_MODULE_LIST]
                f.seek(start_offset + mod_entry["rva"])
                mod_count_data = f.read(4)
                if len(mod_count_data) == 4:
                    num_modules = struct.unpack("<I", mod_count_data)[0]
                    # Each module entry is 108 bytes
                    for m_idx in range(min(num_modules, 1024)):
                        f.seek(start_offset + mod_entry["rva"] + 4 + (m_idx * 108))
                        m_data = f.read(108)
                        if len(m_data) < 108:
                            break

                        base_of_img, size_of_img, checksum, ts, name_rva = struct.unpack(
                            "<QIIII", m_data[:24]
                        )
                        # Read Fixed File Version (VS_FIXEDFILEINFO) at offset 24..76
                        file_ver_ms, file_ver_ls = struct.unpack("<II", m_data[32:40])
                        ver_major = file_ver_ms >> 16
                        ver_minor = file_ver_ms & 0xFFFF
                        ver_build = file_ver_ls >> 16
                        ver_rev = file_ver_ls & 0xFFFF
                        ver_str = f"{ver_major}.{ver_minor}.{ver_build}.{ver_rev}" if ver_major > 0 else ""

                        # Read Module Name from MINIDUMP_STRING (Length uint32 followed by UTF-16LE characters)
                        f.seek(start_offset + name_rva)
                        name_len_data = f.read(4)
                        mod_name = ""
                        if len(name_len_data) == 4:
                            name_len = struct.unpack("<I", name_len_data)[0]
                            name_bytes = f.read(min(name_len, 512))
                            try:
                                mod_name = name_bytes.decode("utf-16-le", errors="ignore").rstrip("\x00")
                            except Exception:
                                mod_name = ""

                        clean_filename = os.path.basename(mod_name.replace("/", "\\")) if mod_name else f"module_{m_idx}"

                        mod_ts_str = ""
                        if ts > 0:
                            try:
                                mod_ts_str = datetime.datetime.fromtimestamp(
                                    ts, tz=datetime.timezone.utc
                                ).strftime("%Y-%m-%d")
                            except Exception:
                                pass

                        self.modules.append({
                            "name": clean_filename.lower(),
                            "path": mod_name,
                            "base_address": base_of_img,
                            "base_address_hex": f"0x{base_of_img:016X}",
                            "size": size_of_img,
                            "size_kb": round(size_of_img / 1024, 1),
                            "end_address": base_of_img + size_of_img,
                            "end_address_hex": f"0x{(base_of_img + size_of_img):016X}",
                            "timestamp": mod_ts_str,
                            "version": ver_str,
                            "checksum": hex(checksum)
                        })

            # 4. Parse Unloaded Module List Stream
            if STREAM_UNLOADED_MODULE_LIST in self.streams:
                unloaded_entry = self.streams[STREAM_UNLOADED_MODULE_LIST]
                f.seek(start_offset + unloaded_entry["rva"])
                un_data = f.read(unloaded_entry["size"])
                if len(un_data) >= 8:
                    size_of_header, size_of_entry, num_entries = struct.unpack("<III", un_data[:12]) if len(un_data) >= 12 else (0,0,0)
                    # Track unloaded modules if needed
                    pass

    def _parse_kernel_dump64(self, header_bytes: bytes):
        """
        Parses 64-bit Kernel Crash Dump (_DMP_HEADER64).
        """
        self.is_valid = True
        self.architecture = "x64 (AMD64)"

        # Offset 0x08: MajorVersion (4), MinorVersion (4)
        if len(header_bytes) >= 16:
            maj, min_ = struct.unpack("<II", header_bytes[8:16])
            self.os_version = f"Windows Kernel {maj}.{min_}"

        # Offset 0x28: BugCheckCode (4 bytes uint32)
        if len(header_bytes) >= 44:
            self.bugcheck_code = struct.unpack("<I", header_bytes[0x28 : 0x2C])[0]

        # Offset 0x30: BugCheckCodeParameter (4 * 8 bytes QWORDs)
        if len(header_bytes) >= 0x30 + 32:
            p1, p2, p3, p4 = struct.unpack("<QQQQ", header_bytes[0x30 : 0x30 + 32])
            self.bugcheck_params = [p1, p2, p3, p4]

        # Offset 0xF8: MachineImageType
        if len(header_bytes) >= 0xF8 + 4:
            mach_type = struct.unpack("<I", header_bytes[0xF8 : 0xFC])[0]
            self.architecture = MACHINE_IMAGE_TYPES.get(mach_type, self.architecture)

        # Offset 0x50: ExceptionRecord64 (ExceptionCode 4, ExceptionFlags 4, Record 8, Address 8)
        if len(header_bytes) >= 0x50 + 24:
            e_code, _, _, e_addr = struct.unpack("<IIQQ", header_bytes[0x50 : 0x50 + 24])
            self.exception_code = e_code
            self.exception_address = e_addr

    def _parse_kernel_dump32(self, header_bytes: bytes):
        """
        Parses 32-bit Kernel Crash Dump (_DMP_HEADER).
        """
        self.is_valid = True
        self.architecture = "x86 (32-bit)"

        # Offset 0x38: BugCheckCode (4 bytes uint32)
        if len(header_bytes) >= 0x3C:
            self.bugcheck_code = struct.unpack("<I", header_bytes[0x38 : 0x3C])[0]

        # Offset 0x40: BugCheckCodeParameter (4 * 4 bytes DWORDs)
        if len(header_bytes) >= 0x40 + 16:
            p1, p2, p3, p4 = struct.unpack("<IIII", header_bytes[0x40 : 0x40 + 16])
            self.bugcheck_params = [p1, p2, p3, p4]

    def _resolve_culprit_module(self):
        """
        Maps the exception address, RIP register, or BugCheck parameters
        to the exact driver module that caused the crash.
        """
        target_addresses = []

        # 1. Priority 1: RIP from Context Record
        if self.context_rip > 0:
            target_addresses.append(("Context RIP", self.context_rip))

        # 2. Priority 2: Exception Address from Exception Record
        if self.exception_address > 0:
            target_addresses.append(("Exception Address", self.exception_address))

        # 3. Priority 3: BugCheck-specific parameter addresses
        # 0xD1 / 0x0A: Param 4 is the instruction address
        # 0x7E: Param 2 is the exception address
        # 0x50: Param 4 is trap frame/instruction
        code = self.bugcheck_code & 0xFFFFFFFF
        if code in (0x0A, 0xD1, 0x1000000A, 0x100000D1) and self.bugcheck_params[3] > 0:
            target_addresses.append(("BugCheck Param 4 (Instruction)", self.bugcheck_params[3]))
        elif code in (0x7E, 0x1000007E) and self.bugcheck_params[1] > 0:
            target_addresses.append(("BugCheck Param 2 (Exception Address)", self.bugcheck_params[1]))
        elif code in (0x50, 0x10000050) and self.bugcheck_params[3] > 0:
            target_addresses.append(("BugCheck Param 4 (Trap/Code)", self.bugcheck_params[3]))

        # Look up each candidate address in the loaded modules list
        for addr_label, addr in target_addresses:
            for mod in self.modules:
                base = mod["base_address"]
                end = mod["end_address"]
                if base <= addr < end:
                    offset = addr - base
                    self.culprit_driver = {
                        "name": mod["name"],
                        "path": mod["path"],
                        "base_address_hex": mod["base_address_hex"],
                        "offset_hex": f"+0x{offset:X}",
                        "version": mod.get("version", ""),
                        "timestamp": mod.get("timestamp", ""),
                        "matched_by": addr_label,
                        "faulting_address_hex": f"0x{addr:016X}" if self.architecture != "x86 (32-bit)" else f"0x{addr:08X}"
                    }
                    return

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes parsed dump data into an informative dictionary.
        """
        code_hex = f"0x{self.bugcheck_code:08X}" if self.bugcheck_code else "0x0"
        return {
            "success": self.is_valid,
            "format_type": self.format_type,
            "file_path": self.file_path,
            "file_name": os.path.basename(self.file_path),
            "file_size_bytes": self.file_size,
            "file_size_kb": round(self.file_size / 1024, 1),
            "crash_time": self.crash_time,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "architecture": self.architecture,
            "bugcheck_code": code_hex,
            "bugcheck_code_raw": self.bugcheck_code,
            "bugcheck_parameters": [f"0x{p:X}" for p in self.bugcheck_params],
            "bugcheck_parameters_raw": self.bugcheck_params,
            "exception_code": f"0x{self.exception_code:08X}" if self.exception_code else None,
            "exception_address": f"0x{self.exception_address:X}" if self.exception_address else None,
            "context_rip": f"0x{self.context_rip:X}" if self.context_rip else None,
            "culprit_driver": self.culprit_driver,
            "total_modules_loaded": len(self.modules),
            "modules": self.modules
        }


def analyze_dump_file_with_windbg_fallback(file_path: str) -> Dict[str, Any]:
    """
    Analyzes a dump file using the built-in pure Python parser,
    with an optional deep analysis pass using cdb.exe/windbg.exe if installed.
    """
    parser = MinidumpParser(file_path)
    result = parser.parse()

    # Optional WinDbg / CDB enrichment if tools are installed locally
    cdb_paths = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe"
    ]
    cdb_executable = None
    for p in cdb_paths:
        if os.path.exists(p):
            cdb_executable = p
            break

    if cdb_executable and os.path.exists(file_path):
        try:
            cmd = [cdb_executable, "-z", file_path, "-c", "!analyze -v; q"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if proc.returncode == 0 and proc.stdout:
                result["windbg_raw_analysis"] = proc.stdout[:8000]
                result["has_windbg_output"] = True
        except Exception:
            pass

    return result
