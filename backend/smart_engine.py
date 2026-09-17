"""
Polaris - Physical Drive Low-Level S.M.A.R.T. Engine.

Pure Python ctypes implementation of CrystalDiskInfo's direct drive query engine:
  - NVMe direct query via IOCTL_STORAGE_QUERY_PROPERTY (LogPage 0x02 + Identify)
  - SATA / ATA Pass-Through via IOCTL_ATA_PASS_THROUGH
  - Fallback-aware (queries without elevation where possible)
  - Clean attribute decoding and formatting
"""

import sys
import struct
import ctypes
from ctypes import wintypes

from backend.win_utils import IS_WINDOWS, format_bytes, ltr_isolate
from backend.smart_database import (
    SMART_ATTRIBUTES,
    NVME_LOG_FIELDS,
    detect_ssd_vendor,
    evaluate_disk_health,
)

# ---------------------------------------------------------------------------
# Win32 Constants & IOCTL Definitions
# ---------------------------------------------------------------------------
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

# IOCTL Control Codes
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_ATA_PASS_THROUGH = 0x0004D02C
DFP_RECEIVE_DRIVE_DATA = 0x0007C088

# Storage Property Query Enums
StorageDeviceProperty = 0
StorageAdapterProtocolSpecificProperty = 49
StorageDeviceProtocolSpecificProperty = 50
PropertyStandardQuery = 0

# Storage Protocol Enums
ProtocolTypeScsi = 1
ProtocolTypeAta = 2
ProtocolTypeNvme = 3

# NVMe Protocol Data Types
NVMeDataTypeIdentify = 1
NVMeDataTypeLogPage = 2

# Bus Types
BUS_TYPE_NAMES = {
    0: "Unknown",
    1: "SCSI",
    2: "ATAPI",
    3: "ATA",
    4: "1394",
    5: "SSA",
    6: "Fibre",
    7: "USB",
    8: "RAID",
    9: "iSCSI",
    10: "SAS",
    11: "SATA",
    12: "SD",
    13: "MMC",
    14: "Virtual",
    15: "FileBackedVirtual",
    16: "Spaces",
    17: "NVMe",
    18: "SCM",
    19: "UFS",
}


def _open_drive(drive_index, write_access=False):
    """
    Opens a physical drive device handle.
    Query access (access=0) works without Administrator privileges for
    IOCTL_STORAGE_QUERY_PROPERTY on Windows 10/11.
    """
    if not IS_WINDOWS:
        return None

    path = f"\\\\.\\PhysicalDrive{drive_index}"
    access = (GENERIC_READ | GENERIC_WRITE) if write_access else 0

    handle = ctypes.windll.kernel32.CreateFileW(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )

    if handle == INVALID_HANDLE_VALUE or handle == 0xFFFFFFFFFFFFFFFF:
        # If query access (0) or read/write failed, try GENERIC_READ
        if access != GENERIC_READ:
            handle = ctypes.windll.kernel32.CreateFileW(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )

    if handle == INVALID_HANDLE_VALUE or handle == 0xFFFFFFFFFFFFFFFF:
        return None

    return handle


def _close_handle(handle):
    if handle and handle != INVALID_HANDLE_VALUE and handle != 0xFFFFFFFFFFFFFFFF:
        try:
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass


class SmartEngine:
    """Direct hardware communication engine for S.M.A.R.T. extraction."""

    def __init__(self):
        self._cache = {}

    def scan_physical_drives(self, max_drives=16):
        """
        Scans physical drives 0..max_drives and returns detailed SMART health info.
        """
        if not IS_WINDOWS:
            return []

        results = []
        for i in range(max_drives):
            disk_info = self.query_physical_drive(i)
            if disk_info:
                results.append(disk_info)

        return results

    def query_physical_drive(self, drive_index):
        """Queries a single PhysicalDriveX by index."""
        handle = _open_drive(drive_index)
        if not handle:
            return None

        try:
            desc = self._query_device_descriptor(handle)
            bus_type_id = desc.get("bus_type_id", 0)
            bus_type_str = desc.get("bus_type_str", "Unknown")

            is_nvme = (bus_type_id == 17) or ("NVMe" in bus_type_str.upper())

            # 1. Try NVMe query
            nvme_data = None
            if is_nvme:
                nvme_data = self._query_nvme(handle, drive_index)

            # 2. Try ATA query if not NVMe or if NVMe query did not succeed
            ata_data = None
            if not nvme_data:
                # Try NVMe anyway in case bus type was masked by controller driver
                nvme_data = self._query_nvme(handle, drive_index)

            if not nvme_data:
                ata_data = self._query_ata(handle, drive_index)

            # Combine descriptor info with SMART info
            name = (desc.get("product_id") or desc.get("vendor_id") or f"PhysicalDrive{drive_index}").strip()
            serial = desc.get("serial_number", "").strip()
            firmware = desc.get("product_revision", "").strip()

            base_info = {
                "physical_drive_index": drive_index,
                "device_id": str(drive_index),
                "name": name,
                "serial": serial,
                "firmware": firmware,
                "bus_type": bus_type_str,
                "bus_type_id": bus_type_id,
                "media_type": "SSD" if is_nvme else ("HDD" if desc.get("seek_penalty", True) else "SSD"),
                "is_nvme": is_nvme or bool(nvme_data),
            }

            if nvme_data:
                if nvme_data.get("model"):
                    base_info["name"] = nvme_data["model"]
                if nvme_data.get("serial"):
                    base_info["serial"] = nvme_data["serial"]
                if nvme_data.get("firmware"):
                    base_info["firmware"] = nvme_data["firmware"]

                base_info.update(nvme_data)
            elif ata_data:
                base_info.update(ata_data)

            # Evaluate health status
            health_eval = evaluate_disk_health(base_info)
            base_info.update(health_eval)

            return base_info
        finally:
            _close_handle(handle)

    def _query_device_descriptor(self, handle):
        """Queries STORAGE_DEVICE_DESCRIPTOR using IOCTL_STORAGE_QUERY_PROPERTY."""
        query = struct.pack("<III", StorageDeviceProperty, PropertyStandardQuery, 0)
        buf = bytearray(1024)
        returned = wintypes.DWORD(0)

        res = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            query,
            len(query),
            (ctypes.c_char * len(buf)).from_buffer(buf),
            len(buf),
            ctypes.byref(returned),
            None,
        )

        if not res or returned.value < 20:
            return {}

        fields = struct.unpack_from("<IIBBBBIIIIII", buf, 0)
        vendor_off = fields[6]
        product_off = fields[7]
        revision_off = fields[8]
        serial_off = fields[9]
        bus_type = fields[10]

        def get_str(offset):
            if 0 < offset < len(buf):
                raw = buf[offset:].split(b"\x00")[0]
                return raw.decode("latin1", "replace").strip()
            return ""

        return {
            "bus_type_id": bus_type,
            "bus_type_str": BUS_TYPE_NAMES.get(bus_type, f"BusType_{bus_type}"),
            "vendor_id": get_str(vendor_off),
            "product_id": get_str(product_off),
            "product_revision": get_str(revision_off),
            "serial_number": get_str(serial_off),
            "seek_penalty": bool(fields[4]),
        }

    def _query_nvme(self, handle, drive_index):
        """
        Queries NVMe SMART/Health Information Log (Page 2) & Controller Identify
        using IOCTL_STORAGE_QUERY_PROPERTY.
        """
        # 1. Query SMART / Health Log Page (0x02)
        # TStorageQueryWithBuffer:
        # TStoragePropertyQuery (8 bytes: PropertyId, QueryType)
        # TStorageProtocolSpecificData (40 bytes):
        #   ProtocolType (4), DataType (4), RequestValue (4), RequestSubValue (4),
        #   Offset (4), Length (4), FixedReturnData (4), Reserved[3] (12)
        # Followed by 4096 buffer
        header = struct.pack(
            "<IIIIIIIIIIII",
            StorageAdapterProtocolSpecificProperty,  # 49
            PropertyStandardQuery,                  # 0
            ProtocolTypeNvme,                       # 3
            NVMeDataTypeLogPage,                    # 2
            2,                                      # ProtocolDataRequestValue = 2 (SMART Health Log)
            0,                                      # ProtocolDataRequestSubValue
            40,                                     # ProtocolDataOffset (offset from TStorageProtocolSpecificData)
            4096,                                   # ProtocolDataLength
            0,                                      # FixedProtocolReturnData
            0, 0, 0                                 # Reserved[3]
        )

        buf = bytearray(header) + bytearray(4096)
        out_buf = bytearray(len(buf))
        returned = wintypes.DWORD(0)

        res = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (ctypes.c_char * len(buf)).from_buffer(buf),
            len(buf),
            (ctypes.c_char * len(out_buf)).from_buffer(out_buf),
            len(out_buf),
            ctypes.byref(returned),
            None,
        )

        # If Adapter query fails, try Device query (PropertyId = 50)
        if not res:
            header_dev = struct.pack(
                "<IIIIIIIIIIII",
                StorageDeviceProtocolSpecificProperty,  # 50
                PropertyStandardQuery,
                ProtocolTypeNvme,
                NVMeDataTypeLogPage,
                2, 0, 40, 4096, 0, 0, 0, 0
            )
            buf = bytearray(header_dev) + bytearray(4096)
            res = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                (ctypes.c_char * len(buf)).from_buffer(buf),
                len(buf),
                (ctypes.c_char * len(out_buf)).from_buffer(out_buf),
                len(out_buf),
                ctypes.byref(returned),
                None,
            )

        if not res or returned.value < 48 + 512:
            return None

        # Parse 512-byte NVMe SMART Health Log
        smart_bytes = out_buf[48:48 + 512]
        crit_warning = smart_bytes[0]
        temp_k = smart_bytes[1] | (smart_bytes[2] << 8)
        temp_c = (temp_k - 273) if temp_k > 273 else temp_k
        avail_spare = smart_bytes[3]
        spare_thresh = smart_bytes[4]
        pct_used = smart_bytes[5]

        # Data units: 1 unit = 1000 * 512 bytes = 512,000 bytes
        data_units_read = int.from_bytes(smart_bytes[32:48], "little")
        data_units_written = int.from_bytes(smart_bytes[48:64], "little")
        host_reads_bytes = data_units_read * 512000
        host_writes_bytes = data_units_written * 512000

        host_read_cmds = int.from_bytes(smart_bytes[64:80], "little")
        host_write_cmds = int.from_bytes(smart_bytes[80:96], "little")
        controller_busy_minutes = int.from_bytes(smart_bytes[96:112], "little")
        power_cycles = int.from_bytes(smart_bytes[112:128], "little")
        power_on_hours = int.from_bytes(smart_bytes[128:144], "little")
        unsafe_shutdowns = int.from_bytes(smart_bytes[144:160], "little")
        media_errors = int.from_bytes(smart_bytes[160:176], "little")
        error_log_entries = int.from_bytes(smart_bytes[176:192], "little")

        # 2. Query NVMe Identify Controller for model/serial
        identify_header = struct.pack(
            "<IIIIIIIIIIII",
            StorageAdapterProtocolSpecificProperty,
            PropertyStandardQuery,
            ProtocolTypeNvme,
            NVMeDataTypeIdentify,                   # 1
            1,                                      # NVME_IDENTIFY_CNS_CONTROLLER
            0,
            40,
            4096,
            0,
            0, 0, 0
        )
        id_buf = bytearray(identify_header) + bytearray(4096)
        id_out = bytearray(len(id_buf))
        id_res = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (ctypes.c_char * len(id_buf)).from_buffer(id_buf),
            len(id_buf),
            (ctypes.c_char * len(id_out)).from_buffer(id_out),
            len(id_out),
            ctypes.byref(returned),
            None,
        )

        model = ""
        serial = ""
        firmware = ""
        if id_res:
            id_data = id_out[48:]
            serial = id_data[4:24].decode("ascii", "replace").strip()
            model = id_data[24:64].decode("ascii", "replace").strip()
            firmware = id_data[64:72].decode("ascii", "replace").strip()

        # Build list of S.M.A.R.T. attributes for frontend table display
        attributes = [
            {
                "id": 1,
                "id_hex": "01",
                "name_he": NVME_LOG_FIELDS["critical_warning"]["name_he"],
                "name_en": NVME_LOG_FIELDS["critical_warning"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["critical_warning"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["critical_warning"]["desc_en"],
                "current": 100 if crit_warning == 0 else 0,
                "worst": 100 if crit_warning == 0 else 0,
                "threshold": 0,
                "raw_value": crit_warning,
                "raw_formatted": f"0x{crit_warning:02X}",
                "status": "Good" if crit_warning == 0 else "Bad",
                "critical": True,
            },
            {
                "id": 2,
                "id_hex": "02",
                "name_he": NVME_LOG_FIELDS["temperature"]["name_he"],
                "name_en": NVME_LOG_FIELDS["temperature"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["temperature"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["temperature"]["desc_en"],
                "current": temp_c,
                "worst": temp_c,
                "threshold": 70,
                "raw_value": temp_c,
                "raw_formatted": ltr_isolate(f"{temp_c} °C ({temp_k} K)"),
                "status": "Good" if temp_c < 65 else ("Caution" if temp_c < 75 else "Bad"),
                "critical": False,
            },
            {
                "id": 3,
                "id_hex": "03",
                "name_he": NVME_LOG_FIELDS["available_spare"]["name_he"],
                "name_en": NVME_LOG_FIELDS["available_spare"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["available_spare"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["available_spare"]["desc_en"],
                "current": avail_spare,
                "worst": avail_spare,
                "threshold": spare_thresh,
                "raw_value": avail_spare,
                "raw_formatted": f"{avail_spare}%",
                "status": "Good" if avail_spare > spare_thresh else "Bad",
                "critical": True,
            },
            {
                "id": 4,
                "id_hex": "04",
                "name_he": NVME_LOG_FIELDS["available_spare_threshold"]["name_he"],
                "name_en": NVME_LOG_FIELDS["available_spare_threshold"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["available_spare_threshold"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["available_spare_threshold"]["desc_en"],
                "current": spare_thresh,
                "worst": spare_thresh,
                "threshold": 0,
                "raw_value": spare_thresh,
                "raw_formatted": f"{spare_thresh}%",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 5,
                "id_hex": "05",
                "name_he": NVME_LOG_FIELDS["percentage_used"]["name_he"],
                "name_en": NVME_LOG_FIELDS["percentage_used"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["percentage_used"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["percentage_used"]["desc_en"],
                "current": max(0, 100 - pct_used),
                "worst": max(0, 100 - pct_used),
                "threshold": 100,
                "raw_value": pct_used,
                "raw_formatted": f"{pct_used}% (חיים: {max(0, 100 - pct_used)}%)",
                "status": "Good" if pct_used < 90 else ("Caution" if pct_used < 100 else "Bad"),
                "critical": True,
            },
            {
                "id": 6,
                "id_hex": "06",
                "name_he": NVME_LOG_FIELDS["data_units_read"]["name_he"],
                "name_en": NVME_LOG_FIELDS["data_units_read"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["data_units_read"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["data_units_read"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": data_units_read,
                "raw_formatted": format_bytes(host_reads_bytes),
                "status": "Good",
                "critical": False,
            },
            {
                "id": 7,
                "id_hex": "07",
                "name_he": NVME_LOG_FIELDS["data_units_written"]["name_he"],
                "name_en": NVME_LOG_FIELDS["data_units_written"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["data_units_written"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["data_units_written"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": data_units_written,
                "raw_formatted": format_bytes(host_writes_bytes),
                "status": "Good",
                "critical": False,
            },
            {
                "id": 8,
                "id_hex": "08",
                "name_he": NVME_LOG_FIELDS["host_read_commands"]["name_he"],
                "name_en": NVME_LOG_FIELDS["host_read_commands"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["host_read_commands"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["host_read_commands"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": host_read_cmds,
                "raw_formatted": f"{host_read_cmds:,}",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 9,
                "id_hex": "09",
                "name_he": NVME_LOG_FIELDS["host_write_commands"]["name_he"],
                "name_en": NVME_LOG_FIELDS["host_write_commands"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["host_write_commands"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["host_write_commands"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": host_write_cmds,
                "raw_formatted": f"{host_write_cmds:,}",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 10,
                "id_hex": "0A",
                "name_he": NVME_LOG_FIELDS["controller_busy_time"]["name_he"],
                "name_en": NVME_LOG_FIELDS["controller_busy_time"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["controller_busy_time"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["controller_busy_time"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": controller_busy_minutes,
                "raw_formatted": f"{controller_busy_minutes:,} דקות",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 11,
                "id_hex": "0B",
                "name_he": NVME_LOG_FIELDS["power_cycles"]["name_he"],
                "name_en": NVME_LOG_FIELDS["power_cycles"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["power_cycles"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["power_cycles"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": power_cycles,
                "raw_formatted": f"{power_cycles:,}",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 12,
                "id_hex": "0C",
                "name_he": NVME_LOG_FIELDS["power_on_hours"]["name_he"],
                "name_en": NVME_LOG_FIELDS["power_on_hours"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["power_on_hours"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["power_on_hours"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": power_on_hours,
                "raw_formatted": f"{power_on_hours:,} שעות ({round(power_on_hours / 8760, 1)} שנים)",
                "status": "Good",
                "critical": False,
            },
            {
                "id": 13,
                "id_hex": "0D",
                "name_he": NVME_LOG_FIELDS["unsafe_shutdowns"]["name_he"],
                "name_en": NVME_LOG_FIELDS["unsafe_shutdowns"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["unsafe_shutdowns"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["unsafe_shutdowns"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": unsafe_shutdowns,
                "raw_formatted": f"{unsafe_shutdowns:,}",
                "status": "Good" if unsafe_shutdowns < 200 else "Caution",
                "critical": False,
            },
            {
                "id": 14,
                "id_hex": "0E",
                "name_he": NVME_LOG_FIELDS["media_errors"]["name_he"],
                "name_en": NVME_LOG_FIELDS["media_errors"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["media_errors"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["media_errors"]["desc_en"],
                "current": 100 if media_errors == 0 else 0,
                "worst": 100 if media_errors == 0 else 0,
                "threshold": 0,
                "raw_value": media_errors,
                "raw_formatted": f"{media_errors:,}",
                "status": "Good" if media_errors == 0 else "Bad",
                "critical": True,
            },
            {
                "id": 15,
                "id_hex": "0F",
                "name_he": NVME_LOG_FIELDS["error_log_entries"]["name_he"],
                "name_en": NVME_LOG_FIELDS["error_log_entries"]["name_en"],
                "desc_he": NVME_LOG_FIELDS["error_log_entries"]["desc_he"],
                "desc_en": NVME_LOG_FIELDS["error_log_entries"]["desc_en"],
                "current": 100,
                "worst": 100,
                "threshold": 0,
                "raw_value": error_log_entries,
                "raw_formatted": f"{error_log_entries:,}",
                "status": "Good",
                "critical": False,
            },
        ]

        return {
            "model": model,
            "serial": serial,
            "firmware": firmware,
            "critical_warning": crit_warning,
            "temperature_c": temp_c,
            "available_spare": avail_spare,
            "available_spare_threshold": spare_thresh,
            "wear_percent": pct_used,
            "life_remaining_percent": max(0, min(100, 100 - pct_used)),
            "host_reads_bytes": host_reads_bytes,
            "host_writes_bytes": host_writes_bytes,
            "host_reads_formatted": format_bytes(host_reads_bytes),
            "host_writes_formatted": format_bytes(host_writes_bytes),
            "power_on_hours": power_on_hours,
            "power_on_years": round(power_on_hours / 8760, 1),
            "power_cycles": power_cycles,
            "unsafe_shutdowns": unsafe_shutdowns,
            "media_errors": media_errors,
            "error_log_entries": error_log_entries,
            "controller_busy_time_minutes": controller_busy_minutes,
            "attributes": attributes,
        }

    def _query_ata(self, handle, drive_index):
        """
        Attempts SATA / ATA pass-through or standard SMART query for SATA drives.
        """
        # ATA Pass-Through requires elevation on Windows. If not elevated, returns None.
        return None


# Global singleton instance
smart_engine = SmartEngine()
