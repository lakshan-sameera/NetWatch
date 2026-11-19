"""
Minimal real-time ETW (Event Tracing for Windows) consumer built on ctypes.
No third-party dependencies. Requires Administrator.

Providers used:
  Microsoft-Windows-Kernel-Network  TCP connect/accept/disconnect + UDP sends (every connection,
                                    even ones that live for a few milliseconds)
  Microsoft-Windows-DNS-Client      per-process DNS queries and their answers
  Microsoft-Windows-WinINet /
  Microsoft-Windows-WinHttp /
  Microsoft-Windows-WebIO           URLs requested through the Windows HTTP stacks (pre-TLS)
  Microsoft-Windows-Kernel-Process  process start/stop (with parent PID) and image (DLL) loads
"""
import ctypes
import ctypes.wintypes as wt
import socket
import struct
import threading
import uuid

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
tdh = ctypes.WinDLL("tdh")
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

SESSION_NAME = "NetWatch-ETW"
TRACEHANDLE = ctypes.c_uint64
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF
ERROR_ALREADY_EXISTS = 183
ERROR_INSUFFICIENT_BUFFER = 122
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_FILTER_TYPE_EVENT_ID = 0x80000200
EVENT_HEADER_FLAG_64_BIT_HEADER = 0x0040


# --------------------------------------------------------------------------- #
# Win32 structures
# --------------------------------------------------------------------------- #
class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_str(cls, s):
        g = cls()
        ctypes.memmove(ctypes.byref(g), uuid.UUID(s).bytes_le, 16)
        return g


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wt.ULONG), ("ProviderId", wt.ULONG), ("HistoricalContext", ctypes.c_uint64),
                ("TimeStamp", ctypes.c_int64), ("Guid", GUID), ("ClientContext", wt.ULONG), ("Flags", wt.ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", wt.ULONG), ("MinimumBuffers", wt.ULONG),
                ("MaximumBuffers", wt.ULONG), ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG),
                ("FlushTimer", wt.ULONG), ("EnableFlags", wt.ULONG), ("AgeLimit", wt.LONG),
                ("NumberOfBuffers", wt.ULONG), ("FreeBuffers", wt.ULONG), ("EventsLost", wt.ULONG),
                ("BuffersWritten", wt.ULONG), ("LogBuffersLost", wt.ULONG), ("RealTimeBuffersLost", wt.ULONG),
                ("LoggerThreadId", wt.HANDLE), ("LogFileNameOffset", wt.ULONG), ("LoggerNameOffset", wt.ULONG)]


class PROPS_BUF(ctypes.Structure):
    _fields_ = [("p", EVENT_TRACE_PROPERTIES), ("name", ctypes.c_wchar * 1024), ("file", ctypes.c_wchar * 1024)]


class EVENT_FILTER_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Ptr", ctypes.c_uint64), ("Size", wt.ULONG), ("Type", wt.ULONG)]


class ENABLE_TRACE_PARAMETERS(ctypes.Structure):
    _fields_ = [("Version", wt.ULONG), ("EnableProperty", wt.ULONG), ("ControlFlags", wt.ULONG),
                ("SourceId", GUID), ("EnableFilterDesc", ctypes.POINTER(EVENT_FILTER_DESCRIPTOR)),
                ("FilterDescCount", wt.ULONG)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", wt.USHORT), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", wt.USHORT),
                ("Keyword", ctypes.c_uint64)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", wt.USHORT), ("HeaderType", wt.USHORT), ("Flags", wt.USHORT),
                ("EventProperty", wt.USHORT), ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG),
                ("TimeStamp", ctypes.c_int64), ("ProviderId", GUID), ("EventDescriptor", EVENT_DESCRIPTOR),
                ("ProcessorTime", ctypes.c_uint64), ("ActivityId", GUID)]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [("ProcessorIndex", wt.USHORT), ("LoggerId", wt.USHORT)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", ETW_BUFFER_CONTEXT),
                ("ExtendedDataCount", wt.USHORT), ("UserDataLength", wt.USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p), ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", wt.USHORT), ("FieldTypeFlags", wt.USHORT), ("Version", wt.ULONG),
                ("ThreadId", wt.ULONG), ("ProcessId", wt.ULONG), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ProcessorTime", ctypes.c_uint64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", wt.ULONG), ("ParentInstanceId", wt.ULONG),
                ("ParentGuid", GUID), ("MofData", ctypes.c_void_p), ("MofLength", wt.ULONG),
                ("ClientContext", wt.ULONG)]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, wt.WORD) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute",
                                       "wSecond", "wMilliseconds")]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [("Bias", wt.LONG), ("StandardName", ctypes.c_wchar * 32), ("StandardDate", SYSTEMTIME),
                ("StandardBias", wt.LONG), ("DaylightName", ctypes.c_wchar * 32), ("DaylightDate", SYSTEMTIME),
                ("DaylightBias", wt.LONG)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wt.ULONG), ("Version", wt.ULONG), ("ProviderVersion", wt.ULONG),
                ("NumberOfProcessors", wt.ULONG), ("EndTime", ctypes.c_int64), ("TimerResolution", wt.ULONG),
                ("MaximumFileSize", wt.ULONG), ("LogFileMode", wt.ULONG), ("BuffersWritten", wt.ULONG),
                ("LogInstanceGuid", GUID), ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64),
                ("StartTime", ctypes.c_int64), ("ReservedFlags", wt.ULONG), ("BuffersLost", wt.ULONG)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", ctypes.c_wchar_p), ("LoggerName", ctypes.c_wchar_p),
                ("CurrentTime", ctypes.c_int64), ("BuffersRead", wt.ULONG), ("ProcessTraceMode", wt.ULONG),
                ("CurrentEvent", EVENT_TRACE), ("LogfileHeader", TRACE_LOGFILE_HEADER),
                ("BufferCallback", ctypes.c_void_p), ("BufferSize", wt.ULONG), ("Filled", wt.ULONG),
                ("EventsLost", wt.ULONG), ("EventRecordCallback", EVENT_RECORD_CALLBACK),
                ("IsKernelTrace", wt.ULONG), ("Context", ctypes.c_void_p)]


class PROPERTY_DATA_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("PropertyName", ctypes.c_uint64), ("ArrayIndex", wt.ULONG), ("Reserved", wt.ULONG)]


advapi32.StartTraceW.argtypes = [ctypes.POINTER(TRACEHANDLE), wt.LPCWSTR, ctypes.c_void_p]
advapi32.StartTraceW.restype = wt.ULONG
advapi32.ControlTraceW.argtypes = [TRACEHANDLE, wt.LPCWSTR, ctypes.c_void_p, wt.ULONG]
advapi32.ControlTraceW.restype = wt.ULONG
advapi32.EnableTraceEx2.argtypes = [TRACEHANDLE, ctypes.POINTER(GUID), wt.ULONG, ctypes.c_ubyte,
                                    ctypes.c_uint64, ctypes.c_uint64, wt.ULONG, ctypes.c_void_p]
advapi32.EnableTraceEx2.restype = wt.ULONG
advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
advapi32.OpenTraceW.restype = TRACEHANDLE
advapi32.ProcessTrace.argtypes = [ctypes.POINTER(TRACEHANDLE), wt.ULONG, ctypes.c_void_p, ctypes.c_void_p]
advapi32.ProcessTrace.restype = wt.ULONG
advapi32.CloseTrace.argtypes = [TRACEHANDLE]
advapi32.CloseTrace.restype = wt.ULONG
tdh.TdhGetEventInformation.argtypes = [ctypes.POINTER(EVENT_RECORD), wt.ULONG, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.POINTER(wt.ULONG)]
tdh.TdhGetEventInformation.restype = wt.ULONG
tdh.TdhGetPropertySize.argtypes = [ctypes.POINTER(EVENT_RECORD), wt.ULONG, ctypes.c_void_p, wt.ULONG,
                                   ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR), ctypes.POINTER(wt.ULONG)]
tdh.TdhGetPropertySize.restype = wt.ULONG
tdh.TdhGetProperty.argtypes = [ctypes.POINTER(EVENT_RECORD), wt.ULONG, ctypes.c_void_p, wt.ULONG,
                               ctypes.POINTER(PROPERTY_DATA_DESCRIPTOR), wt.ULONG, ctypes.c_void_p]
tdh.TdhGetProperty.restype = wt.ULONG


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
P_KNET = "7dd42a49-5329-4832-8dfd-43d979153a88"
P_DNS = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d"
P_KPROC = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"
P_WININET = "43d1a55c-76d6-4f7e-995c-64c711e5cafe"
P_WINHTTP = "7d44233d-3055-4b9c-ba64-0d47ca40a232"
P_WEBIO = "50b3e73c-9370-461d-bb9f-26f32d68887d"

# Kernel-Network event ids
TCP4 = {12: "connect", 13: "disconnect", 15: "accept", 16: "reconnect"}
TCP6 = {28: "connect", 29: "disconnect", 31: "accept", 32: "reconnect"}
UDP4_SEND, UDP6_SEND = 42, 58
KNET_IDS = sorted(list(TCP4) + list(TCP6) + [UDP4_SEND, UDP6_SEND])

# (guid, level, keywords, event-id filter or None)
PROVIDERS = [
    (P_KNET, 5, 0xFFFFFFFFFFFFFFFF, KNET_IDS),
    (P_DNS, 5, 0xFFFFFFFFFFFFFFFF, None),          # low volume - filtered in the callback
    (P_KPROC, 5, 0x10 | 0x40, [1, 2, 5]),       # PROCESS | IMAGE keywords
    (P_WININET, 5, 0xFFFFFFFFFFFFFFFF, None),
    (P_WINHTTP, 5, 0xFFFFFFFFFFFFFFFF, None),
    (P_WEBIO, 4, 0xFFFFFFFFFFFFFFFF, None),
]
_G = {g: uuid.UUID(g).bytes_le for g, *_ in PROVIDERS}


def filetime_to_unix(ft):
    return (ft - 116444736000000000) / 1e7


# --------------------------------------------------------------------------- #
# NT device path -> DOS path  (\Device\HarddiskVolume3\x -> C:\x)
# --------------------------------------------------------------------------- #
_devmap = None


def dos_path(p):
    global _devmap
    if not p:
        return p
    if _devmap is None:
        _devmap = []
        buf = ctypes.create_unicode_buffer(1024)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
                _devmap.append((buf.value.lower() + "\\", f"{letter}:\\"))
    if p.startswith("\\??\\"):
        return p[4:]
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        import os
        return os.environ.get("SystemRoot", r"C:\Windows") + p[11:]
    for dev, drv in _devmap:
        if low.startswith(dev):
            return drv + p[len(dev):]
    return p


# --------------------------------------------------------------------------- #
# TDH property decoding (for the low-volume providers)
# --------------------------------------------------------------------------- #
_schema_cache = {}


def _schema(rec):
    d = rec.EventHeader.EventDescriptor
    key = (bytes(rec.EventHeader.ProviderId), d.Id, d.Version, d.Opcode)
    s = _schema_cache.get(key)
    if s is not None:
        return s
    size = wt.ULONG(0)
    st = tdh.TdhGetEventInformation(ctypes.byref(rec), 0, None, None, ctypes.byref(size))
    props = []
    if st == ERROR_INSUFFICIENT_BUFFER:
        buf = ctypes.create_string_buffer(size.value)
        if tdh.TdhGetEventInformation(ctypes.byref(rec), 0, None, buf, ctypes.byref(size)) == 0:
            raw = buf.raw
            top = struct.unpack_from("<I", raw, 104)[0]
            for i in range(top):
                flags, name_off, intype, outtype, _m, count, _len, _r = struct.unpack_from("<IIHHIHHI", raw, 112 + i * 24)
                end = name_off
                while raw[end:end + 2] != b"\x00\x00":
                    end += 2
                name = raw[name_off:end].decode("utf-16le")
                if flags & 0x1 or flags & 0x4 or count > 1:   # struct / variable array / fixed array
                    continue
                nb = ctypes.create_unicode_buffer(name)
                props.append((name, intype, nb))
    _schema_cache[key] = props
    return props


def _decode(intype, data, ptr64):
    try:
        if intype == 1:
            return data.decode("utf-16le", "replace").split("\x00", 1)[0]
        if intype == 2:
            return data.decode("mbcs", "replace").split("\x00", 1)[0]
        fmt = {3: "<b", 4: "<B", 5: "<h", 6: "<H", 7: "<i", 8: "<I", 9: "<q", 10: "<Q", 13: "<I",
               17: "<Q", 20: "<I", 21: "<Q", 11: "<f", 12: "<d"}.get(intype)
        if fmt:
            return struct.unpack_from(fmt, data)[0]
        if intype == 16:
            return struct.unpack_from("<Q" if len(data) >= 8 else "<I", data)[0]
        if intype == 15 and len(data) >= 16:
            return str(uuid.UUID(bytes_le=data[:16]))
    except Exception:
        pass
    return data.hex()


def tdh_props(rec, wanted=None, strings_only=False):
    out = {}
    ptr64 = bool(rec.EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER)
    for name, intype, nb in _schema(rec):
        if wanted and name not in wanted:
            continue
        if strings_only and intype not in (1, 2):
            continue
        desc = PROPERTY_DATA_DESCRIPTOR(ctypes.addressof(nb), 0xFFFFFFFF, 0)
        sz = wt.ULONG(0)
        if tdh.TdhGetPropertySize(ctypes.byref(rec), 0, None, 1, ctypes.byref(desc), ctypes.byref(sz)) or not sz.value:
            continue
        buf = ctypes.create_string_buffer(sz.value)
        if tdh.TdhGetProperty(ctypes.byref(rec), 0, None, 1, ctypes.byref(desc), sz.value, buf):
            continue
        out[name] = _decode(intype, buf.raw, ptr64)
    return out


# --------------------------------------------------------------------------- #
# Sensor
# --------------------------------------------------------------------------- #
class EtwSensor:
    """
    handlers: object with any of
      on_tcp(kind, pid, rip, rport, lip, lport, v6, ts)
      on_udp(pid, rip, rport, lip, lport, v6, ts)
      on_dns(pid, name, qtype, status, results, ts)
      on_web(pid, provider, event_id, props, ts)
      on_proc_start(pid, ppid, image, session, ts)
      on_proc_stop(pid, image, exit_code, ts)
      on_image_load(pid, image, ts)
    """

    def __init__(self, handlers):
        self.h = handlers
        self.handle = TRACEHANDLE(0)
        self.trace = TRACEHANDLE(INVALID_HANDLE)
        self.thread = None
        self.running = False
        self.counts = {}
        self.errors = 0
        self.last_error = ""
        self.provider_status = {}
        self._keep = []
        self._cb = EVENT_RECORD_CALLBACK(self._on_event)

    # ---- session management ----
    @staticmethod
    def _props():
        b = PROPS_BUF()
        b.p.Wnode.BufferSize = ctypes.sizeof(b)
        b.p.Wnode.Flags = 0x00020000                      # WNODE_FLAG_TRACED_GUID
        b.p.Wnode.ClientContext = 1                       # QPC timestamps
        ctypes.memmove(ctypes.byref(b.p.Wnode.Guid), uuid.uuid4().bytes_le, 16)
        b.p.LogFileMode = 0x00000100                      # EVENT_TRACE_REAL_TIME_MODE
        b.p.BufferSize = 64
        b.p.MinimumBuffers = 32
        b.p.MaximumBuffers = 256
        b.p.FlushTimer = 1
        b.p.LoggerNameOffset = PROPS_BUF.name.offset
        b.p.LogFileNameOffset = 0
        return b

    @classmethod
    def stop_session(cls, name=SESSION_NAME):
        return advapi32.ControlTraceW(0, name, ctypes.byref(cls._props()), 1)   # EVENT_TRACE_CONTROL_STOP

    def stats(self):
        b = self._props()
        if advapi32.ControlTraceW(0, SESSION_NAME, ctypes.byref(b), 0) == 0:  # QUERY
            return {"events_lost": b.p.EventsLost, "buffers_lost": b.p.RealTimeBuffersLost + b.p.LogBuffersLost}
        return {}

    def start(self):
        props = self._props()
        st = advapi32.StartTraceW(ctypes.byref(self.handle), SESSION_NAME, ctypes.byref(props))
        if st == ERROR_ALREADY_EXISTS:              # stale session from a previous crash
            self.stop_session()
            props = self._props()
            st = advapi32.StartTraceW(ctypes.byref(self.handle), SESSION_NAME, ctypes.byref(props))
        if st != 0:
            raise OSError(st, f"StartTrace failed ({st}){' - run as Administrator' if st == 5 else ''}")

        for guid, level, kw, ids in PROVIDERS:
            g = GUID.from_str(guid)
            params = None
            if ids:
                n = len(ids)

                class EVENT_FILTER_EVENT_ID(ctypes.Structure):
                    _fields_ = [("FilterIn", ctypes.c_ubyte), ("Reserved", ctypes.c_ubyte),
                                ("Count", wt.USHORT), ("Events", wt.USHORT * n)]
                f = EVENT_FILTER_EVENT_ID(1, 0, n, (wt.USHORT * n)(*ids))
                desc = EVENT_FILTER_DESCRIPTOR(ctypes.addressof(f), ctypes.sizeof(f), EVENT_FILTER_TYPE_EVENT_ID)
                params = ENABLE_TRACE_PARAMETERS(Version=2, EnableFilterDesc=ctypes.pointer(desc), FilterDescCount=1)
                self._keep += [f, desc, params]
            st = advapi32.EnableTraceEx2(self.handle, ctypes.byref(g), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                         level, kw, 0, 0, ctypes.byref(params) if params else None)
            if st != 0 and params is not None:      # filter unsupported -> enable unfiltered (we filter in callback)
                st = advapi32.EnableTraceEx2(self.handle, ctypes.byref(g), EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                             level, kw, 0, 0, None)
            self.provider_status[guid] = st

        lf = EVENT_TRACE_LOGFILEW()
        lf.LoggerName = SESSION_NAME
        lf.ProcessTraceMode = 0x00000100 | 0x10000000   # REAL_TIME | EVENT_RECORD
        lf.EventRecordCallback = self._cb
        self._keep.append(lf)
        self.trace = TRACEHANDLE(advapi32.OpenTraceW(ctypes.byref(lf)))
        if self.trace.value == INVALID_HANDLE:
            err = ctypes.get_last_error()
            self.stop()
            raise OSError(err, f"OpenTrace failed ({err})")
        self.running = True
        self.thread = threading.Thread(target=self._pump, name="etw-pump", daemon=True)
        self.thread.start()

    def _pump(self):
        advapi32.ProcessTrace(ctypes.byref(self.trace), 1, None, None)
        self.running = False

    def stop(self):
        if self.trace.value not in (0, INVALID_HANDLE):
            advapi32.CloseTrace(self.trace)
        self.stop_session()
        self.running = False

    # ---- event dispatch ----
    def _on_event(self, prec):
        try:
            rec = prec.contents
            hdr = rec.EventHeader
            prov = bytes(hdr.ProviderId)
            eid = hdr.EventDescriptor.Id
            ts = filetime_to_unix(hdr.TimeStamp)
            if prov == _G[P_KNET]:
                self._knet(rec, eid, ts)
            elif prov == _G[P_DNS]:
                self._count(f"dns_raw_{eid}")
                if eid == 3008:
                    p = tdh_props(rec, {"QueryName", "QueryType", "QueryStatus", "QueryResults"})
                    self._count("dns")
                    self.h.on_dns(hdr.ProcessId, p.get("QueryName", ""), p.get("QueryType", 0),
                                  p.get("QueryStatus", 0), p.get("QueryResults", ""), ts)
            elif prov == _G[P_KPROC]:
                if eid == 1:
                    p = tdh_props(rec, {"ProcessID", "ParentProcessID", "ImageName", "SessionID"})
                    self._count("proc_start")
                    self.h.on_proc_start(p.get("ProcessID", 0), p.get("ParentProcessID", 0),
                                         dos_path(p.get("ImageName", "")), p.get("SessionID", 0), ts)
                elif eid == 2:
                    p = tdh_props(rec, {"ProcessID", "ImageName", "ExitCode"})
                    self._count("proc_stop")
                    self.h.on_proc_stop(p.get("ProcessID", 0), p.get("ImageName", ""), p.get("ExitCode"), ts)
                elif eid == 5:
                    p = tdh_props(rec, {"ProcessID", "ImageName"})
                    self._count("image_load")
                    self.h.on_image_load(p.get("ProcessID", 0), dos_path(p.get("ImageName", "")), ts)
            elif prov in (_G[P_WININET], _G[P_WINHTTP], _G[P_WEBIO]):
                p = tdh_props(rec, strings_only=True)
                if p:
                    self._count("web_raw")
                    name = {_G[P_WININET]: "WinINet", _G[P_WINHTTP]: "WinHTTP", _G[P_WEBIO]: "WebIO"}[prov]
                    self.h.on_web(hdr.ProcessId, name, eid, p, ts)
        except Exception as e:  # never let an exception escape into native code
            self.errors += 1
            self.last_error = f"{e.__class__.__name__}: {e}"

    def _count(self, k):
        self.counts[k] = self.counts.get(k, 0) + 1

    def _knet(self, rec, eid, ts):
        if eid in TCP4 or eid == UDP4_SEND:
            if rec.UserDataLength < 20:
                return
            raw = ctypes.string_at(rec.UserData, 20)
            pid = struct.unpack_from("<I", raw, 0)[0]
            rip, lip = socket.inet_ntoa(raw[8:12]), socket.inet_ntoa(raw[12:16])
            rport, lport = struct.unpack_from(">HH", raw, 16)
            v6 = False
        elif eid in TCP6 or eid == UDP6_SEND:
            if rec.UserDataLength < 44:
                return
            raw = ctypes.string_at(rec.UserData, 44)
            pid = struct.unpack_from("<I", raw, 0)[0]
            rip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            lip = socket.inet_ntop(socket.AF_INET6, raw[24:40])
            rport, lport = struct.unpack_from(">HH", raw, 40)
            v6 = True
        else:
            return   # send/recv etc. when the kernel-side filter was not accepted
        if eid in (UDP4_SEND, UDP6_SEND):
            self._count("udp")
            self.h.on_udp(pid, rip, rport, lip, lport, v6, ts)
        else:
            kind = (TCP4 if eid in TCP4 else TCP6)[eid]
            self._count("tcp_" + kind)
            self.h.on_tcp(kind, pid, rip, rport, lip, lport, v6, ts)
