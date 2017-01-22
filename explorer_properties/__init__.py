from fman import DirectoryPaneCommand
import os
import sys
import ctypes
import ctypes.wintypes

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_INVOKEIDLIST = 0x0000000C

class SHELLEXECUTEINFO(ctypes.Structure):
    _fields_ = (
        ("cbSize",ctypes.wintypes.DWORD),
        ("fMask",ctypes.c_ulong),
        ("hwnd",ctypes.wintypes.HANDLE),
        ("lpVerb",ctypes.c_char_p),
        ("lpFile",ctypes.c_char_p),
        ("lpParameters",ctypes.c_char_p),
        ("lpDirectory",ctypes.c_char_p),
        ("nShow",ctypes.c_int),
        ("hInstApp",ctypes.wintypes.HINSTANCE),
        ("lpIDList",ctypes.c_void_p),
        ("lpClass",ctypes.c_char_p),
        ("hKeyClass",ctypes.wintypes.HKEY),
        ("dwHotKey",ctypes.wintypes.DWORD),
        ("hIconOrMonitor",ctypes.wintypes.HANDLE),
        ("hProcess",ctypes.wintypes.HANDLE),
)

class DisplayExplorerProperties(DirectoryPaneCommand):
    def __call__(self):
        file_name = self.pane.get_file_under_cursor()
        
        if not file_name:
            return

        shell_execute_ex = ctypes.windll.shell32.ShellExecuteEx
        shell_execute_ex.restype = ctypes.wintypes.BOOL
        
        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_INVOKEIDLIST
        sei.lpVerb = str.encode("properties")
        sei.lpFile = str.encode(file_name, sys.getfilesystemencoding())
        sei.nShow = 1
        shell_execute_ex(ctypes.byref(sei))
        