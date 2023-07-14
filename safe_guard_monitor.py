import winappdbg
import psutil
import threading
import os
import signal
import win32file
import win32con
from winappdbg.win32 import PVOID, DWORD, HANDLE, LPDWORD, LPOVERLAPPED
from process_monitor import get_current_running_process
from config import Config


def get_file_name_from_handle(file_handle):
    try:
        file_name = win32file.GetFinalPathNameByHandle(file_handle, win32con.FILE_NAME_NORMALIZED)
        return file_name
    except (Exception, OSError):
        return 'Unknown'


def validate_process_id_and_take_action(process_id, process):
    if Config.DEBUG:
        return
    if process.name() in Config.WHITELIST:
        return
    process.kill()


def validate_safe_guard_access(process_id, file_name, process):
    if Config.DEBUG:
        return
    if str(file_name).find(Config.SAFE_GUARD_MARK) != -1:
        if process.name() in Config.SAFE_GUARD_WHITELIST:
            return
        process.kill()


def pre_create_file_a(event, return_address, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
    try:
        file_name = get_file_name_from_handle(lpFileName)
        if Config.DEBUG:
            print('[+] Pre-Create-File-A', event)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, file_name, process)
    except (Exception, SystemError):
        pass


def pre_create_file_w(event, return_address, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):
    try:
        file_name = get_file_name_from_handle(lpFileName)
        if Config.DEBUG:
            print('[+] Pre-Create-File-W', event)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, file_name, process)
    except (Exception, SystemError):
        pass


def pre_delete_file_a(event, return_address, lpFileName):
    try:
        if Config.DEBUG:
            print('[+] Pre-Delete-File-A', event)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, lpFileName, process)
    except (Exception, SystemError):
        pass


def pre_delete_file_w(event, return_address, lpFileName):
    try:
        if Config.DEBUG:
            print('[+] Pre-Delete-File-W', event)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, lpFileName, process)
    except (Exception, SystemError):
        pass


def pre_write_file(event, return_address, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):
    try:
        file_name = get_file_name_from_handle(hFile)
        if Config.DEBUG:
            print('[+] Pre-Write-File-A', event, file_name)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, file_name, process)
    except (Exception, SystemError):
        pass


def pre_write_file_ex(event, return_address, hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine):
    try:
        file_name = get_file_name_from_handle(hFile)
        if Config.DEBUG:
            print('[+] Pre-Write-File-Ex', event, file_name)
        process_id = event.get_pid()
        process = psutil.Process(process_id)
        validate_process_id_and_take_action(process_id, process)
        validate_safe_guard_access(process_id, file_name, process)
    except (Exception, SystemError):
        pass


class DebugEvents(winappdbg.EventHandler):

    def load_dll(self, event):
        module = event.get_module()

        if module.match_name('kernel32.dll'):

            # List of functions to hook
            address_create_file_a = module.resolve('CreateFileA')
            address_create_file_w = module.resolve('CreateFileW')
            # address_delete_file_a = module.resolve('DeleteFileA')
            # address_delete_file_w = module.resolve('DeleteFileW')
            address_write_file = module.resolve('WriteFile')
            address_write_file_ex = module.resolve('WriteFileEx')

            signature_create_file_a = (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)
            signature_create_file_w = (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)
            # signature_delete_file_a = (PVOID)
            # signature_delete_file_w = (PVOID)
            signature_write_file = (HANDLE, PVOID, DWORD, PVOID, PVOID)
            signature_write_file_ex = (HANDLE, PVOID, DWORD, PVOID, PVOID)

            # Hook function(pid, address, preCB, postCB, paramCount, signature)
            event.debug.hook_function(event.get_pid(), address_create_file_a, preCB=pre_create_file_a,
                                      signature=signature_create_file_a)
            event.debug.hook_function(event.get_pid(), address_create_file_w, preCB=pre_create_file_w,
                                      signature=signature_create_file_w)
            # event.debug.hook_function(event.get_pid(), address_delete_file_a, preCB=pre_create_file_a, signature=signature_delete_file_a)
            # event.debug.hook_function(event.get_pid(), address_delete_file_w, preCB=pre_delete_file_w, signature=signature_delete_file_w)
            event.debug.hook_function(event.get_pid(), address_write_file, preCB=pre_write_file,
                                      signature=signature_write_file)
            event.debug.hook_function(event.get_pid(), address_write_file_ex, preCB=pre_write_file_ex,
                                      signature=signature_write_file_ex)

    def create_process(self, event):
        pass

    def create_thread(self, event):
        pass


def attach_to_pid(pid, name):
    try:
        print('Attaching to pid : {} , process : {}'.format(str(pid), name))
        debug_process = winappdbg.Debug(DebugEvents())
        debug_process.attach(pid)
        debug_process.loop()
    except (Exception, OSError, WindowsError):
        pass


def launch_executable_binary(exe_path):
    debug_process = winappdbg.Debug(DebugEvents())
    debug_process.execv([exe_path])
    debug_process.loop()


if __name__ == '__main__':
    choice = raw_input('[+] Select :- \n\t1) Debug Executable Binary (or) \n\t2) Safe-Guard Monitor Mode\n(1/2) : ')
    if int(choice) == 1:
        Config.DEBUG = True
        exe_path = raw_input('Enter executable binary path : ').replace('"', '').replace("'", "")
        print('[+] Launching executable binary : ', exe_path)
        launch_executable_binary(exe_path)
    elif int(choice) == 2:
        print('[+] Starting Safe-Guard Monitor')
        previous_processes = get_current_running_process()
        while True:
            try:
                current_processes = get_current_running_process()
                new_processes = [p for p in current_processes if p not in previous_processes]
                for pid, name in new_processes:
                    threading.Thread(target=attach_to_pid, args=(pid, name)).start()
                previous_processes = current_processes
            except (OSError, Exception) as _:
                print('[!] Exception in Safe Guard Monitor')
    else:
        print('[+] Invalid Option')
