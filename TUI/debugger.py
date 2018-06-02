# -*- coding: utf-8 -*-

from ctypes import *
from ctypes import wintypes
from ctype_dbg_define import *
from capstone import *
import struct
import pefile
import sys
import os
import distorm3

kernel32 = windll.kernel32

class debugger(object): # 가장 최상위 object
    def __init__(self):      
        self.h_process = None
        self.h_thread = None
        self.context = None
        self.pid = None
        self.bp_address = None
        self.first_breakpoint = True
        self.memory_base_address = None
        self.command = None
        self.exception = None
        self.exception_address = None
        self.stack_address = {}
        self.stack_list = {}
        self.stack_base_address = None
        self.filename = None
        self.attached = False
        self.run_dbg = True
        self.system_bp = True
        self.isbp = False
        self.isstop = False
        self.breakpoints = {} # dictionary, set
        self.guarded_pages = [] # list
        self.memory_breakpoints = {}
        
        global si
        global pi
        global debug_event
        global mbi
        global temp_mbi
        global continue_status
        global context
        global pe32
        
        si = STARTUPINFO() # process attribute information
        memset(byref(si), 0, sizeof(si)) # struct initialize
        si.cb = sizeof(si) # struct size initialize
        
        pi = PROCESS_INFORMATION()
        mbi = MEMORY_BASIC_INFORMATION()
        temp_mbi = MEMORY_BASIC_INFORMATION() # before memory basic information

        pe32 = PROCESSENTRY32()
        debug_event = DEBUG_EVENT()
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        
 # ex command pattern design....... 
 
    def cmdProc(self):
        
        while(True):
            self.command = input("Input Your Command >> ")
        
            if self.command == "start":
                self.filename = input("[*] Filename >> ")
                self.create_process(self.filename)
                
            elif self.command == "stop":
                if self.attached == True:
                    kernel32.DebugActiveProcessStop(self.pid)
                    
                print("[-] Finished debugging. Exit...")
                self.h_process = kernel32.OpenProcess(1, False, self.pid)
                kernel32.TerminateProcess(self.h_process, 100) # number 100 means exit 
                kernel32.CloseHandle(self.h_thread)
                kernel32.CloseHandle(self.h_process)
                
            elif self.command == "attach":
                self.get_process_list()
                
                self.pid = int(input("[*] Input PID >> "))
                self.h_process = self.open_process(self.pid)
                
                if kernel32.DebugActiveProcess(self.pid): # debugger status is running
                    self.attached = True
                    print("[*] Attached process")
                    self.get_debug_event()
                else:
                    print("[-] Error : 0x%08x." % kernel32.GetLastError())
                    break
                    
            elif self.command == "step":
                self.isbp = False
                self.run_dbg = True
                self.set_single_step()
                self.get_debug_event()
                
            elif self.command == "continue" or self.command == "c":
                self.isbp = False
                self.run_dbg = True
                if not self.breakpoints:
                    print("[-] breakpoint is none")
                else: 
                    self.get_debug_event()
                            
            elif self.command == "bp" or self.command == "breakpoint":
                self.bp_address = input("[*] Breakpoint Address >> ")
                self.bp_address = int(self.bp_address, 16)
                bp_ret = self.bp_set(self.bp_address)
                if not bp_ret: # breakpoint is none
                    self.run_dbg = False
                self.get_debug_event()
                
            elif self.command == "del bp" or self.command == "del breakpoint":
                print("[*] Delete All Breakpoint")
                self.breakpoints.clear()
                print(self.breakpoints)

            elif self.command == "show bp" or self.command == "show breakpoint":
                bp_address = list(sorted(self.breakpoints.keys()))
                print("[*] Breakpoint List")
                for i in range(len(bp_address)):
                    print("Breakpoint %d : %s" % (i+1, bp_address[i]))
                
            elif self.command == "reg" or self.command == "register":
                print("[*] Show Current Register Value")
                self.get_thread_context()

            elif self.command == "run" or self.command == "r":
                self.isbp = False
                self.run_dbg = True
                self.get_debug_event()
                
            elif self.command == "disas" or self.command == "disassemble":
                print("[*] View Disassembly code")
                self.get_memory(context.Eip)

            elif self.command == "mmap" or self.command == "memory map":
                self.view_memory_map()
                
            elif self.command == "stack":
                self.view_stack()
            
            elif self.command == "hexdump":
                self.hexdump()

            else:
                print("[-] This is Wrong Command")
                continue
    
    def create_process(self, filename):    
        if not kernel32.CreateProcessW(filename, None, None, None, None, DEBUG_PROCESS, None, None, byref(si), byref(pi)):
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False

        if not self.h_process:
            self.run_dbg = True
            self.system_bp = True
            self.get_debug_event()
            
        
    def bp_set(self, address):
        if not hex(address) in self.breakpoints:
            try:
                # read original byte
                original_byte = self.read_process_memory(address, 1)

                # change memory access
                if not kernel32.VirtualQueryEx(self.h_process,
                                           context.Eip,
                                           byref(mbi),
                                           sizeof(mbi)):
                    print("[-] Error : 0x%08x." % kernel32.GetLastError())
                    return False
                
                if not kernel32.VirtualProtectEx(self.h_process,
                                                 mbi.BaseAddress, mbi.RegionSize,
                                                 PAGE_EXECUTE_READWRITE, byref(mbi.Protect)):
                    print("[-] Error : 0x%08x." % kernel32.GetLastError())
                    return False

                print("[*] Breakpoint Address : 0x%08x" % address)
                
                # set breakpoint "\xcc"    
                self.write_process_memory(address, b"\xCC")
                # overlap "\xcc"
                self.read_process_memory(address, 1)

                # recover original memory protect
                if not kernel32.VirtualProtectEx(self.h_process,
                                                 mbi.BaseAddress, mbi.RegionSize,
                                                 mbi.Protect, byref(temp_mbi.Protect)):
                    return False
                
                # restored breakpoint original byte 
                self.breakpoints[hex(address)] = original_byte
                
                kernel32.FlushInstructionCache(self.h_process, address, 1)

                return True
            
            except Exception as ex:
                print("[-] Breakpoint Execption : %s" % ex)
                return False
        else:
            # restore, delete breakpoints
            self.write_process_memory(address, self.breakpoints[hex(address)]) 
            del self.breakpoints[hex(address)]
            return True
        
    def get_debug_event(self):
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
        
        while(self.run_dbg):
            if kernel32.WaitForDebugEvent(byref(debug_event), 1000):
                print("[*] Event Code : %d" % (debug_event.dwDebugEventCode))
                
                if self.h_thread:
                    kernel32.GetThreadContext(self.h_thread, byref(context))
                    self.view_stack()
                    
                if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                    di = debug_event.u.CreateProcessInfo
                    self.h_process = di.hProcess
                    self.h_thread = self.open_thread(debug_event.dwThreadId)
                    
                    print("=====================================")
                    print("          PROCESS [PID = %d]         " % debug_event.dwProcessId)
                    print("=====================================")
                    print("File = %d" % di.hFile)
                    print("Process = %d" % di.hProcess)
                    print("Thread = %d" % di.hThread)
                    print("BaseOfImage = 0x%08x" % di.lpBaseOfImage)
                    print("ThreadLocalBase = 0x%08x" % di.lpThreadLocalBase)
                    if self.attached == False:
                        print("StartAddress = 0x%08x" % di.lpStartAddress)
                    print("=====================================")

                    self.set_stack()
                    self.view_stack()

                if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                    self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                    self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                
                    print("ExceptionCode = 0x%08x, Exception Address = 0x%08x\n" % (debug_event.u.Exception.ExceptionRecord.ExceptionCode, debug_event.u.Exception.ExceptionRecord.ExceptionAddress))
                    
                    
                    if self.exception == EXCEPTION_ACCESS_VIOLATION:
                        print("Access Violation Detected.")
                        self.run_dbg = False                
                        
                    elif self.exception == EXCEPTION_BREAKPOINT:
                        if self.system_bp:
                            self.exception_handler_breakpoint()
                            self.get_thread_context()
                            self.get_memory(self.exception_address)
                            self.system_bp = False
                            self.run_dbg = False
                        else:
                            print("[*] Breakpoint at " + hex(self.exception_address))
                            self.exception_handler_breakpoint()
                            self.get_thread_context()
                            self.write_process_memory(self.exception_address, self.breakpoints[hex(self.exception_address)]) #encode
                            self.get_memory(int(context.Eip) -1)
                            context.Eip = int(context.Eip) - 1
                            kernel32.SetThreadContext(self.h_thread, byref(context))
                            self.run_dbg = False       

                    elif self.exception == EXCEPTION_SINGLE_STEP:
                        print("[*] Single Step at " + hex(self.exception_address))
                        self.get_thread_context()
                        self.get_memory(int(context.Eip))
                        self.run_dbg = False
                        
                        
                elif debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                        if self.h_process:
                            print("[-] Finished debugging. Exit...")
                            self.h_process = kernel32.OpenProcess(1, False, self.pid)
                            kernel32.TerminateProcess(self.h_process, 100) # number 100 means exit 
                            kernel32.CloseHandle(self.h_thread)
                            kernel32.CloseHandle(self.h_process)
                        return False
                    
                else:
                    kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)

                
    def exception_handler_breakpoint(self):
        # if it is the first Windows driven breakpoint
        # then let's just continue on
        self.isbp = True
        if self.first_breakpoint == True:
            self.first_breakpoint = False
            print("[*] first breakpoint at " + hex(self.exception_address))
        else:
            if not kernel32.VirtualQueryEx(self.h_process,
                                           context.Eip,
                                           byref(mbi),
                                           sizeof(mbi)):
                    print("[-] Error : 0x%08x." % kernel32.GetLastError())
                    return False
                
            if not kernel32.VirtualProtectEx(self.h_process,
                                                 mbi.BaseAddress, mbi.RegionSize,
                                                 PAGE_EXECUTE_READWRITE, byref(mbi.Protect)):
                    print("[-] Error : 0x%08x." % kernel32.GetLastError())
                    return False         
            
    def set_single_step(self):
        context.EFlags |= 0x100 # Trap bit
        if not kernel32.SetThreadContext(self.h_thread, byref(context)):
            print("[-] Failed Set Single Step")
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            context.EFlags ^= 0x100
            return False
        return True
    
    def delete_single_step(self):
        context.EFlags ^= 0x100 # Trap bit
        if not kernel32.SetThreadContext(self.h_thread, byref(context)):
            print("[-] Failed Delete Single Step")
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            context.EFlags |= 0x100
            return False
        return True
    
    def get_thread_context(self, thread_id=None, h_thread=None):  
        if kernel32.GetThreadContext(self.h_thread, byref(context)):
            print("EAX : 0x%08x" % context.Eax)
            print("EBX : 0x%08x" % context.Ebx)
            print("ECX : 0x%08x" % context.Ecx)
            print("EDX : 0x%08x" % context.Edx)
            print("ESP : 0x%08x" % context.Esp)
            print("EBP : 0x%08x" % context.Ebp)
            print("ESI : 0x%08x" % context.Esi)
            print("EDI : 0x%08x" % context.Edi)
            if self.isbp == True:
                bp_eip = int(context.Eip)
                bp_eip -= 1
                print("EIP : 0x%08x" % bp_eip)
            else:
                print("EIP : 0x%08x" % context.Eip)
            print("CS : 0x%08x" % context.SegCs)
            print("DS : 0x%08x" % context.SegDs)
            print("SS : 0x%08x" % context.SegSs)
            print("ES : 0x%08x" % context.SegEs)
            print("FS : 0x%08x" % context.SegFs)
            print("GS : 0x%08x" % context.SegGs)
            print("EFlags : 0x%08x" % context.EFlags)
            return context.Eip
        else:
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False

    def get_memory(self, address):
        buf = create_string_buffer(64)
        count = c_ulong(0)
        
        kernel32.ReadProcessMemory(self.h_process, address, buf, 64, byref(count))
        buf = bytes(buf)
        
        asm = distorm3.Decode(address, buf, distorm3.Decode32Bits) #byte stream start address, byte stream, flag(16, 32, 64)

        print("============================================")
        print("                 disassemble                ")
        print("============================================")
        
        asm_list = []
        
        for addr, size, ins_asm, opcode in asm:
            op_res = ""
            address = "%08x" % addr

            opcode = opcode.decode('utf-8')
            op_length = len(opcode)
            for i in range(op_length):
                if i % 2 == 0:
                    op_res += "%02s " % opcode[0+i:2+i]
                
            byte_code = " : %-23s" % op_res
            disas = "%s" % ins_asm.decode('utf-8')

            result = "0x" + address + byte_code + disas
            #asm_list.append(result)
            print(result)
            
        #print(asm_list)
            
    def get_process_list(self):
        h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not h_snapshot:
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False
                
        pe32.dwSize = sizeof(pe32)
               
        if not kernel32.Process32First(h_snapshot, byref(pe32)):
            print("Error : 0x%08x." % kernel32.GetLastError())
            kernel32.ClostHandle(h_snapshot)
            return False
        print("       [ProcessName]       |   [PID]  |")
        print("+--------------------------+----------+")
        while True:
            print("%-27s|   %-5d  |" % (pe32.szExeFile.decode(), pe32.th32ProcessID))
            if not kernel32.Process32Next(h_snapshot, byref(pe32)):
                print("+--------------------------+----------+")
                break
                    
        kernel32.CloseHandle(h_snapshot)
        
    def view_memory_map(self):
        pe = pefile.PE(self.filename)

        for section in pe.sections:
            print("." + section.Name.decode().lower().replace(".", ""))
            print("start address : " + hex(section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase))
            print("size : " + hex(section.SizeOfRawData))
            print("end address : " + hex(section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase + section.SizeOfRawData))

    def set_stack(self): # stack setting
        kernel32.GetThreadContext(self.h_thread, byref(context))
        self.stack_base_address = context.Esp & 0xFFFFF000
        for i in range(1024):
            self.stack_address["%08x" % (int(self.stack_base_address) + (i*4))] = "%08x" % 0

    def view_stack(self):
        buf = create_string_buffer(4)
        count = c_ulong(0)
        address = int(context.Esp)
        data = ""
 
        if not kernel32.ReadProcessMemory(self.h_process, address, buf, 4, byref(count)):
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False
        
        data = struct.unpack('< L', buf.raw)[0] # change little-endian
        address = ("%08x" % address)
        data = ("%08x" % data)
        self.stack_list[address] = data
        
        if address in list(self.stack_address.keys()):
            self.stack_address[address] = self.stack_list[address]

        print("stack at 0x%08x" % context.Esp)
        print(self.stack_address)
    
    def hexdump(self):
        print('-' * 79)
        
        start_offset=0
        offset = 0
        f = open(self.filename, 'rb')
        buffer = f.read()

        while offset < len(buffer):
            # Offset
            print(' %08X : ' % (offset + start_offset), end='')
     
            if ((len(buffer) - offset) < 0x10) is True:
                data = buffer[offset:]
            else:
                data = buffer[offset:offset + 0x10]
     
            # Hex Dump
            for hex_dump in data:
                print("%02X" % hex_dump, end=' ')
     
            if ((len(buffer) - offset) < 0x10) is True:
                print(' ' * (3 * (0x10 - len(data))), end='')
     
            print('  ', end='')
     
            # Ascii
            for ascii_dump in data:
                if ((ascii_dump >= 0x20) is True) and ((ascii_dump <= 0x7E) is True):
                    print(chr(ascii_dump), end='')
                else:
                    print('.', end='')
     
            offset = offset + len(data)
            print('')
     
        print('-' * 79)

    def read_process_memory(self, address, length):
        data = ""
        original = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
  
        if not kernel32.ReadProcessMemory(self.h_process,
                                          address,
                                          read_buf,
                                          length,
                                          byref(count)):
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False
        
        else:
            original = read_buf.raw
            #print(read_buf.raw.hex())
            read_buf = read_buf.raw.hex()
            data += read_buf
            print("read memory : 0x%s" % data)
            return original
            

    def write_process_memory(self, address, data):
        count = c_ulonglong(0)
        length = len(data)

        c_data = c_char_p(data[count.value:])
        
        if not kernel32.WriteProcessMemory(self.h_process,
                                           address,
                                           c_data,
                                           length,
                                           byref(count)):
            print("[-] Error : 0x%08x." % kernel32.GetLastError())   

            return False
        else:
            return True
        
    def open_process(self, pid):
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if h_process:
            return h_process
        else:
            print("[*] Could not obtain a valid process handle")
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")


    
