
from ctypes import *
from ctypes import wintypes
from dbg_define_header import *
from capstone import *
import pefile
import copy
import binascii
import sys
import os
import struct

kernel32 = windll.kernel32

class debugger:
    def __init__(self, filename):
        self.h_process = None
        self.h_thread = None
        self.thread_id = None
        self.context = None
        self.pid = None
        self.bp_address = None
        self.start_addr = 0
        self.first_breakpoint = True
        self.dump_address = None
        self.command = None
        self.exception = None
        self.exception_address = None
        self.filename = filename
        self.attached = False
        self.run_dbg = True
        self.system_bp = True
        self.isbp = False
        self.breakpoints = {}
        self.guarded_pages = []
        self.memory_breakpoints = {}
        
        global si
        global pi
        global debug_event
        global mbi
        global temp_mbi
        global continue_status
        global context

        si = STARTUPINFO()
        pi = PROCESS_INFORMATION()
        mbi = MEMORY_BASIC_INFORMATION()
        temp_mbi = MEMORY_BASIC_INFORMATION()
        
        si.cb = sizeof(si)
        debug_event = DEBUG_EVENT()
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

 # ex command pattern design....... 
 
    def cmdProc(self):
        
        while(True):
            self.command = input("input >> ")
        
            if self.command == "start":
                self.start()
                
            elif self.command == "stop":
                #if self.attached:
                    #kernel32.DebugActiveProcessStop(self.pid):
                    #print "[-] Finished debugging. Exit..."
                    #break
                    #sys.exit()
                #else:
                    #print "[-] Error : 0x%08x." % kernel32.GetLastError()
                    #break
                    #sys.exit()
                
                kernel32.CloseHandle(self.h_process)
                kernel32.CloseHandle(self.h_thread)
                
            elif self.command == "attach":
                if self.h_process:
                    kernel32.CloseHandle(self.h_process)
                os.system('tasklist')
                self.pid = input("Please Input PID >> ")
                self.h_thread = self.open_processs(self.pid)
                    
                if self.h_thread:
                    if kernel32.DebugActiveProcess(self.pid):
                        self.attached = True
                        print("[*] Attached process")
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
                self.get_debug_event()
                            
            elif self.command == "bp" or self.command == "breakpoint":
                self.bp_address = input("bp address -> ")
                self.bp_address = int(self.bp_address, 16)
                bp_ret = self.bp_set(self.bp_address)
                if not bp_ret: #breakpoint is none
                    self.run_dbg = False
                self.get_debug_event()
                
            elif self.command == "del bp" or self.command == "del breakpoint":
                #print self.breakpoints.items()
                print("[*] Delete All Breakpoint")
                self.breakpoints.clear()
                print(self.breakpoints)

            elif self.command == "show bp" or self.command == "show breakpoint":
                bp_address = list(sorted(self.breakpoints.keys()))
                for i in range(len(bp_address)):
                    print("Breakpoint %d : %s" % (i+1, bp_address[i]))
                
            elif self.command == "disas" or self.command == "disassemble":
                print("disas")
                
            elif self.command == "reg" or self.command == "register":
                print("[*] Show Current Register Value")
                self.get_thread_context()
                
            elif self.command == "stack":
                print("stack")
                
            else:
                print("Wrong Command")
                continue
        
    def start(self):    
        kernel32.CreateProcessW(filename, None, None, None, None, DEBUG_PROCESS, None, None, byref(si), byref(pi))

        if not self.h_process:
            address = self.get_debug_event()
            self.system_bp == False
            
    def bp_set(self, address):
        if not hex(address) in self.breakpoints:
            try:
                original_byte = self.read_process_memory(address, 1)

                #print context.Eip
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

                print("[*] Breakpoint address : 0x%08x" % address)
                    
                self.write_process_memory(address, b"\xCC")

                bp = self.read_process_memory(address, 1)
                
                if not kernel32.VirtualProtectEx(self.h_process,
                                                 mbi.BaseAddress, mbi.RegionSize,
                                                 mbi.Protect, byref(temp_mbi.Protect)):
                    return False
                
                # registered breakpoint
                self.breakpoints[hex(address)] = original_byte
                
                kernel32.FlushInstructionCache(self.h_process, address, 1)

                return True
            
            except Exception as ex:
                print("[-] Breakpoint Execption is %s" % ex)
                return False
        else:
            del self.breakpoints[hex(address)]
            return True
            
    def get_debug_event(self):
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
            
        while(self.run_dbg):
            if kernel32.WaitForDebugEvent(byref(debug_event), 1000):
                print("[*] Event Code : %d" % (debug_event.dwDebugEventCode)) 
        
                if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                        di = debug_event.u.CreateProcessInfo
                        print("===== CREATE PROCESS [PID = %d] =====" % debug_event.dwProcessId)
                        print("File = %d" % di.hFile)
                        print("Process = %d" % di.hProcess)
                        print("Thread = %d" % di.hThread)
                        print("BaseOfImage = 0x%08x" % di.lpBaseOfImage)
                        print("ThreadLocalBase = 0x%08x" % di.lpThreadLocalBase)
                        print("StartAddress = 0x%08x" % di.lpStartAddress)
                        print("=====================================")
                        self.h_process = pi.hProcess
                        self.thread_id = pi.dwThreadId
                        self.h_thread = self.open_thread(self.thread_id)
                        self.start_addr = di.lpStartAddress                        
                                            
                if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                    self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                    self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                    di = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                    print("ExceptionCode = 0x%08x, Exception Address = 0x%08x\n" % (debug_event.u.Exception.ExceptionRecord.ExceptionCode, debug_event.u.Exception.ExceptionRecord.ExceptionAddress))
                    
                    if self.exception == EXCEPTION_ACCESS_VIOLATION:
                        print("Access Violation Detected.")
                        self.run_dbg = False
                        
                    elif self.exception == EXCEPTION_BREAKPOINT:
                        if self.system_bp:
                            self.exception_handler_breakpoint()
                            self.get_thread_context()                          
                            self.system_bp = False
                            self.run_dbg = False
                        else:
                            print("[*] Breakpoint at " + hex(self.exception_address))
                            self.exception_handler_breakpoint()
                            self.get_thread_context()
                            #del self.breakpoints[hex(self.exception_address)]
                            self.run_dbg = False
                            
                    elif self.exception == EXCEPTION_SINGLE_STEP:
                        print("[*] Single Step at " + hex(self.exception_address))
                        ret_eip = self.get_thread_context()
                        self.run_dbg = False
                            
                elif debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                        if pi.hProcess:
                            kernel32.CloseHandle(pi.hProcess)
                            print("[-] Process Debug Exit.")
                            sys.exit()
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

            self.write_process_memory(self.exception_address, bytes(self.breakpoints[hex(self.exception_address)], 'utf8'))
            
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
            print("ESI : 0x%08x" % context.Esi)
            print("EDI : 0x%08x" % context.Edi)
            print("EBP : 0x%08x" % context.Ebp)
            print("ESP : 0x%08x" % context.Esp)
            if self.isbp == True:
                bp_eip = int(context.Eip)
                bp_eip -= 1
                print("EIP : 0x%08x" % bp_eip)
            else:
                print("EIP : 0x%08x" % context.Eip)
            return context.Eip
        else:
            print("[-] Error : 0x%08x." % kernel32.GetLastError())
            return False

    def read_process_memory(self, address, length):
        data = ""
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
            #print(read_buf.raw.hex())
            read_buf = read_buf.raw.hex()
            data += read_buf
            print("read memory : 0x%s" % data)
            return data
            

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
        return h_process

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")
  
if __name__ == "__main__":
    filename = sys.argv[1]
    debug = debugger(filename)
    print("============================================")
    print(" TUI Debugger started. Please input command.\n")
    print(" start / stop / attach")
    print(" step / continue / bp(breakpoint)")
    print(" disas / regs / dump")
    print("============================================")
    debug.cmdProc()


    
