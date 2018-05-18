from ctypes import *
from ctypes import wintypes
from dbg_define_header import *
from capstone import *
import pefile
import sys
import os
import distorm3

kernel32 = windll.kernel32

class debugger(object): # the most object
    def __init__(self):      
        self.h_process = None
        self.h_thread = None
        self.thread_id = None
        self.context = None
        self.pid = None
        self.bp_address = None
        self.start_addr = 0
        self.first_breakpoint = True
        self.memory_base_address = None
        self.command = None
        self.exception = None
        self.exception_address = None
        self.filename = None
        self.attached = False
        self.run_dbg = True
        self.system_bp = True
        self.isbp = False
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
                filename = input("Please Input Filename >> ")
                self.create_process(filename)
                
            elif self.command == "stop":
                if self.attached:
                    kernel32.DebugActiveProcessStop(self.pid)
                    print("[-] Finished debugging. Exit...")
                    sys.exit()
                
                kernel32.CloseHandle(self.h_process)
                kernel32.CloseHandle(self.h_thread)
                sys.exit()
                
            elif self.command == "attach":
                os.system('tasklist')
                self.pid = int(input("Please Input PID >> "))
                self.h_process = self.open_process(self.pid)
                
                if kernel32.DebugActiveProcess(self.pid):
                    self.attached = True
                    print("[*] Attached process")
                    self.h_process = self.open_process(self.pid)
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
                self.bp_address = input("bp address -> ")
                self.bp_address = int(self.bp_address, 16)
                bp_ret = self.bp_set(self.bp_address)
                if not bp_ret: # breakpoint is none
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
                #print(self.breakpoints.items())
                
            elif self.command == "reg" or self.command == "register":
                print("[*] Show Current Register Value")
                self.get_thread_context()

            elif self.command == "run" or self.command == "r":
                self.isbp = False
                self.run_dbg = True
                self.get_debug_event()
                
            else:
                print("Wrong Command")
                continue
    
    def create_process(self, filename):    
        kernel32.CreateProcessW(filename, None, None, None, None, DEBUG_PROCESS, None, None, byref(si), byref(pi))
        
        if not self.h_process:
            self.get_debug_event()
            self.system_bp == False
        
    def bp_set(self, address):
        if not hex(address) in self.breakpoints:
            try:
                original_byte = self.read_process_memory(address, 1)

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

                self.read_process_memory(address, 1)
                
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
            self.write_process_memory(address, self.breakpoints[hex(address)].encode())
            del self.breakpoints[hex(address)]
            return True
        
    def get_debug_event(self):
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
            
        while(self.run_dbg):
            if kernel32.WaitForDebugEvent(byref(debug_event), 1000):
                print("[*] Event Code : %d" % (debug_event.dwDebugEventCode)) 
        
                if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                        di = debug_event.u.CreateProcessInfo
                        print("=====================================")
                        print("          PROCESS [PID = %d]         " % debug_event.dwProcessId)
                        print("=====================================")
                        print("File = %d" % di.hFile)
                        print("Process = %d" % di.hProcess)
                        print("Thread = %d" % di.hThread)
                        print("BaseOfImage = 0x%08x" % di.lpBaseOfImage)
                        print("ThreadLocalBase = 0x%08x" % di.lpThreadLocalBase)
                        print(di.lpStartAddress)
                        #print("StartAddress = 0x%08x" % di.lpStartAddress)
                        print("=====================================")

                        self.h_process = self.open_thread(di.hProcess)
                        self.h_thread = self.open_thread(di.hThread)
                        #self.start_addr = di.lpStartAddress                        
                                            
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
                            self.get_memory(int(context.Eip) - 1)
                            self.system_bp = False
                            self.run_dbg = False
                        else:
                            print("[*] Breakpoint at " + hex(self.exception_address))
                            self.exception_handler_breakpoint()
                            self.get_thread_context()
 
                            self.write_process_memory(self.exception_address, self.breakpoints[hex(self.exception_address)].encode())

                            self.get_memory(int(context.Eip) - 1)
                            self.run_dbg = False
                            
                    elif self.exception == EXCEPTION_SINGLE_STEP:
                        print("[*] Single Step at " + hex(self.exception_address))
                        self.get_thread_context()
                        self.get_memory(context.Eip)
                        self.run_dbg = False
                            
                elif debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                        if self.h_process:
                            kernel32.CloseHandle(self.h_process)
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
                
            byte_code = " : %-3s" % op_res
            disas = "  %s" % ins_asm.decode('utf-8')

            result = "0x" + address + byte_code + disas
            #asm_list.append(result)
            print(result)
            
        #print(asm_list)
        
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


    
