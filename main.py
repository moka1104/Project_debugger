from python3_TUI_debugger import *

def main():
    pass

if __name__ == "__main__":
    main()
    debug = debugger() 
    print("============================================")
    print(" TUI Debugger started. Please input command.\n")
    print(" start / stop / attach")
    print(" step / c(continue) / bp(breakpoint)")
    print(" show bp / del bp / regs / stack")
    print("============================================")
    debug.cmdProc()
