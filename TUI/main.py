from debugger import *

def main():
    pass

if __name__ == "__main__":
    main()
    debug = debugger() # create debugger object
    print("============================================")
    print(" TUI Debugger started. Please input command.\n")
    print(" start / stop / attach")
    print(" step / continue(c) / run")
    print(" breakpoint(bp) / show bp / del bp")
    print(" register / stack")
    print("============================================")
    debug.cmdProc() # call functions
