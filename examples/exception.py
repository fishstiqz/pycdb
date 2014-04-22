import sys
import os

print os.path.join("..", "pycdb")
sys.path.append(os.path.join("..", "pycdb"))

import pycdb   
from pycdb import PyCdb, PyCdbPipeClosedException
    
    
class ExceptionCatcher(PyCdb):
    def __init__(self):
        PyCdb.__init__(self)
        
        self.ignore_exceptions = [
            0x4000001f              # wow64 exception
        ]
    
    def on_create_window_ex_w(self, bpnum, output):
        print "CreateWindowExW breakpoint hit, adding crash code"
        crash_code  = "B8EFBEADDE"       # mov eax, 0xdeadbeef
        crash_code += "C700EDACEF0D"     # mov [eax], 0xdefaced
        self.write_mem('@$scopeip', crash_code.decode('hex'))
    
    def on_load_module(self, event):
        print "on_load_module: %08X, %08X, %s" % (event.base, event.length, event.module)
    
    def test_commands(self):
        print "lm output:"
        print self.execute('lm')

        print "bytes at ntdll headers:"
        print self.read_mem('ntdll', 0x100).encode('hex')
        print "%08X" % (self.read_u32("ntdll"))
                
        print "read invalid address"
        badread = self.read_mem(0x00000012, 0x10)
        print "badread: %u" % (len(badread))
        
        print "registers dict"
        print self.registers()
        
        print "modules:"
        print self.modules()
        
        print "PEB evaluate:"
        print hex(self.evaluate('@$peb'))
    
    
    def run(self, prog_args):
        # run the process
        self.spawn(prog_args)
        
        try:
            # wait until the first prompt
            # this works because initial_breakpoint is True
            self.read_to_prompt()
            
            # test commands
            self.test_commands()
            
            # set a breakpoint with a handler
            self.breakpoint("user32!CreateWindowExW", self.on_create_window_ex_w)
        
            # simple debugging loop
            while True:
                # continue and wait for a prompt
                self.continue_debugging()       
                output = self.read_to_prompt()
                             
                # what was the stop event?
                event = self.lastevent()
                
                print "got debugger event: %s" % (event['desc'])
                
                if 'exception' in event:
                    exception = event['exception']
                    code = exception['code']
                    if code in  self.ignore_exceptions:
                        print "ignoring exception: %08X" % (code)
                    else:
                        print "Exception %08X (%s) occured at %08X" % (code, exception['desc'], exception['address'])
                        print ""
                        print self.execute('ub @$scopeip L5').strip()
                        print "*** Exception here ***"
                        print self.execute('u @$scopeip L5').strip()
                        print ""
                        print self.execute('r')
                        break
                        
        except PyCdbPipeClosedException:
            print "pipe closed"
            
        finally:
            if not self.closed():
                self.write_pipe('q\r\n')
    
 
if __name__ == "__main__":
    dbg = ExceptionCatcher()
    # run calc
    dbg.run(['calc.exe'])
 
