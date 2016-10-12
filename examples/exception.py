import sys
import os
import struct
import getopt

sys.path.append(os.path.join("..", "pycdb"))

import pycdb
from pycdb import PyCdb, PyCdbPipeClosedException, ExceptionEvent


class ExceptionCatcher(PyCdb):
    """
    A simple demonstration class to show how to use PyCdb to
    issue commands, install breakpoints, and catch exceptions
    """
    def __init__(self):
        PyCdb.__init__(self)

        self.ignore_exceptions = [
            0x4000001f, # wow64 exception
            0xe06d7363, # C++ exception
            0x40080201,0x80010108, 0x8001010D, 0x6A6, 0x8001010D, 0x40080201
        ]

    def on_create_window_ex_w(self, event):
        """
        when this breakpoint is hit, write some code at the current
        instruction pointer that will cause an access violation
        """
        print "CreateWindowExW breakpoint hit, adding crash code"
        crash_code  = "B8EFBEADDE"       # mov eax, 0xdeadbeef
        crash_code += "C700EDACEF0D"     # mov [eax], 0xdefaced
        self.write_mem('@$scopeip', crash_code.decode('hex'))

    def on_load_module(self, event):
        """
        just print the module that was loaded. note that this does callback
        does not drop you to a prompt. it is simply a notification callback.
        """
        print "on_load_module: %08X, %s" % (event.base, event.module)

    def test_commands(self):
        """
        run some commands...
        """
        if self.cpu_type == pycdb.CPU_X64:
            print "X64"
        else:
            print "X86"

        print "lm output:"
        print self.execute('lm')

        print "bytes at ntdll headers:"
        print self.read_mem('ntdll', 0x100).encode('hex')
        print "%08X" % (self.read_u32("ntdll"))

        print "read invalid address"
        badread = self.read_mem(0x00000012, 0x10)
        print "badread: %u" % (len(badread))

        print "registers dict"
        print self.registers

        print "stack contents"
        stack = 0



        try:
            stack = self.registers.rsp
        except (AttributeError, KeyError) as ex:
            stack = self.registers.esp
        print "stack at %08X" % (stack)
        contents = struct.unpack('<LLLLLLLL',self.read_mem(stack, 0x20))
        for i, dword in enumerate(contents):
            print "%02u : %08X" % (i, dword)

        print "modules:"
        print self.modules()

        print "PEB evaluate:"
        print hex(self.evaluate('@$peb'))


    def run(self):
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
                print "continuing debugging"
                # continue and wait for a prompt
                self.continue_debugging()
                print "reading to prompt"
                output = self.read_to_prompt()
                print "returned from prompt"

                # what was the stop event?
                # processes the event which will automatically
                # call any breakpoint handlers as well
                event = self.process_event()
                print "got debugger event: %s" % (event.description)

                if type(event) == ExceptionEvent:
                    exception = event
                    if exception.code in  self.ignore_exceptions:
                        print "ignoring exception: %08X" % (exception.code)
                    else:
                        print "Exception %08X (%s) occured at %08X" % (exception.code, exception.description, exception.address)

                        print ""
                        print "Disas:"
                        pre = self.execute('ub @$scopeip L5').strip().splitlines()
                        for l in pre:
                            print ' '*3 + l.strip()
                        post = self.execute('u @$scopeip L5').strip().splitlines()
                        for i, l in enumerate(post):
                            c = ' '*3
                            if i == 1:
                                c = '>'*3
                            print c + l

                        print ""
                        print "Registers:"
                        print self.execute('r')

                        print ""
                        print "Stacktrace:"
                        print self.execute('kb')

                        print ""
                        print "Stack contents:"
                        print self.execute('dp @$csp L30')


                        regs = pycdb.Registers(self)
                        print regs
                        print regs.all

                        print hex(regs.eip)
                        print hex(regs.get('$scopeip'))
                        print hex(regs.get('$t0'))

                        print hex(regs.eax)
                        print hex(regs['$scopeip'])
                        print type(regs['$scopeip'])
                        print hex(regs['$peb'])
                        print hex(regs['$t0'])
                        regs['$t0'] = 0x1337
                        print hex(regs['$t0'])

                        self.shell()

                        break

        except PyCdbPipeClosedException:
            print "pipe closed"

        finally:
            if not self.closed():
                self.write_pipe('q\r\n')


def usage():
    print "usage: %s [-p|--pid] <pid or program>" % (sys.argv[0])

if __name__ == "__main__":
    pid = False
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'p', ['pid'])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(1)
    for o, a in opts:
        if o in ('-p', '--pid'):
            pid = True
        else:
            assert False, 'unhandled option'

    dbg = ExceptionCatcher()

    if pid:
        # attach to the specified pid
        dbg.attach(int(args[0]))
    else:
        # run the specified command (or notepad)
        if not args or len(args) == 0:
            args = ['notepad.exe']
        dbg.spawn(args)
    # run the debug session
    dbg.run()



