import sys
import os
import struct
import getopt
import time

sys.path.append(os.path.join("..", "pycdb"))

import pycdb
from pycdb import PyCdb, PyCdbPipeClosedException

SYMPATH = "z:\work\win_syms\symbols"

class IEDebugLog(PyCdb):
    """
    A simple demonstration that uses a breakpoint on Math.min to log messages
    to the debugger from Internet Explorer
    """
    def __init__(self):
        PyCdb.__init__(self)
        self.ignore_exceptions = [
            0x4000001f              # wow64 exception
        ]

    def on_math_min(self, bpnum):
        val = self.read_u32(self.registers.esp + 0x10)
        val = val >> 1
        if val == 0x111111:
            ptr_data = self.read_u32(self.read_u32(self.registers.esp + 0x14) + 0xC)
            len_data = self.read_u32(self.read_u32(self.registers.esp + 0x14) + 0x8) * 2
            data = self.read_mem(ptr_data, len_data)
            print "%s: %s" % (time.ctime(), data.decode('utf-16le'))

    def run(self):
        try:
            # wait until the first prompt
            # this works because initial_breakpoint is True
            self.read_to_prompt()

            # set our sympath
            print self.execute('.sympath %s' % (SYMPATH))

            # set a breakpoint with a handler
            # break on jscript9!Js::Math::Min
            self.breakpoint("jscript9!Js::Math::Min", self.on_math_min)

            # simple debugging loop
            while True:
                # continue and wait for a prompt
                self.continue_debugging()
                output = self.read_to_prompt()

                # what was the stop event?

                # processes the event which will automatically
                # call any handlers associated with the events
                event = self.process_event()
                #print "got debugger event: %s" % (event.description)


        except PyCdbPipeClosedException:
            print "pipe closed"

        finally:
            if not self.closed():
                self.write_pipe('q\r\n')


def usage():
    print "usage: %s [-p|--pid] <pid>" % (sys.argv[0])

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
    if not pid:
        usage()
        sys.exit(1)

    dbg = IEDebugLog()

    # attach to the specified pid
    dbg.attach(int(args[0]))
    # run the debug session
    dbg.run()

