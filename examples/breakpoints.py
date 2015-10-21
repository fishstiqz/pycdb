import sys
import os
import struct
import getopt

sys.path.append(os.path.join("..", "pycdb"))

import pycdb
from pycdb import PyCdb, PyCdbPipeClosedException


class BreakpointExample(PyCdb):
    """
    A simple demonstration class to show how to use PyCdb to set breakpoints
    """
    def __init__(self):
        PyCdb.__init__(self)
        self.ignore_exceptions = [
            0x4000001f              # wow64 exception
        ]

    def on_create_window_ex_w(self, bpnum):
        print "BREAKPOINT CreateWindowExW"
        print self.execute('u @$scopeip L10')

    def on_create_thread(self, bpnum):
        print "BREAKPOINT CreateThread"
        print self.execute('~.')
        print self.execute('kb 3')

    def on_load_module(self, event):
        print "MODLOAD: %08X: %s" % (event.base, event.module)
        mod = os.path.split(event.module)[1]
        mod = os.path.splitext(mod)[0]
        print self.execute('lm m %s' % (mod))

    def run(self):
        try:
            # wait until the first prompt
            # this works because initial_breakpoint is True
            self.read_to_prompt()

            # set a breakpoint with a handler
            self.breakpoint("user32!CreateWindowExW", self.on_create_window_ex_w)
            self.breakpoint("kernel32!CreateThread", self.on_create_thread)

            # simple debugging loop
            while True:
                # continue and wait for a prompt
                self.continue_debugging()
                output = self.read_to_prompt()

                # what was the stop event?

                # processes the event which will automatically
                # call any handlers associated with the events
                event = self.process_event()
                print "got debugger event: %s" % (event.description)


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

    dbg = BreakpointExample()
    dbg.break_on_load_modules = True

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



