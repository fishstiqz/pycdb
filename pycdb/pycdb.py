#!/usr/bin/python

import os
import sys
import subprocess
import threading
import time
import Queue
import re
import struct

"""
try:
    import readline
except ImportError:
    import pyreadline as readline
"""

# breakpoint types
BREAKPOINT_NORMAL       = 1
BREAKPOINT_UNRESOLVED   = 2
BREAKPOINT_HARDWARE     = 3


def parse_addr(addrstr):
    """
    parse 64 or 32-bit address from string into int
    """
    return int(addrstr.replace('`',''), 16)

def addr_to_hex(addr):
    """
    convert an address as int or long into a string
    """
    str = hex(addr)
    if str[-1] == 'L':
        return str[:-1]
    return str

class PyCdbException(Exception):
    pass

class PyCdbPipeClosedException(PyCdbException):
    def __str__(self):
        return "cdb pipe is closed"

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

class CdbEvent:
    pass

class OutputEvent(CdbEvent):
    def __init__(self, output, closed=False):
        self.output = output
    def __str__(self):
        return "OutputEvent: %s" % (self.output)

class PipeClosedEvent(CdbEvent):
    def __str__(self):
        return "PipeClosedEvent"

class LoadModuleEvent(CdbEvent):
    def __init__(self, module, base, length):
        self.module = module
        self.base = base
        self.length = length
    def __str__(self):
        return "LoadModuleEvent: %s, %08X, %u" % (self.module, self.base, self.length)

class BreakpointEvent(CdbEvent):
    def __init__(self, bpnum):
        self.bpnum = bpnum
    def __str__(self):
        return "BreakpointEvent: %u" % (self.bpnum)

class DbgEvent:
    """
    class that represents the '.lastevent' command. this is an
    event that takes place in the debuggee, not an event that
    is read over the cdb pipe
    """
    def __init__(self, pid, tid, desc):
        self.pid = pid
        self.tid = tid
        self.description = desc
        self.exception = None
        self.breakpoint = None

class DbgException:
    """
    class that represents an exception raised in the debuggee, such
    as an access violation. not to be confused with a python exception
    """
    def __init__(self, address, code, description):
        self.address = address
        self.code = code
        self.description = description
        self.params = []

class CdbReaderThread(threading.Thread):
    def __init__(self, pipe):
        threading.Thread.__init__(self)
        self.queue = Queue.Queue()
        self.pipe = pipe

    def process_line(self, line):
        #print "process_line: %s" % (line)
        if line.startswith("ModLoad: "):
            # stuff a load module event into the queue
            elems = re.split(r'\s+', line, 3)
            base = parse_addr(elems[1])
            end = parse_addr(elems[2])
            self.queue.put(LoadModuleEvent(elems[3].strip(), base, end-base))

    def run(self):
        #print 'ReaderThread.run()'
        curline = ''
        # read from the pipe
        while True:
            ch = self.pipe.stdout.read(1)
            #print 'ReaderThread.run(): read %s' % (ch)
            if not ch:
                # add a closed event to the queue
                self.queue.put(PipeClosedEvent())
                #print 'ReaderThread.run(): read nothing'
                break
            self.queue.put(OutputEvent(ch))
            curline += ch
            if ch == '\n':
                self.process_line(curline)
                curline = ''


class PyCdb(object):
    _registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "eip", "esp", "ebp",
                  "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rip", "rsp", "rbp",
                   "r8",  "r9", "r10", "r11", "r12", "r13", "r14", "r15"]


    def __init__(self, cdb_path=None):
        self.pipe = None
        if cdb_path:
            self.cdb_path = cdb_path
        else:
            self.cdb_path = self._find_cdb_path()
        self.initial_command = ''
        self.debug_children = False
        self.initial_breakpoint = True
        self.final_breakpoint = False
        self.pipe_closed = True
        self.qthread = None
        self.breakpoints = {}

    def _find_cdb_path(self):
        # build program files paths
        pg_paths = [ os.environ["PROGRAMFILES"] ]
        if "ProgramW6432" in os.environ:
            pg_paths.append(os.environ["ProgramW6432"])
        if "ProgramFiles(x86)" in os.environ:
            pg_paths.append(os.environ["ProgramFiles(x86)"])
        # potential paths to the debugger in program files
        dbg_paths = [
            "Windows Kits\\10\\Debuggers\\x64",
            "Windows Kits\\10\\Debuggers\\x86",
            "Windows Kits\\8.1\\Debuggers\\x64",
            "Windows Kits\\8.1\\Debuggers\\x86",
            "Windows Kits\\8.0\\Debuggers\\x64",
            "Windows Kits\\8.0\\Debuggers\\x86",
            "Debugging Tools for Windows (x64)",
            "Debugging Tools for Windows (x86)",
            "Debugging Tools for Windows",
        ]
        # search the paths
        for p in pg_paths:
            for d in dbg_paths:
                test_path = os.path.join(p, d, 'cdb.exe')
                if os.path.exists(test_path):
                    return test_path
        # couldn't locate, raise an exception
        raise PyCdbException('Could not locate the cdb executable!')

    def _create_pipe(self, cmdline):
        self.pipe = subprocess.Popen(cmdline,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        self.qthread = CdbReaderThread(self.pipe)
        self.qthread.start()
        self.pipe_closed = False

    def _run_cdb(self, arguments):
        cmdline = [self.cdb_path]
        if self.debug_children:
            cmdline.append('-o')
        if not self.initial_breakpoint:
            cmdline.append('-g')
        if not self.final_breakpoint:
            cmdline.append('-G')
        if self.initial_command and len(self.initial_command) > 0:
            cmdline += ['-c', '"%s"' % (self.initial_command)]
        self._create_pipe(cmdline + arguments)

    def closed(self):
        """
        return True if the pipe is closed
        """
        return self.pipe_closed

    def read_to_prompt(self, keep_output=True, debug=False):
        """
        This is the main 'wait' function, it dequeues event objects from
        the cdb output queue and acts on them.
        The actual output buffer is returned.
        """
        buf = ''
        lastch = None
        while True:
            event = self.qthread.queue.get()
            #print "read_to_prompt: %s" % (event)
            if isinstance(event, OutputEvent):
                ch = event.output
                # read one character at a time until we see a '> '
                if debug:
                    print 'read: %s' % (ch)
                if keep_output:
                    buf += ch

                # look for prompt
                if lastch == '>' and ch == ' ':
                    # see if queue is empty, if so, we've found the prompt
                    if self.qthread.queue.empty():
                        break
                lastch = ch
            elif isinstance(event, PipeClosedEvent):
                self.pipe_closed = True
                raise PyCdbPipeClosedException()
            elif isinstance(event, LoadModuleEvent):
                self.on_load_module(event)
            """
            elif isinstance(event, BreakpointEvent):
                self.on_breakpoint(event)
            """
        return buf

    def write_pipe(self, buf):
        self.pipe.stdin.write(buf)

    def continue_debugging(self):
        """
        tell cdb to go but don't issue a read to prompt
        """
        self.write_pipe('g\r\n')

    def on_load_module(self, event):
        pass

    def unhandled_breakpoint(self, bpnum):
        # no handler, just continue execution
        self.continue_debugging()

    def on_breakpoint(self, event):
        handled = False
        bpnum = event.bpnum
        # call the handler if there is one
        if bpnum in self.breakpoints:
            handler = self.breakpoints[bpnum]
            if handler:
                handler(bpnum)
                # continue execution
                # self.continue_debugging()
                handled = True
        if not handled:
            self.unhandled_breakpoint(bpnum)

    def spawn(self, arguments):
        self._run_cdb(arguments)

    def attach(self, pid):
        self._run_cdb(['-p', str(pid)])

    def execute(self, command):
        self.write_pipe(command + '\r\n')
        # return the entire output except the prompt string
        output = self.read_to_prompt()
        return "\n".join(output.splitlines()[:-1])+"\n"

    def evaluate(self, expression):
        output = self.execute("? " + expression)
        m = re.match(r'Evaluate expression: ([0-9]+) =', output)
        if m:
            return int(m.group(1))
        else:
            return None

    @property
    def registers(self):
        """
        return a map of registers and their current values.
        """
        map = AttrDict()
        regs = self.execute("r")
        all = re.findall(r'([A-Za-z0-9]+)\=([0-9A-Fa-f]+)', regs)
        for entry in all:
            map[entry[0]] = int(entry[1], 16)
        return map

    def __getattr__(self, name):
        if name in self._registers:
            return self.registers()[name]

        return super(A, self).__getattribute__(name)

    def read_mem(self, address, len):
        mem = ''
        rem = len
        if type(address) in (int, long):
            address = addr_to_hex(address)
        output = self.execute('db %s L%X' % (address, len))
        for line in output.splitlines():
            chunk = 16
            if chunk > rem:
                chunk = rem
            elems = re.split(r'[\ -]+', line)[1:1+chunk]
            for value in elems:
                if value == '??':
                    break
                mem += value.decode('hex')
            rem -= chunk
        return mem

    def read_u32(self, address):
        buf = self.read_mem(address, 4)[0]
        print buf.encode('hex')
        return struct.unpack('<L', self.read_mem(address, 4))[0]

    def read_u16(self, address):
        return struct.unpack('<H', self.read_mem(address, 2))[0]

    def read_u8(self, address):
        return self.read_mem(address, 1)


    def write_mem(self, address, buf):
        if type(address) in (int, long):
            address = addr_to_hex(address)
        bytes = ''
        for b in buf:
            bytes += b.encode('hex') + ' '
        return self.execute('eb %s %s' % (address, bytes))

    def write_u32(self, address, val):
        return write_mem(address, struct.pack('<L', val))

    def write_u16(self, address, val):
        return write_mem(address, struct.pack('<H', val))

    def write_u8(self, address, val):
        return write_mem(address, struct.pack('<B', val))


    def modules(self):
        map = {}
        output = self.execute('lmf')
        for line in output.splitlines()[1:]:
            elems = re.split(r'\s+', line, 3)
            base = parse_addr(elems[0])
            end = parse_addr(elems[1])
            map[elems[2].lower()] = [base, end-base, elems[3].strip()]
        return map

    def _get_bp_nums(self):
        bpnums = []
        output = self.execute('bl')
        for line in output.splitlines():
            line = line.strip()
            elems = re.split(r'\s+', line)
            if len(elems) > 1 and len(elems[0]) > 0:
                bpnums.append(int(elems[0]))
        return bpnums

    def breakpoint(self, address, handler=None, bptype=BREAKPOINT_NORMAL, bpmode="e"):
        if type(address) in (int, long):
            address = addr_to_hex(address)
        cmd = 'bp'
        if bptype == BREAKPOINT_UNRESOLVED:
            cmd = 'bu'
        elif bptype == BREAKPOINT_HARDWARE:
            cmd = 'ba %s 1' % bpmode

        nums_before = self._get_bp_nums()
        output = self.execute('%s %s' % (cmd, address))
        nums_after = self._get_bp_nums()
        added_num = list(set(nums_after) - set(nums_before))
        if len(added_num) == 0:
            raise PyCdbException(output.strip())
        else:
            bpnum = added_num[0]
            self.breakpoints[bpnum] = handler
            return bpnum

    def remove_breakpoint(self, bpnum):
        self.execute("bc %u" % (bpnum))

    def lastexception(self):
        output = self.execute('.lastevent')
        m = re.match(r'Last event: ([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\: ([^-]+) - code ([0-9A-Fa-f]+) \(([^\)]+)\)', output)
        if m:
            pid, tid, desc, code, chance = m.groups()
        else:
            return None

    def exception_info(self):
        output = self.execute('.exr -1')
        if output.find('not an exception') != -1:
            return None
        m = re.search(r'ExceptionAddress: ([0-9A-Fa-f]+)', output)
        if not m:
            return None
        address = int(m.group(1), 16)
        m = re.search(r'ExceptionCode: ([0-9A-Fa-f]+) \(([^\)]+)\)', output)
        if not m:
            return None
        code = int(m.group(1), 16)
        desc = m.group(2)
        ex = DbgException(address, code, desc)
        m = re.search(r'NumberParameters: ([0-9]+)', output)
        num_params = int(m.group(1))
        params = []
        for n in xrange(num_params):
            m = re.search(r'Parameter\[%u\]: ([0-9A-Fa-f]+)'%(n), output)
            if not m:
                return None
            params.append(int(m.group(1), 16))
        ex.params = params
        return ex

    def _breakpoint_info(self, event_desc):
        m = re.search(r'Hit breakpoint ([0-9]+)', event_desc)
        if not m:
            return None
        bpnum = int(m.group(1))
        bp = BreakpointEvent(bpnum)
        print "_breakpoint_info: %s" % (bp)
        return bp

    def lastevent(self):
        output = self.execute('.lastevent')
        m = re.search(r'Last event: ([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\: (.*)$',
                output, re.MULTILINE)
        if m:
            pid, tid, desc = m.groups()
            event = DbgEvent(pid, tid, desc)

            # was this a breakpoint?
            bp = self._breakpoint_info(desc)
            if bp:
                event.breakpoint = bp
            else:
                # was it an exception?
                exception = self.exception_info()
                if exception:
                    event.exception = exception
            return event
        else:
            return None

    def process_event(self):
        event = self.lastevent()
        if event and event.breakpoint:
            self.on_breakpoint(event.breakpoint)
        return event

    def shell(self):
        print "Dropping to cdb shell.  'quit' to exit."
        p = '> '
        while True:
            try:
                input = raw_input(p)
                p = ''
                if input.strip().lower() == 'quit':
                    break
                self.write_pipe(input + '\r\n')
                output = self.read_to_prompt()
                sys.stdout.write(output)
            except EOFError:
                break

