#!/usr/bin/python

import os
import sys
import subprocess
import threading
import time
import Queue
import re
import struct
import shlex

# breakpoint types
BREAKPOINT_NORMAL       = 1
BREAKPOINT_UNRESOLVED   = 2
BREAKPOINT_HARDWARE     = 3

COMMAND_FINISHED_MARKER = "CMDH@ZF1N1$H3D"

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
    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, value):
        if self.setterCallback:
            self.setterCallback(key, value)
        else:
            self[key] = value

class CdbEvent(object):
    pass

class OutputEvent(CdbEvent):
    def __init__(self, output, closed=False):
        self.output = output
    def __str__(self):
        return "OutputEvent: %s" % (self.output)

class PipeClosedEvent(CdbEvent):
    def __str__(self):
        return "PipeClosedEvent"

class DebuggerEvent(CdbEvent):
    def __init__(self):
        self.pid = 0
        self.tid = 0
        self.description = ''
    def set_base(self, pid=None, tid=None, desc=None):
        if type(pid) == str:
            pid = int(pid, 16)
        if type(tid) == str:
            tid = int(tid, 16)
        self.pid = pid
        self.tid = tid
        self.description = desc
    def __str__(self):
        return "DebuggerEvent(%x,%x)" % (self.pid, self.tid)

class LoadModuleEvent(DebuggerEvent):
    def __init__(self, module, base):
        self.module = module
        self.base = base
    def __str__(self):
        return "LoadModuleEvent(%x,%x): %s, %08X" % (self.pid, self.tid, self.module, self.base)

class BreakpointEvent(DebuggerEvent):
    def __init__(self, bpnum):
        self.bpnum = bpnum
    def __str__(self):
        return "BreakpointEvent(%x,%x): %u" % (self.pid, self.tid, self.bpnum)

class ExceptionEvent(DebuggerEvent):
    """
    class that represents an exception raised in the debuggee, such
    as an access violation. not to be confused with a python exception
    """
    def __init__(self, address, code, description):
        self.address = address
        self.code = code
        self.description = description
        self.params = []
    def __str__(self):
        return "ExceptionEvent(%x,%x): %08X: code=%08X: %s" % (
                self.pid, self.tid, self.address, self.code, self.description)


class CdbReaderThread(threading.Thread):
    def __init__(self, pipe):
        threading.Thread.__init__(self)
        self.queue = Queue.Queue()
        self.pipe = pipe

    def process_line(self, line):
        if line.startswith("ModLoad: "):
            # stuff a load module event into the queue
            elems = re.split(r'\s+', line, 3)
            base = parse_addr(elems[1])
            end = parse_addr(elems[2])
            self.queue.put(LoadModuleEvent(elems[3].strip(), base))

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
        self.break_on_load_modules = False
        self.pipe_closed = True
        self.qthread = None
        self.breakpoints = {}
        self.bit_width = 32
        self.first_prompt_read = False
        self.cdb_cmdline = []

    def _find_cdb_path(self):
        # build program files paths
        pg_paths = [ os.environ["PROGRAMFILES"] ]
        if "ProgramW6432" in os.environ:
            self.bit_width = 64
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

    def add_cmdline_option(self, option):
        if type(option) == list:
            self.cdb_cmdline.append(option)
        else:
            self.cdb_cmdline.append(shlex.split(option))

    def _run_cdb(self, arguments):
        cmdline = [self.cdb_path]
        if len(self.cdb_cmdline) > 0:
            cmdline += self.cdb_cmdline
        if self.debug_children:
            cmdline.append('-o')
        if not self.initial_breakpoint:
            cmdline.append('-g')
        if not self.final_breakpoint:
            cmdline.append('-G')
        if self.break_on_load_modules:
            cmdline += ['-xe', 'ld']
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
                buf += ch

                # look for prompt
                if lastch == '>' and ch == ' ' and self.qthread.queue.empty():
                    # For initial breakpoint since we cant insert our marker
                    # On this one
                    if not self.first_prompt_read:
                        self.first_prompt_read = True
                        break

                    if COMMAND_FINISHED_MARKER in buf:
                        buf = buf.replace("%s\n" % (COMMAND_FINISHED_MARKER), "")
                        break
                lastch = ch
            elif isinstance(event, PipeClosedEvent):
                self.pipe_closed = True
                raise PyCdbPipeClosedException()
            elif isinstance(event, LoadModuleEvent):
                # this is a bit tricky, if we ARE breaking on modload
                # then we don't want to call the handler as it will be
                # called when process_event is called. However, if
                # we ARE NOT breaking on modload, then we probably should
                # call here
                if not self.break_on_load_modules:
                    self.on_load_module(event)
        return buf if keep_output else ""

    def write_pipe(self, buf):
        self.pipe.stdin.write('%s ; .echo %s\r\n' % (buf, COMMAND_FINISHED_MARKER))

    def continue_debugging(self):
        """
        tell cdb to go but don't issue a read to prompt
        """
        self.write_pipe('g')

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

    def on_exception(self, event):
        pass

    def spawn(self, arguments):
        self._run_cdb(arguments)

    def attach(self, pid):
        self._run_cdb(['-p', str(pid)])

    def execute(self, command):
        self.write_pipe(command)
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
        map = AttrDict(setterCallback=self.setRegister)
        regs = self.execute("r")
        all = re.findall(r'([A-Za-z0-9]+)\=([0-9A-Fa-f]+)', regs)
        for entry in all:
            map[entry[0]] = int(entry[1], 16)
        return map

    def setRegister(self, register, value):
        self.execute("r @%s=%x" % (register, value))

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

    def search(self, value, mode="d", begin=0, end=0xFFFFFFFF):
        if self.bit_width == 64 and end == 0xFFFFFFFF:
            end = 0xFFFFFFFFFFFFFFFF

        if mode == "d" or mode == "w":
            return self.execute("s -%s %x L?%x %x" % (mode, begin, end, value))

        elif mode == "a" or mode == "b":
            return self.execute("s -%s %x L?%x %s" % (mode, begin, end, value))

        return ""

    def search_int(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "d", begin, end)

    def search_ascii(self, value, begin=0, end=0xFFFFFFFF):
        return self.search(value, "a", begin, end)

    def search_bytes(self, value, begin=0, end=0xFFFFFFFF):
        """ value should be a string "fe ed fa ce" """
        if isinstance(value, basestring):
            return self.search(value, "b", begin, end)

        print "Error: search_bytes called with non-string value."
        return ""


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
            print line
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

    def breakpoint_disable(self, bpnum):
        self.execute("bd %u" % bpnum)

    def breakpoint_enable(self, bpnum):
        self.execute("be %u" % bpnum)

    def breakpoint_remove(self, bpnum):
        self.execute("bc %u" % (bpnum))

    def _exception_info(self):
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
        ex = ExceptionEvent(address, code, desc)
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
        # print "_breakpoint_info: %s" % (bp)
        return bp

    def _load_module_info(self, event_desc):
        m = re.search(r'Load module (.*) at ([0-9A-Fa-f`]+)', event_desc)
        if not m:
            return None
        module_path = m.group(1)
        module_base = int(m.group(2).replace('`',''), 16)
        lme = LoadModuleEvent(module_path, module_base)
        return lme

    def lastevent(self):
        event = None
        output = self.execute('.lastevent')
        m = re.search(r'Last event: ([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)\: (.*)$',
                output, re.MULTILINE)
        if m:
            pid, tid, desc = m.groups()
            #
            # what type of event was this?
            #
            while True: # always breaks at end
                # was this a breakpoint?
                event = self._breakpoint_info(desc)
                if event:
                    break
                # was this a load module event?
                event = self._load_module_info(desc)
                if event:
                    break
                # was it an exception?
                event = self._exception_info()
                # always break at the end
                break
            # if we have an event, set the base info
            if event:
                event.set_base(pid, tid, desc)
        return event

    def process_event(self):
        event = self.lastevent()
        if type(event) == BreakpointEvent:
            self.on_breakpoint(event)
        elif type(event) == LoadModuleEvent:
            self.on_load_module(event)
        elif type(event) == ExceptionEvent:
            self.on_exception(event)
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
                self.write_pipe(input)
                output = self.read_to_prompt()
                sys.stdout.write(output)
            except EOFError:
                break

