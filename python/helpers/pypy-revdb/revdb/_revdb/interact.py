import os, re
import socket
import traceback, linecache
from contextlib import contextmanager

import time
from urllib import quote
import sys, threading
from revdb_comm import CMD_RUN, CMD_GET_FRAME, CMD_ADD_EXCEPTION_BREAK, CMD_SET_BREAK, CMD_VERSION, \
    CMD_THREAD_CREATE, CMD_THREAD_SUSPEND, CMD_STEP_BACK, CMD_THREAD_RUN, CMD_STEP_OVER, CMD_STEP_INTO, \
    CMD_REMOVE_BREAK
from revdb_comm import set_global_debugger
from revdb_comm import WriterThread, ReaderThread

up = os.path.dirname

root = up(up(up(up(__file__)))) + "/pydev"
sys.path.insert(0, root)

from _pydev_bundle.pydev_is_thread_alive import is_thread_alive
from _pydevd_bundle.pydevd_constants import get_thread_id, dict_contains
from _pydevd_bundle.pydevd_xml import make_valid_xml_value, frame_vars_to_xml
from _pydevd_bundle.pydevd_comm import pydevd_find_thread_by_id



def __getfilesystemencoding():
    '''
    Note: there's a copy of this method in interpreterInfo.py
    '''
    try:
        ret = sys.getfilesystemencoding()
        if not ret:
            raise RuntimeError('Unable to get encoding.')
        return ret
    except:
        try:
            # Handle Jython
            from java.lang import System  # @UnresolvedImport
            env = System.getProperty("os.name").lower()
            if env.find('win') != -1:
                return 'ISO-8859-1'  # mbcs does not work on Jython, so, use a (hopefully) suitable replacement
            return 'utf-8'
        except:
            pass

        # Only available from 2.3 onwards.
        if sys.platform == 'win32':
            return 'mbcs'
        return 'utf-8'


def getfilesystemencoding():
    try:
        ret = __getfilesystemencoding()

        # Check if the encoding is actually there to be used!
        if hasattr('', 'encode'):
            ''.encode(ret)
        if hasattr('', 'decode'):
            ''.decode(ret)

        return ret
    except:
        return 'utf-8'


file_system_encoding = getfilesystemencoding()

ID_TO_MEANING = {
    '101': 'CMD_RUN',
    '102': 'CMD_LIST_THREADS',
    '103': 'CMD_THREAD_CREATE',
    '104': 'CMD_THREAD_KILL',
    '105': 'CMD_THREAD_SUSPEND',
    '106': 'CMD_THREAD_RUN',
    '107': 'CMD_STEP_INTO',
    '108': 'CMD_STEP_OVER',
    '109': 'CMD_STEP_RETURN',
    '110': 'CMD_GET_VARIABLE',
    '111': 'CMD_SET_BREAK',
    '112': 'CMD_REMOVE_BREAK',
    '113': 'CMD_EVALUATE_EXPRESSION',
    '114': 'CMD_GET_FRAME',
    '115': 'CMD_EXEC_EXPRESSION',
    '116': 'CMD_WRITE_TO_CONSOLE',
    '117': 'CMD_CHANGE_VARIABLE',
    '118': 'CMD_RUN_TO_LINE',
    '119': 'CMD_RELOAD_CODE',
    '120': 'CMD_GET_COMPLETIONS',
    '121': 'CMD_CONSOLE_EXEC',
    '122': 'CMD_ADD_EXCEPTION_BREAK',
    '123': 'CMD_REMOVE_EXCEPTION_BREAK',
    '124': 'CMD_LOAD_SOURCE',
    '125': 'CMD_ADD_DJANGO_EXCEPTION_BREAK',
    '126': 'CMD_REMOVE_DJANGO_EXCEPTION_BREAK',
    '127': 'CMD_SET_NEXT_STATEMENT',
    '128': 'CMD_SMART_STEP_INTO',
    '129': 'CMD_EXIT',

    '130': 'CMD_SIGNATURE_CALL_TRACE',

    '131': 'CMD_SET_PY_EXCEPTION',
    '132': 'CMD_GET_FILE_CONTENTS',
    '133': 'CMD_SET_PROPERTY_TRACE',
    '134': 'CMD_EVALUATE_CONSOLE_EXPRESSION',
    '135': 'CMD_RUN_CUSTOM_OPERATION',
    '136': 'CMD_GET_BREAKPOINT_EXCEPTION',
    '137': 'CMD_STEP_CAUGHT_EXCEPTION',
    '138': 'CMD_SEND_CURR_EXCEPTION_TRACE',
    '139': 'CMD_SEND_CURR_EXCEPTION_TRACE_PROCEEDED',
    '140': 'CMD_IGNORE_THROWN_EXCEPTION_AT',
    '141': 'CMD_ENABLE_DONT_TRACE',
    '142': 'CMD_SHOW_CONSOLE',
    '143': 'CMD_GET_ARRAY',
    '144': 'CMD_STEP_INTO_MY_CODE',
    '145': 'CMD_GET_CONCURRENCY_EVENT',
    '146': 'CMD_SHOW_RETURN_VALUES',
    '147': 'CMD_INPUT_REQUESTED',
    '148': 'CMD_GET_DESCRIPTION',

    '149': 'CMD_PROCESS_CREATED',

    '150': 'CMD_STEP_BACK',

    '501': 'CMD_VERSION',
    '502': 'CMD_RETURN',
    '901': 'CMD_ERROR',
}


def to_string(x):
    if isinstance(x, basestring):
        return x
    else:
        return str(x)


class NetCommand:
    next_seq = 0

    def __init__(self, id, seq, text):
        self.id = id
        if seq == 0:
            NetCommand.next_seq += 2
            seq = NetCommand.next_seq
        self.seq = seq
        self.text = text
        encoded = quote(to_string(text), '/<>_=" \t')
        self.outgoing = '%s\t%s\t%s\n' % (id, seq, encoded)


try:
    import readline
except ImportError:
    pass

from _revdb.process import ReplayProcessGroup
from _revdb.process import Breakpoint

if sys.version_info < (3,):
    import thread
else:
    import _thread as thread
PROG_RES = 500000

ERASE_LINE = '\x1b[K'

r_cmdline = re.compile(r"([a-zA-Z0-9_]\S*|.)\s*(.*)")
r_dollar_num = re.compile(r"\$(\d+)\b")


class RevDebugControl(object):
    def __init__(self, revdb_log_filename, executable=None,
                 pygments_background=None, port=None, host=None):
        with open(revdb_log_filename, 'rb') as f:
            header = f.readline()
        assert header.endswith('\n')
        fields = header[:-1].split('\t')
        if len(fields) < 2 or fields[0] != 'RevDB:':
            raise ValueError("file %r is not a RevDB log" % (
                revdb_log_filename,))
        if executable is None:
            executable = fields[1]
        if not os.path.isfile(executable):
            raise ValueError("executable %r not found" % (executable,))
        linecacheoutput = self.getlinecacheoutput(pygments_background)
        self.pgroup = ReplayProcessGroup(executable, revdb_log_filename,
                                         linecacheoutput,
                                         (PROG_RES, self.progress_callback))
        self._running_thread_ids = {}
        self._main_lock = thread.allocate_lock()
        set_global_debugger(self)
        self.sock = None
        self.bp = {}
        self.ready = False
        self.init_network(host, port)

    def init_network(self, host, port):
        self.connect(host, int(port))
        new_port = self.get_new_port()
        sys.stderr.write("Received port {}\n".format(new_port))
        self.sock.shutdown(socket.SHUT_RD)
        self.sock.shutdown(socket.SHUT_WR)
        self.sock.close()
        self.connect(host, int(new_port))
        self.writer = WriterThread(self.sock)
        self.reader = ReaderThread(self.sock)
        self.writer.start()
        self.reader.start()

        time.sleep(0.1)

    def connect(self, host, port):
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        MAX_TRIES = 100
        i = 0
        while i < MAX_TRIES:
            try:
                self.sock.connect((host, port))
            except:
                i += 1
                time.sleep(0.2)
                continue
            return

    def get_new_port(self):
        read_buffer = ""
        try:
            try:
                r = self.sock.recv(1024)
            except:
                traceback.print_exc()
                return
            if hasattr(r, 'decode'):
                r = r.decode('utf-8')

            read_buffer += r

            if len(read_buffer) == 0:
                return
            while read_buffer.find('\n') != -1:
                command, read_buffer = read_buffer.split('\n', 1)

                args = command.split('\t', 2)
                try:
                    port = args[2]
                    return port
                except:
                    traceback.print_exc()
        except:
            traceback.print_exc()

    def process_cmd(self, cmd_id, seq, text):
        sys.stdout.write("%d \n" % self.pgroup.get_current_time())
        if cmd_id == CMD_GET_FRAME:
            try:
                xml = "<xml>"
                locals = self.pgroup.get_locals()
                sys.stdout.write(str(locals))
                xml += frame_vars_to_xml(locals)
                xml += "</xml>"
                self.writer.add_command(NetCommand(CMD_GET_FRAME, seq, xml))
            except:
                traceback.print_exc()
        elif cmd_id == CMD_STEP_OVER:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_OVER)))
            self.command_next(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                               self.make_thread_suspend_str(text, CMD_STEP_OVER)))
        elif cmd_id == CMD_STEP_BACK:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_BACK)))
            self.command_bnext(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                               self.make_thread_suspend_str(text, CMD_STEP_BACK)))
        elif cmd_id == CMD_VERSION:
            cmd = NetCommand(CMD_VERSION, seq, "build")
            self.writer.add_command(cmd)
        elif cmd_id == CMD_SET_BREAK:
            type, file, line, func_name, suspend_policy, condition, expression = text.split('\t', 6)
            file = file.encode(getfilesystemencoding())
            self.command_break(file + ':' + str(line))
            self.file = file
        elif cmd_id == CMD_REMOVE_BREAK:
            breakpoint_type, file, line = text.split('\t', 2)
            self.command_delete(file+":" + str(line))
        elif cmd_id == CMD_ADD_EXCEPTION_BREAK:
            sys.stderr.write("Exceptional breakpoints are not supported\n")
        elif cmd_id == CMD_RUN:
            self.command_continue(None)
            self.ready = True
        elif cmd_id == CMD_THREAD_RUN:
            t = pydevd_find_thread_by_id(text)
            if t:
                self.writer.add_command(NetCommand(CMD_THREAD_RUN, -1, text))
                self.command_continue(None)

                self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                                       self.make_thread_suspend_str(text, CMD_SET_BREAK)))
        elif cmd_id == CMD_STEP_INTO:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_OVER)))
            self.command_step(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                                   self.make_thread_suspend_str(text, CMD_STEP_OVER)))


    def process_internal_commands(self):
        self._main_lock.acquire()
        try:
            program_threads_alive = {}
            all_threads = threading.enumerate()
            program_threads_dead = []
            try:
                for t in all_threads:
                    if is_thread_alive(t):
                        thread_id = get_thread_id(t)
                        program_threads_alive[thread_id] = t

                        if not dict_contains(self._running_thread_ids, thread_id) and t.getName() == "MainThread":
                            self._running_thread_ids[thread_id] = t
                            name = make_valid_xml_value(t.getName())
                            cmdText = '<thread name="%s" id="%s" />' % (quote(name), thread_id)
                            cmdText = "<xml>" + cmdText + "</xml>"
                            self.writer.add_command(NetCommand(CMD_THREAD_CREATE, 0, cmdText))

                thread_ids = list(self._running_thread_ids.keys())
                for tId in thread_ids:
                    if not dict_contains(program_threads_alive, tId):
                        program_threads_dead.append(tId)
            except:
                pass

        finally:
            self._main_lock.release()

    def make_thread_suspend_str(self, thread_id, stop_reason):
        cmd_text_list = ["<xml>"]
        append = cmd_text_list.append
        append('<thread id="%s" stop_reason="%s" message="%s">' % (thread_id, stop_reason, ""))
        try:
            my_id = self.pgroup.get_stack_id(1)
            my_name = '?'
            myFile = self.file
            myLine = self.pgroup.get_line_no()
            variables = ''
            append('<frame id="%s" name="%s" ' % (my_id, make_valid_xml_value(my_name)))
            append('file="%s" line="%s">' % (quote(myFile, '/>_= \t'), myLine))
            append(variables)
            append("</frame>")
        except:
            traceback.print_exc()

        append("</thread></xml>")
        return ''.join(cmd_text_list)

    def interact(self):
        flag = True

        try:
            while True:
                    self.process_internal_commands()
                    time.sleep(0.1)
                    # v It's to be changed v
                    if flag and self.ready:
                        self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                                           self.make_thread_suspend_str(
                                                               get_thread_id(threading.currentThread()), CMD_SET_BREAK)))
                        flag = False
        except:
            self.writer.killReceived = True
            self.reader.killReceived = True
            self.reader.do_kill_pydev_thread()
            self.command_quit(None)

    def print_lines_before_prompt(self):
        last_time = self.pgroup.get_current_time()
        if last_time != self.previous_time:
            print ERASE_LINE
            if self.pgroup.get_current_thread() != self.previous_thread:
                self.previous_thread = self.pgroup.get_current_thread()
                if self.previous_thread == 0:
                    print ('-------------------- in main thread #0 '
                           '--------------------')
                else:
                    print ('-------------------- in non-main thread '
                           '#%d --------------------' % (self.previous_thread,))
            self.pgroup.update_watch_values()
            last_time = self.pgroup.get_current_time()
        if last_time != self.previous_time:
            self.pgroup.show_backtrace(complete=0)
            self.previous_time = last_time
        if self.print_extra_pending_info:
            print self.print_extra_pending_info
            self.print_extra_pending_info = None
        prompt = '(%d)$ ' % last_time
        return prompt

    def display_prompt(self, prompt):
        self.pgroup.wait_for_prompt = True
        try:
            cmdline = raw_input(prompt).strip()
        except EOFError:
            print
            cmdline = 'quit'
        if not cmdline:
            cmdline = self.last_command
        return cmdline

    def run_command(self, cmdline):
        match = r_cmdline.match(cmdline)
        if not match:
            return
        self.last_command = cmdline
        command, argument = match.groups()
        try:
            runner = getattr(self, 'command_' + command)
        except AttributeError:
            print >> sys.stderr, "no command '%s', try 'help'" % (command,)
        else:
            try:
                runner(argument)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                traceback.print_exc()
                print >> sys.stderr
                print >> sys.stderr, 'Something went wrong.  You are now',
                print >> sys.stderr, 'in a pdb; press Ctrl-D to continue.'
                import pdb
                pdb.post_mortem(sys.exc_info()[2])
                print >> sys.stderr
                print >> sys.stderr, 'You are back running %s.' % (
                    sys.argv[0],)

    def command_help(self, argument):
        """Display commands summary"""
        print 'Available commands:'
        lst = dir(self)
        commands = [(name[len('command_'):], getattr(self, name))
                    for name in lst
                    if name.startswith('command_')]
        seen = {}
        for name, func in commands:
            seen.setdefault(func, []).append(name)
        for _, func in commands:
            if func in seen:
                names = seen.pop(func)
                names.sort(key=len, reverse=True)
                docstring = func.__doc__ or 'undocumented'
                print '\t%-16s %s' % (', '.join(names), docstring)

    def command_quit(self, argument):
        """Exit the debugger"""
        self.pgroup.close()
        sys.exit(0)

    command_q = command_quit

    def command_go(self, argument):
        """Jump to time ARG"""
        arg = int(argument or self.pgroup.get_current_time())
        self.pgroup.jump_in_time(arg)

    def command_info(self, argument):
        """Display various info ('info help' for more)"""
        display = getattr(self, 'cmd_info_' + argument, self.cmd_info_help)
        return display()

    def cmd_info_help(self):
        """Display info topics summary"""
        print 'Available info topics:'
        for name in dir(self):
            if name.startswith('cmd_info_'):
                command = name[len('cmd_info_'):]
                docstring = getattr(self, name).__doc__ or 'undocumented'
                print '\tinfo %-12s %s' % (command, docstring)

    def cmd_info_paused(self):
        """List current paused subprocesses"""
        lst = [str(n) for n in sorted(self.pgroup.paused)]
        print ', '.join(lst)

    def _bp_kind(self, num):
        break_at = self.pgroup.all_breakpoints.num2break.get(num, '??')
        if break_at[0] == 'B':
            kind = 'breakpoint'
            name = break_at[4:]
        elif break_at[0] == 'W':
            kind = 'watchpoint'
            name = self.pgroup.all_breakpoints.sources.get(num, '??')
        elif num == -3:
            kind = 'stoppoint'
            name = 'explicit stop'
        elif num == -4:
            kind = 'switchpoint'
            name = 'thread switch'
        else:
            kind = '?????point'
            name = repr(break_at)
        return kind, name

    def _bp_new(self, source_expr, break_code, break_at, nids=None):
        b = self.pgroup.edit_breakpoints()
        new = 1
        while new in b.num2break:
            new += 1
        b.set_num2break(new, break_code, break_at)
        b.sources[new] = source_expr
        if break_code == 'W':
            b.watchvalues[new] = ''
            if nids:
                b.watchuids[new] = self.pgroup.nids_to_uids(nids)
        return new

    def cmd_info_breakpoints(self):
        """List current breakpoints and watchpoints"""
        lst = self.pgroup.all_breakpoints.num2break.keys()
        if lst:
            for num in sorted(lst):
                kind, name = self._bp_kind(num)
                print '\t%s %d: %s' % (kind, num, name)
        else:
            print 'no breakpoints/watchpoints.'

    cmd_info_watchpoints = cmd_info_breakpoints

    def move_forward(self, steps):
        self.remove_tainting()
        try:
            self.pgroup.go_forward(steps)
            return None
        except Breakpoint as b:
            self.hit_breakpoints(b)
            return b

    def move_backward(self, steps):
        try:
            self.pgroup.go_backward(steps)
            return None
        except Breakpoint as b:
            self.hit_breakpoints(b, backward=True)
            return b

    def hit_breakpoints(self, b, backward=False):
        printing = []
        for num in b.regular_breakpoint_nums():
            kind, name = self._bp_kind(num)
            printing.append('%s %s%s: %s' % (
                'Reverse-hit' if backward else 'Hit',
                kind,
                '' if kind == 'stoppoint' else ' %d' % (num,),
                name))
        self.print_extra_pending_info = '\n'.join(printing)
        if self.pgroup.get_current_time() != b.time:
            target_time = b.time
            if backward and any(self._bp_kind(num)[0] == 'watchpoint'
                                for num in b.regular_breakpoint_nums()):
                target_time += 1
            self.pgroup.jump_in_time(target_time)

    def remove_tainting(self):
        if self.pgroup.is_tainted():
            self.pgroup.jump_in_time(self.pgroup.get_current_time())
            assert not self.pgroup.is_tainted()

    def command_step(self, argument):
        """Run forward ARG steps (default 1)"""
        arg = int(argument or '1')
        self.move_forward(arg)

    command_s = command_step

    def command_bstep(self, argument):
        """Run backward ARG steps (default 1)"""
        arg = int(argument or '1')
        self.move_backward(arg)

    command_bs = command_bstep

    @contextmanager
    def _stack_id_break(self, stack_id):
        # add temporarily a breakpoint that hits when we enter/leave
        # a frame from/to the frame identified by 'stack_id'
        b = self.pgroup.edit_breakpoints()
        b.stack_id = stack_id
        try:
            yield
        finally:
            b.stack_id = 0

    @contextmanager
    def _thread_num_break(self, thread_num):
        # add temporarily a breakpoint that hits when we enter/leave
        # the given thread
        b = self.pgroup.edit_breakpoints()
        b.thread_num = thread_num
        try:
            yield
        finally:
            b.thread_num = -1

    def command_next(self, argument):
        """Run forward for one step, skipping calls"""
        while True:
            stack_id = self.pgroup.get_stack_id(is_parent=False)
            with self._stack_id_break(stack_id):
                b = self.move_forward(1)
            while b is not None:
                # if we hit a regular breakpoint, stop
                if any(b.regular_breakpoint_nums()):
                    return
                # we hit only calls and returns inside stack_id.  If the
                # last one of these is a "return", then we're now back inside
                # stack_id, so stop
                if b.nums[-1] == -2:
                    break
                # else, the last one is a "call", so we entered another frame.
                # Continue running until the next call/return event occurs
                # inside stack_id
                with self._stack_id_break(stack_id):
                    b = self.move_forward(self.pgroup.get_max_time() -
                                          self.pgroup.get_current_time())
                    # and then look at that 'b' again (closes the loop)

            # we might be at a "<<" position on the same line as before,
            # which returns a get_hiddenpos_level() value of 1.  Continue
            # until we reach a get_hiddenpos_level() value of 0.
            if b is None or self.pgroup.get_hiddenpos_level() == 0:
                break

    command_n = command_next

    def command_bnext(self, argument):
        """Run backward for one step, skipping calls"""
        while True:
            stack_id = self.pgroup.get_stack_id(is_parent=False)
            with self._stack_id_break(stack_id):
                b = self.move_backward(1)
            while b is not None:
                # if we hit a regular breakpoint, stop
                if any(b.regular_breakpoint_nums()):
                    return
                # we hit only calls and returns inside stack_id.  If the
                # first one of these is a "call", then we're now back inside
                # stack_id, so stop
                if b.nums[0] == -1:
                    break
                # else, the first one is a "return", so before, we were
                # inside a different frame.  Continue running until the next
                # call/return event occurs inside stack_id
                with self._stack_id_break(stack_id):
                    b = self.move_backward(self.pgroup.get_current_time() - 1)
                    # and then look at that 'b' again (closes the loop)

            # we might be at a "<<" position on the same line as before,
            # which returns a get_hiddenpos_level() value of 1.  Continue
            # until we reach a get_hiddenpos_level() value of 0.
            if self.pgroup.get_hiddenpos_level() == 0:
                break

    command_bn = command_bnext

    def command_finish(self, argument):
        """Run forward until the current function finishes"""
        stack_id = self.pgroup.get_stack_id(is_parent=True)
        if stack_id == 0:
            print 'No caller.'
        else:
            with self._stack_id_break(stack_id):
                self.command_continue('')

    def command_bfinish(self, argument):
        """Run backward until the current function is called"""
        stack_id = self.pgroup.get_stack_id(is_parent=True)
        if stack_id == 0:
            print 'No caller.'
        else:
            with self._stack_id_break(stack_id):
                self.command_bcontinue('')

    def command_continue(self, argument):
        """Run forward"""
        self.move_forward(self.pgroup.get_max_time() -
                          self.pgroup.get_current_time())

    command_c = command_continue

    def command_bcontinue(self, argument):
        """Run backward"""
        self.move_backward(self.pgroup.get_current_time() - 1)

    command_bc = command_bcontinue

    def _cmd_thread(self, argument, cmd_continue):
        argument = argument.lstrip('#')
        if argument:
            arg = int(argument)
            if arg == self.pgroup.get_current_thread():
                print 'Thread #%d is already the current one.' % (arg,)
                return
        else:
            # use the current thread number to detect switches to any
            # other thread (this works because revdb.c issues a
            # breakpoint whenever there is a switch FROM or TO the
            # thread '#arg').
            arg = self.pgroup.get_current_thread()
        #
        with self._thread_num_break(arg):
            cmd_continue('')

    def command_nthread(self, argument):
        """Run forward until thread switch (optionally to #ARG)"""
        self._cmd_thread(argument, self.command_continue)

    def command_bthread(self, argument):
        """Run backward until thread switch (optionally to #ARG)"""
        self._cmd_thread(argument, self.command_bcontinue)

    def command_print(self, argument):
        """Print an expression or execute a line of code"""
        # locate which $NUM appear used in the expression
        nids = map(int, r_dollar_num.findall(argument))
        self.pgroup.print_cmd(argument, nids=nids)

    command_p = command_print
    locals()['command_!'] = command_print

    def command_backtrace(self, argument):
        """Show the backtrace"""
        self.pgroup.show_backtrace(complete=1)

    command_bt = command_backtrace

    def command_list(self, argument):
        """Show the current function"""
        self.pgroup.show_backtrace(complete=2)

    def command_locals(self, argument):
        """Show the locals"""
        self.pgroup.show_locals()

    def command_break(self, argument):
        """Add a breakpoint"""
        if not argument:
            sys.stdout.write("Break where?\n")
            return
        num = self._bp_new(argument, 'B', argument)
        self.pgroup.update_breakpoints()
        b = self.pgroup.edit_breakpoints()
        if num not in b.num2break:
            sys.stdout.write("Breakpoint not added\n")
        else:
            kind, name = self._bp_kind(num)
            sys.stdout.write("Breakpoint %d added: %s\n" % (num, name))

    command_b = command_break

    def command_delete(self, argument):
        """Delete a breakpoint/watchpoint"""
        b = self.pgroup.edit_breakpoints()
        try:
            arg = int(argument)
        except ValueError:
            for arg in b.num2break:
                if self._bp_kind(arg)[1] == argument:
                    break
            else:
                print "No such breakpoint/watchpoint: %s\n" % (argument,)
                return
        if arg not in b.num2break:
            print "No breakpoint/watchpoint number %d\n" % (arg,)
        else:
            kind, name = self._bp_kind(arg)
            b.num2break.pop(arg, '')
            b.sources.pop(arg, '')
            b.watchvalues.pop(arg, '')
            b.watchuids.pop(arg, '')
            print "%s %d deleted: %s" % (kind.capitalize(), arg, name)

    command_del = command_delete

    def command_watch(self, argument):
        """Add a watchpoint (use $NUM in the expression to watch)"""
        if not argument:
            print "Watch what?\n"
            return
        #
        ok_flag, compiled_code = self.pgroup.compile_watchpoint_expr(argument)
        if not ok_flag:
            print compiled_code  # the error message
            print 'Watchpoint not added\n'
            return
        #
        nids = map(int, r_dollar_num.findall(argument))
        ok_flag, text = self.pgroup.check_watchpoint_expr(compiled_code, nids)
        if not ok_flag:
            print text
            print 'Watchpoint not added\n'
            return
        #
        new = self._bp_new(argument, 'W', compiled_code, nids=nids)
        self.pgroup.update_watch_values()
        print "Watchpoint %d added\n" % (new,)

    def getlinecacheoutput(self, pygments_background):
        if not pygments_background or pygments_background == 'off':
            return
        try:
            from pygments import highlight
            from pygments.lexers import PythonLexer
            from pygments.formatters import TerminalFormatter
        except ImportError as e:
            print >> sys.stderr, 'ImportError: %s\n' % (e,)
            return None
        #
        lexer = PythonLexer()
        fmt = TerminalFormatter(bg=pygments_background)

        #
        def linecacheoutput(filename, lineno):
            line = linecache.getline(filename, lineno)
            return highlight(line, lexer, fmt)

        return linecacheoutput

    def progress_callback(self, tick, previous):
        if previous:
            sys.stdout.write('\x08' * previous)
        if tick is not None:
            msg = '(%d...)' % tick
            sys.stdout.write(msg + ERASE_LINE)
            sys.stdout.flush()
            return len(msg)
