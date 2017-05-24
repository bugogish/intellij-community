import os
import sys
import re
import threading
import time
import traceback
from urllib import quote

from cStringIO import StringIO

to_console = sys.stdout.write
up = os.path.dirname
PYPY_PATH = "/usr/local/lib/pypy/"
REVDB_PATH = up(up(PYPY_PATH)) + "/pypy-revdb/"
PYDEV_PATH = up(up(__file__)) + "/pydev"

sys.path.insert(0, PYPY_PATH)
from rpython.rlib import revdb

sys.path.insert(0, REVDB_PATH)
to_console(str(REVDB_PATH))
from _revdb.message import *
from _revdb.interact import RevDebugControl
from _revdb.process import RecreateSubprocess

sys.path.insert(0, PYDEV_PATH)
from _pydevd_bundle.pydevd_comm import NetCommand, NetCommandFactory, pydevd_find_thread_by_id
from _pydevd_bundle.pydevd_constants import get_thread_id, dict_contains
from _pydev_bundle.pydev_is_thread_alive import is_thread_alive
from _pydevd_bundle.pydevd_xml import make_valid_xml_value, frame_vars_to_xml, var_to_xml

if sys.version_info < (3,):
    import thread
else:
    import _thread as thread

from utils.revdb_comm import ReaderThread, WriterThread, Dispatcher, CMD_THREAD_SUSPEND, \
    CMD_SET_BREAK, CMD_THREAD_CREATE, CMD_GET_FRAME, CMD_STEP_OVER, CMD_THREAD_RUN, CMD_STEP_BACK, \
    CMD_EVALUATE_EXPRESSION, CMD_VERSION, getfilesystemencoding, CMD_REMOVE_BREAK, CMD_ADD_EXCEPTION_BREAK, CMD_RUN, \
    CMD_STEP_INTO


class capture_revdb_output(object):
    def __enter__(self):
        self.old_stdout = sys.stdout
        sys.stdout = self.buffer = StringIO()
        return self.buffer

    def __exit__(self, *args):
        sys.stdout = self.old_stdout


class revDB():
    def __init__(self, port, host, cmd_executor):
        self.cmd_executor = cmd_executor
        self._running_thread_ids = {}  # <--------
        self._main_lock = thread.allocate_lock()  # <--------
        self.ready = False
        sock = Dispatcher().init_network(host, port)
        self.writer = WriterThread(sock)
        self.reader = ReaderThread(sock, self)
        self.writer.start()
        self.reader.start()
        time.sleep(0.1)

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
            my_id = self.cmd_executor.pgroup.get_stack_id(1)
            my_name = '?'
            myFile = self.file
            myLine = self.cmd_line_no()
            variables = ''
            append('<frame id="%s" name="%s" ' % (my_id, make_valid_xml_value(my_name)))
            append('file="%s" line="%s">' % (quote(myFile, '/>_= \t'), myLine))
            append(variables)
            append("</frame>")
        except:
            traceback.print_exc()

        append("</thread></xml>")
        return ''.join(cmd_text_list)

    def process_net_cmd(self, cmd_id, seq, text):
        sys.stdout.write("%d \n" % self.cmd_executor.pgroup.get_current_time())
        if cmd_id == CMD_GET_FRAME:
            try:
                xml = "<xml>"
                locals = self.cmd_get_locals()
                sys.stdout.write(str(locals))
                xml += frame_vars_to_xml(locals)
                xml += "</xml>"
                self.writer.add_command(NetCommand(CMD_GET_FRAME, seq, xml))
            except:
                traceback.print_exc()
        elif cmd_id == CMD_STEP_OVER:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_OVER)))
            self.cmd_executor.command_next(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                               self.make_thread_suspend_str(text, CMD_STEP_OVER)))
        elif cmd_id == CMD_STEP_BACK:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_BACK)))
            self.cmd_executor.command_bnext(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                               self.make_thread_suspend_str(text, CMD_STEP_BACK)))
        elif cmd_id == CMD_EVALUATE_EXPRESSION:
            try:
                thread_id, frame_id, scope, expression, trim, temp_name = text.split('\t', 5)
            except ValueError:
                thread_id, frame_id, scope, expression, trim = text.split('\t', 4)
            result = str(self.cmd_evaluate(str(expression.replace('@LINE@', '\n'))))
            xml = "<xml>"
            xml += var_to_xml(result, expression, int(trim) == 1)
            xml += "</xml>"
            self.writer.add_command(NetCommand(CMD_EVALUATE_EXPRESSION, seq, xml))
        elif cmd_id == CMD_VERSION:
            cmd = NetCommand(CMD_VERSION, seq, "build")
            self.writer.add_command(cmd)
        elif cmd_id == CMD_SET_BREAK:
            type, file, line, func_name, suspend_policy, condition, expression = text.split('\t', 6)
            file = file.encode(getfilesystemencoding())
            self.cmd_executor.command_break(file + ':' + str(line))
            self.file = file
        elif cmd_id == CMD_REMOVE_BREAK:
            breakpoint_type, file, line = text.split('\t', 2)
            self.cmd_executor.command_delete(file + ":" + str(line))
        elif cmd_id == CMD_ADD_EXCEPTION_BREAK:
            sys.stderr.write("Exceptional breakpoints are not supported\n")
        elif cmd_id == CMD_RUN:
            self.cmd_executor.command_continue(None)
            self.ready = True
        elif cmd_id == CMD_THREAD_RUN:
            t = pydevd_find_thread_by_id(text)
            if t:
                self.writer.add_command(NetCommand(CMD_THREAD_RUN, -1, text))
                self.cmd_executor.command_continue(None)

                self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                                   self.make_thread_suspend_str(text, CMD_SET_BREAK)))
        elif cmd_id == CMD_STEP_INTO:
            self.writer.add_command(NetCommand(CMD_THREAD_RUN, 0,
                                               str(text) + "\t" + str(CMD_STEP_OVER)))
            self.cmd_executor.command_step(None)
            self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0,
                                               self.make_thread_suspend_str(text, CMD_STEP_OVER)))

    def interact(self):
        flag = True
        try:
            while True:
                self.process_internal_commands()
                time.sleep(0.1)
                # v It's to be changed v
                if flag and self.ready:
                    self.writer.add_command(NetCommand(CMD_THREAD_SUSPEND, 0, self.make_thread_suspend_str(
                        get_thread_id(threading.currentThread()), CMD_SET_BREAK)))
                    flag = False
        except:
            self.writer.killReceived = True
            self.reader.killReceived = True
            self.reader.do_kill_pydev_thread()
            self.cmd_executor.command_quit(None)

    def cmd_line_no(self):
        with capture_revdb_output() as buffer:
            self.cmd_executor.pgroup.show_backtrace()
        code_str = buffer.getvalue()
        match = re.search(".*?, line (\d*) in .*", code_str)
        return int(match.group(1))

    def cmd_get_locals(self):
        with capture_revdb_output() as buffer:
            self.cmd_executor.command_locals()
        locals_str = buffer.getvalue()
        locals_str = locals_str.split('\n', 1)[-1].strip()
        try:
            return {line.split('=')[0].strip(): line.split('=')[1].strip() for line in locals_str.split('\n')}
        except:
            return {}

    def cmd_evaluate(self, expression):
        with capture_revdb_output() as buffer:
            self.cmd_executor.command_print(expression)
        return buffer.getvalue().strip()

    def recv_txt_answ(self):
        result = ""
        while True:
            msg = self.cmd_executor.pgroup.active.recv()
            if msg.cmd == ANSWER_TEXT:
                result += msg.extra
            elif msg.cmd == ANSWER_READY:
                self.cmd_executor.pgroup.active.update_times(msg)
                break
        return result


def lineno():
    sys.stdout.write("IN LINENO:\n")
    frame = fetch_cur_frame()
    revdb.send_output(frame.get_last_lineno())


lambda_lineno = lambda: lineno


def setup():
    revdb.register_debug_command(25, lambda_lineno)


def comment_foo():
    """just a comment"""


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Reverse debugger')
    parser.add_argument('log', metavar='LOG', help='log file name')
    parser.add_argument('-x', '--executable', dest='executable',
                        help='name of the executable file '
                             'that recorded the log')
    parser.add_argument('-c', '--color', dest='color',
                        help='colorize source code (dark,light,off)')
    parser.add_argument('--port', dest='port')
    parser.add_argument('--client', dest='host')
    options = parser.parse_args()

    sys.path.insert(0, os.path.abspath(
        os.path.join(__file__, '..', '..', '..', '..')))
    ctrl = RevDebugControl(options.log, executable=options.executable,
                           pygments_background=options.color)
    setup()
    revDB = revDB(options.port, options.host, ctrl).interact()
