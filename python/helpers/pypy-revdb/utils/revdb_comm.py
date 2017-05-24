import Queue as _queue
import time
import threading
import socket

try:
    from urllib import quote_plus, unquote, unquote_plus
except:
    from urllib.parse import quote_plus, unquote, unquote_plus
import sys
import traceback

IS_PY3K = False
IS_PY34_OLDER = False
IS_PY2 = True
IS_PY27 = False
IS_PY24 = False
try:
    if sys.version_info[0] >= 3:
        IS_PY3K = True
        IS_PY2 = False
        if (sys.version_info[0] == 3 and sys.version_info[1] >= 4) or sys.version_info[0] > 3:
            IS_PY34_OLDER = True
    elif sys.version_info[0] == 2 and sys.version_info[1] == 7:
        IS_PY27 = True
    elif sys.version_info[0] == 2 and sys.version_info[1] == 4:
        IS_PY24 = True
except AttributeError:
    pass


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


CMD_RUN = 101
CMD_LIST_THREADS = 102
CMD_THREAD_CREATE = 103
CMD_THREAD_KILL = 104
CMD_THREAD_SUSPEND = 105
CMD_THREAD_RUN = 106
CMD_STEP_INTO = 107
CMD_STEP_OVER = 108
CMD_STEP_RETURN = 109
CMD_GET_VARIABLE = 110
CMD_SET_BREAK = 111
CMD_REMOVE_BREAK = 112
CMD_EVALUATE_EXPRESSION = 113
CMD_GET_FRAME = 114
CMD_EXEC_EXPRESSION = 115
CMD_WRITE_TO_CONSOLE = 116
CMD_CHANGE_VARIABLE = 117
CMD_RUN_TO_LINE = 118
CMD_RELOAD_CODE = 119
CMD_GET_COMPLETIONS = 120

# Note: renumbered (conflicted on merge)
CMD_CONSOLE_EXEC = 121
CMD_ADD_EXCEPTION_BREAK = 122
CMD_REMOVE_EXCEPTION_BREAK = 123
CMD_LOAD_SOURCE = 124
CMD_ADD_DJANGO_EXCEPTION_BREAK = 125
CMD_REMOVE_DJANGO_EXCEPTION_BREAK = 126
CMD_SET_NEXT_STATEMENT = 127
CMD_SMART_STEP_INTO = 128
CMD_EXIT = 129

CMD_SIGNATURE_CALL_TRACE = 130

CMD_SET_PY_EXCEPTION = 131
CMD_GET_FILE_CONTENTS = 132
CMD_SET_PROPERTY_TRACE = 133
# Pydev debug console commands
CMD_EVALUATE_CONSOLE_EXPRESSION = 134
CMD_RUN_CUSTOM_OPERATION = 135
CMD_GET_BREAKPOINT_EXCEPTION = 136
CMD_STEP_CAUGHT_EXCEPTION = 137
CMD_SEND_CURR_EXCEPTION_TRACE = 138
CMD_SEND_CURR_EXCEPTION_TRACE_PROCEEDED = 139
CMD_IGNORE_THROWN_EXCEPTION_AT = 140
CMD_ENABLE_DONT_TRACE = 141
CMD_SHOW_CONSOLE = 142

CMD_GET_ARRAY = 143
CMD_STEP_INTO_MY_CODE = 144
CMD_GET_CONCURRENCY_EVENT = 145
CMD_SHOW_RETURN_VALUES = 146
CMD_INPUT_REQUESTED = 147
CMD_GET_DESCRIPTION = 148

CMD_PROCESS_CREATED = 149

CMD_STEP_BACK = 150

CMD_VERSION = 501
CMD_RETURN = 502
CMD_ERROR = 901

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

    '501': 'CMD_VERSION',
    '502': 'CMD_RETURN',
    '901': 'CMD_ERROR',
}

MAX_IO_MSG_SIZE = 1000  # if the io is too big, we'll not send all (could make the debugger too non-responsive)
# this number can be changed if there's need to do so

VERSION_STRING = "@@BUILD_NUMBER@@"

file_system_encoding = getfilesystemencoding()


class Dispatcher():
    def init_network(self, host, port):
        self.connect(host, int(port))
        new_port = self.get_new_port()
        sys.stderr.write("Received port {}\n".format(new_port))
        self.sock.shutdown(socket.SHUT_RD)
        self.sock.shutdown(socket.SHUT_WR)
        self.sock.close()
        self.connect(host, int(new_port))
        return self.sock

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



class RevDBDaemonThread(threading.Thread):
    created_pydb_daemon_threads = {}

    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.killReceived = False
        self.is_pydev_daemon_thread = True

    def run(self):
        created_pydb_daemon = self.created_pydb_daemon_threads
        created_pydb_daemon[self] = 1
        try:
            try:
                self._on_run()
            except:
                if sys is not None and traceback is not None:
                    traceback.print_exc()
        finally:
            del created_pydb_daemon[self]

    def _on_run(self):
        raise NotImplementedError('Should be reimplemented by: %s' % self.__class__)

    def do_kill_pydev_thread(self):
        self.killReceived = True


# =======================================================================================================================
# ReaderThread
# =======================================================================================================================
class ReaderThread(RevDBDaemonThread):
    """ reader thread reads and dispatches commands in an infinite loop """

    def __init__(self, sock, gdb):
        RevDBDaemonThread.__init__(self)
        self.sock = sock
        self.setName("pydevd.Reader")
        self.global_debugger_holder = gdb

    def do_kill_pydev_thread(self):
        # We must close the socket so that it doesn't stay halted there.
        self.killReceived = True
        try:
            self.sock.shutdown(SHUT_RD)  # shutdown the socket for read
        except:
            # just ignore that
            pass

    def _on_run(self):
        read_buffer = ""
        try:
            while not self.killReceived:
                try:
                    r = self.sock.recv(1024)
                except:
                    if not self.killReceived:
                        traceback.print_exc()
                    return  # Finished communication.

                # Note: the java backend is always expected to pass utf-8 encoded strings. We now work with unicode
                # internally and thus, we may need to convert to the actual encoding where needed (i.e.: filenames
                # on python 2 may need to be converted to the filesystem encoding).
                if hasattr(r, 'decode'):
                    r = r.decode('utf-8')

                read_buffer += r
                sys.stderr.write('debugger: received >>%s<<\n' % (read_buffer,))
                sys.stderr.flush()

                if len(read_buffer) == 0:
                    break
                while read_buffer.find('\n') != -1:
                    command, read_buffer = read_buffer.split('\n', 1)

                    args = command.split('\t', 2)
                    try:
                        cmd_id = int(args[0])
                        sys.stderr.write(
                            'Received command: %s %s\n' % (ID_TO_MEANING.get(str(cmd_id), '???'), command,))
                        self.process_command(cmd_id, int(args[1]), args[2])
                    except:
                        traceback.print_exc()
                        sys.stderr.write("Can't process net command: %s\n" % command)
                        sys.stderr.flush()

        except:
            traceback.print_exc()

    def process_command(self, cmd_id, seq, text):
        self.global_debugger_holder.process_net_cmd(cmd_id, seq, text)


# ----------------------------------------------------------------------------------- SOCKET UTILITIES - WRITER
# =======================================================================================================================
# WriterThread
# =======================================================================================================================
class WriterThread(RevDBDaemonThread):
    """ writer thread writes out the commands in an infinite loop """

    def __init__(self, sock):
        RevDBDaemonThread.__init__(self)
        self.sock = sock
        self.setName("revdb.Writer")
        self.cmdQueue = _queue.Queue()

    def add_command(self, cmd):
        """ cmd is NetCommand """
        if not self.killReceived:  # we don't take new data after everybody die
            self.cmdQueue.put(cmd)

    def _on_run(self):
        """ just loop and write responses """
        get_has_timeout = sys.hexversion >= 0x02030000  # 2.3 onwards have it.
        try:
            while True:
                try:
                    try:
                        if get_has_timeout:
                            cmd = self.cmdQueue.get(1, 0.1)
                        else:
                            time.sleep(.01)
                            cmd = self.cmdQueue.get(0)
                    except _queue.Empty:
                        if self.killReceived:
                            try:
                                self.sock.shutdown(SHUT_WR)
                                self.sock.close()
                            except:
                                pass

                            return  # break if queue is empty and killReceived
                        else:
                            continue
                except:
                    # pydevd_log(0, 'Finishing debug communication...(1)')
                    # when liberating the thread here, we could have errors because we were shutting down
                    # but the thread was still not liberated
                    return
                # out = cmd.outgoing
                out = cmd.outgoing
                out_message = 'sending cmd --> '
                out_message += "%20s" % ID_TO_MEANING.get(out[:3], 'UNKNOWN')
                out_message += ' '
                out_message += unquote(unquote(out)).replace('\n', ' ')
                try:
                    sys.stderr.write('%s\n' % (out_message,))
                except:
                    traceback.print_exc()

                if IS_PY3K:
                    out = bytearray(out, 'utf-8')

                self.sock.send(
                    out)  # TODO: this does not guarantee that all message are sent (and jython does not have a send
                # all)
                if cmd.id == CMD_EXIT:
                    break
                if time is None:
                    break  # interpreter shutdown
                time.sleep(0.1)
        except Exception:
            traceback.print_exc()

    def empty(self):
        return self.cmdQueue.empty()
