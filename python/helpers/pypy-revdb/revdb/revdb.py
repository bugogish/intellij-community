#!/usr/bin/env python2

import sys, os


# if __name__ == '__main__':
#     import argparse
#     parser = argparse.ArgumentParser(description='Reverse debugger')
#     parser.add_argument('log', metavar='LOG', help='log file name')
#     parser.add_argument('-x', '--executable', dest='executable',
#                         help='name of the executable file '
#                              'that recorded the log')
#     parser.add_argument('-c', '--color', dest='color',
#                         help='colorize source code (dark,light,off)')
#     options = parser.parse_args()
#
#     sys.path.insert(0, os.path.abspath(
#         os.path.join(__file__, '..', '..', '..', '..')))
#
#     from _revdb.interact import RevDebugControl
#     ctrl = RevDebugControl(options.log, executable=options.executable,
#                            pygments_background=options.color)
#     ctrl.interact()
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

    from _revdb.interact import RevDebugControl
    ctrl = RevDebugControl(options.log, executable=options.executable,
                           pygments_background=options.color, port=options.port, host=options.host)
    sys.stdout.write("Interact starts...\n")
    ctrl.interact()