# ______________________________________________________________________
"""Module pytokenize

THIS FILE WAS COPIED FROM pypy/module/parser/pytokenize.py AND ADAPTED
TO BE ANNOTABLE (Mainly made lists homogeneous)

This is a modified version of Ka-Ping Yee's tokenize module found in the
Python standard library.

The primary modification is the removal of the tokenizer's dependence on the
standard Python regular expression module, which is written in C.  The regular
expressions have been replaced with hand built DFA's using the
basil.util.automata module.

$Id: pytokenize.py,v 1.3 2003/10/03 16:31:53 jriehl Exp $
"""
# ______________________________________________________________________

from pypy.interpreter.pyparser import automata

__all__ = [ "tokenize" ]

# ______________________________________________________________________
# Automatically generated DFA's

accepts = [True, True, True, True, True, True, True, True,
           True, True, False, True, True, True, True, False,
           False, False, False, True, False, False, True,
           False, False, True, False, True, True, False,
           True, False, False, True, False, False, True,
           True, True, False, False, True, False, False,
           False, True]
states = [
    # 0
    {'\t': 0, '\n': 13, '\x0c': 0,
     '\r': 14, ' ': 0, '!': 10, '"': 17,
     '#': 19, '$': 15, '%': 12, '&': 12,
     "'": 16, '(': 13, ')': 13, '*': 7,
     '+': 12, ',': 13, '-': 12, '.': 6,
     '/': 11, '0': 4, '1': 5, '2': 5,
     '3': 5, '4': 5, '5': 5, '6': 5,
     '7': 5, '8': 5, '9': 5, ':': 13,
     ';': 13, '<': 9, '=': 12, '>': 8,
     '@': 13, 'A': 1, 'B': 2, 'C': 1,
     'D': 1, 'E': 1, 'F': 1, 'G': 1,
     'H': 1, 'I': 1, 'J': 1, 'K': 1,
     'L': 1, 'M': 1, 'N': 1, 'O': 1,
     'P': 1, 'Q': 1, 'R': 3, 'S': 1,
     'T': 1, 'U': 2, 'V': 1, 'W': 1,
     'X': 1, 'Y': 1, 'Z': 1, '[': 13,
     '\\': 18, ']': 13, '^': 12, '_': 1,
     '`': 13, 'a': 1, 'b': 2, 'c': 1,
     'd': 1, 'e': 1, 'f': 1, 'g': 1,
     'h': 1, 'i': 1, 'j': 1, 'k': 1,
     'l': 1, 'm': 1, 'n': 1, 'o': 1,
     'p': 1, 'q': 1, 'r': 3, 's': 1,
     't': 1, 'u': 2, 'v': 1, 'w': 1,
     'x': 1, 'y': 1, 'z': 1, '{': 13,
     '|': 12, '}': 13, '~': 13},
    # 1
    {'0': 1, '1': 1, '2': 1, '3': 1,
     '4': 1, '5': 1, '6': 1, '7': 1,
     '8': 1, '9': 1, 'A': 1, 'B': 1,
     'C': 1, 'D': 1, 'E': 1, 'F': 1,
     'G': 1, 'H': 1, 'I': 1, 'J': 1,
     'K': 1, 'L': 1, 'M': 1, 'N': 1,
     'O': 1, 'P': 1, 'Q': 1, 'R': 1,
     'S': 1, 'T': 1, 'U': 1, 'V': 1,
     'W': 1, 'X': 1, 'Y': 1, 'Z': 1,
     '_': 1, 'a': 1, 'b': 1, 'c': 1,
     'd': 1, 'e': 1, 'f': 1, 'g': 1,
     'h': 1, 'i': 1, 'j': 1, 'k': 1,
     'l': 1, 'm': 1, 'n': 1, 'o': 1,
     'p': 1, 'q': 1, 'r': 1, 's': 1,
     't': 1, 'u': 1, 'v': 1, 'w': 1,
     'x': 1, 'y': 1, 'z': 1},
    # 2
    {'"': 17, "'": 16, '0': 1, '1': 1,
     '2': 1, '3': 1, '4': 1, '5': 1,
     '6': 1, '7': 1, '8': 1, '9': 1,
     'A': 1, 'B': 1, 'C': 1, 'D': 1,
     'E': 1, 'F': 1, 'G': 1, 'H': 1,
     'I': 1, 'J': 1, 'K': 1, 'L': 1,
     'M': 1, 'N': 1, 'O': 1, 'P': 1,
     'Q': 1, 'R': 3, 'S': 1, 'T': 1,
     'U': 1, 'V': 1, 'W': 1, 'X': 1,
     'Y': 1, 'Z': 1, '_': 1, 'a': 1,
     'b': 1, 'c': 1, 'd': 1, 'e': 1,
     'f': 1, 'g': 1, 'h': 1, 'i': 1,
     'j': 1, 'k': 1, 'l': 1, 'm': 1,
     'n': 1, 'o': 1, 'p': 1, 'q': 1,
     'r': 3, 's': 1, 't': 1, 'u': 1,
     'v': 1, 'w': 1, 'x': 1, 'y': 1,
     'z': 1},
    # 3
    {'"': 17, "'": 16, '0': 1, '1': 1,
     '2': 1, '3': 1, '4': 1, '5': 1,
     '6': 1, '7': 1, '8': 1, '9': 1,
     'A': 1, 'B': 1, 'C': 1, 'D': 1,
     'E': 1, 'F': 1, 'G': 1, 'H': 1,
     'I': 1, 'J': 1, 'K': 1, 'L': 1,
     'M': 1, 'N': 1, 'O': 1, 'P': 1,
     'Q': 1, 'R': 1, 'S': 1, 'T': 1,
     'U': 1, 'V': 1, 'W': 1, 'X': 1,
     'Y': 1, 'Z': 1, '_': 1, 'a': 1,
     'b': 1, 'c': 1, 'd': 1, 'e': 1,
     'f': 1, 'g': 1, 'h': 1, 'i': 1,
     'j': 1, 'k': 1, 'l': 1, 'm': 1,
     'n': 1, 'o': 1, 'p': 1, 'q': 1,
     'r': 1, 's': 1, 't': 1, 'u': 1,
     'v': 1, 'w': 1, 'x': 1, 'y': 1,
     'z': 1},
    # 4
    {'.': 25, '0': 22, '1': 22, '2': 22,
     '3': 22, '4': 22, '5': 22, '6': 22,
     '7': 22, '8': 24, '9': 24, 'B': 23,
     'E': 26, 'J': 13, 'L': 13, 'O': 21,
     'X': 20, 'b': 23, 'e': 26, 'j': 13,
     'l': 13, 'o': 21, 'x': 20},
    # 5
    {'.': 25, '0': 5, '1': 5, '2': 5,
     '3': 5, '4': 5, '5': 5, '6': 5,
     '7': 5, '8': 5, '9': 5, 'E': 26,
     'J': 13, 'L': 13, 'e': 26, 'j': 13,
     'l': 13},
    # 6
    {'0': 27, '1': 27, '2': 27, '3': 27,
     '4': 27, '5': 27, '6': 27, '7': 27,
     '8': 27, '9': 27},
    # 7
    {'*': 12, '=': 13},
    # 8
    {'=': 13, '>': 12},
    # 9
    {'<': 12, '=': 13, '>': 13},
    # 10
    {'=': 13},
    # 11
    {'/': 12, '=': 13},
    # 12
    {'=': 13},
    # 13
    {},
    # 14
    {'\n': 13},
    # 15
    {'0': 28, '1': 28, '2': 28, '3': 28,
     '4': 28, '5': 28, '6': 28, '7': 28,
     '8': 28, '9': 28},
    # 16
    {automata.DEFAULT: 32, '\n': 29,
     '\r': 29, "'": 30, '\\': 31},
    # 17
    {automata.DEFAULT: 35, '\n': 29,
     '\r': 29, '"': 33, '\\': 34},
    # 18
    {'\n': 13, '\r': 14},
    # 19
    {automata.DEFAULT: 19, '\n': 29, '\r': 29},
    # 20
    {'0': 36, '1': 36, '2': 36, '3': 36,
     '4': 36, '5': 36, '6': 36, '7': 36,
     '8': 36, '9': 36, 'A': 36, 'B': 36,
     'C': 36, 'D': 36, 'E': 36, 'F': 36,
     'a': 36, 'b': 36, 'c': 36, 'd': 36,
     'e': 36, 'f': 36},
    # 21
    {'0': 37, '1': 37, '2': 37, '3': 37,
     '4': 37, '5': 37, '6': 37, '7': 37},
    # 22
    {'.': 25, '0': 22, '1': 22, '2': 22,
     '3': 22, '4': 22, '5': 22, '6': 22,
     '7': 22, '8': 24, '9': 24, 'E': 26,
     'J': 13, 'L': 13, 'e': 26, 'j': 13,
     'l': 13},
    # 23
    {'0': 38, '1': 38},
    # 24
    {'.': 25, '0': 24, '1': 24, '2': 24,
     '3': 24, '4': 24, '5': 24, '6': 24,
     '7': 24, '8': 24, '9': 24, 'E': 26,
     'J': 13, 'e': 26, 'j': 13},
    # 25
    {'0': 25, '1': 25, '2': 25, '3': 25,
     '4': 25, '5': 25, '6': 25, '7': 25,
     '8': 25, '9': 25, 'E': 39, 'J': 13,
     'e': 39, 'j': 13},
    # 26
    {'+': 40, '-': 40, '0': 41, '1': 41,
     '2': 41, '3': 41, '4': 41, '5': 41,
     '6': 41, '7': 41, '8': 41, '9': 41},
    # 27
    {'0': 27, '1': 27, '2': 27, '3': 27,
     '4': 27, '5': 27, '6': 27, '7': 27,
     '8': 27, '9': 27, 'E': 39, 'J': 13,
     'e': 39, 'j': 13},
    # 28
    {'0': 28, '1': 28, '2': 28, '3': 28,
     '4': 28, '5': 28, '6': 28, '7': 28,
     '8': 28, '9': 28},
    # 29
    {},
    # 30
    {"'": 13},
    # 31
    {automata.DEFAULT: 42, '\n': 13, '\r': 14},
    # 32
    {automata.DEFAULT: 32, '\n': 29,
     '\r': 29, "'": 13, '\\': 31},
    # 33
    {'"': 13},
    # 34
    {automata.DEFAULT: 43, '\n': 13, '\r': 14},
    # 35
    {automata.DEFAULT: 35, '\n': 29,
     '\r': 29, '"': 13, '\\': 34},
    # 36
    {'0': 36, '1': 36, '2': 36, '3': 36,
     '4': 36, '5': 36, '6': 36, '7': 36,
     '8': 36, '9': 36, 'A': 36, 'B': 36,
     'C': 36, 'D': 36, 'E': 36, 'F': 36,
     'L': 13, 'a': 36, 'b': 36, 'c': 36,
     'd': 36, 'e': 36, 'f': 36, 'l': 13},
    # 37
    {'0': 37, '1': 37, '2': 37, '3': 37,
     '4': 37, '5': 37, '6': 37, '7': 37,
     'L': 13, 'l': 13},
    # 38
    {'0': 38, '1': 38, 'L': 13, 'l': 13},
    # 39
    {'+': 44, '-': 44, '0': 45, '1': 45,
     '2': 45, '3': 45, '4': 45, '5': 45,
     '6': 45, '7': 45, '8': 45, '9': 45},
    # 40
    {'0': 41, '1': 41, '2': 41, '3': 41,
     '4': 41, '5': 41, '6': 41, '7': 41,
     '8': 41, '9': 41},
    # 41
    {'0': 41, '1': 41, '2': 41, '3': 41,
     '4': 41, '5': 41, '6': 41, '7': 41,
     '8': 41, '9': 41, 'J': 13, 'j': 13},
    # 42
    {automata.DEFAULT: 42, '\n': 29,
     '\r': 29, "'": 13, '\\': 31},
    # 43
    {automata.DEFAULT: 43, '\n': 29,
     '\r': 29, '"': 13, '\\': 34},
    # 44
    {'0': 45, '1': 45, '2': 45, '3': 45,
     '4': 45, '5': 45, '6': 45, '7': 45,
     '8': 45, '9': 45},
    # 45
    {'0': 45, '1': 45, '2': 45, '3': 45,
     '4': 45, '5': 45, '6': 45, '7': 45,
     '8': 45, '9': 45, 'J': 13, 'j': 13},
    ]
pseudoDFA = automata.DFA(states, accepts)

accepts = [False, False, False, False, False, True]
states = [
    # 0
    {automata.DEFAULT: 0, '"': 1, '\\': 2},
    # 1
    {automata.DEFAULT: 4, '"': 3, '\\': 2},
    # 2
    {automata.DEFAULT: 4},
    # 3
    {automata.DEFAULT: 4, '"': 5, '\\': 2},
    # 4
    {automata.DEFAULT: 4, '"': 1, '\\': 2},
    # 5
    {automata.DEFAULT: 4, '"': 5, '\\': 2},
    ]
double3DFA = automata.NonGreedyDFA(states, accepts)

accepts = [False, False, False, False, False, True]
states = [
    # 0
    {automata.DEFAULT: 0, "'": 1, '\\': 2},
    # 1
    {automata.DEFAULT: 4, "'": 3, '\\': 2},
    # 2
    {automata.DEFAULT: 4},
    # 3
    {automata.DEFAULT: 4, "'": 5, '\\': 2},
    # 4
    {automata.DEFAULT: 4, "'": 1, '\\': 2},
    # 5
    {automata.DEFAULT: 4, "'": 5, '\\': 2},
    ]
single3DFA = automata.NonGreedyDFA(states, accepts)

accepts = [False, True, False, False]
states = [
    # 0
    {automata.DEFAULT: 0, "'": 1, '\\': 2},
    # 1
    {},
    # 2
    {automata.DEFAULT: 3},
    # 3
    {automata.DEFAULT: 3, "'": 1, '\\': 2},
    ]
singleDFA = automata.DFA(states, accepts)

accepts = [False, True, False, False]
states = [
    # 0
    {automata.DEFAULT: 0, '"': 1, '\\': 2},
    # 1
    {},
    # 2
    {automata.DEFAULT: 3},
    # 3
    {automata.DEFAULT: 3, '"': 1, '\\': 2},
    ]
doubleDFA = automata.DFA(states, accepts)

#_______________________________________________________________________
# End of automatically generated DFA's

endDFAs = {"'" : singleDFA,
           '"' : doubleDFA,
           'r' : None,
           'R' : None,
           'u' : None,
           'U' : None,
           'b' : None,
           'B' : None}

for uniPrefix in ("", "u", "U", "b", "B"):
    for rawPrefix in ("", "r", "R"):
        prefix = uniPrefix + rawPrefix
        endDFAs[prefix + "'''"] = single3DFA
        endDFAs[prefix + '"""'] = double3DFA

whiteSpaceStatesAccepts = [True]
whiteSpaceStates = [{'\t': 0, ' ': 0, '\x0c': 0}]
whiteSpaceDFA = automata.DFA(whiteSpaceStates, whiteSpaceStatesAccepts)

# ______________________________________________________________________
# COPIED:

triple_quoted = {}
for t in ("'''", '"""',
          "r'''", 'r"""', "R'''", 'R"""',
          "u'''", 'u"""', "U'''", 'U"""',
          "b'''", 'b"""', "B'''", 'B"""',
          "ur'''", 'ur"""', "Ur'''", 'Ur"""',
          "uR'''", 'uR"""', "UR'''", 'UR"""',
          "br'''", 'br"""', "Br'''", 'Br"""',
          "bR'''", 'bR"""', "BR'''", 'BR"""'):
    triple_quoted[t] = t
single_quoted = {}
for t in ("'", '"',
          "r'", 'r"', "R'", 'R"',
          "u'", 'u"', "U'", 'U"',
          "b'", 'b"', "B'", 'B"',
          "ur'", 'ur"', "Ur'", 'Ur"',
          "uR'", 'uR"', "UR'", 'UR"',
          "br'", 'br"', "Br'", 'Br"',
          "bR'", 'bR"', "BR'", 'BR"'):
    single_quoted[t] = t

tabsize = 8

# PYPY MODIFICATION: removed TokenError class as it's not needed here

# PYPY MODIFICATION: removed StopTokenizing class as it's not needed here

# PYPY MODIFICATION: removed printtoken() as it's not needed here

# PYPY MODIFICATION: removed tokenize() as it's not needed here

# PYPY MODIFICATION: removed tokenize_loop() as it's not needed here

# PYPY MODIFICATION: removed generate_tokens() as it was copied / modified
#                    in pythonlexer.py

# PYPY MODIFICATION: removed main() as it's not needed here

# ______________________________________________________________________
# End of pytokenize.py

