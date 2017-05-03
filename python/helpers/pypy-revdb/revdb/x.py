import os

class Foo(object):
    value = 5

lst1 = [Foo() for i in range(100)]
lst1[50].value += 1
for x in lst1:
    x.value += 1

for x in lst1:
    if x.value != 6:
        print "Hey"
        os._exit(1)
