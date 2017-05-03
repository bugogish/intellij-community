#
# A minimal example of setup.py to install a Python module
# together with the custom C extension module generated by CFFI.
#

from setuptools import setup

setup(name='revdb',
      scripts=['revdb.py'],
      packages=['_revdb'],
      setup_requires=["cffi>=1.0.0"],
      cffi_modules=["_revdb/_ancillary_build.py:ffibuilder"],
      install_requires=["cffi>=1.0.0"],
      )
