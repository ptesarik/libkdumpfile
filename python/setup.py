from distutils.core import setup, Extension
import libtoolize
import disthelpers
import os

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

cfg = ConfigParser()
cfg.read('setup.cfg')
srcdir = cfg.get('kdumpfile', 'srcdir')
top_builddir = cfg.get('kdumpfile', 'top_builddir')
include_dir=os.path.join(top_builddir, 'include')
addrxlat_la = os.path.join(
    top_builddir, 'src', 'addrxlat', 'libaddrxlat.la')
kdumpfile_la = os.path.join(
    top_builddir, 'src', 'kdumpfile', 'libkdumpfile.la')

classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+) ",
    "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)  ",
    "Programming Language :: Python",
    "Programming Language :: Python :: Implementation :: CPython",
    "Topic :: Software Development :: Debuggers "]

setup(name='libkdumpfile',
      version=cfg.get('kdumpfile', 'version'),
      description='Python bindings for libkdumpfile',
      author='Petr Tesarik',
      author_email='ptesarik@suse.com',
      url='https://github.com/ptesarik/libkdumpfile',
      packages=['addrxlat', 'kdumpfile'],
      package_dir={'': srcdir},
      ext_modules=[
          Extension('_addrxlat', [os.path.join(srcdir, 'addrxlat.c')],
                    include_dirs=[include_dir],
                    extra_objects=[addrxlat_la]),
          Extension('_kdumpfile', [os.path.join(srcdir, 'kdumpfile.c')],
                    include_dirs=[include_dir],
                    export_symbols=["init_kdumpfile",
                                    "PyInit__kdumpfile",
                                    "kdumpfile_object_from_native"],
                    extra_objects=[kdumpfile_la]),
      ],
      cmdclass={
          'build_ext': libtoolize.build_ext,
          'install_lib': libtoolize.install_lib,
          'get_build_platlib': disthelpers.get_build_platlib,
      },
)
