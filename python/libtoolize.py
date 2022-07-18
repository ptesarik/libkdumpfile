"""libtool

Build and install extensions using libtool.
"""

import os
from distutils import log
from distutils.util import split_quoted
from distutils.dir_util import mkpath
from distutils.file_util import copy_file
from distutils.spawn import spawn
from distutils.errors import DistutilsFileError

from distutils.command.build_ext import build_ext as _build_ext
class build_ext(_build_ext):
    def initialize_options(self):
        _build_ext.initialize_options(self)
        self.libtool = None
        self.pyexecdir = None

    def finalize_options(self):
        _build_ext.finalize_options(self)

        if self.libtool is None:
            self.libtool = 'libtool'
        if self.pyexecdir is None:
            import sysconfig
            self.pyexecdir = sysconfig.get_path('platlib')
        self.cmd_libtool = split_quoted(self.libtool)

    def libtoolize(self, key, mode, *args):
        val = getattr(self.compiler, key)
        val = val[:1] + list(args) + val[1:]
        setattr(self.compiler, key,
                self.cmd_libtool + [ '--mode='+mode ] + val)

    def build_extensions(self):
        self.compiler.obj_extension = '.lo'
        self.libtoolize('compiler', 'compile')
        self.libtoolize('compiler_so', 'compile')
        self.libtoolize('linker_exe', 'link')
        self.libtoolize('linker_so', 'link',
                        '-module', '-avoid-version',
                        '-export-symbols-regex', 'init.*|PyInit_.*|kdumpfile_object_from_native',
                        '-rpath', self.pyexecdir)
        _build_ext.build_extensions(self)

from distutils.command.install_lib import install_lib as _install_lib
class install_lib(_install_lib):
    def initialize_options(self):
        _install_lib.initialize_options(self)
        self.libtool_install = None

    def finalize_options(self):
        _install_lib.finalize_options(self)

        if self.libtool_install is None:
            self.libtool_install = 'libtool --mode=install install'
        self.cmd_libtool_install = split_quoted(self.libtool_install)

    def copy_tree(self, infile, outfile, preserve_mode=1, preserve_times=1,
                   preserve_symlinks=0, level=1):
        """Copy the build directory tree, respecting dry-run and force flags.
        Special treatment of libtool files.
        """
        if not self.dry_run and not os.path.isdir(infile):
            raise DistutilsFileError(
                  "cannot copy tree '%s': not a directory" % infile)
        try:
            names = os.listdir(infile)
        except OSError as e:
            if self.dry_run:
                names = []
            else:
                raise DistutilsFileError(
                      "error listing files in '%s': %s" % (infile, e.strerror))

        if not self.dry_run:
            mkpath(outfile)

        outputs = []

        for n in names:
            src_name = os.path.join(infile, n)
            dst_name = os.path.join(outfile, n)

            if n.startswith('.nfs'):
                # skip NFS rename files
                continue
            if n in ('.libs', '_libs'):
                # skip libtool directories
                continue

            if preserve_symlinks and os.path.islink(src_name):
                link_dest = os.readlink(src_name)
                log.info("linking %s -> %s", dst_name, link_dest)
                if not self.dry_run:
                    os.symlink(link_dest, dst_name)
                outputs.append(dst_name)

            elif os.path.isdir(src_name):
                outputs.extend(
                    self.copy_tree(src_name, dst_name, preserve_mode,
                                   preserve_times, preserve_symlinks))

            elif n.endswith('.la'):
                spawn(self.cmd_libtool_install + [ src_name, dst_name ],
                      dry_run=self.dry_run)

            else:
                copy_file(src_name, dst_name, preserve_mode,
                          preserve_times, not self.force,
                          dry_run=self.dry_run)
                outputs.append(dst_name)

        return outputs

def sysconfig_replace_ext(varname, newext):
    """Replace the extension in a system config variable.
    """
    from distutils.sysconfig import _config_vars
    val = _config_vars.get(varname, '')
    suffpos = val.rfind('.')
    if suffpos >= 0:
        val = val[:suffpos]
    _config_vars[varname] = val + newext

# change default shared object suffix to .la
from distutils.sysconfig import get_config_vars
get_config_vars()
sysconfig_replace_ext('EXT_SUFFIX', '.la')
sysconfig_replace_ext('SO', '.la')
