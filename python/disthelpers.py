from distutils.core import Command

class get_build_platlib(Command):
    """This command shows the platform build directory.
    """
    description = ("Show platform build directory")
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        cmd = self.get_finalized_command('build')
        print(cmd.build_platlib)
