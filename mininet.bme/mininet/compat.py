__all__ = ["Compat"]

import commands

class Compat( object ):
    version = 0

    @staticmethod
    def get_version():
        if Compat.version:
            return Compat.version
        Compat.version = commands.getoutput( 'ofprotocol -V | cut -f2 -d" "' )
        Compat.version = Compat.version.strip()
        return Compat.version
