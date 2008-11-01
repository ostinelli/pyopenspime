from pyopenspime.protocol.extension.conf import *


# import extensions loaded
for ext in PYOPENSPIME_EXTENSIONS_LOADED:
    exec( 'import pyopenspime.protocol.extension.%s' % ext )
