import logging
import os
import sys

__all__ = ['logging']

if 'LOG_LEVEL' not in os.environ or not os.environ['LOG_LEVEL']:
    os.environ['LOG_LEVEL'] = 'INFO'
else:
    os.environ['LOG_LEVEL'] = os.environ['LOG_LEVEL'].upper()

log = logging.getLogger()
# undocumented behavior
level = logging.getLevelName(os.environ['LOG_LEVEL'])
log.setLevel(level)

log.addHandler(logging.StreamHandler())

if 'LOG_FILE' not in os.environ:
    if sys.argv[0] and not sys.argv[0].startswith('-') and os.path.basename(sys.argv[0]) != 'ipython':
        name_without_ext, _ = os.path.splitext(sys.argv[0])
        os.environ['LOG_FILE'] = '{}.log'.format(name_without_ext)
    else:
        os.environ['LOG_FILE'] = ''
if os.environ['LOG_FILE']:
    handler = logging.FileHandler(os.environ['LOG_FILE'])
    fmt_str = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'
    formatter = logging.Formatter(fmt_str)
    handler.setFormatter(formatter)
    log.addHandler(handler)
