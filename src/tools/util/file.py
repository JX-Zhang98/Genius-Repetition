import json
import os


def read(path, default=None, mode='r'):
    if not os.path.exists(path):
        return default
    with open(path, mode) as fp:
        return fp.read()


def write(path, data, mode='w'):
    with open(path, mode) as fp:
        fp.write(data)


def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as fp:
            return json.load(fp)
    except ValueError:
        return default


def write_json(path, data):
    with open(path, 'w') as fp:
        json.dump(data, fp, indent=4, separators=(',', ': '), sort_keys=True)
