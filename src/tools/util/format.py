import re


def normalize_version(v):
    """Normalize version number."""
    v = v.replace('-rc', '.-1.')
    # remove all data after '-g'
    v = v.split('-g', 1)[0]
    # remove all tailing '.0'
    v = re.sub(r'(\.0+)*$', '', v)
    return [int(x) for x in v.split(".")] + [0]


def normalize_cve_id(cve_id):
    """Normalize CVE id."""
    cve_id = cve_id.replace('_', '-').upper()
    if not cve_id.startswith('CVE-'):
        cve_id = 'CVE-' + cve_id
    return cve_id


def normalize_symbol(fn):
    """Normalize function name."""
    return fn.split('.', 1)[0]
