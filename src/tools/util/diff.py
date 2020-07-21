import difflib

from .iter import seq_add


def calc_diff(before, after):
    """Calculate diff between two sequences, return indexes, start from 1."""
    before_uniq = []
    after_uniq = []
    common = []
    before_idx = 1
    after_idx = 1
    for d in difflib.ndiff(before, after):
        if d.startswith(' '):
            common.append((before_idx, after_idx))
            before_idx += 1
            after_idx += 1
        elif d.startswith('+'):
            after_uniq.append(after_idx)
            after_idx += 1
        elif d.startswith('-'):
            before_uniq.append(before_idx)
            before_idx += 1
    return dict(before=before_uniq, after=after_uniq, common=common)


def calc_partly_diff(before, after, before_range, after_range):
    """Calculate diff between two subsequences, return indexes, start from 1."""
    before_begin, before_end = before_range
    after_begin, after_end = after_range
    diff = calc_diff(before[before_begin:before_end + 1], after[after_begin:after_end + 1])
    return dict(
        before=list(seq_add(diff['before'], before_begin)),
        after=list(seq_add(diff['after'], after_begin)),
        common=[(x + before_begin, y + after_begin) for x, y in diff['common']],
    )

