import subprocess


def show_commit(commit):
    return subprocess.check_output(['git', 'show', commit])


def show_file(commit, filename):
    return subprocess.check_output(
        ['git', 'show', '{}:{}'.format(commit, filename)])


def get_parent_commit(commit):
    cmd = ['git', 'rev-parse', '{}~'.format(commit)]
    return subprocess.check_output(cmd).strip().decode()


def get_modify_commits(filename):
    cmd = 'git log --all --oneline {}'.format(filename)
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        return
    for line in output.split('\n'):
        yield line.split(' ', 1)[0]


def get_history_commits(commit):
    output = subprocess.check_output(['git', 'log', '--oneline', commit])
    for line in output.strip().split(b'\n'):
        line.split()[0].decode()


def is_ancestor(parent, commit):
    try:
        subprocess.check_call(
            ['git', 'merge-base', '--is-ancestor', parent, commit])
    except subprocess.CalledProcessError as err:
        if err.returncode != 1:
            raise
        return False
    return True
