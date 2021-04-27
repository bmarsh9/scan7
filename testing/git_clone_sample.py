# pip3 install gitpython
# requires ssh key

import os
from git import Repo
from git import Git

def test_authentication(id):
    return True

def clone_repo(git_url,key_path,output_dir,auth=None):
    # maybe: check if output_dir aleady exists
    env_dict = {}
    if auth:
        # get appropriate ssh key
        #git_ssh_identity_file = os.path.expanduser('~/.ssh/id_ed25519')
        git_ssh_cmd = 'ssh -oStrictHostKeyChecking=no -i {}'.format(key_path)
        env_dict = {"GIT_SSH_COMMAND": git_ssh_cmd}
    result = Repo.clone_from(git_url, output_dir, env=env_dict)
    return True

# clone public repo
git_url="git@github.com:nexB/scancode-toolkit.git"
repo_dir="out-public"
clone_repo(git_url,repo_dir)


# clone private repo
git_url="git@github.com:bmarsh9/api-scan.git"
repo_dir="out-private"
clone_repo(git_url,repo_dir)
