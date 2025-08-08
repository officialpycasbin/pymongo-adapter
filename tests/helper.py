import os


def get_fixture(path):
    """
    get model path
    """
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)
