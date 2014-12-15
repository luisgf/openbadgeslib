import sys, os.path

path = os.path.dirname(__file__)
path = os.path.join(path, os.path.pardir)
if sys.path[0] != path :
    sys.path.insert(0, path)

