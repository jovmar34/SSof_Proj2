from ast import *
from collections import defaultdict

def build_tree(vulns, program):
    root = BlockStatement(program)
    #print(root.toString())
    
    shared = defaultdict(list)
    stack = []

    root.visit(vulns, shared, stack)