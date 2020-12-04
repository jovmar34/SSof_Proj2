from ast import *
import ast
from collections import defaultdict
import json

def build_tree(vulns, program, output_file_name):
    root = BlockStatement(program)
    #print(root.toString())

    shared = [defaultdict(list)]
    stack = []
    out_sinks = []

    root.visit(vulns, shared, stack, out_sinks)
    
    with open(output_file_name, "w") as out_file:
        out_file.write(json.dumps(out_sinks, indent=2))
        print(json.dumps(out_sinks, indent=2))
