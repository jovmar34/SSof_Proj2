from ast import *

def getVulns(vulns, ind):
    ret = []
    for vuln in vulns:
        #FIXME only general tainted or untainted
        if ind in vulns[vuln]['sources']:
            return True

    return False

def evalBinary(vulns, curr):
    return

def seeAssignment(vulns, tainted, left, right):
    l_name = ""
    if left['type'] == "Identifier":
        name = left['name']

    if name not in tainted:
        tainted[name] = False

    if right['type'] == "Literal":
        tainted[name] = (tainted[name] or False)
    elif right['type'] == "Identifier":
        tainted[name] = (tainted[name] or tainted[right['name']])
    elif right['type'] == "CallExpression":
        tainted[name] = (tainted[name] or getVulns(vulns, right['callee']['name']))
    elif right['type'] == "BinaryExpression":
        tainted[name] = (tainted[name] or evalBinary(vulns, right))

def build_tree(vulns, program):
    root = BlockStatement(program)
    print(root.toString())
    
    shared = {}
    stack = []

    root.visit(vulns, shared, stack)