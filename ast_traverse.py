from ast import *

def getVulns(vulns, ind):
    for vuln in vulns:
        #FIXME only general tainted or untainted
        if ind in vulns[vuln]['sources']:
            return True

    return False

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

def work(vulns, program):
    tainted = {}
    stack = []
    unvisited = [program]

    while len(unvisited) != 0:
        curr = unvisited[0]
        unvisited = unvisited[1:]

        if curr['type'] == "Program":
            unvisited = curr['body'] + unvisited
        elif curr['type'] == "ExpressionStatement":
            unvisited = [curr['expression']] + unvisited
        elif curr['type'] == "AssignmentExpression":
            seeAssignment(vulns, tainted, curr['left'], curr['right'])
            print (tainted)
