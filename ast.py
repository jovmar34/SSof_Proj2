import re
from collections import defaultdict, OrderedDict

def merge_shared(context, shared, replace=False):
    for var in context:
        if var not in shared[0]:
            shared[0][var] = context[var]
            continue
        if replace:
            shared[0][var] = context[var]
        for source in context[var]:
            if source not in shared[0][var]:
                shared[0][var] += [source]

def print_sink(sinks, out_sinks):
    for sink in sinks:
        ret = {}
        ret['vulnerability'] = sink[0]
        ret['source'] = [sink[1]]
        ret['sink'] = [sink[2]]
        if (sink[3] == None):
            ret['sanitizer'] = []
        else:
            ret['sanitizer'] = [sink[3]]
        out_sinks += [ret]

def combine_stack(stack):
    ret = []
    for level in stack:
        ret += level
    return ret

def sanitize(vulns, shared, source, name):
    ret = []
    for info in source:
        change = False
        for vuln in vulns[info[0]]:
            if name in vuln[types["sanitizers"]]:
                ret += [(info[0], name)]
                change = True 
        if not change:
            ret += [info]
    return ret

types = {"vulnerability": 0, "sinks": 1, "sanitizers": 2}

def getExpression(json_expression):
    expr_type = json_expression['type']

    if expr_type == "Literal":
        return Literal(json_expression)
    elif expr_type == "Identifier":
        return Identifier(json_expression)
    elif expr_type == "BinaryExpression":
        return BinaryExpression(json_expression)
    elif expr_type == "CallExpression":
        return CallExpression(json_expression)
    elif expr_type == "MemberExpression":
        return MemberExpression(json_expression)
    elif expr_type == "AssignmentExpression":
        return AssignmentExpression(json_expression)

def getStatement(json_statement):
    stm_type = json_statement['type']
    if stm_type == 'ExpressionStatement':
        return ExpressionStatement(json_statement)
    elif stm_type == 'IfStatement':
        return IfStatement(json_statement)
    elif stm_type == 'WhileStatement':
        return WhileStatement(json_statement)
    elif stm_type == "BlockStatement":
        return BlockStatement(json_statement)

# TODO: doesn't work for a = document; sink = a.source

class Literal:
    # no attribute
    def __init__(self, json):
        return

    def __repr__(self):
        return "Literal"

    def visit(self, vulns, shared, stack, out_sinks):
        return []

class Identifier:
    # self.name = string
    def __init__(self, json):
        self.name = json['name']

    def __repr__(self):
        return "Identifier<name: " + self.name + ">"

    def toString(self):
        ret = "Identifier\n"
        ret += "name: " + repr(self.name) + "\n" 

    # a = document [^document[|\..*]]
    # b = a.url (document.url)

    def visit(self, vulns, shared, stack, out_sinks):
        for level in shared:
            if self.name in level:
                return level[self.name]
        for vuln in vulns:
            if (re.search(f"^{self.name}(\.[a-zA-Z][a-zA-Z0-9]*)*$", vuln)):
                return [(self.name, None)]
        return []

    def sinks(self, vulns, shared, info):
        sinks = []
        for id in info:
            id_vulns = vulns[id[0]]
            #vuln = (name, sources, sinks, sanitizers)
            for vuln in id_vulns:
                if self.name in vuln[types["sinks"]]:
                    # (name, source, sink, sanitizer)
                    sinks += [(vuln[0], id[0], self.name, id[1])]
        return sinks

    def getName(self):
        return self.name

class BinaryExpression:
    # self.left : Expression
    # self.right : Expression
    #self.operator : ???
    def __init__(self, json):
        self.left = getExpression(json['left'])
        self.right = getExpression(json['right'])
         
    def __repr__(self):
        return "Binary<left: " + repr(self.left) + "; right: " + repr(self.right) + ">"

    def visit(self, vulns, shared, stack, out_sinks):
        left_sources = self.left.visit(vulns, shared, stack, out_sinks)
        right_sources = self.right.visit(vulns, shared, stack, out_sinks)
        ret = list(OrderedDict.fromkeys(left_sources + right_sources))
        return ret

class CallExpression:
    # self.func : Expression
    # self.args : list(Expression)
    def __init__(self, json):
        self.args = []
        self.func = getExpression(json['callee'])
        for expr in json['arguments']:
            self.args += [getExpression(expr)]

    def __repr__(self):
        return "Call<func: " + repr(self.func) + "; args: " + repr(self.args) + ">"

    def visit(self, vulns, shared, stack, out_sinks):
        func_source = self.func.visit(vulns, shared, stack, out_sinks)

        args_sources = []
        for arg in self.args:
            source = arg.visit(vulns, shared, stack, out_sinks)
            source = sanitize(vulns, shared, source, self.func.getName())
            args_sources += source

        args_sources = list(OrderedDict.fromkeys(args_sources))
        my_sinks = self.func.sinks(vulns, shared, args_sources)
        
        if len(my_sinks) > 0:
            print_sink(my_sinks, out_sinks)
        
        return func_source + args_sources

class MemberExpression:
    # document.url
    # self.object : Expression
    # self.property : Expression
    def __init__(self, json):
        self.object = getExpression(json['object'])
        self.property = getExpression(json['property'])
    
    def __repr__(self):
        return "Member<object: " + repr(self.object) + "; property: " + repr(self.property) + ">" 

    def visit(self, vulns, shared, stack, out_sinks): 
        names = [self.getName()]

        obj_info = self.object.visit(vulns, shared, stack, out_sinks) # taints in object

        for prefix in obj_info:
            names += [prefix[0] + "." + self.property.getName()]

        for name in names:
            for level in shared:
                if name in level:
                    return level[name] + obj_info
            for vuln in vulns:
                if (re.search(f"^{name}(\.[a-zA-Z][a-zA-Z0-9]*)*$", vuln)):
                    return [(name, None)] + obj_info
        return obj_info

    def sinks(self, vulns, shared, info):
        names = [self.getName()]

        share = []
        for level in shared:
            if self.object.getName() in level:
                share = level[self.object.getName()]
                break

        for prefix in share:
            names += [prefix + "." + self.property.getName()]

        sinks = []
        
        for id in info:
            id_vulns = vulns[id[0]]
            #vuln = (name, sources, sanitizers, sinks)
            for vuln in id_vulns:
                for name in names:
                    if name in vuln[types["sinks"]]:
                        # (name, source, sink, sanitizer)
                        sinks += [(vuln[0], id[0], name, id[1])]
        
        return sinks

    def getName(self):
        return self.object.getName() + "." + self.property.getName()

    # XXX
    # c -> func, safe -> func
    # c = safe
    # sink(c())
    # sink(b)
    # XXX

class AssignmentExpression:
    # self.left : Expression
    # self.right : Expression
    # operator again? for print reasons only
    def __init__(self, json):
        self.left = getExpression(json['left'])
        self.right = getExpression(json['right'])

    def __repr__(self):
        return "Assignement<left: " + repr(self.left) + "; right: " + repr(self.right) + ">" 

    def visit(self, vulns, shared, stack, out_sinks):
        right_info = self.right.visit(vulns, shared, stack, out_sinks)
        right_info += combine_stack(stack)

        shared[0][self.left.getName()] = right_info # assignments in highest context stay in this context

        sinks = self.left.sinks(vulns, shared, right_info)
        if (len(sinks) > 0):
            print_sink(sinks, out_sinks)

        return right_info
    
class ExpressionStatement:
    # self.expression : Expression
    def __init__(self, json):
        self.expression = getExpression(json['expression'])
    
    def __str__(self):
        return f"ExpressionStatement<{self.expression}>"

    def toString(self, level = 0):
        ret = " " * level + "ExpressionStatement\n" 
        ret += " " * level + "expression: " + repr(self.expression) + "\n"
        return ret

    def visit(self, vulns, shared, stack, out_sinks):
        self.expression.visit(vulns, shared, stack, out_sinks)
        return

class IfStatement:
    # self.test : Expression
    # self.then : Statement
    # self.alternative : Statement
    # does not support directly if else
    def __init__(self, json):
        self.test = getExpression(json['test'])
        self.then = getStatement(json['consequent'])

        if json['alternate'] == None:
            self.alternative = None
        else:
            self.alternative = getStatement(json['alternate'])


    def __str__(self):
        return f"IfStatement[\ntest: {self.test}\nthen: {self.then}\nelse: {self.alternative}\n]"

    def toString(self, level = 0):
        ret = " " * level + "IfStatement\n" 
        ret += " " * level + "test: " + repr(self.test) + "\n"
        ret += " " * level + "then:\n" + self.then.toString(level + 2) + "\n"
        if (self.alternative != None):
            ret += " " * level + "else:\n" + self.alternative.toString(level + 2) + "\n"
        else:
            ret += " " * level + "else: None\n"
        
        return ret

    def visit(self, vulns, shared, stack, out_sinks):
        aux_test_source = self.test.visit(vulns, shared, stack, out_sinks)
        test_source = []

        for vuln in aux_test_source:
            if vuln[0] in vulns:
                test_source += [vuln]

        stack = [test_source] + stack

        shared = [defaultdict(list)] + shared

        self.then.visit(vulns, shared, stack, out_sinks)

        then_context, shared = shared[0], shared[1:]

        if (self.alternative != None):
            shared = [defaultdict(list)] + shared
            self.alternative.visit(vulns, shared, stack, out_sinks)
            alt_context, shared = shared[0], shared[1:]

            merge_shared(then_context, shared, True)
            merge_shared(alt_context, shared)
        else:
            merge_shared(then_context, shared)

        stack = stack[1:]

        return

class WhileStatement:
    # self.test : Expression
    # self.body : Statement
    def __init__(self, json):
        self.test = getExpression(json['test'])
        
        self.body = getStatement(json['body'])
    
    def __str__(self):
        return f"WhileStatement[\ntest: {self.test}\nbody: {self.body}\n]"

    def toString(self, level = 0):
        ret = " " * level + "WhileStatement\n" 
        ret += " " * level + "test: " + repr(self.test) + "\n"
        ret += " " * level + "body:\n" + self.body.toString(level + 2) + "\n"
        return ret

    def visit(self, vulns, shared, stack, out_sinks):
        aux_test_source = self.test.visit(vulns, shared, stack, out_sinks)
        test_source = []

        for vuln in aux_test_source:
            if vuln[0] in vulns:
                test_source += [vuln]

        stack = [test_source] + stack

        shared = [defaultdict(list)] + shared

        self.body.visit(vulns, shared, stack, out_sinks)

        body1_context, shared = shared[0], shared[1:]

        merge_shared(body1_context, shared)

        self.body.visit(vulns, [defaultdict(list)] + shared, stack, out_sinks)

        stack = stack[1:]

        return

class BlockStatement:
    # self.statements : list(Statement)
    def __init__(self, json):
        self.statements = []
        for stm in json['body']:
            self.statements += [getStatement(stm)]

    def __str__(self):
        return "{" + ";\n".join([str(x) for x in self.statements]) + "\n}"

    def toString(self, level=0):
        ret = " " * level + "BlockStatement\n"
        ret += " " * level + "{\n"
        for stm in self.statements:
            ret += stm.toString(level + 2)
        ret += " " * level + "}"
        return ret

    def visit(self, vulns, shared, stack, out_sinks):
        for stm in self.statements:
            stm.visit(vulns, shared, stack, out_sinks)
        return
