import re

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

    def visit(self, vulns, shared, stack):
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

    def visit(self, vulns, shared, stack):
        if self.name in shared:
            return shared[self.name]
        else:
            for vuln in vulns:
                if (re.search(f"^{self.name}(\.[a-zA-Z][a-zA-Z0-9]*)*$", vuln)):
                    return [self.name]
        return []

    def sinks(self, vulns, shared, info):
        sinks = []
        for id in info:
            id_vulns = vulns[id]
            #vuln = (name, sources, sanitizers, sinks)
            for vuln in id_vulns:
                if self.name in vuln[types["sinks"]]:
                    # (name, source, sink, sanitizer)
                    sinks += [(vuln[0], id, self.name, None)]
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

    def visit(self, vulns, shared, stack):
        return
    
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

    def visit(self, vulns, shared, stack):
        func_source = self.func.visit(vulns, shared, stack)

        args_sources = []
        for arg in self.args:
            args_sources += arg.visit(vulns, shared, stack)

        my_sinks = self.func.sinks(vulns, args_sources)
        
        if len(my_sinks) > 0:
            print("SINK!!!", my_sinks)
        
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

    def visit(self, vulns, shared, stack):
        names = [self.getName()]

        for prefix in shared[self.object.getName()]:
            names += [prefix + "." + self.property.getName()]

        for name in names:
            if name in shared:
                return shared[name]
            else:
                for vuln in vulns:
                    if (re.search(f"^{name}(\.[a-zA-Z][a-zA-Z0-9]*)*$", vuln)):
                        return [name]
        return []

    def sinks(self, vulns, shared, info):
        names = [self.getName()]

        for prefix in shared[self.object.getName()]:
            names += [prefix + "." + self.property.getName()]

        sinks = []
        
        for id in info:
            id_vulns = vulns[id]
            #vuln = (name, sources, sanitizers, sinks)
            for vuln in id_vulns:
                for name in names:
                    if name in vuln[types["sinks"]]:
                        # (name, source, sink, sanitizer)
                        sinks += [(vuln[0], id, name, None)]
        
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

    def visit(self, vulns, shared, stack):
        right_info = self.right.visit(vulns, shared, stack)

        shared[self.left.getName()] = right_info

        print(shared)

        sinks = self.left.sinks(vulns, shared, right_info)
        if (len(sinks) > 0):
            print("SINK!!!", sinks)

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

    def visit(self, vulns, shared, stack):
        self.expression.visit(vulns, shared, stack)
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

    def visit(self, vulns, shared, stack):
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

    def visit(self, vulns, shared, stack):
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

    def visit(self, vulns, shared, stack):
        for stm in self.statements:
            stm.visit(vulns, shared, stack)
        return
