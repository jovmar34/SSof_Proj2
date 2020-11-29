types = {"safe": 0, "tainted": 1, "solved": 2}

class Literal:
    def __init__(self):
        self.tainted = False

    def tainted(self):
        return self.tainted

class Indentifier:
    def __init__(self, name):
        self.tainted = False
        self.name = name

    def __repr__(self):
        return "Identifier(" + self.name + ")"

    def setTainted(self, tainted):
        self.tainted = True

    def tainted(self):
        return self.tainted

class BinaryExpression:
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def tainted(self):
        return (self.right.tainted() or self.left.tainted())

class CallExpression:
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def tainted(self):
        taint = self.func.tainted()
        for arg in self.args:
            taint  = (taint or arg.tainted())

        return taint

class CallExpression:
    def __init__(self, func, args):
        self.func = func
        self.args = args

    def tainted(self):
        taint = self.func.tainted()
        for arg in self.args:
            taint  = (taint or arg.tainted())

        return taint

class MemberExpression:
    def __init__(self, obj, prop):
        self.obj = obj
        self.property = prop

    def tainted(self):
        return self.obj.tainted() or self.property.tainted()

class AssignmentExpression:
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def tainted(self):
        return self.right.tainted()


class ExpressionStatement:
    def __init__(self, expr, directive):
        self.expr = expr
        self.directive = directive

    def tainted(self):
        return self.expr.tainted()

class IfStatement:
    def __init__(self, test, then, alt):
        self.test = test
        self.then = then
        self.alt = alt

    def tainted(self):
        return self.test.tainted()

class WhileStatement:
    def __init__(self, test, body):
        self.test = test
        self.body = body

    def tainted(self):
        return self.test.tainted()

class BlockStatement:
    def __init__(self, statements):
        self.statements = statements

    def tainted(self):
        taint = False
        for statement in self.statements:
            taint = taint or statement.tainted()
        return taint
