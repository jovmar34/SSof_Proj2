types = {"safe": 0, "tainted": 1, "solved": 2}

class Literal:
    # no attribute
    def __init__(self, json):
        self.tainted = False

    def tainted(self):
        return self.tainted

class Indentifier:
    # self.name = string
    def __init__(self, json):
        return

    def __repr__(self):
        return "Identifier(" + self.name + ")"

    def setTainted(self, tainted):
        self.tainted = True

    def tainted(self):
        return self.tainted

class BinaryExpression:
    # self.left : Expression
    # self.right : Expression
    def __init__(self, json):
        return

    def tainted(self):
        return (self.right.tainted() or self.left.tainted())

class CallExpression:
    # self.func : Expression
    # self.args : list(Expression)
    def __init__(self, json):
        return

    def tainted(self):
        taint = self.func.tainted()
        for arg in self.args:
            taint  = (taint or arg.tainted())

        return taint

class MemberExpression:
    # document.url
    # self.object : Expression
    # self.property : Expression
    def __init__(self, json):
        return

    def tainted(self):
        return self.obj.tainted() or self.property.tainted()

class AssignmentExpression:
    # self.left : Expression
    # self.right : Expression
    def __init__(self, json):
        return

    def tainted(self):
        return self.right.tainted()


class ExpressionStatement:
    # self.expression : Expression
    # self.directive : boolean ?
    def __init__(self, json):
        return

    def tainted(self):
        return self.expr.tainted()

class IfStatement:
    # self.test : Expression
    # self.then : Statement
    # self.alternative : Statement
    # does not support directly if else
    def __init__(self, test, then, alt):
        return

    def tainted(self):
        return self.test.tainted()

class WhileStatement:
    # self.test : Expression
    # self.body : Statement
    def __init__(self, test, body):
        self.test = test
        self.body = body

    def tainted(self):
        return self.test.tainted()

class BlockStatement:
    # self.statements : list(Statement)
    def __init__(self, json):
        

    def tainted(self):
        taint = False
        for statement in self.statements:
            taint = taint or statement.tainted()
        return taint
