"""Error types.

WardenError        - ordinary runtime error; catchable by try/catch in scripts.
WardenSyntaxError  - compile-time error.
SecurityViolation  - a blocked attack or unsafe operation; NOT catchable by
                     scripts, always aborts the request and is logged.
LimitExceeded      - a resource limit was hit (CPU steps, memory, recursion);
                     NOT catchable, aborts the request.
"""


class WardenSyntaxError(Exception):
    def __init__(self, msg, filename="<input>", line=0):
        super().__init__("%s:%d: syntax error: %s" % (filename, line, msg))
        self.msg = msg
        self.filename = filename
        self.line = line


class WardenError(Exception):
    def __init__(self, msg, line=0, value=None):
        super().__init__(msg)
        self.msg = msg
        self.line = line
        self.value = value  # thrown script value, if any


class SecurityViolation(Exception):
    def __init__(self, msg, kind="security"):
        super().__init__(msg)
        self.msg = msg
        self.kind = kind


class LimitExceeded(Exception):
    pass


class ExitSignal(Exception):
    """Raised by exit()/die() to stop a script normally."""
