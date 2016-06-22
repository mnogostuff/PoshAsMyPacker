import re

def f7(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]

class PowershellProperties:
    protected_variables = ["$", "?", "^", "args", "confirmpreference", "consolefilename", "debugpreference", "error", "erroractionpreference", "errorview", "executioncontext", "false", "formatenumerationlimit", "home", "host", "input", "maximumaliascount", "maximumdrivecount", "maximumerrorcount", "maximumfunctioncount", "maximumhistorycount", "maximumvariablecount", "myinvocation", "nestedpromptlevel", "null", "outputencoding", "pid", "profile", "progresspreference", "psboundparameters", "pscommandpath", "psculture", "psdefaultparametervalues", "psemailserver", "pshome", "psise", "psscriptroot", "pssessionapplicationname", "pssessionconfigurationname", "pssessionoption", "psuiculture", "psunsupportedconsoleapplications", "psversiontable", "pwd", "shellid", "stacktrace", "true", "verbosepreference", "warningpreference", "whatifpreference"]
    def __init__(code=''):
        self.code = code
        return

class PowershellCompact:
    def __init__(self, code):
        self.code = code

    def artificial_endlines(self, code=''):
        self.code = self.code.replace('`\n', '')

    def whitespace_surrounding_statements(self, code=''):
        # let's make sure we got them all... is there a better way to do this?
        for _ in range(5): self.code = re.sub(r'\s?([\+\-]?[\=\;\,\|])\s?', r'\1', self.code)
        self.code = re.sub(r'\s([\-\+])\s', r'\1', self.code)


    def whitespace_surrounding_equation(self, code=''):
        self.code = re.sub(r'\s([\-\+])\s', r'\1', self.code)
        
    def repeating_whitespace(self, code=''):
        self.code = re.sub(r'(\s).*?(\S)', r'\1\2', self.code)

    def comments(self):
        comments_1 = re.compile("(<\#.*?\#>)", re.DOTALL)
        comments_2 = re.compile('(\#.*)')
        self.code = re.sub(comments_1, "", self.code)
        self.code = re.sub(comments_2, "", self.code)
        
    def empty_lines(self):
        ret = []
        for line in self.code.split('\n'):
            if (not re.match(r'^\s*$', line)):
                ret.append(line)
        self.code = '\n'.join(ret)

    def compact(self, code=''):
        self.comments()
        self.empty_lines()
        self.artificial_endlines()
        self.whitespace_surrounding_equation()
        self.whitespace_surrounding_statements()
        self.repeating_whitespace()
        self.empty_lines()
        return self.code
