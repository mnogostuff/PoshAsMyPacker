import sys
import pyparsing
import string
import gzip
import base64
import StringIO
import random
import re

def gen_alpha(variable_length):
    return ''.join(random.choice(string.letters) for _ in range(variable_length))

def gen_alpha_value_table(variable_length=8):
    table = []
    i = 0
    
    for c in range(32,126):
        table.append({'var':gen_alpha(variable_length), 'val':chr(c)})
    return table

def f7(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]

def extractBetweenMatchingChar(begin_ch, end_ch, text, index=0):
    i = text.find(begin_ch, index)
    count = 0
    for c in text[i:]:
        if c == begin_ch:
            count += 1
        if c == end_ch:
            count -= 1
            if count == 0:
                break
        i += 1
    return i+1

def code_between_parens(code):
    i = code.find('(')
    j = i
    betw_parens = []
    while i < len(code):
        i = extractBetweenMatchingChar('(', ')', code, index=i)
        betw_parens.append(code[j:i])
        i = code.find('(', i)
        if j > i: break
        j = i
    return betw_parens

def match_exclude_lines_with_strings(expression, data):
    # match regex pattern to exclude a string
    # this doesn't actually work properly and could be done
    # in regex without this
    ret = []
    expression = re.compile(expression, re.IGNORECASE)
    """
    for line in data.split('\n'):
        s = expression.findall(line+'\n')
        if s:
            if not ('"' in line):
                ret.append(''.join(s))
            else:
                sys.stderr.write(line+'\n')
    """
    return expression.findall(data)

from PowershellProperties import PowershellProperties
from PowershellProperties import PowershellCompact

class PoshCrypt: 
    replacement_variables = []
    replacement_functions = []
    protected_variables = PowershellProperties.protected_variables + ["pscmdlet","name", "value"]
    protected_values = ['LocalFile', 'WebFile', 'Bytes', 'WString', 'String', 'Void', 'void',
                             'ParameterSetName', 'ValidateSet']
    protected_whitespace_line_values = ['CmdletBinding','param', 'function', '{', '}', 'if', 'else', 'while', 'for', 'switch']
    protected_whitespace_line_values_ = r'CmdLetBinding|param|function|Function|\{|\}|if|else|while|for|switch'

    def __init__(self, code=''):
        self.code = code
        return

    def add_code(self, code):
        self.code += '\n'+code
        return

    def remove_debug(self):
        # NOTE: this should come first, otherwise it wipes out the whole line... should rework this
        remove_debug_1 = re.compile('(Write-Verbose.*)')
        remove_debug_2 = re.compile('(Write-Debug.*)')
        remove_debug_3 = re.compile('(Write-Error.*)')
        remove_debug_4 = re.compile('(Write-Warning.*)')
        remove_debug_5 = re.compile('(throw) .*', re.IGNORECASE)
        # NOTE: this also deletes the associated action, most PoSH doesn't use this, right?
        self.code = re.sub(remove_debug_1, "", self.code)
        self.code = re.sub(remove_debug_2, "", self.code)
        self.code = re.sub(remove_debug_3, "", self.code)
        self.code = re.sub(remove_debug_4, "", self.code)
        self.code = re.sub(remove_debug_5, r"\1 '1'", self.code)
        return

    def remove_unnecessary_whitespace(self):
        posh_compactor = PowershellCompact(self.code)
        self.code = posh_compactor.compact()

        for p in code_between_parens(self.code):
            self.code = self.code.replace(p, p.replace('\n',''))

        _code = ''
        for line in self.code.split('\n'):
            line_restricted = False
            for protected in self.protected_whitespace_line_values:
                if protected.lower() in line.lower():
                    line_restricted = True
            if line_restricted:
                _code += line + '\n'
            else:
                _code += line + ';'
        self.code = _code.replace('\n{\n', '{').replace('\n}\n', '}')
        #m = re.compile(r'([\{\s])*?[\S]', re.DOTALL)
        #self.code = m.sub(_code, '\{')
        return 

    def encode_strings(self, variable_length=8):
        # NOTE: can encode numbers too!
        # NOTE: can also get more creative with how strings are stored... a table at the top is pretty obvious
        find_strings_1 = re.compile("(\"[\w].*?\")")
        find_strings_2 = re.compile("(\'[\w].*?\')")
        ignore_parameter_strings_1 = re.compile('ParameterSetName=(\'[\w].*?\')', flags=re.DOTALL|re.IGNORECASE)
        ignore_parameter_strings_2 = re.compile('ParameterSetName=(\"[\w].*?\")', flags=re.DOTALL|re.IGNORECASE)

        _strings = f7(find_strings_1.findall(self.code)+(find_strings_2.findall(self.code)))
        ignore_strings = f7(ignore_parameter_strings_1.findall(self.code)+ignore_parameter_strings_2.findall(self.code))
        for line in self.code.split('\n'):
            if 'ValidateSet' in line:
                for x in f7(find_strings_1.findall(line)+find_strings_2.findall(line)):
                    ignore_strings.append(x)
        for ignore in f7(ignore_strings):
            _strings.remove(ignore)
        string_assignments = []

        table = gen_alpha_value_table()
        new_strings = []
        i = 0
        for st in _strings:
            j = []
            for char in st:
                k = ((item for item in table if item['val'] == char).next())
                j.append(k["var"])
            repl = '"$'+'$'.join(j[1:len(j)-1])+'"'
            self.code = self.code.replace(st, repl)
        for t in table:
            if t['val'] in ['\'','`']:
                self.code = '$'+t['var']+'=\'`'+t['val']+'\'\n' + self.code
            else:
                self.code = '$'+t['var']+'=\''+t['val']+'\'\n' + self.code
        return 

        
    # NOTE: making all variables lower-case, powershell doesn't care so neither should we
    # Because powershell doesn't care, I could also scramble the case
    def scramble_variables(self, variable_length=8):
        find_variables = re.compile(r"\$([a-z].*?)\W", re.IGNORECASE)
        variables = f7(find_variables.findall(self.code))
        for variable in variables:
            gen = ''
            if not variable.lower() in self.protected_variables:
                replacement_variable = gen_alpha(variable_length)
                self.code = re.sub(r'(\W[\$\-])'+variable+r'(\b)', r'\1'+replacement_variable+r'\2', self.code, flags=re.IGNORECASE)
        return self.code

    def scramble_functions(self, function_length=8):
        functions = f7(match_exclude_lines_with_strings(r'function\s([a-z\-].*?)[\s\{]', self.code))
        for f in functions:
            replacement_function = gen_alpha(function_length)
            #self.code = re.sub(r'\b'+replacement_function)
            self.code = self.code.replace(f, replacement_function)
        return self.code

    def squash_and_scramble(self, code=''):
        if code: self.code = code
        self.remove_debug()
        self.remove_unnecessary_whitespace()
        self.scramble_variables(variable_length=8)
        self.scramble_functions(function_length=8)

        self.encode_strings()
        #self.remove_unnecessary_whitespace()
        return self.code
