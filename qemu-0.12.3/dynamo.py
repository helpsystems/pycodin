import types, new 
def RegisterConfig(name, *args):
    def y():
        pass

    source = """def __init__(self, a):
                        print "ACAAAAAAAAAA" """

    
    #compiled_code = compile(source, name, "single")

    code = compile(source, name, "single")

    nlocals = 10

    compiled_code = types.CodeType(1, nlocals, code.co_stacksize, code.co_flags,
    code.co_code, code.co_consts, code.co_names,
    code.co_varnames, code.co_filename,
    code.co_name,
    code.co_firstlineno, code.co_lnotab,
    code.co_freevars,
    code.co_cellvars)
    #compiled_code = y.func_code
    f = new.function(compiled_code, globals(), "init")
     
    print f("a")

    clase = new.classobj(name, (), {})

    im = new.instancemethod(f, name, ())

    setattr(clase, "__init__", im)    
    
    return clase
    #        return types.ClassType("i386", (), {'__init__':im})
    
        
                        
        

if __name__ == "__main__":
    config = RegisterConfig("i386", "eax", "ebx", "ecx", "edx")
    configI386 = config()
    configI386.__init__()

