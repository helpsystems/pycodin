#!/usr/bin/env python

"""

qemu // pyqemu // unitTestEgg // 

import pyqemu

def mycallback( tranr , environment )
    print tranr
    print environment
    return CONTINUE

pyqemu.init_vmx86_linux()
pyqemu.set_instruction_callback( mycallback )
pyqemu.exec_code( "\x90\x90\x90" )

pyqemu.set_callback_at_offset( mycallback , 10 )

pyqemu.set_callback_at_address( mycallback , 0xffff00b )

pyqemu.end_virtualization()


"""


try:
    import ctypes
except ImportError:
    raise ImportError, 'you need ctypes'

import ctypes.util as utils
#load library

_pyqemu = ctypes.cdll.LoadLibrary('pyqemu')

class TINYState(ctypes.Structure):
    """Define TINYState structure in python. This structure
    contain the cpu context."""
    _fields_ = [("eax", ctypes.c_uint32),
    ("ebx", ctypes.c_uint32),
    ("ecx", ctypes.c_uint32),
    ("edx", ctypes.c_uint32),
    ("edi", ctypes.c_uint32),
    ("esi", ctypes.c_uint32),
    ("esp", ctypes.c_uint32),
    ("ebp", ctypes.c_uint32),
    ("eip", ctypes.c_uint32),
    ("eflasg", ctypes.c_uint32),
    ("cr", ctypes.c_uint32 * 5)]

_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_int32, *(ctypes.c_int32, ctypes.POINTER(TINYState)))

set_callback = pyqemu.set_callback 
set_callback.restype = None
set_callback.argtypes = _CALLBACK,

#def pyqemu_instruction_callback(TINYState):
#    return 0

#pyqemu_callback = _CALLBACK(pyqemu_instruction_callback)


set_breakpoint = pyqemu.set_breakpoint
set_breakpoint.restype = ctypes.c_char_p
set_breakpoint.argtypes = ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32

exec_shellcode = pyqemu.exec_shellcode
exec_shellcode.restype = ctypes.c_int
exec_shellcode.argtype = ctypes.c_char_p

#CONTINUE = 1
#NOCONTINUE = 0
#EXCP_DEBUG = 0x10002

#class Register():
#    """this is a register"""
#    def __init__(self, cpu_register):
#        self.register = cpu_register
#    
#    def get_register(self):
#        return self.register
#    
#    def set_register(self, value):
#        pass
#
#    register = property(get_register, set_register)

class Environ(object):
    """enviroment class for test."""
    def __init__(self, cpuenv):
        self._cpuenv = cpuenv
        #self.eax = self.cpuenv_orig.contents.eax 
        #self.ebx = self.cpuenv.contents.ebx 
        #self.ecx = self.cpuenv.contents.ecx
        #self.edx = self.cpuenv.contents.edx
        #self.esi = self.cpuenv.contents.esi
        #self.edi = self.cpuenv.contents.edi
        #self.esp = self.cpuenv.contents.esp
        #self.ebp = self.cpuenv.contents.ebp

    def set_eax(self, value):
        self._cpuenv.contents.eax = value
    
    def get_eax(self):
        return self._cpuenv.contents.eax 

    eax = property(get_eax, set_eax)
    #############################################

    def set_ebx(self, value):
        self._cpuenv.contents.ebx = value
    
    def get_ebx(self):
        return self._cpuenv.contents.ebx 

    ebx = property(get_ebx, set_ebx)
    #############################################

    def set_ecx(self, value):
        self._cpuenv.contents.ecx = value
    
    def get_ecx(self):
        return self._cpuenv.contents.ecx 

    ecx = property(get_ecx, set_ecx)
    ############################################

    def set_edx(self, value):
        self._cpuenv.contents.edx = value
    
    def get_edx(self):
        return self._cpuenv.contents.edx 

    edx = property(get_edx, set_edx)
    ############################################

    def set_esi(self, value):
        self._cpuenv.contents.esi = value
    
    def get_esi(self):
        return self._cpuenv.contents.esi 

    esi = property(get_esi, set_esi)
    ############################################

    def set_edi(self, value):
        self._cpuenv.contents.edi = value
    
    def get_edi(self):
        return self._cpuenv.contents.edi 

    edi = property(get_edi, set_edi)
    ############################################

    def set_esp(self, value):
        self._cpuenv.contents.esp = value
    
    def get_esp(self):
        return self._cpuenv.contents.esp

    esp = property(get_esp, set_esp)
    ############################################

    def set_ebp(self, value):
        self._cpuenv.contents.ebp = value
    
    def get_ebp(self):
        return self._cpuenv.contents.ebp

    ebp = property(get_ebp, set_ebp)
    ############################################

    def set_eip(self, value):
        self._cpuenv.contents.eip = value
    
    def get_eip(self):
        return self._cpuenv.contents.eip

    eip = property(get_eip, set_eip)


class TestLoader():
    _test_method_prefix = "test"
    _middle = ("instruction", "offset")
    _delim = '_'

    def getTestCases(self, testCaseClass):
        """get a class and return a """
        test_methods = self._get_test_methods_from(testCaseClass)
        dic_methods = self._parse_methods(test_methods)
        return dic_methods

    def _get_test_methods_from(self, testClass):
        """get the methods thats begin with test word. 
        Example:
                test_instruction_1
        """

        len_prefix = len(self._test_method_prefix)
        test_methods = [method[len_prefix + len(self._delim):] for method in dir(testClass) if method.startswith(self._test_method_prefix)]
        return test_methods

    def _parse_methods(self, methods):
        """ revice an instruction_numbero or offset_number and return a dictionary:
            {'instruction'{1:test_instruction_1}, offset:{1, test_offset_1}}"""
        test_dic = self._create_test_dic()
        for method in methods:
            if method.startswith(self._middle): 
                type_test = self._get_prefix_type(method)
                param_number = self._get_suffix_number(method)
                test_dic[type_test][param_number] = self._test_method_prefix + self._delim + method
            
        return test_dic 
   
    def _get_prefix_type(self, method):
        """recive instruction_number or offset_number and return: instruction or offset"""
        prefix = 0
        return self._get_part(method, prefix)

    def _get_suffix_number(self, method):
        """recive instruction_number or offset_number and return: number"""
        suffix = 1
        return int(self._get_part(method, suffix))

    def _get_part(self, method, part):
        return method.split(self._delim)[part]
        
    def _create_test_dic(self):
        #this must be a dictionary comprehension
        return dict([(element, {}) for element in self._middle])


class TestCaseEGG():
    """class used for earch test case"""
    _begin_egg = "\xcd\x98"
    _end_egg = "\xcd\x99"

    def __init__(self, egg):
        self.egg = self._add_delim_egg(egg)
        self._set_callback(self._capture_traps)
        loader = TestLoader()
        self._test = loader.getTestCases(self)
        self._instruction_number = 0

    def run(self):
        """call exec_shellcode from dll"""
        exec_shellcode(self.egg)
    
    def handletrap(self, trapnr, environ):
        """handler for each trap, this method is overwrited for the tester. By default call test_instruction_number and test_offset_number"""
        
        if self._instruction_number == 0:
            self._base = self._get_base(environ)
            return

        if self._instruction_number in self._test['instruction'].keys():
            self._call_test(self._test['instruction'][self._instruction_number], *(trapnr, environ))

        if self.get_offset(environ) in self._test['offset'].keys():
            self._call_test(self._test['offset'][self.get_offset(environ)], *(trapnr, environ))          

    def get_offset(self, environ):
        return environ.eip - self._base

    def _call_test(self, to_call, *args):
        call = getattr(self, to_call)
        call(args[0], args[1])

    def _capture_traps(self, trapnr, cpuenv):
        """convert to Environ class a cpuenv then call handletrap method that is overwrited by tester"""
        CONTINUE = 1
        environ = Environ(cpuenv)
        self.handletrap(trapnr, environ)
        self._instruction_number += 1
        return CONTINUE

    def _set_callback(self, callback):
        """set a python callback for a c function"""
        self._call = _CALLBACK(callback)
        set_callback(self._call)
   
    def _add_delim_egg(self, egg):
        tmp_egg = self._add_begin_egg(egg)
        return self._add_end_egg(tmp_egg)

    def _add_begin_egg(self, egg):
        return self._begin_egg + egg

    def _add_end_egg(self, egg):
        return egg + self._end_egg 
    
    def _get_base(self, environ):
        return environ.eip
    

class TestCase(TestCaseEGG):
    def assert_equal( self , valueOrExpression , value , error_msg ):
        """this method is a testcase method"""
        if not valueOrExpression == value:
            self.error( error_msg +  " obtained : %s  expceted : %s " % ( valueOrExpression, value ) )
    
    def error( self , error_msg ):
        self.errors+=1
        print error_msg

#test
if __name__ == '__main__':
    
   
    class TestCase_exit(TestCase):
        def test_instruction_1(self, trapnr, environ):
            print trapnr
            print "ACAAA" 
        def test_offset_2(self, trapnr,environ):
            print "testing offset 2"
        #def handletrap(self, trapnr, cpuenv):
        #    print cpuenv.eax
        #    cpuenv.eax = 2
            #ahora handleamos el trap que retorna la opcion de single step
 
    #test_exit = TestCase_exit("\x31\xc0\xb0\x01\x31\xdb\xcd\x80")

    test_exit = TestCase_exit("\x90"*3)
    #test_getpc1.capture_traps = capture_traps
    test_exit.run()




