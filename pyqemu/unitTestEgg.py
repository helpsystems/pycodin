#!/usr/bin/env python
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

import pyqemu 
from pyqemu import IARG_ADDRINT, IARG_PTR, IARG_BOOL, IARG_UINT32, IARG_INT, IARG_LONG, IARG_ULONG, FUNCTION_HOOK_LEN, get_virtual_string

environ = None

class TypeTestError ( Exception ):
    pass

class TestLoader():
    _test_method_prefix = "test"
    _middle = ( "instruction", "offset", "instructions", "address" )
    _delim = '_'

    def getTestCases( self, testCaseClass ):
        """get a class and return a """
        test_methods = self._get_test_methods_from( testCaseClass )
        dic_methods = self._parse_methods( test_methods )
        return dic_methods

    def _get_test_methods_from(self, testClass):
        """get the methods thats begin with test word. 
        Example:
                test_instruction_1
        """

        len_prefix = len( self._test_method_prefix )
        test_methods = [ method [ len_prefix + len(self._delim): ] for method in dir(testClass) if method.startswith( self._test_method_prefix ) ]
        return test_methods

    def _parse_methods(self, methods):
        """ recive an instruction_number or offset_number and return a dictionary:
            {'instruction'{1:test_instruction_1}, offset:{1, test_offset_1}, address:{0x7, test_address_0x7}
            to test all instruction ( test_instructions ), the value to key instruction is -1"""

        test_dic = self._create_test_dic()
        for method in methods:
            if method.startswith( self._middle ): 
                type_test = self._get_prefix_type(method)
                param_number = self._get_suffix_number(method)
                test_dic[type_test][param_number] = self._test_method_prefix + self._delim + method
            
            else:
                raise TypeTestError, "Invalid Type Test %s " % method 
             
        return test_dic 
   
    def _get_prefix_type(self, method):
        """recive instruction_number or offset_number and return: instruction or offset"""
        prefix = 0
        return self._get_part(method, prefix)

    def _get_suffix_number(self, method):
        """recive instruction_number or offset_number and return: number"""
        suffix = 1
        return self._str2num( self._get_part( method, suffix ) )

    def _get_part(self, method, part):
        try:
            return method.split( self._delim )[ part ]
        except IndexError:
            return '-1'
        
    def _create_test_dic(self):
        #this must be a dictionary comprehension
        return dict( [ ( element, {} ) for element in self._middle] )

    def _str2num(self, s):
        return int(s, 16) if "x" in s else int(s)


class TestCaseEGG():
    """class used for earch test case"""
    _end_egg = pyqemu.END_EGG 

    def __init__(self, egg):
        self.egg = self._add_delim_egg ( egg )

        self.code_addr = 0x0
        self.code_size = 0x2000
        self.core_entry_point = 0x0
        
        self.stack_addr = 0x0
        self.stack_size = 0x200

        self.fs_addr = 0x0
        self.fs_size = 0x200

        self.extra_codes = list ()

        loader = TestLoader ( )
        self._test = loader.getTestCases ( self )
        self._instruction_number = 0
        self._set_callbacks ( )

    def register_function ( self, virtual_address , python_function, c_convention, ret_type, *args ):
        pyqemu.register_function_hook_handler ( virtual_address, python_function, c_convention, ret_type, *args ) 

    def run(self):
        """call exec_shellcode from dll"""
       
        self.configure_memory ( )

        #configure the code 
        self.configure_code( )

        #configure the stack 
        self.configure_stack ( )

        self.configure_segments ( )
        
        #init vm and make environ
        if self.code_size < len ( self.egg ):
            self.code_size = len ( self.egg )

        pyqemu.init_vmx86_linux ( self.code_size, addr = self.code_addr )
        
        pyqemu.allocate_stack ( self.stack_addr, self.stack_size )
         
        pyqemu.allocate_fs ( self.fs_addr, self.fs )

        self._add_extra_codes ( )

        global environ
        environ = pyqemu.environ

        self.configure_init_regs ( pyqemu.environ )

        pyqemu.exec_code ( self.egg, addr = self.code_addr, entry_point = self.code_entry_point )
    
    def _add_extra_codes ( self ):
        for addr, code in self.extra_codes:
            pyqemu.revase_code ( code, addr )
        
        self.extra_codes = list()

    def map_memory ( self, dict_addr_len ):
        pyqemu.map_memory ( dict_addr_len )
    def revase_code ( self, addr, code ):
        self.extra_codes.append ( (addr, code) )

    def handletrap( self, trapnr, environ ):
        """handler for each trap, this method is overwrited for the tester. By default call test_instruction_number and test_offset_number"""
        
        if self._test['instruction'].get( self._instruction_number ):
            self._call_test( self._test['instruction'][self._instruction_number], *( trapnr, environ ) )

        if self._test['instructions']:
            self._call_test( self._test['instructions'][ -1 ], *( trapnr, environ ) )
        
    def configure_stack ( self ):
        pass

    def configure_code ( self ):
        pass

    def configure_init_regs ( self, environ ):
        pass

    def configure_segments ( self ):
        pass
    
    def configure_memory ( self ):
        pass

    def get_virtual_string ( self, v_addr ):
        return pyqemu.get_virtual_string ( v_addr )

    def exit ( self ):
        pyqemu.end_virtualization ( )

    def _call_test ( self, to_call, *args ):
        """ call the test defined in subclass"""
        call = getattr(self, to_call)
        call(args[0], args[1])

    def _capture_traps_for_each_instruction ( self, trapnr ):

        if trapnr == pyqemu.END_EGG_TRAP:
            return pyqemu.STOP
        
        self._instruction_number += 1
        self.handletrap ( trapnr, pyqemu.environ )
        
        return pyqemu.CONTINUE

    def _offset_handler ( self, trapnr ):

        if trapnr == pyqemu.END_EGG_TRAP:
            return pyqemu.STOP

        self._call_test( self._test[ "offset" ][ pyqemu.environ.get_offset() ], *( trapnr, pyqemu.environ ) ) 

        return pyqemu.CONTINUE 

    def _address_handler ( self, trapnr ):
        if trapnr == pyqemu.END_EGG_TRAP:
            return pyqemu.STOP

        self._call_test( self._test[ "address" ][ pyqemu.environ.eip ], *( trapnr, pyqemu.environ ) ) 
        
        return pyqemu.CONTINUE

    def _set_callbacks ( self ):
        self._set_ins_callback ( )
        self._set_offset_callback ( )
        self._set_address_callback ( )
    
    def _set_ins_callback ( self ):
        """ set all callback related with instructions """
        pyqemu.set_instruction_callback( self._capture_traps_for_each_instruction )

    def _set_offset_callback ( self ):
        """ set all callback related with offsets"""
        for offset_number in self._test [ "offset" ].keys( ):
            pyqemu.set_callback_at_offset ( self._offset_handler, offset_number )
    
    def _set_address_callback ( self ):
        """ set all callback related with address """

        for address_number in self._test [ "address" ].keys():
            pyqemu.set_callback_at_address ( self._address_handler, address_number )

    def _add_delim_egg ( self, egg ):
        return self._add_end_egg( egg )

    def _add_end_egg ( self, egg ):
        return egg + self._end_egg 
    

class TestCase ( TestCaseEGG ):
    def assert_equal( self , valueOrExpression , value , error_msg ):
        """this method is a testcase method"""
        if not valueOrExpression == value:
            self.error( error_msg +  " obtained : %x  expected : %x " % ( valueOrExpression, value ) )
            exit()

    def error( self , error_msg ):
        print error_msg

#test
if __name__ == '__main__':
    
   
    class TestCase_exit ( TestCase ):
        def configure_env ( self, environ ):
            environ.cs.base = 0x0
            environ.eax = 0x100

        #def test_instructions ( self, trapnr, environ ):
        #    
        #    print "test all instruction"

        def test_instruction_1 ( self, trapnr, environ ):
            print "test_instruction_1"

        def test_offset_6 ( self, trapnr, environ ):
            print "testing offset 6"

        def test_offset_4 ( self, trapnr, environ ):
            print "testing offset 4"
        
        def test_address_0x2 ( self, trapnr, environ ):
            print "test address 0x2"

        #def handletrap(self, trapnr, cpuenv):
        #    print cpuenv.eax
        #    cpuenv.eax = 2
            #ahora handleamos el trap que retorna la opcion de single step
 
    test_exit = TestCase_exit("\x31\xc0\xb0\x01\x31\xdb\xcd\x80")

    #test_exit = TestCase_exit("\x90"*3)
    #test_getpc1.capture_traps = capture_traps
    test_exit.run()

