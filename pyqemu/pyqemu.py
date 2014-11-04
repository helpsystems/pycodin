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
    import _ctypes
except ImportError:
    raise ImportError, 'you need ctypes'

import ctypes.util as utils
#load library

#_pyqemu = ctypes.cdll.LoadLibrary('pyqemulib')
_pyqemu = None 

class SegmentCache( ctypes.Structure ):

    _fields_ = [( "selector", ctypes.c_uint32),
    ( "base", ctypes.c_uint32 ),
    ( "limit", ctypes.c_uint32 ),
    ( "flags", ctypes.c_uint32 )]

class CPUX86State( ctypes.Structure ):
    """Define CPUX86State structure in python. This structure
    contain the cpu context."""
    TARGET_ULONG = ctypes.c_uint32
    _fields_ = [( "regs", TARGET_ULONG * 8),
    ( "eip", TARGET_ULONG ),
    ( "eflags", TARGET_ULONG ),

    ( "cc_src", TARGET_ULONG ),
    ( "cc_dst", TARGET_ULONG ),
    ( "cc_op", ctypes.c_uint32 ),
    ( "df", ctypes.c_int32 ),
    ( "hflags", ctypes.c_uint32 ),
    ( "hflags2", ctypes.c_uint32 ),

    ( "segs", SegmentCache * 6 ),]

    """
    ( "ldt", SegmentCache ),
    ( "tr", SegmentCache ),
    ( "gdt", SegmentCache ),
    ( "idt", SegmentCache ),
    ( "cr", TARGET_ULONG * 5 ),
    ( "a20_mask", ctypes.c_int32 ),
    ( "fpstt", ctypes.c_uint32 ),
    ( "fpus", ctypes.c_uint16 ), 
    ( "fpuc", ctypes.c_uint16 ),
    ( "fptags", ctypes.c_uint8 * 8 ),
    #( "fpregs", FPReg * 8 ),
    ( "fp_status", ctypes.c_void_p ),
    ( "ft0", ctypes.c_long ),
    ( "mmx_status", ctypes.c_void_p ),
    ( "sse_status", ctypes.c_void_p ),
    ( "mxcsr", ctypes.c_uint32 ),
    ( "xmm_regs", ctypes.c_void_p * 8 ),
    ( "xmm_t0", ctypes.c_void_p ),
    ( "mmx_to", ctypes.c_void_p),
    #( "xmm_regs", XMMReg * 8 ),
    #( "xmm_t0", XMMReg ),
    #( "mmx_to", MMXReg ),
    ( "sysenter_cs", ctypes.c_uint32 ),
    ( "sysenter_esp", TARGET_ULONG ),
    ( "sysenter_eip", TARGET_ULONG ),
    ( "efer", ctypes.c_uint64 ),
    ( "star", ctypes.c_uint64 ),

    ( "vm_hsave", ctypes.c_uint64 ),
    ( "vm_vmcb", ctypes.c_uint64 ),
    ( "tsc_target", ctypes.c_uint64 ),
    ( "intercept", ctypes.c_uint64 ),
    ( "intercept_cr_read", ctypes.c_uint64 ),
    ( "intercept_cr_write", ctypes.c_uint64 ),
    ( "intercept_dr_read", ctypes.c_uint64 ),
    ( "intercept_dr_write", ctypes.c_uint64 ),
    ( "intercept_exception", ctypes.c_uint64 ),
    ( "v_tpr", ctypes.c_uint8 ),

    ( "system_timer_msr", ctypes.c_uint64 ),
    ( "wall_clock_msr", ctypes.c_uint64 ),
    ( "tsc", ctypes.c_uint64 ),
    ( "pat", ctypes.c_uint64 ),

    ( "error_code", ctypes.c_int ),
    ( "exeption_is_int", ctypes.c_int ),

    ( "exeption_next_eip", TARGET_ULONG ),
    ( "dr", TARGET_ULONG * 8),
    ( "hwbreakpoint", ctypes.c_void_p),
    
    ( "smbase", ctypes.c_uint32 ),
    ( "old_exception", ctypes.c_int )]
    """

#TODO: ESTO NO ME GUSTA NI UN POCO...
class pyCPUX86State(object):
    """enviroment class for test. this class define getters and setters for registers and segments"""
    #__singletone = None

    def __init__(self, cpuenv):
        self._cpuenv = cpuenv
        
        self.es = self._cpuenv.contents.segs[ 0 ]
        self.cs = self._cpuenv.contents.segs[ 1 ]
        self.ss = self._cpuenv.contents.segs[ 2 ]
        self.ds = self._cpuenv.contents.segs[ 3 ]
        self.fs = self._cpuenv.contents.segs[ 4 ]
        self.gs = self._cpuenv.contents.segs[ 5 ]

    def _set_eax(self, value):
        R_EAX = 0
        self._cpuenv.contents.regs[R_EAX] = value
    
    def _get_eax(self):
        R_EAX = 0
        return self._cpuenv.contents.regs[R_EAX] 

    eax = property(_get_eax, _set_eax)

    def _set_ecx(self, value):
        R_ECX = 1
        self._cpuenv.contents.regs[R_ECX] = value
    
    def _get_ecx(self):
        R_ECX = 1
        return self._cpuenv.contents.regs[R_ECX] 

    ecx = property(_get_ecx, _set_ecx)

    def _set_edx(self, value):
        R_EDX = 2
        self._cpuenv.contents.regs[R_EDX] = value
    
    def _get_edx(self):
        R_EDX = 2
        return self._cpuenv.contents.regs[R_EDX] 

    edx = property(_get_edx, _set_edx)

    def _set_ebx(self, value):
        R_EBX = 3
        self._cpuenv.contents.regs[R_EBX] = value
    
    def _get_ebx(self):
        R_EBX = 3
        return self._cpuenv.contents.regs[R_EBX] 

    ebx = property(_get_ebx, _set_ebx)

    def _set_esp(self, value):
        R_ESP = 4
        self._cpuenv.contents.regs[R_ESP] = value
    
    def _get_esp(self):
        R_ESP = 4
        return self._cpuenv.contents.regs[R_ESP]

    esp = property(_get_esp, _set_esp)

    def _set_ebp(self, value):
        R_EBP = 5
        self._cpuenv.contents.regs[R_EBP] = value
    
    def _get_ebp(self):
        R_EBP = 5
        return self._cpuenv.contents.regs[R_EBP]

    ebp = property(_get_ebp, _set_ebp)

    def _set_esi(self, value):
        R_ESI = 6
        self._cpuenv.contents.regs[R_ESI] = value
    
    def _get_esi(self):
        R_ESI = 6
        return self._cpuenv.contents.regs[R_ESI] 

    esi = property(_get_esi, _set_esi)

    def _set_edi(self, value):
        R_EDI = 7
        self._cpuenv.contents.regs[R_EDI] = value
    
    def _get_edi(self):
        R_EDI = 7
        return self._cpuenv.contents.regs[R_EDI] 

    edi = property(_get_edi, _set_edi)

    def _set_eip(self, value):
        self._cpuenv.contents.eip = value
    
    def _get_eip(self):
        return self._cpuenv.contents.eip

    eip = property(_get_eip, _set_eip)

    def get_offset(self):
        return self.eip - self.cs.base
    
   # def __new__( self ): 
   #     if not Test.__singletone:
   #         Test.__singletone = super ( Test,  self ).__new__( self )
   #
   #     return Test.__singletone

#class RegisterConfigBuilder:
#    def __init__(self, *args):
        

#class Segment:
#    def __init__ ( self, address, size ):
#        self.addr = address
#        self.size = size
#        allocate_memory ( self.addr, size )
#    
#    def _copy_from ( self, address, bytes ):
#        begin_addr = self.addr
#        end_addr = self.addr + self.size
#
#        if address < begin_addr or
#           address > end_addr or
#           address + len( bytes) > end_addr:
#           raise Exeption, "Adress or Size not valid"
#           
#        copy_egg_to ( bytes, address)
#      
#    
#class Code ( Segment ):
#    def __init__ ( self, address, size ):
#        Segment.__init__ ( self, address, size )
#        self._code = None
#        self._entry_point = 0x0
#
#    def _get_code ( self ):
#        return self._code
#    
#    def _set_code ( self, shellcode ):
#        self._code = shellcode
#        self._copy ( self.addr, shellcode )
#
#    code = property ( _get_code, _set_code )
#
#class Fs ( Segment ):
#    def __init__ ( self, address, size ):
#        Segment.__init_ ( self, address, size )
         
#class Machine :
#    def __init__ ( self, size, addr ):
#        init_vmx86_linux ( size, addr )
#        self.code_list = list ()
#        self._initial_code = None
#    
#    def add_code ( self, unCode ):
#        self.code_list.insert( unCode )
#    
#    def add_segment ( self, unSegment )
#        self.segments_list.insert ( unSegment )
#
#    def run ( self ):
#        for segment in self.segments_list:
#            self.segment.configure ( )
#        
#        for code in self.code_list:
#            code.register ( self )
#
#        self._initial_code.run ( )
#
#    def end ( self ):
#        end_virtualization ( )
#
#    def __del__ ( self ):
#        self.end ( )
#

_CALLBACK = ctypes.CFUNCTYPE( ctypes.c_int32, *( ctypes.c_int32, ctypes.POINTER( CPUX86State ) ) )


STOP = 0
CONTINUE = 1
END_EGG = '\xcd\x99'
END_EGG_TRAP = 0x99

IARG_ADDRINT = 1
IARG_PTR = 2
IARG_BOOL = 3
IARG_UINT32 = 4
IARG_INT = 5
IARG_LONG = 6
IARG_ULONG = 7

def default_call( trapnr ):
    """this function is called for each instruction by default"""
    return STOP if trapnr == END_EGG_TRAP else CONTINUE

#define the current callback
current_callback = default_call 

instruction_callback = current_callback

addr_callback = dict()
offset_callback = dict()

#egg environ
environ = None

def log_debug(msg):
    print "[log_debug] " + msg

def pyqemu_callback( trapnr , env_ll ):
    """ determine the callback. if the address is defined in addr_callback his callback is called. similar to offset_callback """
    ret = STOP

    try:
        _py_set_current_callback ( instruction_callback )

        if addr_callback:
            _py_set_current_callback ( addr_callback.get( environ.eip, current_callback ) )

        if offset_callback:
            _py_set_current_callback ( offset_callback.get( environ.get_offset(), current_callback ) )

        # ret = current_callback( trapnr, env ) 

        # current_callback ahora solo va a recivir el numero de trap
        ret = current_callback( trapnr )

    except Exception, e:
        log_debug(e)
    finally:
        return ret


def _ll_set_callback( callback ):
    """ low level callback set the callback using c function """
    _call = _CALLBACK( callback )
    _pyqemu.set_callback( _call )

def align_x86 ( len ):
    return ( ( len / 4096 ) + 1 ) * 4096


#def duple_union ( setA, setB ):
#    init, end = setA
#    tmp_init, tmp_end = setB
#    return min ( init, tmp_init ), max ( end, tmp_end )

#def included ( setA, setB ):
#    init, end = setA
#    tmp_init, tmp_end = setB

#    return True if init < tmp_init < end and init < tmp_end < end else False
#
#def is_intersect ( setA, setB ):
#    init, end = setA
#    tmp_init, tmp_end = setB
#    return True if init < tmp_init < end and  tmp_init < end < tmp_end else False

#def get_operation ( duple, tmp_duple ):
#
#    if included ( duple, tmp_duple ):
#        return duple
#    elif included ( tmp_duple, duple):
#        return tmp_duple
#    elif is_intersect ( duple, tmp_duple ):
#        return duple_union ( duple, tmp_duple )
#    elif is_intersect ( duple, tmp_duple ):
#        return duple_union ( tmp_duple, duple )
#
#    return duple 

#def get_address ( duple, tmp_duple ):
#    return min ( duple[0], tmp_duple[0] ), max ( duple[1], tmp_duple[1] )

#def get_end_list ( duple, tmp_list ):
#    res = {}
#    for tmp_duple in tmp_list:
#        print "duple = " + str ( duple )
#        print "tmp_duple = " + str ( tmp_duple )
#        res [ get_operation ( duple, tmp_duple ) ] = 1
#    
#    return res.keys()

def create_duple_list ( dict_addr_len ):
    tmp_list = []
    tmp_begin_end = [ ( addr, addr + dict_addr_len.get ( addr ) ) for addr in dict_addr_len.keys() ]
    map ( lambda x : tmp_list.extend ( zip ( x , ( "c", "f" ) ) ), tmp_begin_end )
    return tmp_list

def to_addr_len ( tmp_list ):
    return dict ( [ ( init, end - init ) for init, end in tmp_list ] )

def final_allocation_list ( list_allocation ):
    counter =0 
    end_list = []
    for addr, type in list_allocation:
        counter += 1 if type == 'c' else -1
        if ( type == 'c' and counter == 1 ) or ( type == 'f' and counter == 0 ):
            end_list.append ( addr )
    
    return zip ( end_list [::2], end_list [1::2] )
    
def calculate_pages ( addr_len ):
    duple_begin_end = create_duple_list ( addr_len )
    duple_begin_end = sorted ( duple_begin_end, cmp = lambda x, y: cmp ( x[0], y[0] ) or cmp ( x[1], y [1] ) )
    page_list = final_allocation_list ( duple_begin_end )
    return to_addr_len ( page_list ) 
    ##return  page_list
        

page_list = {}
def map_memory ( dict_addr_len ):
    global page_list 
    dict_addr_len = dict ( [ ( addr, align_x86 ( dict_addr_len [ addr ] ) ) for addr in dict_addr_len ] )
    page_list = calculate_pages ( dict_addr_len )
    
    #for addr in page_list:
    #    print "addr = %x " % addr
    #    print "page_list[addr] = %x" % page_list[addr]
    

def init_vmx86_linux( mem_size = 0x0, addr = 0x0 ):
    """ init environ, set default callback, define size of memory to machine """
    global _pyqemu
    global page_list 

    global environ
    if _pyqemu == None:
        _pyqemu = ctypes.cdll.LoadLibrary( 'pyqemulib' )
        _ll_set_callback( pyqemu_callback )
        _pyqemu.init_vm.restype = ctypes.POINTER( CPUX86State )
        full_env = _pyqemu.init_vm( addr )
        env = pyCPUX86State( full_env )
        environ = env

    
    environ.eip = addr
    for addr in page_list:
        allocate_memory  ( addr, page_list[ addr ]  )


def allocate_memory( from_addr, mem_size ):
    _pyqemu.allocate_memory( from_addr, mem_size )

def _py_set_current_callback(callback):
    global current_callback
    current_callback = callback

def set_instruction_callback ( callback ):
    global instruction_callback
    instruction_callback = callback
    #_py_set_current_callback(callback)

def copy_egg(egg, to):
    _pyqemu.copy_egg(to, egg, len(egg))

def exec_code(code, addr = 0x0, entry_point = 0x0):
   environ.eip = addr + entry_point
   _pyqemu.exec_shellcode.restype = ctypes.c_int
   _pyqemu.exec_shellcode.argtype =  ctypes.POINTER( CPUX86State ) , ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32
   #print type ( environ._cpuenv )
   #print type ( code )
   #print type ( addr )
   _pyqemu.exec_shellcode(environ._cpuenv, code, addr, len(code))

def set_callback_at_offset( callback , offsetnr ):
    global offset_callback
    offset_callback [ offsetnr ] = callback 

def set_callback_at_address( callback , address ):
    global addr_callback
    addr_callback [ address ] = callback

def revase_code ( code, addr ):
    _pyqemu.revase_code( code, addr, len( code ) + 1 ) 

def allocate_stack ( addr, len ):
    environ.esp = addr
    environ.ebp = addr


def get_virtual_string ( virtual_addr ):
    _pyqemu.get_virtual_string.restype = ctypes.c_char_p
    _pyqemu.get_virtual_string.argtype = ctypes.c_uint32
    return _pyqemu.get_virtual_string ( virtual_addr )


hookers_list = {}

FUNCTION_HOOK_LEN = 3
def _hooker ( *args ):
    """this is the hooker, here you can do convertion types"""

    py_func, ret_type, typle_args = hookers_list [ environ.eip - FUNCTION_HOOK_LEN ] 
    return py_func ( environ, *args ) 


def register_function_hook_handler( virtual_address , python_function , c_convention , ret_type, *args ):
   IARG_END = 0
   arg_types = { 
                 IARG_PTR : ctypes.c_void_p,
                 IARG_BOOL : ctypes.c_int32,
                 IARG_UINT32 : ctypes.c_uint32,
                 IARG_INT : ctypes.c_int,
                 IARG_LONG : ctypes.c_long,
                 IARG_ULONG : ctypes.c_ulong 
               } 
   
   ctypes_args = tuple( [ arg_types[ argument ] for argument in args ] )
   
   #this must be a WINFUNCTYPE to clean the stack 
   func_ptr = ctypes.WINFUNCTYPE( arg_types [ ret_type ], *ctypes_args ) 

   #func_ptr = ctypes.CFUNCTYPE( arg_types [ ret_type ], *ctypes_args )
   #_call = func_ptr ( python_function )
   hookers_list [ virtual_address ] = ( python_function, ret_type, args ) 
   _call = func_ptr ( _hooker )
   _pyqemu.register_function_hook_handler( virtual_address , len( args ) ,  _call, ret_type, *( args ) )
 

def allocate_fs ( addr, fs ):
    environ.fs.base = addr
    environ.fs.limit = len( fs )
    revase_code ( fs, addr )



def end_virtualization( ):
    _pyqemu.end_vm ( environ._cpuenv )
    global page_list 
    page_list = None

    """
    import _ctypes
    global _pyqemu
    global environ
    #TODO
    _pyqemu.end_vm ( environ._cpuenv )
    del environ._cpuenv
    del environ
    environ = None
    handle = _pyqemu._handle
    _pyqemu = None
    #_ctypes.dlclose( handle )
    _ctypes.FreeLibrary( handle )
    import time
    time.sleep(0.001)
    """



if __name__ == '__main__':
    def test_call( trapnr ):
        print "test_call"
        print trapnr
        print "eax = %x" % environ.eax
        print "ebx = %x" % environ.ebx
        print "ecx = %x" % environ.ecx
        print "edx = %x" % environ.edx
        print "esi = %x" % environ.esi
        print "edi = %x" % environ.edi
        print "eip = %x" % environ.eip
        print "esp = %x" % environ.esp

        environ.ebx = 0

        if trapnr == END_EGG_TRAP:
            return STOP

        return CONTINUE

    def test_function_hook (environ, un_int, un_int2, un_ptr ):
        print "en test_function_hook"
        print "un_int = " + str( hex ( un_int ) )
        print "un_int2 = " + str( hex ( un_int2 ) )
        print "un_ptr = " + str( hex ( un_ptr ) )
        return 0


    def test_instruction_call( trapnr ):
        print "test_instruction_call"
        print trapnr
        print "eip = %x" % environ.eip
        
        if environ.eip > 0x40404050:
            exit(0)
    
        if trapnr == END_EGG_TRAP:
            return STOP
 
        return CONTINUE 

    def test_offset_call( trapnr ):
        print "test_offset_call"
        print trapnr
        print "ebx = %x" % environ.ebx
        print "eip = %x" % environ.eip
        if trapnr == END_EGG_TRAP:
            return STOP
        
        return CONTINUE

    map_memory ( {0x0044777F:0x1024, 0x40404040:FUNCTION_HOOK_LEN, 0x40404041: 0x1,  0x00120000:0x200 , 0x40404041:50} )
    #set_instruction_callback( test_instruction_call )
    init_vmx86_linux( 0x0044777F )
    register_function_hook_handler ( 0x40404040, test_function_hook, "stdcall", IARG_INT, *( IARG_ULONG, IARG_ULONG, IARG_PTR  ) )
    allocate_stack ( 0x00120000, 0x200 )
    environ.esp = environ.ebp = 0x00120000 + 0x200

    for i in xrange ( 101 ):
        print "Ejecucion numero = " + str ( i )
        exec_code ( "\x68\x11\x11\x11\x11\x68\xCA\xCA\xCA\xCA\x68\x7F\x77\x44\x00\xE8\xAD\xC8\xFB\x3F" + END_EGG, addr = 0x044777F )

    end_virtualization ()
    
    """
    print "SEGUNDA SECUENCIA"
    
    map_memory ( {0x0044777F:0x1024, 0x40404040:FUNCTION_HOOK_LEN, 0x00120000:0x200} )
    #set_instruction_callback( test_instruction_call )
    init_vmx86_linux( 0x0044777F )
    register_function_hook_handler ( 0x40404040, test_function_hook, "stdcall", IARG_INT, *( IARG_ULONG, IARG_ULONG, IARG_PTR  ) )
    allocate_stack ( 0x00120000, 0x200 )
    environ.esp = environ.ebp = 0x00120000 + 0x200

    for i in xrange ( 101 ):
        print "Ejecucion numero = " + str ( i )
        exec_code ( "\x68\x11\x11\x11\x11\x68\xCA\xCA\xCA\xCA\x68\x7F\x77\x44\x00\xE8\xAD\xC8\xFB\x3F" + END_EGG, addr = 0x044777F )
    
    end_virtualization
    """
    """
    init_vmx86_linux( 0x1024, 0x00400000 )

    environ.eip = 0x0
    environ.eax = 0x0
    environ.ebx = 0x0
    environ.ecx = 0x0
    environ.edx = 0x0
    environ.esi = 0x0
    environ.edi = 0x0

    allocate_stack ( 0x00120000, 200 )
    
    register_function_hook_handler ( 0x40404040, test_function_hook, "stdcall", IARG_INT, *( IARG_ULONG, IARG_ULONG, IARG_PTR ) )
    #set_instruction_callback( test_instruction_call )

    #revase_code ( "\x43\x43\x43\x43\xcd\x99", 0x40404040 )
    #exec_code ( "\x40\x40\x40\x40\xE8\x4F\xC8\xFB\x3F" + END_EGG, addr = 0x004477E8 ) 

    exec_code ( "\x68\x11\x11\x11\x11\x68\xCA\xCA\xCA\xCA\x68\x1F\x00\x40\x00\xE8\x2C\x40\x00\x40" + END_EGG + "\x90" + END_EGG, addr = 0x00400000)
    #set_callback_at_address( test_call, 0x1 )
    #set_callback_at_address( test_call, 0x8 )
    #set_callback_at_address( test_call, 0x9 )
    #set_callback_at_offset( test_offset_call, 0x10 )
    

    #exec_code( ( '\x40' * 0x16 ) + END_EGG, entry_point = 0x10 , addr = 0x447700 )

    #set_callback_at_address( test_call, 0x17 )
    #set_callback_at_address( test_call, 0x18 )

    #exec_code( ( '\x43' * 0x10 ) + END_EGG, addr = 0x16 )

    end_virtualization()
    """

    #exec_code( ( '\x40' * 0x16 ) + END_EGG, entry_point = 0x10 , addr = 0x447700 )

    #set_callback_at_address( test_call, 0x17 )
    #set_callback_at_address( test_call, 0x18 )

    #exec_code( ( '\x43' * 0x10 ) + END_EGG, addr = 0x16 )

#    class RegisterConfiguration: # i386
#        def __init__( self , eax = 0x0 , ebx = 0x0 , ecx = 0x0 , edx = 0x0 ):
#            self.__eax = eax
#            self.__ebx = eax
#            self.__ecx = eax
#            self.__edx = eax

 
#    register_config = RegisterConfiguration(
#                                              eax = 0x1,
#                                              ebx = 0x2,
#                                              eee = 0x3,
#                                            )

#class RegisterConfigBuilder( type ):
#    def __init__( self , *regs ):

#
#i386RegisterConfig = RegisterConfigBuilder("eax","ebx","ecx")
#x64RegisterConfig = RegisterConfigBuilder("rax","rbx","rcx")


#    configure_registers(registers_configuration)
 
#set_callback = pyqemu.set_callback 
#set_callback.restype = None
#set_callback.argtypes = _CALLBACK,

#def pyqemu_instruction_callback(TINYState):
#    return 0

#pyqemu_callback = _CALLBACK(pyqemu_instruction_callback)


#set_breakpoint = pyqemu.set_breakpoint
#set_breakpoint.restype = ctypes.c_char_p
#set_breakpoint.argtypes = ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32

#exec_shellcode = pyqemu.exec_shellcode
#exec_shellcode.restype = ctypes.c_int
#C:\cygwin\home\User\originales\9\pyqemu

#CONTINUE = 1
#NOCONTINUE = 0
#EXCP_DEBUG = 0x10002

