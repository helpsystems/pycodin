#!/usr/bin/env python
import pyqemu_ll

class TestCase_getpc1(pyqemu_ll.TestCase):
    def handletrap(self, trapnr, environ):
        pass

class TestEGG():


    #def assert_return_equal ( self , anObject , method, value, error_msg , params = () , kparams = {} ):
    #    self.assert_equal(getattr( anObject , method )( *params , **kparams ), value, error_msg)
    
    #def assert_error( self , anObject , method , error , params = () , kparams = {} ):
    #    try:
    #        getattr( anObject , method )( *params , **kparams )
    #    except Exception , e:
    #        if not isinstance( e , error ):
    #            self.error(" exception not expected :%s , exptected was: %s" % (e,error) )
                
    #def assert_predicate( self , value , predicate , error_message ):
    #    if not predicate( value ):
    #        self.error( error_message )
    
    def tests(self):
        getpc1 = TestCase_getpc1("\xEB\x03\x5F\x57\xC3\xE8\xF8\xFF\xFF\xFF")
        getpc1.run()

        #getpc2 = TestCase_getpc2("")
        #getpc2.run()

        #getpc3 = TestCase_getpc3("")
        #getpc3.run()
    
if __name__ == '__main__':
    test = TestEGG()
    test.tests()

