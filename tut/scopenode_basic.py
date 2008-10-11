
"""ScopeNode, basic code"""


###### Imports
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.client import Client


class TheScopeNode(Client):
    """
    PyOpenSpime 0.2 Basic ScopeNode
    """

    def on_request_received(self, reqobj):
        """
        Called when an OpenSpime extension request has been received.
        """
        
        if reqobj.extname == 'core.datareporting':
            # prepare response, will be automatically handled by client
            self.send_response(reqobj.accepted())
            
            # example of an error response:
            # self.send_response( reqobj.error(error_type='modify', error_cond='inconsistent-data-with-scope', error_namespace='openspime:protocol:extension:data:error', \
            #                error_description='Data is not consistent with scope of this ScopeNode.') )
            
            # print on screen
            print "======== \/ RECEIVED DATA ========"
            for entry_n in reqobj.entries:
                print entry_n
            print "======== /\ RECEIVED DATA ========"
            # extension has been treated, return True
            return True


if __name__ == "__main__":
    ###### Logging
    import logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("MyScopeNode")
    
    ###### OpenSpime
    c = TheScopeNode('dev-scopenode-2@developer.openspime.com/scope', log_callback_function = log.log)
    c.run();

