
"""Spime, basic code"""


###### Imports
import sys, os
os.chdir(os.path.abspath(os.path.dirname(sys.argv[0])))
sys.path.append('../lib') # use the local library
from pyopenspime.client import Client
import pyopenspime.protocol.extension.core.datareporting

class TheSpime(Client):
    """
    PyOpenSpime 0.2 Basic Spime
    """
    
    def on_connect(self):
        """
        When connected, sends a data reporting message to a scopenode.
        """
        self.send_data()

    def send_data(self):
        """
        Send a data reporting message using the OpenSpime data reporting core extension.
        """
        # create data reporting message which requests for confirmation (i.e. of type 'iq')
        dr_reqobj = pyopenspime.protocol.extension.core.datareporting.ReqObj('iq')

        # add xml data node
        dr_reqobj.add_entry(u"""<entry>
                <date>2008-10-09T10:02:22+01:00</date>
                <exposure>outdoor</exposure>
                <lat>45.475841199050905</lat>
                <lon>9.172725677490234</lon>
                <ele unit='m'>120.0</ele>
                <ppm>176.4</ppm>
            </entry>""")

        # send request
        req_id = self.send_request(dr_reqobj, 'dev-scopenode-2@developer.openspime.com/scope', encrypt = True, sign = True)

    def on_response_success(self, stanza_id, stanza):
        print "iq with id '%s' was successfully received by recipient." % stanza_id
        
    def on_response_failure(self, stanza_id, error_cond, error_description, stanza):
        print "error in sending iq with id '%s' [%s]: %s" % (stanza_id, error_cond, error_description)

    def on_response_timeout(self, stanza_id):
        print "timeout waiting for response to sent iq with id '%s'." % stanza_id
            
    

if __name__ == "__main__":
    ###### Logging
    import logging
    logging.basicConfig(level = 10, format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger("MySpime")
    
    ###### OpenSpime
    c = TheSpime('dev-spime-2@developer.openspime.com/spime', log_callback_function = log.log)
    c.run();

