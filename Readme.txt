======================================================================
PyOpenSpime v0.2
2008-12-18
======================================================================

PyOpenSpime is an OpenSpime <http://openspime.org> network library
written in Python.

Currently supported:
. Networking with the SpimeGate server.
. Nearly complete OpenSpime Core protocol (missing claim).
. Data Reporting OpenSpime Core protocol extension.



COMPONENTS
======================================================================
The PyOpenSpime package contains a python library to connect easily
to a OpenSpime SpimeGate infrastructure.

Each entity (spime, scopenode, service) is identified by its osid
(OpenSpime ID) which is a special JID (JabberID) on a SpimeGate server.
The configuration of a single entity can be written inside python code,
but it is suggested to use a bundle called OpenSpime Package (ospkg)
which is a special folder containing all the entity-related data.


OPENSPIME PACKAGE (OSPKG)
----------------------------------------------------------------------
The directory structure of an OpenSpime Package is the following:

osid@developers.openspime.com/
    client1/
        conf.xml
        keys/
            public.pem
            private.pem
    client2/
    ...
    clientN/

The root folder MUST have the same name of the bare jid of the osid,
while the first subdirectory identifies the resource of a specific
client. That maps exactly to a full jid:

    osid@developers.openspime.com/client1

The keys/ subfolder is optional, but required for any cryptographic
operation since it contains the public and the private keys.

For a full documentation please consult http://openspime.org.



INSTALLATION
======================================================================
1. Install core dependencies
2. Install PyOpenSpime
3. Read and Run the tutorials


1. INSTALL CORE DEPENDENCIES
----------------------------------------------------------------------
Install the dependencies not included in this package:

. Python 2.5 <http://www.python.org/download/>
  -> direct download link for win32 users: 
  <http://www.python.org/ftp/python/2.5.2/python-2.5.2.msi>  

. M2Crypto <http://chandlerproject.org/bin/view/Projects/MeTooCrypto>
  -> direct download link for Windows (win32) users:
     <http://chandlerproject.org/pub/Projects/MeTooCrypto/M2Crypto-0.18.2.win32-py2.5.exe>
  -> direct download link for Mac OSX (Leopard 10.5, i386) users:
     <http://chandlerproject.org/pub/Projects/MeTooCrypto/M2Crypto-0.18.2-py2.5-macosx-10.5-i386.egg>
     NOTE: you can rename .egg to .zip and just take the M2Crypto subfolder.


2. INSTALL PYOPENSPIME
----------------------------------------------------------------------
Unzip the PyOpenSpime package in a directory.

Inside you'll find the folders:
. doc/ containing all the documentation
. lib/ containing PyOpenSpime package and the required dependencies (missing M2Crypto)
. tut/ containing some example files with inline explanation comments


3. READ AND RUN THE TUTORIALS
----------------------------------------------------------------------
The sub directory tut/ contains some commented python scripts to
explain through examples how the OpenSpime network and the
PyOpenSpime library work.



ADDITIONAL DEPENDENCIES
======================================================================
Included in this package are also these additional dependencies:
. dnspython <http://www.dnspython.org>
. PyXML <http://pyxml.sourceforge.net> (just c14n.py)
. xmpppy <http://xmpppy.sourceforge.net> (patched)

NOTE: the xmpppy version included in the package has been patched
      and should be used instead of the release version.



======================================================================
Copyright (C) 2008         Roberto Ostinelli, Davide 'Folletto' Casali