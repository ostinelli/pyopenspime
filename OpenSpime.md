# Introduction #

OpenSpime is an open protocol and a reference architecture for an open internet of things.


# Details #

The OpenSpime protocol is a custom XMPP protocol extension.

The Extensible Messaging and Presence Protocol (XMPP) is defined in the XMPP Core (RFC 3920), and XMPP IM (RFC 3921) specifications contributed by the XMPP Standards Foundation to the Internet Standards Process, which is managed by the Internet Engineering Task Force in accordance with RFC 2026. Any protocol defined within OpenSpime has been developed outside the Internet Standards Process and is to be understood as an extension to XMPP rather than as an evolution, development, or modification of XMPP itself.


## Core protocol ##

The OpenSpime protocol is a set of custom XMPP protocol extensions. The OpenSpime Core protocol defines the XMPP protocol extension that can be used to:

  * **encrypt** the data content sent between two entities (end-to-end encryption);
  * **digitally sign** the data content sent between two entities;
  * **claim** the authority to perform operations in the name of another entity.

The OpenSpime Core protocol is the reference container which can be used to further develop extensions.


## Core protocol extensions ##

Based on the OpenSpime Core protocol, three OpenSpime extensions have already been defined. These allow:

  * **data reporting** from an entity to another entity;
  * **claiming**, i.e. the mechanism which authorizes an entity of the OpenSpime network to perform trustful operations in the name of another entity which has allowed it;
  * **SpimeSeek**, i.e. the process which allows to seek for other entities data across the network.