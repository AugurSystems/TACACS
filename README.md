# Introduction
The TACACS+ protocol is used by network departments for access control.  In general it provides *authentication* (validate a "user" ID), *authorization* (return permissions/roles for the authenticated "user"), and *accounting* (log stuff related to the "user" activity).  Collectively, this is abbreviated as AAA.  For more information, try the Wikipedia page: https://en.wikipedia.org/wiki/TACACS

## Why
This Java API was developed to integrate our customers' existing TACACS+ servers as the AAA service for our product, [TrapStation](http://www.augur.com/)<sup>TM</sup> &mdash; a fancy SNMP trap forwarder.  Existing open-source Java implementations of TACACS+ clients at the time (2016) were not complete enough for our purposes.  (Although we thank them for their open source, which helped us more-quickly understand the formal specifications.)

## Understanding TACACS+
You will need a good understanding of TACACS+.  The IETF documentation is the best source, although necessarily technical.  At this time (2016), the "The TACACS+ Protocol" draft document is being actively updated, after sitting idle for nearly two decades.  Eventually, it may become an official RFC, published at: <http://ietf.org/>  Until then, the latest draft of the documentation is at: <https://datatracker.ietf.org/doc/draft-ietf-opsawg-tacacs/>



# Getting Started
A TACACS+ **client** will contact a server to authenticate a user, and possibly retrieve attributes that can be used to determine that user's authorizations within your application.  And your application might want to record some logs of user activity.  If this sounds like what you want, look at the `ExampleClient` class. Everything needed to integrate a Java-based application to use TACACS+ for AAA purposes should be in this API for you.

A TACACS+ **server** must handle requests from users, which may be software applications, or more likely, networking equipment (routers, etc.).  A server must respond to requests based on its configuration (a database, files, whatever).  A good server may have a GUI to aid configuration, manage logs, etc.  If this sounds like you, then look at the `TacacsServer` class, which creates a socket server to handle incoming requests.  It decodes the packets into the appropriate Java objects, and then the `SessionServer` class blindly returns failure responses to the client.  It's up to you to replace those dummy responses with code that determines real responses based on a configuration system and policies that you also design.  This "skeleton" code worked fine for testing the client features of this API, but you'll have to do a lot of work in order to develop a real TACACS+ server.  However, this API will give you a head start -- a good step beyond fiddling with the bits and bytes of the protocol.

## Code Overview
There is a separate Java class for each type of packet sent or received.  All packet types for developing a client or server are fully implemented.

The IETF document specifies many flags and values with formal upper-case names, organized hierarchically (mostly).  In this API, they are all encapsulated in the `TACACS_PLUS` Java class, which contains a bunch of nested enumerations.  It looks ugly!  However, in use, it makes your code very readable since the names nicely mirror the documentation, and your IDE's code-completion tool will like the scoped enumerations since they will help you logically reference these constants.  For example, to use the flag documented as *TAC_PLUS_AUTHEN_LOGIN*, the Java code would reference the enumeration `TAC_PLUS.AUTHEN.LOGIN`

As noted above, you should start exploring the code from either `ExampleClient`, or `TacacsServer` and `SessionServer`.

## Compliance
This implementation was developed based on the IETF draft document version "draft-ietf-opsawg-tacacs-00" dated December 15, 2015.  Updates in 2016 are mostly for clarification, but also include support for TLS encryption.  TLS has not been addressed in this code, except for adding a related flag in the enumeration of constants.



# TACACS+ Wishes
For the most part, TACACS+ is a clean single query/reply exchange between a client and server.  A notable exception is the ASCII authentication sub-type, in which the server can reply with a question.  (Note that *ASCII* here is just the name of the authentication type; it doesn't have a strong relation to the ASCII character encoding, other than there's some text that passes back and forth.)  Most importantly, the ASCII authentication type is interactive... The client code has to reply with an answer, obtained either from some client configuration or from actual user interaction.  In typical scenarios, the client tries to login with just an ID, then the server asks for a password.  For this simple ID/password example, your client could choose to use the PAP authentication type instead of ASCII, since PAP provides for an ID and password in one packet, and the server replies with a simple pass/fail response.  However, ASCII also exists for more advanced purposes, such as two-factor authentication.  For example, the server might transmit a unique code number to the user's phone, while prompting the user to enter the code into the client app, which would then send it back to the TACACS+ server, thus completing a secondary proof of identity.  

For cases like two-factor authentication, ASCII is the only option in TACACS+.  Yet ASCII's interactive nature is an oddball.  It works so much differently than the other authentication types.  That makes the code more complex.  We wish interactive authentication was defined as a completely separate part of the protocol, with its own family of packet types.  Maybe even a new packet type for each and every unique authentication protocol that comes along over time.  It would have made this and future API implementations significantly less complex, easier to maintain, and therefore less susceptible to bugs.  

Furthermore, in the interactive ASCII authentication process, the **server** provides the exact text to be presented for any user prompt.  It just seems weird that your client's user-facing interactions would be controlled by a foreign server, but that's how it works.  Ideally, each server-initiated request would have it's own code number, so the client could present suitable prompts based on locale, user's language, client design style, etc.

We've made these arguments to the authors of the new draft specification.  They were sympathetic, although their hands are tied for historical/compatibility reasons.  Maybe these shortcomings can be addressed if/when a version 2.0 of the TACACS+ protocol is designed.



# Support or Contact
You can [contact Augur Systems](http://www.augur.com/) for help, or commercial support.

