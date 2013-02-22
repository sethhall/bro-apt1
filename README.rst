Bro module for Mandiant APT1 Report
===================================

This is a script module for Bro 2.1+ that encapsulates and detects 
activity related to the Mandiant APT1 report which can be found here:

  http://intelreport.mandiant.com/

The module is fully self-contained with the data extracted from the report.
Currently it is representing the FQDN, file MD5, and SSL certificate 
information included with the report appendix.

This is a fairly naive implementation which in the future will use 
the upcoming intelligence framework to get a number of performance
and operational improvements.

Installation
------------

::

	cd <prefix>/share/bro/site/
	git clone git://github.com/sethhall/bro-apt1.git apt1
	echo "@load apt1" >> local.bro

Configuration
-------------

There is no configuration necessary unless you want to expand the default 
file hashing.

File Hashing
~~~~~~~~~~~~
By default Bro is configured to only MD5 hash windows executables transferred
over HTTP.  CPU performance impacts appear to be on the order of ~10% for hashing
all HTTP reply bodies over HTTP.  To configure your Bro installation to hash
all HTTP reply bodies, add the following to your local.bro::

  redef HTTP::generate_md5=/.*/;

Output
------

This module generates three notices::

		APT1::Domain_Hit
		APT1::Certificate_Hit
		APT1::File_MD5_Hit
