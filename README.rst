Bro module for Mandiant APT1 Report
===================================

This is a script module for Bro 2.2+ that encapsulates and detects 
activity related to the 
`Mandiant APT1 report <http://intelreport.mandiant.com/>`_.

The module is fully self-contained with the data extracted from the report.
Currently it is representing the domain names and file MD5 sums included 
with the report appendix and the SSL certificate hashes included in a 
follow up `blog post <https://www.mandiant.com/blog/md5-sha1/>`_ that 
Mandiant did about the report.

Installation
------------

::

	cd <prefix>/share/bro/site/
	git clone git://github.com/sethhall/bro-apt1.git apt1
	echo "@load apt1" >> local.bro

Configuration
-------------

There is no configuration necessary.

Output
------

This module will result in log lines in the `intel.log` log file and
`Intel::Notice` notices which will be logged in the `notice.log` log
file.
