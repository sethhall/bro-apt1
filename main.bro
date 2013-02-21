
@load base/frameworks/notice

module APT1;

export {
	redef enum Notice::Type += {
		## A lookup for a domain name listed in the 
		## `Appendix D (Digital) - FQDNs.txt` file was seen.
		APT1::Domain_Hit,
		## A certificate matching the serial number and subject
		## from the `Appendix F (Digital) - SSLCertificates.pdf`
		## file was seen.
		APT1::Certificate_Hit,
		## A file MD5 transferred over HTTP with an MD5 hash
		## in the `Appendix E (Digital) - MD5s.txt` file was seen.
		APT1::File_MD5_Hit,
	};
}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	if ( [cert$serial, cert$subject] in APT1::x509_serials_and_subjects )
		{
		NOTICE([$note=APT1::Certificate_Hit,
		        $conn=c,
		        $msg=fmt("A possible certificate from the APT1 report seen: %s", cert$subject),
		        $identifier=cat(cert$serial, cert$subject)]);
		}
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( query in APT1::domains )
		{
		NOTICE([$note=APT1::Domain_Hit,
		        $conn=c,
		        $msg=fmt("A domain from the APT1 report seen: %s", query),
		        $identifier=cat(query)]);
		}
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &priority=-5
	{
	if ( c?$http && c$http?$md5 && c$http$md5 in APT1::file_md5s )
		{
		NOTICE([$note=APT1::File_MD5_Hit,
		        $conn=c,
		        $msg=fmt("A file MD5 from the APT1 report seen: %s", c$http$md5),
		        $identifier=cat(c$http$md5)]);
		}
	}