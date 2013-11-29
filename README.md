logfs
=====

In the true \*NIX tradition of "everything is a file" ...a FUSE filesystem that syslogs (or writes to a real file) all writes. Written with the FOSS version of NGINX (no syslog) in mind, but would work for anything that writes to a file. 

You will need my [utilities](https://github.com/ericrobbins/utilities) repo as well. It does most of the string handling for parsing the configuration file.

Configuration is in /etc/logfs.conf:

	// comments can be // or #, but not /* */
	file "blah.log" {
		loglevel daemon.info   ## any valid facility.level pair works here.. like syslog.conf
		remote 10.100.101.101  ## logs to a remote syslog server, port 514, UDP only for now
		file /var/log/blah.log ## local regular file 
		local /dev/log         ## this writes to /dev/log socket
	}

	file "blah2.log" {
		## some options go here
	}


I run it as <code>logfs -o allow_other /mountpoint</code> so that daemons run as non root users can log. I have tested with valgrind, and generated spammy log messages to test, and believe I have caught any leaks. There is MUCH tightening up to be done, there are many places I do not properly check return codes. I thought it best to get something up and working first, and clean up later. I would say this is not production ready at all but it should not be too difficult to make so.

------
Future possibilities:   

wildcard file names    
file -> twitter     
file -> sendgrid    
file -> twilio (text to speech)     
file -> database row insert?    
file -> all the things    
