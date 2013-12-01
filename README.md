logfs
=====

In the true \*NIX tradition of "everything is a file" ...a FUSE filesystem that syslogs (or writes to a real file) all writes to configured file names. Written with the FOSS version of NGINX (no syslog) in mind, but would work for anything that writes logs out to a file. 


You will need: gcc, FUSE, and my [utilities](https://github.com/ericrobbins/utilities) repo. It does most of the string handling for parsing the configuration file.

Configuration is in /etc/logfs.conf:

	// comments can be // or #, but not /* */
	file "blah.log" {
		loglevel daemon.info   ## any valid facility.level pair works here.. like syslog.conf
		label nginx            ## label for syslog message.. ie Nov 28 23:10:39 myserver nginx: test123
		remote 10.100.101.101  ## logs to a remote syslog server, port 514, UDP only for now
		file /var/log/blah.log ## local regular file 
		local /dev/log         ## this writes to /dev/log socket
	}

	file "blah2.log" {
		## options go here, like previous file
	}

which will send any writes to "blah.log" to /dev/log, /var/log/blah.log, and to the remote syslog server 10.100.101.101. You can configure as many files as you need, but no subdirectories are allowed. The keywords used in the sample above (loglevel, label, remote, file, local) are the only currently valid options. The files are write only, and do not track any metadata such as bytes written, though this could change in the future.   

I run it as <code>logfs -o allow_other /mountpoint</code> so that daemons run as non root users can log. Then just configure nginx to log to /mountpoint/filefromlogfsconf.log and kill -HUP nginx. I have tested with valgrind, and generated spammy log messages to test, and believe I have caught any leaks. There is MUCH tightening up to be done, there are many places I do not properly check return codes. I thought it best to get something up and working first, and clean up later. I would say this is not production ready at all but it should not be too difficult to make so.

------
TODO: 
* Reconnect/reopen bad fds
* Tighten up checking of return codes, expecially malloc()
* Option to buffer disk writes
* Option to restrict max queue size

------
Future possibilities:   

wildcard file names    
file -> twitter     
file -> sendgrid    
file -> twilio (text to speech)     
file -> database row insert?    
file -> all the things    
