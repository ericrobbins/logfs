logfs
=====

In the true \*NIX tradition of "everything is a file" ...a FUSE filesystem that syslogs all writes. Written with the FOSS version of NGINX (no syslog) in mind, but would work for anything that writes to a file.

Configuration:
/etc/logfs.conf
file "blah.log" {
	facility LOG_DAEMON
	level LOG_INFO
	remote 10.100.101.101
	file /var/log/blah.log
	local /dev/log # this writes to /dev/log
}

file "blah2.log" {
	...
}


Future possibilities:

wildcard file names 
file -> twitter 
file -> sendgrid 
file -> twilio (text to speech) 
file -> database row insert? 
file -> all the things 
