/*
 * logfs - syslog (or file) logging filesystem. configured from /etc/logfs.conf. Write only, no read.
 *
 * config file gets reread with a SIGHUP.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <fuse.h>
#include <syslog.h>
#include <ctype.h>
#include <stdlib.h>
#include <splitbuf.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>

#include <readfiles.h>
#include <debug.h>

#define CONFIGFILE "/etc/logfs.conf"

struct loglevels {
	char *label;
	int level;
};

static struct loglevels levels[] = {
	{ "emerg", 	LOG_EMERG },
	{ "alert", 	LOG_ALERT },
	{ "crit", 	LOG_CRIT },
	{ "err", 	LOG_ERR },
	{ "warning", 	LOG_WARNING },
	{ "notice", 	LOG_NOTICE },
	{ "info", 	LOG_INFO },
	{ "debug", 	LOG_DEBUG },
	{ NULL, 	0 }
};

static struct loglevels facilities[] = {
	{ "auth", 	LOG_AUTH },
	{ "authpriv",	LOG_AUTHPRIV },
	{ "cron",	LOG_CRON },
	{ "daemon",	LOG_DAEMON },
	{ "ftp",	LOG_FTP },
	{ "kern",	LOG_KERN },
	{ "lpr",	LOG_LPR },
	{ "mail",	LOG_MAIL },
	{ "news",	LOG_NEWS },
	{ "syslog",	LOG_SYSLOG },
	{ "user",	LOG_USER },
	{ "uucp",	LOG_UUCP },
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL,		0 }
};

#define ACT_LOCAL 1
#define ACT_REMOTE 2
#define ACT_FILE 3

struct logaction {
	int type;
	char *target;
	int fd;
	char *outbuf;
	int outbuflen;
};

struct logfile {
	char *name;
	char *label;
	int loglevel;
	struct logaction *actions;
	int numactions;
	char *inbuf;
	int inbuflen;
	pthread_mutex_t alock;
};

static struct logfile *logfiles = NULL;
static int numlogfiles = 0;

static volatile int loading_config = 0;

static int 
getval(char *label, struct loglevels *ll)
{
	int i;

	for (i = 0; ll[i].label; i++)
	{
		if (!strcasecmp(ll[i].label, label))
			return(ll[i].level);
	}

	return(-1);
}

static void
free_all_logfiles(struct logfile **first, int *num)
{
	int i;
	for (i = 0; i < *num; i++)
	{
		struct logfile *this = &((*first)[i]);
		if (this->name)
			free(this->name);
		int j;
		for (j = 0; j < this->numactions; j++)
		{
			struct logaction *that = &(this->actions)[j];
			free(that->target);
			if (that->fd > -1)
				close(that->fd);
			if (that->outbuf)
				free(that->outbuf);
		}
		if (this->actions)
			free(this->actions);
		if (this->label)
			free(this->label);
		pthread_mutex_destroy(&(this->alock));
		if (this->inbuf)
			free(this->inbuf);
	}

	free(*first);
	*first = NULL;
	*num = 0;

	return;
}

static int
lookup_action(char *target, struct logfile *lf)
{
	int i;
	for (i = 0; i < lf->numactions; i++)
	{
		if (!strcmp(lf->actions[i].target, target))
			return(i);
	}

	return(-1);
}

// call with full = true when path from fuse (/filename not filename)
static int
lookup_file(const char *name, int full)
{
	int i = numlogfiles;

	while (i-- > 0)
	{
		if (!strcmp(name + (full ? 1 : 0), logfiles[i].name))
			return(i);
	}

	return -1;
}

static int
open_file(char *name)
{
	int fd = open(name, O_WRONLY|O_CREAT|O_NONBLOCK|O_APPEND, 0644);
	if (fd >= 0)
		return(fd);

	debug(1, "open(): %s", strerror(errno));
	return(-1);
}

static int
get_sock(char *host, int port, int family, int proto)
{
	struct sockaddr *soc = malloc(sizeof(struct sockaddr));

	int fd = socket(family, proto, 0);
	if (family == AF_INET)
	{
		struct hostent *hp = gethostbyname(host);
		struct sockaddr_in *sin = (struct sockaddr_in *)soc;
		if (fd == -1)
		{
			debug(1, "socket(): %s", strerror(errno));
			free(soc);
			return(-1);
		}
		if (!hp)
		{
			debug(1, "gethostbyname(): %s", hstrerror(h_errno));
			free(soc);
			close(fd);
			return(-1);
		}
	
		bzero(sin, sizeof(struct sockaddr));
		sin->sin_family = family;
		sin->sin_port = htons(port);
		memcpy(&(sin->sin_addr), hp->h_addr, hp->h_length);
	}
	else if (family == AF_UNIX)
	{
		struct sockaddr_un *sun = (struct sockaddr_un *)soc;
		sun->sun_family = family;
		strcpy(sun->sun_path, host);
	}
	if (connect(fd, soc, sizeof(struct sockaddr)) == -1)
	{
		close(fd);
		free(soc);
		debug(1, "connect(): %s", strerror(errno));
		return(-1);
	}
	// set non blocking
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	free(soc);

	return(fd);
}

static int
open_fd(int type, char *val)
{
	int fd;

	switch (type) {
		case ACT_LOCAL:
			fd = get_sock(val, 0, AF_UNIX, SOCK_DGRAM);
			break;
		case ACT_REMOTE:
			fd = get_sock(val, 514, AF_INET, SOCK_DGRAM);
			break;
		case ACT_FILE:
			fd = open_file(val);
			break;
		default:
			debug(1, "unknown type %i", type);
			fd = -1;
			break;
	}

	return(fd);
}

static int
add_log_action(struct logfile *log, int type, char *val)
{
	int fd;

	fd = open_fd(type, val);
	if (fd == -1)
		debug(1, "open_fd() failed");

	struct logaction *t, *this;
	t = realloc(log->actions, sizeof (struct logaction) * (log->numactions + 1));
	if (!t)
	{
		close(fd);
		debug(1, "realloc(): %s", strerror(errno));
		return(0);
	}
	log->actions = t;
	this = &(t[log->numactions]);
	this->type = type;
	this->target = malloc(strlen(val) + 1);
	strcpy(this->target, val);
	this->fd = fd;
	this->outbuf = NULL;
	this->outbuflen = 0;
	log->numactions++;
		
	return(1);
}

static void
load_config(int sig)
{
	int inblock = 0;
	struct logfile *newlogfiles = NULL;
	int numnewlogfiles = 0;

	loading_config = 1;

	char *configfile = readwholefile(CONFIGFILE, READFILES_ALL);

	if (!configfile)
	{
		debug(0, "could not read config file");
		goto bailout;
	}

	debug(2, "configfile:\n%s", configfile);

	char **config;
	int numelements = splitbuf(SPLITBUF_GROUP|SPLITBUF_STRIPENCLOSE, configfile, " \t\r\n", "\"", &config);

// file "blah.log" { loglevel daemon.info remote 10.100.101.101 file /var/log/blah.log local /dev/log }
	int i;
	for (i = 0; i < numelements; )
	{
		debug(2, "index %i, token %s, inblock %i, numnewlogfiles %i", i, config[i], inblock, numnewlogfiles);
		if (inblock)
		{
			if (!strcmp(config[i], "loglevel"))
			{
				int fac, lev;
				char *levstr = strchr(config[i + 1], '.');
				if (levstr)
					*levstr++ = '\0';
				else
				{
					debug(0, "level %s is invalid", config[i + 1]);
					goto bailout2;
				}
				fac = getval(config[i + 1], facilities);
				lev = getval(levstr, levels);
				if (!fac || !lev)
				{
					debug(0, "level %s.%s is invalid", config[i + 1], levstr);
					goto bailout2;
				}
				newlogfiles[numnewlogfiles - 1].loglevel = fac | lev;
				i += 2;
			}
			else if (!strcmp(config[i], "label"))
			{
				newlogfiles[numnewlogfiles - 1].label = malloc(strlen(config[i + 1]) + 1);
				strcpy(newlogfiles[numnewlogfiles - 1].label, config[i + 1]);
				i += 2;
			}
			else if (!strcmp(config[i], "remote"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_REMOTE, config[i + 1]))
					goto bailout2;
				i += 2;
			}
			else if (!strcmp(config[i], "local"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_LOCAL, config[i + 1]))
					goto bailout2;
				i += 2;
			}
			else if (!strcmp(config[i], "file"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_FILE, config[i + 1]))
					goto bailout2;
				i += 2;
			}
			else if (!strcmp(config[i], "}"))
				inblock--, i++;
			else
			{
				debug(0, "unknown keyword '%s'in configuration block", config[i]);
				goto bailout2;
			}
		}
		else
		{
			if (!strcmp(config[i], "file"))
			{
debug(2, "adding new file %s", config[i + 1]);
				struct logfile *this;
				struct logfile *t = realloc(newlogfiles, (numnewlogfiles + 1) * sizeof(struct logfile));
				if (!t)
				{
					debug(0, "realloc() failure");
					goto bailout2;
				}
				newlogfiles = t;
				this = &(newlogfiles[numnewlogfiles]);
				this->name = malloc(strlen(config[i + 1]) + 1);
				strcpy(this->name, config[i + 1]);
				this->actions = NULL;
				this->label = NULL;
				this->numactions = 0;
				this->inbuf = NULL;
				this->inbuflen = 0;
				pthread_mutex_init(&(this->alock), NULL);
				i += 2;
				numnewlogfiles++;
			}
			else if (!strcmp(config[i], "{"))
				inblock++, i++;
			else
			{
				debug(0, "unknown keyword '%s'in configuration block", config[i]);
				goto bailout2;
			}
		}
	}

	int j;
	for (j = 0; j < numnewlogfiles; j++)
	{
		int k = lookup_file(newlogfiles[j].name, 0);
		if (k == -1)
			continue;
		newlogfiles[j].inbuf = logfiles[k].inbuf;
		logfiles[k].inbuf = NULL;
		newlogfiles[j].inbuflen = logfiles[k].inbuflen;
		int m;
		for (m = 0; m < newlogfiles[j].numactions; m++)
		{
			int n = lookup_action(newlogfiles[j].actions[m].target, &(logfiles[k]));
			if (n != -1)
			{
				newlogfiles[j].actions[m].outbuf = logfiles[k].actions[n].outbuf;
				logfiles[k].actions[n].outbuf = NULL;
				newlogfiles[j].actions[m].outbuflen = logfiles[k].actions[n].outbuflen;
			}
		}
	}

	free_all_logfiles(&logfiles, &numlogfiles);
	logfiles = newlogfiles;
	numlogfiles = numnewlogfiles;
bailout:
	if (config)
		free(config);
	if (configfile)
		free(configfile);
	loading_config = 0;
	return;

bailout2:
	if (newlogfiles)
		free_all_logfiles(&newlogfiles, &numnewlogfiles);
	free(config);
	free(configfile);
	loading_config = 0;
	return;
}

static void
show_config()
{
	int i, j;
	for (i = 0; i < numlogfiles; i++)
	{
		debug(2, "file %s:\n\tloglevel %i\n", logfiles[i].name, logfiles[i].loglevel);
		for (j = 0; j < logfiles[i].numactions; j++)
			debug(2, "\ttype %i target %s\n", logfiles[i].actions[j].type,
				logfiles[i].actions[j].target);
	}

	return;
}

void
write_all(struct logaction *one)
{
	if (one->fd == -1)
		one->fd = open_fd(one->type, one->target);

	int rval = write(one->fd, one->outbuf, one->outbuflen);
	if (rval == -1)
	{
		debug(1, "write() error: %s", strerror(errno));
		return;
	}

	one->outbuflen -= rval;
	if (one->outbuflen <= 0)
	{
		if (one->outbuflen < 0)
			debug(0, "outbuflen is less than 0!? %i", one->outbuflen);
		free(one->outbuf);
		one->outbuf = NULL;
		one->outbuflen = 0;
	}
	else
	{
		memcpy(one->outbuf, one->outbuf + rval, one->outbuflen);
		//char *x = realloc(one->outbuf, one->outbuflen);
	}
		
	return;
}

void
send_lines(struct logaction *one, int level, char *label)
{
	char last = one->outbuf[one->outbuflen - 1];
	one->outbuf[one->outbuflen - 1] = '\0'; // I'm not null terminating the buffer.. so a little hack

	char *tmp;
	char *buf = one->outbuf;

	while (buf && ((tmp = strchr(buf, '\n')) != NULL || last == '\n'))
	{
		if (tmp)
			*tmp++ = '\0';
		int thislen = strlen(buf);
		/* +7 ==  <NN>: \0 */
		char *logstr = malloc(thislen + strlen(label ? label : "logfs") + 7);
		sprintf(logstr, "<%i>%s: %s", level, label ? label : "logfs", buf);
		int sendlen = strlen(logstr);
		if (one->fd == -1)
			one->fd = open_fd(one->type, one->target);
		int rval = send(one->fd, logstr, sendlen, 0);
		if (rval != sendlen)
		{
			debug(0, "send() had a problem: %s", strerror(errno));
			break;
		}
		free(logstr);
		buf = tmp;
	}

	if (buf)
	{
		int newlen = strlen(buf) + 1;
		one->outbuf[one->outbuflen - 1] = last;
		memcpy(one->outbuf, buf, newlen);
		one->outbuflen = newlen;
	}
	else
	{
		free(one->outbuf);
		one->outbuf = NULL;
		one->outbuflen = 0;
	}
	
	return;
}

static void 
do_writes(struct logaction *list, int num, int level, char *label)
{
	int i;

	//debug(2, "entering do_writes()");

	for (i = 0; i < num; i++)
	{
		if (list[i].outbuflen == 0)
			continue;

		switch (list[i].type) {
			case ACT_REMOTE:
			case ACT_LOCAL:
				send_lines(&(list[i]), level, label);
				break;
			case ACT_FILE:
				write_all(&(list[i]));
				break;
			default:
				break;
		}
	}
	
	return;
}

static void *
flush_writes(void *arg)
{
	//debug(2, "entering flush_writes(), numlogfiles %i", numlogfiles);
	while (1)
	{
		int i;
startover:
		//debug(2, "looping flush_writes(), numlogfiles %i", numlogfiles);
		for (i = 0; i < numlogfiles; i++)
		{
			if (loading_config == 1)
			{
				usleep(10000);
				goto startover; // this will just spin until config load is done
			}
			//debug(2, "passed loading_config check");
			pthread_mutex_lock(&(logfiles[i].alock));
			char *buf = NULL;
			int buflen = 0;
			if (logfiles[i].inbuf)
			{
				buf = logfiles[i].inbuf;
				buflen = logfiles[i].inbuflen;
				logfiles[i].inbuf = NULL;
				logfiles[i].inbuflen = 0;
			}
			pthread_mutex_unlock(&(logfiles[i].alock));

			if (loading_config == 1)
			{
				usleep(10000);
				goto startover; // this will just spin until config load is done
			}

/* this isn't optimal, since I'm keeping a copy of the buffer for each file route.. but 
   if some outputs block/have errors and some don't, there's no easy way to handle it 
   if I only have 1 buffer
*/
			if (buflen && buf)
			{
				int j;
				for (j = 0; j < logfiles[i].numactions; j++)
				{
					struct logaction *la = &(logfiles[i].actions[j]);
					char *z;
					if (la->outbuflen > 0)
						z = realloc(la->outbuf, la->outbuflen + buflen);
					else
						z = malloc(buflen);
	
					if (!z)
					{
						debug(0, "(re/m)alloc() failed in flush thread! %s", strerror(errno));
					}
					else
					{
						memcpy(z + la->outbuflen, buf, buflen);
						la->outbuf = z;
						la->outbuflen += buflen;
					}
				}
				free(buf);
				if (loading_config == 1)
				{
					usleep(10000);
					goto startover; // this will just spin until config load is done
				}
			}

			do_writes(logfiles[i].actions, logfiles[i].numactions, logfiles[i].loglevel, logfiles[i].label);
		}
		usleep(10000);
	}

	return(NULL);
}

static void
handle_write(int fileno, const char *buf, int size)
{	
	struct logfile *p = &(logfiles[fileno]);

	pthread_mutex_lock(&(p->alock));
	debug(2, "handle_write() called on file %s with size %i", p->name, size);
	char *x;
	if (p->inbuflen > 0)
		x = realloc(p->inbuf, p->inbuflen + size);
	else
		x = malloc(size);

	if (!x)
	{
		debug(0, "(re/m)alloc() failed in handle_write! %s", strerror(errno));
		pthread_mutex_unlock(&(p->alock));
		return;
	}
	memcpy(x + p->inbuflen, buf, size);
	p->inbuf = x;
	p->inbuflen += size;
	pthread_mutex_unlock(&(p->alock));
	
	return;
}

static int 
logfs_getattr(const char *path, struct stat *st)
{
	int res = 0;

	memset(st, 0, sizeof(struct stat));

	if (!strcmp(path, "/"))
	{
		st->st_mode = S_IFDIR | 0777;
		st->st_nlink = 2;
		return res;
	}

	/* check list of opened log files, set appropriate stat fields */
	int i = lookup_file(path, 1);
	if (i == -1)
		return -ENOENT;

	st->st_mode = S_IFREG | 0222;
	st->st_nlink = 1;
	return res;
}

static int 
logfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	// we don't allow subdirectories
	if (strcmp(path, "/")) 
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	int i;
	for (i = 0; i < numlogfiles; i++)
		filler(buf, logfiles[i].name, NULL, 0);

	return 0;
}

static int 
logfs_open(const char *path, struct fuse_file_info *fi)
{
	// must open for write.. don't care about other modes (TRUNC, READ, etc)
	// I dont really care about the result of this, as I am perfectly happy 
	// writing to a file that isn't open for this application... so I'm not keeping track.
	if (! (fi->flags & O_WRONLY))
		return -EACCES;

	return 0;
}

static int 
logfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	// we are write only..
	return -EINVAL;
}

static int 
logfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int fileno = lookup_file(path, 1);
	if (fileno == -1)
		return -EINVAL;

	handle_write(fileno, buf, size);
	return size;
}

static int 
logfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) 
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EACCES;
}

static int 
logfs_truncate(const char *path, off_t newsize)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EACCES;
}

static int 
logfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EACCES;
}

static int 
logfs_mknod(const char *path, mode_t mode, dev_t dev)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EACCES;
}

static int 
logfs_flush(const char *path, struct fuse_file_info *fi)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EACCES;
}

static int 
logfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EINVAL;
}

static int 
logfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{ 
	if (lookup_file(path, 1) != -1)
		return 0; 
	return -EINVAL;
}

static struct fuse_operations logfs_oper = {
	.getattr	= logfs_getattr,
	.readdir	= logfs_readdir,
	.open		= logfs_open,
	.read		= logfs_read, 
	.write		= logfs_write,
	.truncate	= logfs_truncate,
	.ftruncate	= logfs_ftruncate,
	.create		= logfs_create,
	.mknod		= logfs_mknod,
	.flush		= logfs_flush,
	.fsync		= logfs_fsync,
	.fsyncdir	= logfs_fsyncdir,
};

static pthread_t flushthread;
static pthread_mutex_t flushlock;

int main(int argc, char *argv[])
{
	debuglevel = 2;
	load_config(0);
	pthread_mutex_init(&flushlock, NULL);
	int rval = pthread_create(&flushthread, NULL, flush_writes, NULL);
	if (rval == -1)
		debug(0, "pthread_create() failed: %s", strerror(errno));
	//pthread_detach(flushthread);
	signal(SIGUSR1, load_config);
	show_config();
	debug(0, "my pid: %i", getpid());
	//sleep(600);
	//exit(0);

	return fuse_main(argc, argv, &logfs_oper, NULL);
}

