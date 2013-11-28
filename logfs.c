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

#include <readfiles.h>
#include <debug.h>

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
	{ "autpriv",	LOG_AUTHPRIV },
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
	int fd; // if needed
};

struct logfile {
	char *name;
	int loglevel;
	struct logaction *actions;
	int numactions;
};

static struct logfile *logfiles = NULL;
static int numlogfiles = 0;

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
		free(this->name);
		int j;
		for (j = 0; j < this->numactions; j++)
		{
			struct logaction *that = &(this->actions)[j];
			free(that->target);
			if (that->fd > -1)
				close(that->fd);
		}
		free(this->actions);
	}

	free(*first);
	*first = NULL;
	*num = 0;

	return;
}

int
open_file(char *name)
{
	int fd = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd >= 0)
		return(fd);

	debug(1, "open(): %s", strerror(errno));
	return(-1);
}

int
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
			return(-1);
		}
		if (!hp)
		{
			debug(1, "gethostbyname(): %s", hstrerror(h_errno));
			close(fd);
			return(-1);
		}
	
		bzero(sin, sizeof(struct sockaddr));
		sin->sin_port = htons(port);
		memcpy(&(sin->sin_addr), hp->h_addr, hp->h_length);
	}
	else if (family == AF_UNIX)
	{
		struct sockaddr_un *sun = (struct sockaddr_un *)soc;
		sun->sun_family = AF_UNIX;
		strcpy(sun->sun_path, host);
	}
	if (connect(fd, soc, sizeof(struct sockaddr)) == -1)
	{
		close(fd);
		debug(1, "connect(): %s", strerror(errno));
		return(-1);
	}

	return(fd);
}

int
add_log_action(struct logfile *log, int type, char *val)
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
	
	if (fd == -1)
	{
		debug(1, "get_sock()/open_file() failed");
		return(0);
	}

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
	log->numactions++;
		
	return(1);
}
//local
//file

#define CONFIGFILE "/etc/logfs.conf"

static void
load_config(int sig)
{
	int inblock = 0;
	struct logfile *newlogfiles = NULL;
	int numnewlogfiles = 0;


	char *configfile = readwholefile(CONFIGFILE, READFILES_ALL);

	if (!configfile)
	{
		debug(0, "could not read config file");
		goto bailout;
	}

	char **config;
	int numelements = splitbuf(SPLITBUF_GROUP|SPLITBUF_STRIPENCLOSE, configfile, " \t\r\n", "\"", &config);

// file "blah.log" { loglevel daemon.info remote 10.100.101.101 file /var/log/blah.log local /dev/log }
	int i;
	for (i = 0; i < numelements; )
	{
		debug(2, "%i: %s", i, config[i]);
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
			}
			else if (!strcmp(config[i], "remote"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_REMOTE, config[i + 1]))
					goto bailout2;
			}
			else if (!strcmp(config[i], "local"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_LOCAL, config[i + 1]))
					goto bailout2;
			}
			else if (!strcmp(config[i], "file"))
			{
				if (!add_log_action(&(newlogfiles[numnewlogfiles - 1]), ACT_FILE, config[i + 1]))
					goto bailout2;
			}
			else
			{
				debug(0, "unknown keyword in configuration block");
				goto bailout2;
			}
			i += 2;
		}
		else
		{
			if (!strcmp(config[i], "file"))
			{
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
				this->numactions = 0;
				i += 2;
				numnewlogfiles++;
			}
			else if (!strcmp(config[i], "{"))
				inblock++, i++;
			else if (!strcmp(config[i], "}"))
				inblock--, i++;
			else
			{
				debug(0, "error in configuration file");
				goto bailout2;
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
	return;

bailout2:
	if (newlogfiles)
		free_all_logfiles(&newlogfiles, &numnewlogfiles);
	free(config);
	free(configfile);
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
	int i;
	for (i = 0; i < numlogfiles; i++)
	{
		if (!strcmp(path, logfiles[i].name))
		{
			st->st_mode = S_IFREG | 0222;
			st->st_nlink = 1;
			return res;
		}
	}

	// not /, and not a file we have open 
	return -ENOENT;
}

static int logfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	// we don't allow subdirectories
	if (strcmp(path, "/")) 
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, "hello", NULL, 0);

	return 0;
}

static int 
logfs_open(const char *path, struct fuse_file_info *fi)
{
	// must open for write.. don't care about other modes (TRUNC, READ, etc)
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
logfs_write(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	// we are write only..
	return -EINVAL;
}

static struct fuse_operations logfs_oper = {
	.getattr	= logfs_getattr,
	.readdir	= logfs_readdir,
	.open		= logfs_open,
	.read		= logfs_read,
	.write		= logfs_write,
};

int main(int argc, char *argv[])
{
	load_config(0);
	signal(SIGHUP, load_config);
	show_config();
	exit(0);

	return fuse_main(argc, argv, &logfs_oper, NULL);
}

