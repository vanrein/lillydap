/*
 * MITM an LDAP connection.
 *
 * This code connects to an LDAP server and then listens to
 * another port; all data received is passed to the (real)
 * LDAP server, and also dumped to output files (one for
 * input data, one for output data).
 *
 * Typical usage:
 *
 * Suppose you have an LDAP server at db.example.com:389, so
 * that this query returns something:
 *     ldapsearch -h db.example.com -p 389 '(objectclass=device)'
 * It's important that you don't use TLS or similar encryption,
 * because this tool currently doesn't break into that; the
 * -Z flag is (in future) supposed to insert starttls into
 * the stream.
 *
 * To man-in-the-middle log a query to that LDAP server, run
 * ldap-mitm with the same -h and -p flags, while giving
 * -H and -P flags for where it should listen; these default
 * to localhost and 3899.
 *     ldap-mitm -h db.example.com -p 389 -H localhost -P 3899
 * Now the entire conversation of a search can be logged to
 * files by running the query against the new listening server:
 *     ldapsearch -h localhost -p 3899 '(objectclass=device)'
 *
 * The MITM server quits after handling a single conversation.
 * Each chunk of data (e.g. LDAPMessage) is dumped to its own
 * file, numbered serially from 0, and named msg.<serial>.<fd>.bin,
 * the fd can be used to distinguish data from client (i.e. ldapsearch)
 * from data from the server (i.e. the real LDAP server). Generally
 * the conversation is started by the client, so msg.000000.<fd>.bin
 * will tell you which one is the client; if you don't have file-
 * descriptor randomisation in the kernel, 5 is usually the client
 * and 3 is the server.
 *
 */

/*
 *  Copyright 2017, Adriaan de Groot <groot@kde.org>
 *
 *  Redistribution and use is allowed according to the terms of the two-clause BSD license.
 *     https://opensource.org/licenses/BSD-2-Clause
 *     SPDX short identifier: BSD-2-Clause
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>  /* INT_MAX */
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* getopt */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Print usage string and exit with an error. */
void usage()
{
	fprintf(stderr, "\nUsage: ldap-mitm [-h dsthost] [-p dstport] [-H lsthost] [-P lstport]\n"
		"\tdsthost and dstport specify the target host and port, like options\n"
		"\t-h and -p for ldapsearch(1).\n\n"
		"\tlsthost and lstport specify the hostname and port to listen on.\n"
		"\tThen use those values as -h and -p for ldapsearch(1) instead.\n\n");
	exit(1);
}

/* Sets the value pointed to by @p port to the integer value obtained
 * from @p arg; returns 0 on success, -1 on failure (and prints an
 * error message).
 */
int set_port(int *port, const char *arg)
{
	errno = 0;
	long l = strtol(arg, NULL, 10);
	if ((l < 1) || (l > INT_MAX) || errno)
	{
		fprintf(stderr, "Could not understand port '%s'.\n", arg);
		return -1;
	}
	if (port)
	{
		*port = (int)l;
	}
	return 0;
}

int connect_server(const char *hostname, int port)
{
	struct hostent *server = gethostbyname(hostname);
	if (!server)
	{
		fprintf(stderr, "Could not look up host '%s'.\n", hostname);
		return -1;
	}

	int sid = socket(PF_INET, SOCK_STREAM, 0);
	if (sid < 0)
	{
		fprintf(stderr, "Could not open socket for '%s:%d'.\n", hostname, port);
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

	if (connect(sid, (struct sockaddr *)(&addr), sizeof(addr)) < 0)
	{
		perror("Unable to connect:");
		close(sid);
		fprintf(stderr, "Could not connect to '%s:%d'.\n", hostname, port);
		return -1;
	}

	return sid;
}

int listen_client(const char *hostname, int port)
{
	struct hostent *server = gethostbyname(hostname);
	if (!server)
	{
		fprintf(stderr, "Could not look up host '%s'.\n", hostname);
		return -1;
	}

	int sid = socket(PF_INET, SOCK_STREAM, 0);
	if (sid < 0)
	{
		fprintf(stderr, "Could not open socket for '%s:%d'.\n", hostname, port);
		return -1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);

	if (bind(sid, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("Unable to bind:");
		close(sid);
		fprintf(stderr, "Could not bind to '%s:%d'.\n", hostname, port);
		return -1;
	}

	/* Intentionally a one-connection-at-a-time server. */
	if (listen(sid, 1) < 0)
	{
		perror("Unable to listen:");
		close(sid);
		fprintf(stderr, "Could not listen to '%s:%d'.\n", hostname, port);
		return -1;
	}

	int client_fd = accept(sid, NULL, NULL);
	if (client_fd < 0)
	{
		perror("Unable to accept:");
		close(sid);
		fprintf(stderr, "Could not accept connection on '%s:%d'.\n", hostname, port);
		return -1;
	}
	close(sid);
	return client_fd;
}

int write_buf(int destfd, const char *buf, int r, int verbose)
{
	int w = 0;
	int w_d = 0;
	while (w < r)
	{
		w_d = write(destfd, buf+w, r-w);
		if (w_d < 0)
		{
			perror("Unable to write:");
			return -1;
		}
		w += w_d;
		if (verbose)
		{
			fprintf(stdout,"  %d (of %d)\n", w, r);
		}
	}

	return 0;
}

int pump(int srcfd, int destfd, int serial)
{
	static char serialfile[64];
	static char buf[20480];
	int r;

	snprintf(serialfile, sizeof(serialfile), "msg.%06d.%d.bin", serial, srcfd);
	int serialfd = open(serialfile, O_CREAT | O_WRONLY, 0644);
	if (serialfd < 0)
	{
		fprintf(stderr, "Could not open data file '%s'.\n", serialfile);
	}

	fprintf(stdout, "Pump %d -> %d.\n", srcfd, destfd);
	if ((r = read(srcfd, buf, sizeof(buf))) > 0)
	{
		/* Writing to the dump-files may fail, not verbose */
		if (serialfd >= 0)
		{
			write_buf(serialfd, buf, r, 0);
			close(serialfd);
		}
		/* Writing to the other side of the MITM-ed connection is verbose */
		if (write_buf(destfd, buf, r, 1) < 0)
		{
			return -1;
		}
	}
	if (r == 0)
	{
		/* Presume this means socket closed. */
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *hflag = NULL; /* -h, hostname of server */
	int pflag = 389; /* -p, port of server */
	char *ownhflag= NULL; /* -H, hostname for self */
	int ownpflag = 3899; /* -P, port for self */

	static const char localhost[] = "localhost";

	int ch;
	while ((ch = getopt(argc, argv, "h:p:H:P:")) != -1)
	{
		switch (ch)
		{
		case 'p':
			if (set_port(&pflag, optarg) < 0)
			{
				usage();
			}
			break;
		case 'P':
			if (set_port(&ownpflag, optarg) < 0)
			{
				usage();
			}
			break;
		case 'h':
			hflag = optarg;
			break;
		case 'H':
			ownhflag = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc)
	{
		usage();
	}

	int server_fd = connect_server((hflag ? hflag : localhost), pflag);
	if (server_fd < 0)
	{
		usage();
	}

	int client_fd = listen_client((ownhflag ? ownhflag : localhost), ownpflag);
	if (client_fd < 0)
	{
		close(server_fd);
		usage();
	}

	int serial = 0;
	while(1)
	{
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);
		FD_SET(client_fd, &readfds);

		if (select(FD_SETSIZE, &readfds, NULL, NULL, NULL) < 0)
		{
			perror("select(2):");
			break;
		}

		if (FD_ISSET(server_fd, &readfds))
		{
			if (pump(server_fd, client_fd, serial) < 0)
			{
				break;
			}
			++serial;
		}

		if (FD_ISSET(client_fd, &readfds))
		{
			if (pump(client_fd, server_fd, serial) < 0)
			{
				break;
			}
			++serial;
		}
	}
	close(client_fd);
	close(server_fd);
	return 0;
}
