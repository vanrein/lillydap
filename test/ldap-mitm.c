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
 * because this tool currently doesn't break into that.
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
 * The MITM happens in one of two ways:
 *  - with raw sockets and no processing of the messages
 *  - with the LillyDAP processing stack
 * Use the -l flag to select the LillyDAP processing stack.
 *
 * With raw sockets, there is no guarantee that the dumped chunks
 * will be single, complete LDAP messages; a single chunk may be
 * more than one message, or only part of one -- it depends
 * on network and socket buffering.
 *
 * With LillyDAP processing, each individual LDAP message is
 * logged to a separate file.
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

#include <lillydap/api.h>

/* Print usage string and exit with an error. */
void usage()
{
	fprintf(stderr, "\nUsage: ldap-mitm [-h dsthost] [-p dstport] [-H lsthost] [-P lstport] [-l]\n"
		"\tdsthost and dstport specify the target host and port, like options\n"
		"\t-h and -p for ldapsearch(1).\n\n"
		"\tlsthost and lstport specify the hostname and port to listen on.\n"
		"\tThen use those values as -h and -p for ldapsearch(1) instead.\n\n"
		"\tThe -l flag selects for LillyDAP-processing instead of raw packets.\n\n");
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

/* Switches the non-blocking flag (O_NONBLOCK) on the given file-
 * descriptor @p fd on (if @p blocking is non-zero) or off (if
 * @p blocking is zero). Returns -1 on error, 0 on success.
 */
int set_nonblocking(int fd, int blocking)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
	{
		perror("Can't get socket flags");
		close(fd);
		return -1;
	}

	int newflags = flags;
	if (blocking)
	{
		newflags |= O_NONBLOCK;
	}
	else
	{
		newflags &= (~O_NONBLOCK);
	}

	if (flags == newflags)
	{
		/* Nothing to do. */
		return 0;
	}

	if (fcntl(fd, F_SETFL, newflags) < 0)
	{
		perror("Can't set socket flags");
		close(fd);
		return -1;
	}
	return 0;
}


/* Connects to the (LDAP) server with @p hostname on @p port (usually 389).
 * If @p nonblocking is non-zero, sets up the file-descriptor used for
 * communicating with the server to be non-blocking. This is required
 * for LillyDAP, not required for raw packet processing.
 *
 * Returns a file descriptor for communicating with the server, or -1 on error.
 */
int connect_server(const char *hostname, int port, int nonblocking)
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

	if (nonblocking)
	{
		if (set_nonblocking(sid, 1) < 0)
		{
			fprintf(stderr, "Could not set connection options to '%s:%d'.\n", hostname, port);
			return -1;
		}
	}

	return sid;
}

/* Sets up a listening socket, and waits until a client connects
 * to it. Listens on the given @p hostname and @p port combination.
 * If @p nonblocking is non-zero, the resulting file-descriptor
 * is set to non-blocking mode. This is required for LillyDAP
 * processing, not required for raw packet processing.
 *
 * Returns a file descriptor for communicating with the connected
 * client, or -1 on error.
 */
int listen_client(const char *hostname, int port, int nonblocking)
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

	if (nonblocking)
	{
		if (set_nonblocking(client_fd, 1) < 0)
		{
			fprintf(stderr, "Could not set connection options to '%s:%d'.\n", hostname, port);
			return -1;
		}
	}

	return client_fd;
}

/* Write a buffer @p buf of length @p r to an open file descriptor @p destfd.
 * If the flag @p verbose is non-zero, print progress information as the
 * writes are done (in case of partial writes, this will lead to multiple
 * output lines as the total of @p r bytes are written).
 *
 * Returns 0 on succes, -1 on error.
 */
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

/***
 *
 * Raw-packet dumping.
 *
 * The raw packet dump just does read() from the client or server socket,
 * and writes the data received to the other side as well as writing it
 * to a "serial" file. For each packet read, a new file is created in the
 * current directory, named "msg.<serial>.<fd>.bin". The <serial> numbers
 * increase with each packet, while <fd> indicates which descriptor was
 * read for the data; usually this is 3 for the server side, 5 for the
 * client.
 *
 * No guarantee is made that the data packets are valid LDAP messages, or
 * even valid DER: if the socket transport chops up messages and returns
 * them in different read() operations, then the message will be spread
 * out over multiple serial-files; similarly, multiple messages may be
 * concatenated into a single serial-file if they are buffered somewhere.
 *
 * Main entry point is dump_raw_packets(), which calls pump() repeatedly
 * to pump a packet from one side to the other. That calls write_buf()
 * to write to the other side, and calls it again to write the serial file.
 */
int pump_raw(int srcfd, int destfd, int serial)
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

void dump_raw_packets(int server_fd, int client_fd)
{
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
			if (pump_raw(server_fd, client_fd, serial) < 0)
			{
				break;
			}
			++serial;
		}

		if (FD_ISSET(client_fd, &readfds))
		{
			if (pump_raw(client_fd, server_fd, serial) < 0)
			{
				break;
			}
			++serial;
		}
	}
}


/***
 * Lilly-packet dumping.
 *
 * Uses the LillyDAP processing stack to do the same as raw-packet dumping,
 * except that the LillyDAP stack takes care to split things up into
 * individual LDAP messages, so that each dumped serial-file contains
 * exactly one message (which could be dumped by hexio, or processed
 * by lilly-dump).
 *
 * Main entry point is dump_lilly_packets(), which sets up the processing
 * stack and then waits for data, calling lilly() repeatedly to move data
 * from one side to the other.
 */

/* Since the LillyDAP structure is passed up and down the processing stack,
 * we can play some memory-allocation tricks with it: we can add private
 * data to the end of the structure by embedding it in a larger (longer)
 * struct, and then casting the LillyDAP pointers to our own structure
 * type (which is OK as long as we know the pointer we allocate at the
 * beginning is large enough).
 *
 * Here, just add a serial number to the structure. Since we're going
 * to increase the serial number on each packet received, but we have
 * two LillyDAP stacks (one client-to-server, one server-to-client),
 * use a pointer to a shared variable.
 */
typedef struct { LillyDAP ldap; int *serial; } LillyDAPX;

int lillydump_dercursor (LillyDAP *lil, LillyPool qpool, dercursor dermsg)
{
	static char serialfile[64];
	static char buf[20480];

	LillyDAPX *ldap = (LillyDAPX *)lil;

	snprintf(serialfile, sizeof(serialfile), "msg.%06d.%d.bin", (*(ldap->serial))++, lil->get_fd);
	int serialfd = open(serialfile, O_CREAT | O_WRONLY, 0644);
	if (serialfd < 0)
	{
		fprintf(stderr, "Could not open data file '%s'.\n", serialfile);
		return -1;
	}
	else
	{
		if (write_buf(serialfd, (char *)dermsg.derptr, dermsg.derlen, 0) < 0)
		{
			close(serialfd);
			return -1;
		}
		close(serialfd);
	}

	return lillyput_dercursor(lil, qpool, dermsg);
}

int pump_lilly(LillyDAPX *ldap)
{
	fprintf(stdout, "Lilly %d -> %d (msg.%d).\n", ldap->ldap.get_fd, ldap->ldap.put_fd, *(ldap->serial));
	int r;
	int zero_reads = 0;

	while ((r = lillyget_event(&ldap->ldap)) > 0)
	{
		fprintf(stdout, "  Got %d\n", r);
	}
	if ((r < 0) && (errno != EAGAIN))
	{
		perror("get_event");
		return r;
	}
	if (0 == r)
	{
		zero_reads = 1;
	}
	while ((r = lillyput_event(&ldap->ldap)) > 0)
	{
		fprintf(stdout,"  Send %d\n", r);
	}
	if ((r < 0) && (errno != EAGAIN))
	{
		perror("put_event");
		return r;
	}
	if ((r <= 0) && zero_reads)
	{
		/* 0 bytes were read (by lillyget_event()) and there was nothing to write. */
		return -1;
	}

	return 0;
}

void dump_lilly_packets(int server_fd, int client_fd)
{
	/* Configure memory allocation functions -- and be silly about it */
	lillymem_newpool_fun = sillymem_newpool;
	lillymem_endpool_fun = sillymem_endpool;
	lillymem_alloc_fun = sillymem_alloc;

	/* LillyDAP creates and destroys pools as needed, but we need one
	 * for the LillyDAP structure and some other allocations.
	 */
	LillyPool *pool = lillymem_newpool();
	if (pool == NULL)
	{
		perror("newpool");
		return;
	}

	/* This is for messages going server -> client */
	LillyDAPX *ldap_server = lillymem_alloc0(pool, sizeof(LillyDAPX));
	ldap_server->ldap.get_fd = server_fd;
	ldap_server->ldap.put_fd = client_fd;
	ldap_server->ldap.lillyget_dercursor = lillydump_dercursor;
	ldap_server->ldap.lillyput_dercursor = lillyput_dercursor;

	LillyDAPX *ldap_client = lillymem_alloc0(pool, sizeof(LillyDAPX));
	ldap_client->ldap.get_fd = client_fd;
	ldap_client->ldap.put_fd = server_fd;
	ldap_client->ldap.lillyget_dercursor = lillydump_dercursor;
	ldap_client->ldap.lillyput_dercursor = lillyput_dercursor;


	int serial = 0;
	ldap_server->serial = &serial;
	ldap_client->serial = &serial;
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
			if (pump_lilly(ldap_server) < 0)
			{
				break;
			}
		}

		if (FD_ISSET(client_fd, &readfds))
		{
			if (pump_lilly(ldap_client) < 0)
			{
				break;
			}
		}
	}
}

int main(int argc, char **argv)
{
	char *hflag = NULL; /* -h, hostname of server */
	int portval = 389; /* -p, port of server */
	char *ownhflag= NULL; /* -H, hostname for self */
	int ownportval = 3899; /* -P, port for self */
	int lillyflag = 0;

	static const char localhost[] = "localhost";

	int ch;
	while ((ch = getopt(argc, argv, "h:p:H:P:l")) != -1)
	{
		switch (ch)
		{
		case 'p':
			if (set_port(&portval, optarg) < 0)
			{
				usage();
			}
			break;
		case 'P':
			if (set_port(&ownportval, optarg) < 0)
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
		case 'l':
			lillyflag = 1;
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

	int server_fd = connect_server((hflag ? hflag : localhost), portval, lillyflag);
	if (server_fd < 0)
	{
		usage();
	}

	int client_fd = listen_client((ownhflag ? ownhflag : localhost), ownportval, lillyflag);
	if (client_fd < 0)
	{
		close(server_fd);
		usage();
	}

	if (lillyflag)
	{
		dump_lilly_packets(server_fd, client_fd);
	}
	else
	{
		dump_raw_packets(server_fd, client_fd);
	}

	close(client_fd);
	close(server_fd);
	return 0;
}
