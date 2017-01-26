/* CMatch.c -- Match a test run with given parameters, and deliver to CTest
 *
 * The CTest framework is fairly simple, in that it only evaluates the
 * exit value of a program.  It cannot match stdout production, for instance.
 *
 * This program adds such capabilities, by running the test program and
 * ensuring its output matches a file, as well as having a desired exit code.
 * There are many ways in which this program can be expanded, and indeed has
 * option processing been used to accommodate that.  When called without any
 * options, the exit value of the child program is imply copied.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <getopt.h>


/* Commandline arguments; terminate with -- to separate the program under test.
 */
const static char *options_short = "x:o:";
struct option options_long [] = {
	{ "exitcode", required_argument, NULL, 'x' },
	{ "output-match", required_argument, NULL, 'o' },
	{ NULL, 0, NULL, 0 }
};



/* Variables with the options' values */
char *optarg_exitcode;
char *optarg_output_match;


int main (int argc, char **argv) {
	//
	// Parse the commandline
	int ch;
	int lidx;
	while ((ch = getopt_long (argc, argv,
				options_short, options_long, &lidx)) != -1) {
		char **optvar = NULL;
		switch (ch) {
		case 'x':
			optvar = &optarg_exitcode;
			break;
		case 'o':
			optvar = &optarg_output_match;
			break;
		default:
			exit (1);
		}
		if (optvar) {
			if (*optvar != NULL) {
				fprintf (stderr, "%s: You gave option -%c and/or --%s more than once.\n", argv [0], ch, options_long [lidx].name);
				exit (1);
			}
			*optvar = strdup (optarg);
		}
	}
	int    argc_sub = argc - optind;
	char **argv_sub = argv + optind;
	//
	// Setup any options as desired
	TODO;
	if (optarg_output_match != NULL) {
		realout = dup (1);
		close (1);
		TODO;
	}
	//
	// Call the program (sub_argc,sub_argv)
	TODO;
	//
	// Harvest output
	TODO;


	exit (0);
}

