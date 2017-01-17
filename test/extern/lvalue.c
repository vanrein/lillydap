#include <stdlib.h>
#include <stdio.h>

int main (int argc, char *argv []) {

	int xs [3];
	int *xp;
	int i;

	// Is this allowed?

	xp = xs;
	//NO// (xp? *xp++: xs [2]) = 15;
	//NO// (xp? *xp++: xs [1]) = 25;
	//NO// (xp? *xp++: xs [0]) = 35;

	xp = xs;
	//NO// (*xp++ || xs [2]) = 15;
	//NO// (*xp++ || xs [1]) = 25;
	//NO// (*xp++ || xs [0]) = 35;

	xp = xs;
	*(xp? xp++: xs+2) = 15; //YES//
	*(xp? xp++: xs+1) = 25; //YES//
	*(xp? xp++: xs+0) = 35; //YES//
	printf ("%d,%d,%d\n", xs [0], xs [1], xs [2]);

	xp = NULL;
	*(xp? xp++: xs+2) = 15; //YES//
	*(xp? xp++: xs+1) = 25; //YES//
	*(xp? xp++: xs+0) = 35; //YES//
	printf ("%d,%d,%d\n", xs [0], xs [1], xs [2]);

	i=0;
	xp = NULL;
	*(xp? &xp [i++]: xs+2) = 15; //YES//
	*(xp? &xp [i++]: xs+1) = 25; //YES//
	*(xp? &xp [i++]: xs+0) = 35; //YES//
	printf ("%d,%d,%d; i=%d\n", xs [0], xs [1], xs [2], i);

	i=0;
	xp = xs;
	*(xp? &xp [i++]: xs+2) = 15; //YES//
	*(xp? &xp [i++]: xs+1) = 25; //YES//
	*(xp? &xp [i++]: xs+0) = 35; //YES//
	printf ("%d,%d,%d; i=%d\n", xs [0], xs [1], xs [2], i);

	xp = xs;
	//NO// *(xp++ || xs+2) = 15;
	//NO// *(xp++ || xs+1) = 25;
	//NO// *(xp++ || xs+0) = 35;

	return 0;
}
