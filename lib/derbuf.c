/* DER-based in/out of buffers.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

#include <quick-der/api.h>
#include <lillydap/api.h>


/* Signal that information is available for reading to lillyget_xxx()
 * processing.  This first loads a header, determines the total length to
 * read and allocates a buffer for it; then, it incrementally loads the
 * buffer and delivers it to downwards processing routines.
 *
 * The return value of this function is like that of read() -- under
 * blocking I/O, expect 0 for EOF and -1 on error (with errno set) -- and
 * for non-blocking I/O, additionally expect -1 for errno==EGAIN in the
 * case where non-blocking properties reared its tail.
 *
 * This function can be a run_forever() style function for blocking I/O,
 * or a probe-as-much-as-possible for non-blocking I/O.
 */
ssize_t lillyget_event (LDAP *lil) {
	//
	// Stage 1.  Have a qpool for allocations.
loop_more_data:
	if (lil->get_qpool == NULL) {
		if ((lil->get_qpool = lillymem_newpool ()) == NULL) {
			errno = ENOMEM;
			goto bail_out;
		}
		lil->get_gotten = 0;
	}
	//
	// Stage 2.  Collect 6 bytes to read header info.
	//           Note: It is possible to overlay get_head6 with get_msg.
	if (lil->get_gotten < 6) {
		int8_t gotten = read (lil->get_fd, lil->get_head6 + lil->get_gotten, 6 - lil->get_gotten);
		if (gotten <= 0) {
			//TODO// Closed on 0, error on -1, unregister FD
			return gotten;
		} else {
			if ((lil->get_gotten += gotten) < 6) {
				return gotten;
			}
			uint8_t tag = lil->get_head6 [0];
			size_t len = lil->get_head6 [1];
			uint8_t hlen = 2;
			if (len > 0x84) {
				errno = ERANGE;
				goto bail_out;
			}
			if (len >= 0x80) {
				uint8_t lenlen = len;
				hlen += lenlen;
				len = 0;
				uint8_t *ptr = lil->get_head6 + 2;
				while (lenlen-- > 0x80) {
					len <<= 8;
					len += *ptr++;
				}
			}
			if ((tag != 0x30) || (hlen + len < 6)) {
				errno = EINVAL;
				goto bail_out;
			}
			uint8_t *qbuf = lillymem_alloc (lil->get_qpool,
							hlen + len);
			if (qbuf == NULL) {
				errno = ENOMEM;
				goto bail_out;
			}
			memcpy (qbuf, lil->get_head6, 6);
			lil->get_msg.derptr = qbuf;
			lil->get_msg.derlen = hlen + len;
		}
	}
	//
	// Stage 3.  Read lil->get_msg.derlen bytes into lil->get_msg.derptr
	if (lil->get_gotten < lil->get_msg.derlen) {
		ssize_t gotten = read (lil->get_fd,
				lil->get_msg.derptr + lil->get_gotten,
				lil->get_msg.derlen - lil->get_gotten);
		if (gotten <= 0) {
			// 0 for closing, or -1 for error
			return gotten;
		} else {
			if ((lil->get_gotten += gotten) < lil->get_msg.derlen) {
				return gotten;
			}
		}
	}
	//
	// Stage 4.  Send the data gotten to lillyget_xxx() processing routines
	if (lil->lillyget_dercursor == NULL) {
		errno = ENOSYS;
		goto bail_out;
	}
	int rv = lil->lillyget_dercursor (lil, lil->get_qpool, lil->get_msg);
	lil->get_qpool = NULL;
	if (rv == -1) {
		goto bail_out;
	}
	//
	// Stage 5.  Cycle back for more
	goto loop_more_data;

bail_out:
	if (lil->get_qpool != NULL) {
		lillymem_endpool (lil->get_qpool);
		lil->get_qpool = NULL;
	}
	return -1;
}

