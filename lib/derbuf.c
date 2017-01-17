/* DER-based in/out of buffers.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <limits.h>

#include <quick-der/api.h>
#include <lillydap/api.h>



#ifdef TODO_PREFER_OLD_FUNCTION_API
/* This function helps a network component determine if it has collected
 * the bytes of a complete DER value.  This can be used to invoke parsers
 * that assume that a full value has been loaded.  Examples are LDAP and
 * GSSAPI.
 *
 * The functions does not copy the buffers, but assumes that the network
 * layer will grow the buffer until it is complete; to help, this function
 * informs the network layer how much more should be loaded before the buffer
 * is full.  (Or the will return maxint if they don't know.)  Upon error,
 * -1 is returned and errno set.  A complete buffer returns the DER value
 * size which is then less than or equal to the size provided.  In the case
 * where not enough has been provided to parse the length, the value in
 * retsz_toolittle is returned; you should set that to a value higher
 * than buflen, even if just buflen+1 -- so you know you need to keep
 * chasing for input.  You might choose to set it to a value < 0 when
 * you find it reasonable to expect that a complete header should be
 * there, but keep in mind that errno will not be set when this value
 * is returned.
 *
 * As soon as the function returns rv where (rv > 0) && (rv <= buflen),
 * one DER value can be processed at <buf,rv> and a remainder may be
 * left at <buf+rv,buflen-rv>.
 */
size_t derbuf_datasize (uint8_t *buf, size_t buflen, size_t retsz_toolittle) {
	size_t len;
	uint8_t hlen;
	uint8_t tag;
	dercursor crs;
	if (buflen < 2) {
		return retsz_toolittle;
	}
	crs.derptr = buf;
	crs.derlen = buflen;
	if (der_header (&crs, &tag, &len, &hlen) == -1) {
		return -1;
	}
	return len;
}
#endif


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

