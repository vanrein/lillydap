/* lillymem_ routines for region-based memory allocation.
 *
 * This module assumes that a few variables will be setup before any action
 * on LDAP bytes is taken.  These variables refer to routines for the
 * creation and deletion of memory pools, and the allocation of memory as
 * part of a pool, but there is no freeing of memory -- instead, this is
 * done by pool deletion.  Pools are useful per LDAP connection and per
 * query, which LillyDAP does to simplify code, speed it up and avoid
 * memory fragmentation.
 *
 * See also: <lillydap/mem.h>
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <stdbool.h>

#include <memory.h>

#include <errno.h>

#include <lillydap/api.h>
#include <lillydap/mem.h>


/* The following symbols are shared between the LillyDAP modules for their
 * allocation of memory.  They must be setup by the application before
 * processing the first LDAP message.  There are no defaults; if you
 * invoke LillyDAP before setting up these lillymem_ variables, you will
 * be amused by your operation system's most creative side while it tries
 * to run whatever code it finds at the NULL address.
 */
lillydap_newpool lillymem_newpool_fun;
lillydap_endpool lillymem_endpool_fun;
lillydap_alloc   lillymem_alloc_fun;


/* Ensure having a memory pool.  When the pointer has a NULL value, it will be
 * allocated on the spot.  If that fails, errno will be set to ENOMEM and the
 * success-indicating return value is False.
 */
bool lillymem_havepool (LillyPool *pool) {
	if (*pool == NULL) {
		*pool = lillymem_newpool ();
		if (*pool == NULL) {
			errno = ENOMEM;
			return false;
		}
	}
	return true;
}


/* This is an extension to memory allocation which clears the memory.
 */
void *lillymem_alloc0 (LillyPool pool, size_t szbytes) {
	void *rv = lillymem_alloc (pool, szbytes);
	if (rv != NULL) {
		memset (rv, 0, szbytes);
	}
	return rv;
}


/* Allocate connection-bound memory.  This will be removed when the
 * connection is properly closed.
 */
void *lillymem_alloc_cnx (LDAP *lil, size_t szbytes) {
	return lillymem_alloc (lil->cnxpool, szbytes);
}


/* This is a stupid implementation of test-and-set, not fit for concurrency.
 */
#define testandset(var,old,new) (((var)==(old))? ((var)=(old),1): 0)


/* Allocate an unused MessageID value for the given LillyDAP connection.
 * This can be used to prepare for sending a Request; for sending a
 * Response, you should recycle the MessageID from the Request.
 *
 * The value returned is an internal notation; in fact, the high bit will
 * be set to distinguish these outward initiatives (put Requests, get
 * Responses) from inward initiatives (get Requests, put Responses) and
 * still use one hash table with MessageID and LillyPool values.
 *
 * When a pointer to a LillyPool is provided, it will be filled with the
 * newly created memory pool for the query.
 */
LillyMsgId lillymsg_id_alloc (LDAP *lil, LillyPool *newpool) {
	uint32_t rv;
	uint16_t slot;
	bool todo;
already_taken:
	rv |= 0x80000000;   // Mark as an internal initiative
	todo = true;
	// Insert as new hash entry, set todo = false when added
	slot = rv & (LILLYDAP_MSGID_LAYERSIZE - 1);
	struct LillyMsgLayer **layer = &lil->msghash;
	while (1) {
		if (*layer == NULL) {
			// Need to insert a layer (and have it set to 0)
			struct LillyMsgLayer *newlayer = lillymem_alloc0 (
						lil->cnxpool,
						sizeof (struct LillyMsgLayer));
			if (newlayer == NULL) {
				return 0;
			}
			// Maybe someone else beat us to it; then add at end
			struct LillyMsgLayer **layer2 = layer;
			while (!testandset (*layer2, NULL, newlayer)) {
				layer2 = &(*layer2)->next_layer;
			}
		}
		// Now *layer is not NULL, and points to the next to test
		if (testandset ((*layer)->msgid_info [slot].reqid, 0, rv)) {
			// We dropped our rv, so we're settling
			// we can add a pool now, safe since rv is unpublished
			LillyPool pool = lillymem_newpool ();
			if (newpool != NULL) {
				*newpool = pool;
			}
			if (pool == NULL) {
				// Failed to allocate, cleanup and fail
				(*layer)->msgid_info [slot].reqid = 0;
				return 0;
			}
			(*layer)->msgid_info [slot].reqpool = pool;
			return rv;
		} else {
			if ((*layer)->msgid_info [slot].reqid == rv) {
				// Force another cycle with another ID
				goto already_taken;
			}
		}
	}
	return rv;
}


/* Free a MessageID from the given LillyDAP connection.  This also clears
 * the related memory pool for the query.
 */
void lillymsg_id_free (LDAP *lil, LillyMsgId cango) {
	struct LillyMsgLayer *layer = lil->msghash;
	uint16_t slot = cango & (LILLYDAP_MSGID_LAYERSIZE - 1);
	while (layer) {
		if (layer->msgid_info [slot].reqid == cango) {
			// We can cleanup, but should free the reqid last,
			// so the slot cannot be reclaimed before we're done
			lillymem_endpool (layer->msgid_info [slot].reqpool);
			layer->msgid_info [slot].reqpool = NULL;
			layer->msgid_info [slot].reqid = 0;
			// The reqid occurs only once, so we're done
			return;
		}
		layer = layer->next_layer;
	}
	//TODO// We should never end up here; maybe we're leaking memory
}


/* After lillymsg_id_alloc() and before lillymsg_id_free(), the query's
 * memory pool can be requested from the connection's hash pool.
 */
LillyPool lillymsg_id_qpool (LDAP *lil, LillyMsgId mid) {
	//TODO// Much of this code is shared -- centralise it?
	struct LillyMsgLayer *layer = lil->msghash;
	uint16_t slot = mid & (LILLYDAP_MSGID_LAYERSIZE - 1);
	while (layer) {
		if (layer->msgid_info [slot].reqid == mid) {
			// Jackpot!  This is the sought reqpool
			return layer->msgid_info [slot].reqpool;
		}
		layer = layer->next_layer;
	}
	//TODO// We should never end up here; maybe we're confused
	return NULL;
}


