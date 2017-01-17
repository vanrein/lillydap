/* lillydap_mem -- the external dependencies that LillyDAP makes for memory.
 *
 * The environment in which LillyDAP is expected to run should have some
 * form of pool- or region-based memory allocation.  LillyDAP can
 * allocate memory for the following pools separately, so they can be
 * cleaned all at once:
 *
 *  - LDAP connections (represented by the (LDAP *) endpoints.
 *  - LDAP queries
 * 
 * There is a module "sillymem" that you might use to initialise lillymem
 * if you really have no implementation (perhaps while your code is in
 * development).  The name for this module refers to the non-optimised
 * manner in which this runs on top of malloc() with pointers between the
 * various allocations.  Properly pooled allocation works much better, it
 * can help to avoid memory fragmentation and it is fast -- and simpler
 * at cleanup time.  Most environments probably have something like it.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef LILLYMEM_H
#define LILLYMEM_H


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


/* The type of a pool is opaque, as far as LillyDAP is concerned.
 */
typedef void *LillyPool;


/* The type of a MessageId in its internal notation.  Internal means
 * that outward initiatives have the highest bit set (and reset before
 * it is actually sent).
 */
typedef uint32_t LillyMsgId;


/* The hash of LillyMsgId uses layers, and this determines the risk of a hit.
 * This may be set to a rough estimate of the number of quick requests while
 * a slower one is in action.  By way of a default, we make an estimated
 * based on the size of the address space.
 */
#ifndef LILLYDAP_MSGID_LAYERSIZE
#define LILLYDAP_MSGID_LAYERSIZE (16 * sizeof (void *))
#endif


/* Create a new pool.  This is expected to be sufficiently lightweight that
 * it can be done for individual LDAP queries.
 */
typedef LillyPool (*lillydap_newpool) (void);


/* Destroy a pool.  This will first free all the memory still held, so it
 * replaces many individual free() calls that would be needed in standard
 * software.  There is no problem with resetting the pool and recycling it,
 * but this is considered out of scope for LillyDAP -- because it probably
 * is already done, somewhere.
 */
typedef void (*lillydap_endpool) (LillyPool cango);


/* Allocate memory within a pool.  Note that there is no matching _free()
 * statement, this is done with lillydap_endpool() instead.  The memory
 * does not have to be cleared before delivery; that would not add much
 * security because it is likely that future pool allocations follow this
 * one directly, and they would have to be wiped too.  In general, it is
 * better to wipe sensitive data as soon as they have lost their use.
 */
typedef void * (*lillydap_alloc) (LillyPool pool, size_t szbytes);



/* The following symbols are shared between the LillyDAP modules for their
 * allocation of memory.  They must be setup by the application before
 * processing the first LDAP message.  There are no defaults; if you
 * invoke LillyDAP before setting up these lillymem_ variables, you will
 * be amused by your operation system's most creative side while it tries
 * to run whatever code it finds at the NULL address.
 */
extern lillydap_newpool lillymem_newpool_fun;
extern lillydap_endpool lillymem_endpool_fun;
extern lillydap_alloc   lillymem_alloc_fun;


/* The following wrappers help with access of the function pointers.
 */
#define lillymem_newpool (*lillymem_newpool_fun)
#define lillymem_endpool (*lillymem_endpool_fun)
#define lillymem_alloc   (*lillymem_alloc_fun  )

/* Ensure having a memory pool.  When the pointer has a NULL value, it will be
 * allocated on the spot.  If that fails, errno will be set to ENOMEM and the
 * success-indicating return value is False.
 */
bool lillymem_havepool (LillyPool *pool);


/* This is an extension to memory allocation which clears the memory.
 */
void *lillymem_alloc0 (LillyPool pool, size_t szbytes);


/* The sillymem module, definitions are optionally included
 */
#ifdef USE_SILLYMEM
LillyPool sillymem_newpool (void);
void sillymem_endpool (LillyPool cango);
void *sillymem_alloc (LillyPool pool, size_t szbytes);
#endif /* USE_SILLYMEM */


/* Connections hold a hash of requests.  They are indexed by MessageID, and
 * have a memory pool attached.
 *
 * The hashes are stored in layers, usually not too many.  The number of
 * layers adapts to a high degree of concurrency, and will not shrink.
 * Note that the generation of MessageID values is internally initiated,
 * so attacks are not to be expected.
 *
 * The entries can be wiped given the LillyMsgId, and at that time the
 * query-specific memory pool will be cleaned up.  Once a LillyMsgId has
 * been supplied to an application, it has been given the responsibility
 * to cause this cleanup.
 *
 * Entries in the cache are considered free when the reqid is 0; attempts
 * to replace the reqid are performed with an atomic test-and-set operation.
 * Access to the other field (reqpool) is guarded by this field.
 *
 * Similarly, adding a new LillyMsgLayer is done by replacing the last in
 * the list with a test-and-set operation that requires the old value to
 * be NULL.
 */
struct LillyMsgInfo {
	LillyMsgId reqid;
	LillyPool reqpool;
};
struct LillyMsgLayer {
	struct LillyMsgLayer *next_layer;
	struct LillyMsgInfo msgid_info [LILLYDAP_MSGID_LAYERSIZE];
};


#endif /* LILLYMEM_H */
