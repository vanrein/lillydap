/* The silly memory allocation routines -- only used during development.
 *
 * These routines should not be shipped along with a product.  LillyMem
 * expects to run in an environment with pooled/region-based memory
 * allocation, and it will free memory by destroying the pool.  Pools
 * are created per connection, and even per LDAP query.  Memory is only
 * allocated from those pools, and never deleted, until finally the
 * entire pool can go.
 *
 * Unlike the rest of LilyDAP, you must not assume that these routines
 * are re-entrant.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifdef USE_SILLYMEM


#include <lillydap/mem.h>


/* All allocated memory in a region is independent (I told you this would be
 * silly!) and start with a pointer to the next region, or NULL.  The pool
 * is just a memory holding the first pointer and nothing else.  Again, I
 * told you so.  Now go and use your own allocator, it'll be much better.
 */
struct sillymem_pre {
	struct sillymem_pre *next;
};


LillyPool sillymem_newpool (void) {
	struct sillymem_pre *pool;
	pool = malloc (sizeof (struct sillymem_pre));
	if (pool != NULL) {
		pool->next = NULL;
	}
	return pool;
}


void sillymem_endpool (LillyPool cango) {
	struct sillymem_pre *next, *here;
	here = cango;
	while (cango != NULL) {
		next = ((struct sillymem_pre *) cango)->next;
		free (cango);
		cango = next;
	}
}


void *sillymem_alloc (LillyPool pool, size_t szbytes) {
	struct sillymem_pre *new;
	struct sillymem_pre *start = pool;
	new = malloc (sizeof (struct sillymem_pre) + szbytes);
	new->next = start->next;
	start->next = new;
	return (&new->next) + 1;
}


#endif /* USE_SILLYMEM */

