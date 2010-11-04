/* Very simple malloc implementation */
//#define NDEBUG
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "shared.h"

#ifdef NDEBUG
#define assert(x) do {} while (0)
#else
#define assert(x)					\
	do {						\
		if (!(x))				\
			*(unsigned long *)NULL = 5;	\
	} while (0)
#endif

//#define dbg(x, ...) do { printf((x), ## __VA_ARGS__ ); } while (0)
#define dbg(x, ...) do {} while (0)

static struct allocation_site
internal_allocation;

static struct allocation_site *
as_hash_heads[NR_AS_HASH_HEADS];
static unsigned
lock;

static unsigned
hash_alloc_key(const struct alloc_key *key)
{
	unsigned hash = 0;
	unsigned long rip = key->rip ^ (key->size * 4296540811ul);
	while (rip) {
		hash ^= rip % NR_AS_HASH_HEADS;
		rip /= NR_AS_HASH_HEADS;
	}
	return hash % NR_AS_HASH_HEADS;
}

static int
alloc_keys_eq(const struct alloc_key *k1, const struct alloc_key *k2)
{
	return k1->rip == k2->rip && k1->size == k2->size;
}

static void *
cmpxchg_ptr(void **what, void *from, void *to)
{
	void *res;
	asm volatile ("lock cmpxchg %[to], %[what]\n"
		      : [what] "=m" (*what),
			"=a" (res)
		      : "1" (from),
			[to] "r" (to)
		      : "memory", "cc");
	return res;
}

static unsigned
cmpxchg_uint(unsigned *what, unsigned from, unsigned to)
{
	unsigned res;
	asm volatile ("lock cmpxchg %[to], %[what]\n"
		      : [what] "=m" (*what),
			"=a" (res)
		      : "1" (from),
			[to] "r" (to)
		      : "memory", "cc");
	return res;
}

/* Read with acquire semantics */
#define acquire_read(x) (*(volatile typeof(x) *)&(x))
/* Write with release semantics */
#define release_write(x, val)				\
	do {						\
		*(volatile typeof(x) *)&(x) = (val);	\
	} while (0)

/* Stall for a moment */
static void
relax(void)
{
	asm volatile("rep; nop\n");
}

static void *
allocate_in_arena(struct arena *a, size_t s)
{
	int idx;
	assert(a->nr_free != 0);
	idx = 0;
	while (1) {
		if (a->free_bitmap[idx / 8] & (1 << (idx % 8))) {
			a->free_bitmap[idx / 8] &= ~(1 << (idx % 8));
			a->nr_free--;
			return a->data + idx * s + sizeof(struct arena *);
		}
		idx++;
	}
}


static void *_internal_malloc(void *ra, size_t s);
#define internal_malloc(s) _internal_malloc(__builtin_return_address(0), (s))

static struct allocation_site *
find_allocation_site(const struct alloc_key *k)
{
	struct allocation_site **pas;
	struct allocation_site *as, *orig_head, *new_as;
	unsigned h = hash_alloc_key(k);

	new_as = NULL;
retry:
	pas = &as_hash_heads[h];
	orig_head = acquire_read(*pas);
	as = orig_head;
	while (as) {
		if (alloc_keys_eq(&as->key, k)) {
			dbg("Re-use alloc site %lx\n", k->rip);
			return as;
		}
		pas = &as->next;
		as = *pas;
	}
	if (orig_head != as_hash_heads[h])
		goto retry;

	if (new_as)
		as = new_as;
	else
		as = sbrk(sizeof(*as));
	as->head_arena = NULL;
	as->key = *k;
	as->next = orig_head;
	if (cmpxchg_ptr((void **)&as_hash_heads[h], orig_head, as) != orig_head) {
		printf("Race creating alloc site %lx\n", k->rip);
		/* This can leak, but it should be rare enough not to matter. */
		new_as = as;
		goto retry;
	}
	dbg("New alloc site %d %lx\n", h, k->rip);
	return as;
}

static void *
_internal_malloc(void *ra, size_t s)
{
	struct alloc_key ak;
	struct allocation_site *as;
	struct arena *arena;
	void *res;
	size_t data_size;
	size_t arena_size;
	int i;

	dbg("malloc(%p, %zd)\n", ra, s);

	s += sizeof(struct arena *);
	s = (s + 7) & ~7ul;

	if (s >= (1ul << 31)) {
		/* Do it with mmap */
		abort();
#warning Write me
	}

	ak.rip = (unsigned long)ra;
	ak.size = s;
	as = find_allocation_site(&ak);
	while (cmpxchg_uint(&lock, 0, 1) != 0)
		relax();

	dbg("malloc2(%zd)\n", s);

	for (arena = as->head_arena; arena; arena = arena->next) {
		dbg("arena %p\n", a);
		if (arena->nr_free) {
			res = allocate_in_arena(arena, s);
			release_write(lock, 0);
			return res;
		}
	}

	/* Nothing in any of the available arenas.  Build a new one. */
	data_size = size_to_arena_size(s);
	arena_size = sizeof(struct arena) + data_size / 8;
	arena_size = (arena_size + 7) & ~7ul;

	/* The arena structure itself comes out of sbrk memory. */
	arena = sbrk(arena_size);
	memset(arena->free_bitmap, 0xff, data_size / 8);
	arena->nr_free = data_size / s;
	arena->size = s;

	/* The data area is mmap()ed. */
	arena->data = mmap(NULL, data_size, PROT_READ|PROT_WRITE,
			   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	for (i = 0; i < arena->nr_free; i++) {
		struct arena **h;
		h = arena->data + i * s;
		*h = arena;
	}

	arena->next = as->head_arena;
	as->head_arena = arena;
	dbg("new arena %p\n", arena);
	res = allocate_in_arena(arena, s);
	release_write(lock, 0);
	return res;
}

#define internal_malloc(s) _internal_malloc(__builtin_return_address(0), (s))

void *
malloc(size_t s)
{
	return internal_malloc(s);
}

void *
calloc(size_t n, size_t s)
{
	void *r = internal_malloc(n * s);
	if (!r)
		return r;
	memset(r, 0, n * s);
	return r;
}

void
free(void *x)
{
	struct arena *a;
	int idx;

	dbg("free %p\n", x);
	if (!x)
		return;

	x -= 8;
	/* Handle memalign()-style aligned chunks */
	if ( *(unsigned long *)x & 1)
		x = (void *)(*(unsigned long *)x & ~1ul);

	a = *(struct arena ** *)x;
	assert(!((unsigned long)a & 1));

	dbg("arena %p\n", a);

	while (cmpxchg_uint(&lock, 0, 1) == 0)
		relax();

	idx = (x - a->data) / a->size;
	dbg("idx %d\n", idx);
	assert( !(a->free_bitmap[idx /8] & (1 << (idx % 8))) );
	a->free_bitmap[idx/8] |= 1 << (idx % 8);
	a->nr_free++;

	release_write(lock, 0);
}

void
cfree(void *x)
{
	free(x);
}

static void *
_memalign(void *ra, size_t boundary, size_t size)
{
	void *real_alloc;
	void *aligned_alloc;
	unsigned long *ah;

	if (boundary <= 8)
		return _malloc(ra, size);
	real_alloc = _malloc(ra, size + boundary + sizeof(*ah));
	aligned_alloc = real_alloc + sizeof(*ah);
	aligned_alloc = (void *)((unsigned long)aligned_alloc + boundary -
				 ((unsigned long)aligned_alloc % boundary));
	ah = aligned_alloc;
	ah[-1] = (unsigned long)real_alloc | 1;
	return aligned_alloc;
}

void *
memalign(size_t boundary, size_t size)
{
	return _memalign(__builtin_return_address(0), boundary, size);
}

size_t
malloc_usable_size(const void *_x)
{
	const unsigned long *x = _x;
	struct arena *a;
	if (x[-1] & 1) {
		abort();
#warning Write me
	}
	a = (struct arena *)x[-1];
	return a->size - sizeof(struct arena *);
}

void *
realloc(void *x, size_t s)
{
	size_t old_size;
	void *y;

	if (!x)
		return internal_malloc(s);
	if (!s) {
		free(x);
		return NULL;
	}
	old_size = malloc_usable_size(x);
	if (old_size >= s)
		return x;
	y = internal_malloc(s);
	memcpy(y, x, old_size);
	free(x);
	return y;
}

void *
valloc(size_t s)
{
	return _memalign(__builtin_return_address(0), PAGE_SIZE, s);
}

void *
pvalloc(size_t s)
{
	return _memalign(__builtin_return_address(0), PAGE_SIZE, (s + PAGE_SIZE) & ~(PAGE_SIZE - 1));
}

void *
malloc_get_state(void)
{
	return (void *)1;
}

void
malloc_set_state(void *x)
{
}

void **
independent_calloc(size_t n_elements, size_t element_size, void *chunks[])
{
	int x;
	void **res;
	if (chunks)
		res = chunks;
	else
		res = malloc(sizeof(void *) * n_elements);
	for (x = 0; x < n_elements; x++) {
		res[x] = internal_malloc(element_size);
		memset(res[x], 0, element_size);
	}
	return res;
}

void **
independent_comalloc(size_t n_elements, size_t sizes[], void *chunks[])
{
	void **res;
	int x;

	if (chunks)
		res = chunks;
	else
		res = malloc(sizeof(void *) * n_elements);
	for (x = 0; x < n_elements; x++)
		res[x] = internal_malloc(sizes[x]);
	return res;
}

static long
my_strtol(const char *start, int *error)
{
	long r;
	char *e;

	errno = 0;
	r = strtol(start, &e, 10);
	if (errno == ERANGE || e == start || *e != 0) {
		*error = 1;
		return -1;
	} else {
		*error = 0;
		return r;
	}
}

static int
get_env_int(const char *name)
{
	char *var;
	long val;
	int err;

	var = getenv(name);
	if (!var)
		errx(1, "%s not set", name);
	val = my_strtol(var, &err);
	if (err || val != (int)val)
		errx(1, "%s not a valid integer", name);
	return val;
}

static void initialise(void) __attribute__((constructor));
static void
initialise(void)
{
	int to_master_fd;
	int from_master_fd;
	int buf;
	void *hash_table = as_hash_heads;
	void *lock_address = &lock;

	if (!getenv("_NDC_to_master")) /* Just use the allocator */
		return;

	to_master_fd = get_env_int("_NDC_to_master");
	from_master_fd = get_env_int("_NDC_from_master");

	/* Tell master where our main lookup table is */
	write(to_master_fd, &hash_table, sizeof(hash_table));
	write(to_master_fd, &lock_address, sizeof(lock_address));

	close(to_master_fd);
	/* Wait for master to release us.  This should always fail,
	   we're just waiting for the master to call close() */
	read(from_master_fd, &buf, sizeof(buf));
	close(from_master_fd);

	/* Put everything back to how it was */
	if (getenv("_NDC_ld_preload"))
		setenv("LD_PRELOAD", getenv("_NDC_ld_preload"), 1);
	else
		unsetenv("LD_PRELOAD");
	unsetenv("_NDC_to_master");
	unsetenv("_NDC_from_master");
	unsetenv("_NFC_ld_preload");
}
