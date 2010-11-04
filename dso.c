/* Very simple malloc implementation */
//#define NDEBUG
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "shared.h"

#define PAGE_SIZE 4096ul
#define ARENA_MIN_SIZE PAGE_SIZE

/* Present at head and foot of every allocation */
struct chunk_word {
	unsigned long size:62;
	unsigned free:1;
	unsigned aligned:1;
};

struct chunk_header {
	struct chunk_word h;
	struct arena *arena;
};

struct aligned_header {
	struct chunk_word h;
	void *real_allocation;
};

#define FOOTER_REDZONE 0x11223344aabbccddul
struct chunk_footer {
	unsigned long red;
	struct chunk_word h;
};

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
_malloc(struct allocation_site *as, size_t s)
{
	struct arena *a;
	struct chunk_header *head, *next_head;
	struct chunk_footer *footer, *next_footer;
	unsigned offset;
	size_t arena_size;

	dbg("malloc(%zd)\n", s);

	while (cmpxchg_uint(&lock, 0, 1) != 0)
		relax();

	s = (s + 15 + sizeof(struct chunk_header) + sizeof(struct chunk_footer)) & ~15ul;
	if (s >= (1 << 31)) {
		/* Do it with mmap */
		abort();
#warning Write me
	}
	dbg("malloc2(%zd)\n", s);
top:
	for (a = as->head_arena; a; a = a->next) {
		dbg("arena %p\n", a);
		for (offset = 0; offset != a->size; offset += head->h.size) {
			head = (struct chunk_header *)(a->content + offset);
			footer = (struct chunk_footer *)((unsigned long)head + head->h.size) - 1;
			dbg("Inspect %p size %lx free %d\n", head,
			    (unsigned long)head->h.size, head->h.free);
			assert(head->h.free == footer->h.free);
			assert(head->h.size == footer->h.size);
			assert(!head->h.aligned);
			assert(!footer->h.aligned);
			assert(footer->red == FOOTER_REDZONE);
			if (head->h.free && head->h.size >= s) {
				/* Grab it. */
				dbg("grab %p\n", head);
				head->h.free = 0;
				assert(footer->red == FOOTER_REDZONE);
				if (head->h.size >= s + 64) {
					/* Split */
					next_footer = footer;
					footer =
						(struct chunk_footer *)((unsigned long)head + s) - 1;
					footer->red = FOOTER_REDZONE;
					next_head = (struct chunk_header *)(footer + 1);

					next_head->h.size = head->h.size - s;
					next_head->h.free = 1;
					next_head->h.aligned = 0;
					next_head->arena = a;
					next_footer->h = next_head->h;
					next_footer->red = FOOTER_REDZONE;
					head->h.size = s;
					dbg("split %p to size %lx; next %p size %lx\n",
					    head, s, next_head, (unsigned long)next_head->h.size);
				}

				footer->h = head->h;

				/* We're done */
				dbg("res %p\n", head + 1);
				release_write(lock, 0);
				return head + 1;
			}
		}
	}

	/* Nothing in any of the available arenas.  Build a new one. */
	arena_size = ARENA_MIN_SIZE;
	while (s * 32 > arena_size)
		arena_size *= 2;

	a = mmap(NULL, arena_size, PROT_READ|PROT_WRITE,
		 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (a == MAP_FAILED) {
		release_write(lock, 0);
		return NULL;
	}
	a->next = as->head_arena;
	a->size = arena_size - sizeof(struct arena);
	a->as = as;
	head = (struct chunk_header *)a->content;
	head->h.free = 1;
	head->h.size = a->size;
	head->arena = a;
	footer = (struct chunk_footer *)((unsigned long)head + head->h.size) - 1;
	footer->h = head->h;
	footer->red = FOOTER_REDZONE;
	as->head_arena = a;
	dbg("new arena %p\n", a);
	goto top;
}

#define get_alloc_key(as, sz)						\
	do {								\
		(as)->rip = (unsigned long)__builtin_return_address(0);	\
		(as)->size = (sz);					\
	} while (0)
#define get_alloc_site(sz)			\
	({					\
		struct alloc_key key;		\
		get_alloc_key(&key, sz);	\
		find_allocation_site(&key);	\
	})

static struct allocation_site *
find_allocation_site(const struct alloc_key *k)
{
	struct allocation_site **pas;
	struct allocation_site *as, *orig_head;
	unsigned h = hash_alloc_key(k);
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

	as = _malloc(&internal_allocation, sizeof(*as));
	as->head_arena = NULL;
	as->key = *k;
	as->next = orig_head;
	if (cmpxchg_ptr((void **)&as_hash_heads[h], orig_head, as) != orig_head) {
		printf("Race creating alloc site %lx\n", k->rip);
		free(as);
		goto retry;
	}
	dbg("New alloc site %d %lx\n", h, k->rip);
	return as;
}

void *
malloc(size_t s)
{
	return _malloc(get_alloc_site(s), s);
}

void *
calloc(size_t n, size_t s)
{
	void *r = _malloc(get_alloc_site(n*s), n * s);
	if (!r)
		return r;
	memset(r, 0, n * s);
	return r;
}

static void
free_aligned(void *x)
{
	struct aligned_header *ah = x;
	ah--;
	assert(ah->h.aligned);
	free(ah->real_allocation);
}

void
free(void *x)
{
	struct chunk_header *header, *prev_header, *next_header;
	struct chunk_footer *footer, *prev_footer, *next_footer;
	struct arena *a;

	if (!x)
		return;

	header = x;
	header--;
	if (header->h.aligned) {
		free_aligned(x);
		return;
	}
	dbg("free %p\n", x);

	while (cmpxchg_uint(&lock, 0, 1) == 0)
		relax();

	a = header->arena;
	header->h.free = 1;
	dbg("header %p size %lx arena %p\n", header, header->h.size, header->arena);
	footer = (struct chunk_footer *)((unsigned long)header + header->h.size) - 1;
	dbg("footer %p\n", footer);
	if ((unsigned long)header != (unsigned long)a->content) {
		/* Try to merge backwards */
		prev_footer = (struct chunk_footer *)header - 1;
		dbg("prev footer %p\n", prev_footer);
		if (prev_footer->h.free) {
			prev_header = (struct chunk_header *)((unsigned long)(prev_footer + 1) - prev_footer->h.size);
			assert(prev_header->h.size == prev_footer->h.size);
			assert(prev_header->arena == a);
			prev_header->h.size += header->h.size;
			header = prev_header;
			dbg("merge backwards to %p new size %lx\n",
			    prev_header, prev_header->h.size);
		}
	}

	next_header = (struct chunk_header *)(footer + 1);
	dbg("next header %p %p %p\n", next_header, a->content, a->content + a->size);
	if ((unsigned long)next_header != (unsigned long)a->content + a->size) {
		/* Try to merge forwards */
		assert(next_header->arena == a);
		dbg("next header %p %lx\n", next_header, next_header->h.size);
		if (next_header->h.free) {
			next_footer = (struct chunk_footer *)((unsigned long)next_header + next_header->h.size) - 1;
			assert(next_footer->h.size == next_header->h.size);
			assert(next_footer->h.free == next_header->h.free);
			header->h.size += next_header->h.size;
			footer = next_footer;
			dbg("merge forwards to %p new size %lx\n",
			    next_header, header->h.size);
		}
	}

	footer->h = header->h;

	release_write(lock, 0);
}

void
cfree(void *x)
{
	free(x);
}

static void *
_memalign(struct allocation_site *as, size_t boundary, size_t size)
{
	void *real_alloc;
	void *aligned_alloc;
	struct aligned_header *ah;

	if (boundary <= 16)
		return _malloc(as, size);
	real_alloc = _malloc(as, size + boundary + sizeof(*ah));
	aligned_alloc = real_alloc + sizeof(*ah);
	aligned_alloc = (void *)((unsigned long)aligned_alloc + boundary -
				 ((unsigned long)aligned_alloc % boundary));
	ah = aligned_alloc;
	ah--;
	ah->h.aligned = 1;
	ah->real_allocation = real_alloc;
	return aligned_alloc;
}

void *
memalign(size_t boundary, size_t size)
{
	return _memalign(get_alloc_site(size), boundary, size);
}

size_t
malloc_usable_size(void *x)
{
	struct chunk_header *h;
	h = x;
	h--;
	return h->h.size - sizeof(*h) - sizeof(struct chunk_footer);
}

void *
realloc(void *x, size_t s)
{
	struct allocation_site *as = get_alloc_site(s);
	size_t old_size;
	void *y;

	if (!x)
		return _malloc(as, s);
	if (!s) {
		free(x);
		return NULL;
	}
	old_size = malloc_usable_size(x);
	if (old_size >= s)
		return x;
	y = _malloc(as, s);
	memcpy(y, x, old_size);
	free(x);
	return y;
}

void *
valloc(size_t s)
{
	return _memalign(get_alloc_site(s), PAGE_SIZE, s);
}

void *
pvalloc(size_t s)
{
	return _memalign(get_alloc_site(s), PAGE_SIZE, (s + PAGE_SIZE) & ~(PAGE_SIZE - 1));
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
	struct allocation_site *as = get_alloc_site(element_size);
	int x;
	void **res;
	if (chunks)
		res = chunks;
	else
		res = malloc(sizeof(void *) * n_elements);
	for (x = 0; x < n_elements; x++) {
		res[x] = _malloc(as, element_size);
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
		res[x] = _malloc(get_alloc_site(sizes[x]), sizes[x]);
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
