/* Very simple malloc implementation */
#include <sys/types.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

#define assert(x)					\
	do {						\
		if (!(x))				\
			*(unsigned long *)NULL = 5;	\
	} while (0)

#define dbg(x, ...) do { } while (0)

struct arena {
	struct arena *next;
	struct arena *prev;
	unsigned long size;
	unsigned long pad;
	char content[];
};

static struct arena *
head_arena;

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

void *
malloc(size_t s)
{
	struct arena *a;
	struct chunk_header *head, *next_head;
	struct chunk_footer *footer, *next_footer;
	unsigned offset;
	size_t arena_size;

	dbg("malloc(%zd)\n", s);
#warning Acquire a lock of some sort
	s = (s + 15 + sizeof(struct chunk_header) + sizeof(struct chunk_footer)) & ~15ul;
	if (s >= (1 << 31)) {
		/* Do it with mmap */
		abort();
#warning Write me
	}
	dbg("malloc2(%zd)\n", s);
top:
	for (a = head_arena; a; a = a->next) {
		dbg("arena %p\n", a);
		for (offset = 0; offset != a->size; offset += head->h.size) {
			head = (struct chunk_header *)(a->content + offset);
			footer = (struct chunk_footer *)((unsigned long)head + head->h.size) - 1;
			dbg("Inspect %p size %lx free %d\n", head,
			       (unsigned long)head->h.size, head->h.free);
			assert(head->h.free == footer->h.free);
			assert(head->h.size == footer->h.size);
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
				return head + 1;
			}
		}
	}

	/* Nothing in any of the available arenas.  Build a new one. */
	arena_size = 1 << 20;
	while (s > arena_size)
		arena_size *= 2;

	a = mmap(NULL, arena_size, PROT_READ|PROT_WRITE,
		 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (a == MAP_FAILED)
		return NULL;
	a->prev = NULL;
	a->next = head_arena;
	a->size = arena_size - sizeof(struct arena);
	head = (struct chunk_header *)a->content;
	head->h.free = 1;
	head->h.size = a->size;
	head->arena = a;
	footer = (struct chunk_footer *)((unsigned long)head + head->h.size) - 1;
	footer->h = head->h;
	footer->red = FOOTER_REDZONE;
	if (head_arena)
		head_arena->prev = a;
	head_arena = a;
	dbg("new arena %p\n", a);
	goto top;
}

void *
calloc(size_t n, size_t s)
{
	void *r = malloc(n * s);
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
	header->h.free = 1;
	dbg("header %p size %lx arena %p\n", header, header->h.size, header->arena);
	a = header->arena;
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
}

void
cfree(void *x)
{
	free(x);
}

void *
memalign(size_t boundary, size_t size)
{
	void *real_alloc;
	void *aligned_alloc;
	struct aligned_header *ah;

	if (boundary <= 16)
		return malloc(size);
	real_alloc = malloc(size + boundary + sizeof(*ah));
	aligned_alloc = real_alloc + sizeof(*ah);
	aligned_alloc = (void *)((unsigned long)aligned_alloc + boundary -
				 ((unsigned long)aligned_alloc % boundary));
	ah = aligned_alloc;
	ah--;
	ah->h.aligned = 1;
	ah->real_allocation = real_alloc;
	return aligned_alloc;
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
	size_t old_size;
	void *y;

	if (!x)
		return malloc(s);
	if (!s) {
		free(x);
		return NULL;
	}
	old_size = malloc_usable_size(x);
	if (old_size >= s)
		return x;
	y = malloc(s);
	memcpy(y, x, old_size);
	free(x);
	return y;
}

void *
valloc(size_t s)
{
	return memalign(4096, s);
}

void *
pvalloc(size_t s)
{
	return valloc((s + 4095) & ~4095ul);
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
	for (x = 0; x < n_elements; x++)
		res[x] = calloc(element_size, 1);
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
		res[x] = malloc(sizes[x]);
	return res;
}
