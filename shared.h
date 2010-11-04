/* Stuff shared between the DSO and the driver */
struct alloc_key {
	unsigned long rip;
	unsigned size;
};

struct allocation_site {
	struct allocation_site *next;
	struct alloc_key key;
	struct arena *head_arena;
};

#define NR_AS_HASH_HEADS 4097

struct arena {
	struct arena *next;
	void *data;
	unsigned nr_free;
	unsigned size;
	unsigned char free_bitmap[];
};

#define ARENA_MIN_SIZE PAGE_SIZE

static inline int
size_to_arena_size(size_t s)
{
	size_t data_size;
	data_size = ARENA_MIN_SIZE;
	while (s * 32 > data_size)
		data_size *= 2;
	return data_size;
}
