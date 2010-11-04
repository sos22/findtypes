/* Stuff shared between the DSO and the driver */
struct arena {
	struct arena *next;
	unsigned long size;
	struct allocation_site *as;
	unsigned long pad;
	char content[];
};

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
