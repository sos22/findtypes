/* Various utility and debug functions */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ft.h"

int
tgkill(int tgid, int tid, int sig)
{
	return syscall(__NR_tgkill, tgid, tid, sig);
}

void
my_setenv(const char *name, const char *fmt, ...)
{
	va_list args;
	char *m;
	va_start(args, fmt);
	vasprintf(&m, fmt, args);
	va_end(args);
	setenv(name, m, 1);
	free(m);
}

void
dsleep(double x)
{
	struct timespec ts;
	ts.tv_sec = x;
	ts.tv_nsec = (x - ts.tv_sec) * 1e9;
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}


#define DRING_SLOT_SIZE 4080
struct debug_ring_slot {
	int prod;
	int cons;
	char content[DRING_SLOT_SIZE];
};

#define NR_DRING_SLOTS 8
struct debug_ring {
	unsigned prod;
	unsigned cons;
	struct debug_ring_slot slots[NR_DRING_SLOTS];
};

static struct debug_ring
dring;

void
vmsg(int prio, const char *fmt, va_list args)
{
	char *m;
	int sz;
	struct debug_ring_slot *drs;

	if (prio < PRIO_RING)
		return;

	vasprintf(&m, fmt, args);

	sz = strlen(m);
	drs = &dring.slots[dring.prod % NR_DRING_SLOTS];
	if (drs->prod + sz + 1 > DRING_SLOT_SIZE) {
		dring.prod++;
		if (dring.prod == dring.cons + NR_DRING_SLOTS) {
			dring.cons++;
			dring.slots[dring.cons % NR_DRING_SLOTS].cons = 0;
		}
		drs = &dring.slots[dring.prod % NR_DRING_SLOTS];
		drs->prod = 0;
		drs->cons = 0;
	}
	assert(drs->prod + sz + 1 <= DRING_SLOT_SIZE);
	memcpy(drs->content + drs->prod,
	       m,
	       sz + 1);
	drs->prod += sz + 1;

	if (prio >= PRIO_STDERR)
		fputs(m, stderr);
	else if (prio >= PRIO_STDOUT)
		fputs(m, stdout);

	free(m);
}

void
msg(int prio, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vmsg(prio, fmt, args);
	va_end(args);
}

void
dump_debug_ring(void)
{
	struct debug_ring_slot *drs;

	do {
		drs = &dring.slots[dring.cons % NR_DRING_SLOTS];
		while (drs->cons < drs->prod) {
			fputs(drs->content + drs->cons, stdout);
			drs->cons += strlen(drs->content + drs->cons) + 1;
		}
		dring.cons++;
	} while (dring.cons <= dring.prod);
	dring.cons--;
}
