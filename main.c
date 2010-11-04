#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <argp.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ft.h"
#include "shared.h"

#define PRELOAD_LIB_NAME "/local/scratch/sos22/findtypes/ft.so"
#define PTRACE_OPTIONS (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK)

static struct allocation_site *currently_investigated;

#define INTERVAL 1

int
thr_stop_status(const struct thread *thr)
{
	assert(thr->_stop_status != -1);
	return thr->_stop_status;
}

bool
thr_is_stopped(const struct thread *thr)
{
	return thr->_stop_status != -1;
}

void
thr_stopped(struct thread *thr, int status)
{
	assert(status != -1);
	assert(thr->_stop_status == -1);
	thr->_stop_status = status;
}

void
thr_resume(struct thread *thr)
{
	assert(thr->_stop_status != -1);
	thr->_stop_status = -1;
}

/* Invoked as an on_exit handler to do any necessary final cleanup */
static void
kill_child(int ign, void *_child)
{
	struct process *child = _child;
	struct thread *thr;
	while (!list_empty(&child->threads)) {
		thr = list_pop(struct thread, list, &child->threads);
		tgkill(child->tgid, thr->pid, SIGKILL);
	}
}

static struct process *
spawn_child(const char *path, char *const argv[])
{
	struct process *work;
	struct thread *thr;
	int p1[2], p2[2];

	work = calloc(sizeof(*work), 1);
	init_list_head(&work->threads);
	init_list_head(&work->breakpoints);

	thr = calloc(sizeof(*thr), 1);
	thr->process = work;
	thr->_stop_status = -1;

	list_push(thr, list, &work->threads);
	work->nr_threads = 1;
	if (pipe(p1) < 0 || pipe(p2) < 0)
		err(1, "pipe()");
	work->tgid = thr->pid = fork();
	if (thr->pid < 0)
		err(1, "fork()");
	if (thr->pid == 0) {
		/* We are the child */
		char *ld_preload;

		close(p1[0]);
		close(p2[1]);
		my_setenv("_NDC_to_master", "%d", p1[1]);
		my_setenv("_NDC_from_master", "%d", p2[0]);

		ld_preload = getenv("LD_PRELOAD");
		if (ld_preload)
			my_setenv("_NDC_ld_preload", "%s", ld_preload);
		if (ld_preload && strcmp(ld_preload, ""))
			my_setenv("LD_PRELOAD", "%s:%s", ld_preload, PRELOAD_LIB_NAME);
		else
			my_setenv("LD_PRELOAD", "%s", PRELOAD_LIB_NAME);

		if (ptrace(PTRACE_TRACEME) < 0)
			err(1, "ptrace(PTRACE_TRACEME)");

		execv(path, argv);
		err(1, "exec %s", path);
	}

	/* We are the parent */
	close(p1[1]);
	close(p2[0]);
	work->from_child_fd = p1[0];
	work->to_child_fd = p2[1];

	on_exit(kill_child, work);

	while (!thr_is_stopped(thr))
		if (!receive_ptrace_event(work))
			abort();
	if (!WIFSTOPPED(thr_stop_status(thr)) ||
	    WSTOPSIG(thr_stop_status(thr)) != SIGTRAP)
		errx(1, "strange status %x from waitpid()", thr_stop_status(thr));

	if (ptrace(PTRACE_SETOPTIONS,
		   thr->pid,
		   NULL,
		   PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS)");

	return work;
}

static int
get_stop_status(pid_t pid, struct pending_wait_status *pws)
{
	int x;
	int status;

	for (x = 0; x < pws->nr_pending; x++) {
		if (pws->pending[x].pid == pid) {
			/* The STOP has already been reported by the
			   kernel.  Use the stashed value. */
			status = pws->pending[x].status;
			memmove(pws->pending + x,
				pws->pending + x + 1,
				sizeof(pws->pending[0]) & (pws->nr_pending - x - 1));
			pws->nr_pending--;
			return status;
		}
	}
	if (waitpid(pid, &status, __WALL) < 0)
		err(1, "waitpid() for new thread %d", pid);
	return status;
}

static void
handle_clone(struct thread *parent)
{
	struct thread *thr;
	unsigned long new_pid;
	int status;

	if (ptrace(PTRACE_GETEVENTMSG, parent->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for clone");
	msg(50, "New pid %ld\n", new_pid);
	thr = calloc(sizeof(*thr), 1);
	thr->pid = new_pid;
	thr->process = parent->process;
	status = get_stop_status(new_pid, &parent->process->pws);
	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "unexpected waitpid status %d for clone\n", status);
		abort();
	}

	/* Set up the normal options */
	if (ptrace(PTRACE_SETOPTIONS, thr->pid, NULL, PTRACE_OPTIONS) < 0)
		err(1, "ptrace(PTRACE_SETOPTIONS) for new thread");

	/* Enlist the new thread in the process */
	list_push(thr, list, &parent->process->threads);
	parent->process->nr_threads++;

	/* And let them both go */
	resume_child(thr);
	resume_child(parent);
}

/* The child fork()ed.  We're not going to trace the new process, but
   we do need to make sure we get rid of all of our breakpoints. */
static void
handle_fork(struct thread *thr)
{
	unsigned long new_pid;
	int status;

	/* Wait for the kernel to attach it to us */
	if (ptrace(PTRACE_GETEVENTMSG, thr->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for fork");
	msg(10, "%d forked %zd, ignoring...\n", thr->pid, new_pid);
	status = get_stop_status(new_pid, &thr->process->pws);
	if (!WIFSTOPPED(status))
		errx(1, "unexpected status %x for fork", status);

	/* Detach it and let it go */
	if (ptrace(PTRACE_DETACH, new_pid) < 0)
		warn("detaching forked child");
}

static void
thread_exited(struct thread *thr, int status)
{
	msg(50, "Thread %d exited\n", thr->pid);
	list_unlink(&thr->list);
	thr->process->nr_threads--;
	if (thr->process->nr_threads == 0) {
		assert(list_empty(&thr->process->threads));
		exit(status);
	}
	free(thr);
}

static void
maybe_dump_debug_ring(int code, void *ignore)
{
	if (code != 0)
		dump_debug_ring();
}

static struct argp_option argp_options[] = {
	{ 0 }
};

static error_t
argp_parser(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	default:
		return ARGP_ERR_UNKNOWN;
	}
}

static struct argp argp = {
	.options = argp_options,
	.parser = argp_parser
};

static struct process *
start_process(char *argv[])
{
	int r;
	struct process *child;
	struct thread *head_thr;

	child = spawn_child(argv[0], argv);
	assert(child->nr_threads == 1);
	head_thr = list_first(&child->threads, struct thread, list);

	/* Child starts stopped. */
	ptrace(PTRACE_CONT, head_thr->pid, NULL, NULL);
	head_thr->_stop_status = -1;

	/* Get the break address */
	r = read(child->from_child_fd, &child->malloc_hash,
		 sizeof(child->malloc_hash));
	if (r != sizeof(child->malloc_hash))
		err(1, "reading child's malloc root address");
	r = read(child->from_child_fd, &child->malloc_lock,
		 sizeof(child->malloc_lock));
	if (r != sizeof(child->malloc_lock))
		err(1, "reading child's malloc lock address");

	/* Close out our file descriptors to set it going properly. */
	close(child->from_child_fd);
	close(child->to_child_fd);

	return child;
}

static void
_fetch_remote(struct process *proc, unsigned long addr, void *buf,
	      size_t buf_size)
{
	int r = _fetch_bytes(list_first(&proc->threads,
					struct thread,
					list),
			     addr,
			     buf,
			     buf_size);
	if (r < 0)
		err(1, "fetch_bytes(%lx)", addr);
}

#define fetch_remote(p, rptr)						\
	({								\
		typeof(rptr) res;					\
		_fetch_remote((p),					\
			      (unsigned long)&(rptr),			\
			      &res,					\
			      sizeof(res));				\
		res;							\
	})

static void
pause_process(struct process *p)
{
	struct thread *thr;
	bool stopped;

	while (1) {
		stopped = true;
		list_foreach(&p->threads, thr, list) {
			if (thr->_stop_status == -1) {
				tgkill(p->tgid, thr->pid, SIGSTOP);
				stopped = false;
			}
		}
		if (stopped)
			break;
		receive_ptrace_event(p);
	}
}

static void
unpause_process(struct process *p)
{
	struct thread *thr;
	list_foreach(&p->threads, thr, list) {
		assert(thr->_stop_status != -1);
		if (WIFSTOPPED(thr->_stop_status) &&
		    WSTOPSIG(thr->_stop_status) == SIGSTOP) {
			resume_child(thr);
		}
	}
}

static int
acquire_malloc_lock(struct process *p)
{
	int cntr = 0;
	unsigned l;
	while (cntr < 100) {
		pause_process(p);
		l = fetch_remote(p, *p->malloc_lock);
		if (l == 0)
			return 0;
		unpause_process(p);
		dsleep(0.01);
		cntr++;
	}
	return -1;
}

static void
release_malloc_lock(struct process *p)
{
	unpause_process(p);
}

static void
remote_mprotect(struct process *p, unsigned long start, unsigned long size, unsigned long prot)
{
	struct thread *thr = list_first(&p->threads, struct thread, list);
	struct user_regs_struct old_regs, new_regs;
	int status;

	get_regs(thr, &old_regs);
	printf("rax %lx, orig_rax %lx\n", old_regs.rax, old_regs.orig_rax);

	if (old_regs.orig_rax != ~0ul) {
		/* The thread is already in the middle of a
		 * syscall.  */
		if (-old_regs.rax == 516 ||
		    -old_regs.rax == 514) {
			/* Yurk.  The kernel won't automatically
			   restart these types, and it confuses
			   various programs (e.g. anything based on
			   glib).  Do it manually. */
			old_regs.rip -= 2;
			old_regs.rax = old_regs.orig_rax;
		}
	}
	new_regs = old_regs;
	/* Hackety hackety hack: we assume that the vsyscall page
	   includes a syscall instruction at a particular address. */
	new_regs.rip = 0xffffffffff60004b;
	new_regs.rax = __NR_mprotect;
	new_regs.rdi = start;
	new_regs.rsi = size;
	new_regs.rdx = prot;
	set_regs(thr, &new_regs);

	/* Now step it through the syscall. */
retry1:
	if (ptrace(PTRACE_SYSCALL, thr->pid, NULL, NULL) < 0)
		err(1, "PTRACE_SYSCALL1");
	if (waitpid(thr->pid, &status, __WALL) < 0)
		err(1, "waitpid for mprotect 1");
	/* ptrace confuses the crap out of me.  Do what seems to be
	   necessary to make it work. */
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
		goto retry1;

	if (ptrace(PTRACE_SYSCALL, thr->pid, NULL, NULL) < 0)
		err(1, "PTRACE_SYSCALL2");
	if (waitpid(thr->pid, &status, __WALL) < 0)
		err(1, "waitpid for mprotect 1");

	/* Did it work? */
	get_regs(thr, &new_regs);
	if (new_regs.rax != 0) {
		errno = new_regs.rax;
		err(1, "remote_mprotect(%d, %lx, %lx, %lx)",
		    thr->pid, start, size, prot);
	}

	/* Put it back to how it was */
	set_regs(thr, &old_regs);
}

static void
stop_investigating(struct process *p, struct allocation_site *ah)
{
	struct arena *a;
	struct thread *thr;
	void *data;
	unsigned s;

	printf("Stop investigating %p\n", ah);
	for (a = fetch_remote(p, ah->head_arena);
	     a != NULL;
	     a = fetch_remote(p, a->next)) {
		data = fetch_remote(p, a->data);
		s = fetch_remote(p, a->size);
		printf("Restore access to %#lx:%#lx\n",
		       (unsigned long)data, (unsigned long)data + size_to_arena_size(s));
		remote_mprotect(p, (unsigned long)data, size_to_arena_size(s), PROT_READ|PROT_WRITE);
	}

	/* Clear out any threads which have picked up SEGVs which
	 * we've not collected (can happen due to a race when
	 * re-enabling access). */
	list_foreach(&p->threads, thr, list) {
		if (thr_is_stopped(thr) &&
		    WIFSTOPPED(thr_stop_status(thr)) &&
		    WSTOPSIG(thr_stop_status(thr)) == SIGSEGV)
			thr->_stop_status = __W_STOPCODE(SIGSTOP);
	}
}

static void
start_investigating(struct process *p, struct allocation_site *ah)
{
	struct arena *a;
	unsigned long s;
	void *data;

	printf("Start investigating %p\n", ah);
	for (a = fetch_remote(p, ah->head_arena);
	     a != NULL;
	     a = fetch_remote(p, a->next)) {
		data = fetch_remote(p, a->data);
		s = size_to_arena_size(fetch_remote(p, a->size));
		printf("Revoke access to %#lx:%#lx\n",
		       (unsigned long)data, (unsigned long)data + s);
		remote_mprotect(p, (unsigned long)data, s, 0);
	}
}

static void
change_investigated_type(struct process *p)
{
	static unsigned target_cntr;
	unsigned x;
	struct allocation_site *ah;
	unsigned cntr;
	bool no_sites;

	if (acquire_malloc_lock(p) < 0)
		return;

retry:
	cntr = 0;
	no_sites = true;
	if (currently_investigated)
		stop_investigating(p, currently_investigated);
	currently_investigated = NULL;
	for (x = 0; x < NR_AS_HASH_HEADS; x++) {
		ah = fetch_remote(p, p->malloc_hash[x]);
		while (ah) {
			no_sites = false;
			if (cntr == target_cntr) {
				assert(!currently_investigated);
				start_investigating(p, ah);
				currently_investigated = ah;
				target_cntr++;
				release_malloc_lock(p);
				return;
			}
			cntr++;
			ah = fetch_remote(p, ah->next);
		}
	}
	if (no_sites) {
		release_malloc_lock(p);
		return;
	}

	target_cntr = 0;
	goto retry;
}

static void
child_got_segv(struct thread *thr)
{
	siginfo_t si;
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETSIGINFO, thr->pid, NULL, &si) < 0)
		err(1, "ptrace(PTRACE_GETSIGINFO) after child segv");
	get_regs(thr, &regs);
	printf("Child %d got segv at %p, rip %lx\n",
	       thr->pid, si.si_addr, regs.rip);
	emulate_instruction(thr);
	resume_child(thr);
}

static void
child_syscall(struct process *proc, struct thread *thr)
{
	struct user_regs_struct urs;
	if (!currently_investigated) {
		resume_child(thr);
		return;
	}
	get_regs(thr, &urs);
	if (-urs.rax != EFAULT) {
		resume_child(thr);
		return;
	}

	/* This syscall touched the some bit of memory.  Unprotect and
	   let it go. */
	while (acquire_malloc_lock(proc) < 0)
		warnx("struggling to acquire malloc lock for %d",
		      thr->pid);
	stop_investigating(proc, currently_investigated);
	currently_investigated = NULL;
	release_malloc_lock(proc);

	/* Retry the syscall */
	urs.rax = urs.orig_rax;
	urs.rip -= 2;
	set_regs(thr, &urs);
	resume_child(thr);
}

int
main(int argc, char *argv[])
{
	struct process *child;
	int arg_index;

	on_exit(maybe_dump_debug_ring, NULL);
	signal(SIGABRT, (void (*)(int))dump_debug_ring);

	errno = argp_parse(&argp, argc, argv, 0, &arg_index, NULL);
	if (errno)
		err(1, "parsing arguments");

	child = start_process(argv + arg_index);

	/* Give it a few seconds to get through any initialisation
	 * code. */
	dsleep(INTERVAL);

	/* wait() and friends don't have convenient timeout arguments,
	   and doing it with signals is a pain, so just have a child
	   process which sleeps 60 seconds and then exits. */
	child->timeout_pid = fork();
	if (child->timeout_pid == 0) {
		dsleep(INTERVAL);
		_exit(0);
	}

	while (1) {
		struct thread *thr;
		bool nothing_ready;

               if (child->timeout_fired) {
                       change_investigated_type(child);
                       child->timeout_fired = false;
                       child->timeout_pid = fork();
                       if (child->timeout_pid == 0) {
                               dsleep(INTERVAL);
                               _exit(0);
                       }
               }

		nothing_ready = true;
		list_foreach(&child->threads, thr, list) {
			if (thr_is_stopped(thr)) {
				nothing_ready = false;
				break;
			}
		}
		if (nothing_ready) {
			receive_ptrace_event(child);
			continue;
		}

		assert(thr_is_stopped(thr));

		if (WIFEXITED(thr_stop_status(thr))) {
			msg(15, "Child exited with status %d, doing the same thing (%x)\n",
			       WEXITSTATUS(thr_stop_status(thr)), thr_stop_status(thr));
			thread_exited(thr, WEXITSTATUS(thr_stop_status(thr)));
		} else if (WIFSIGNALED(thr_stop_status(thr))) {
			msg(100, "Child got signal %d\n", WTERMSIG(thr_stop_status(thr)));
			/* Should arguably raise() the signal here,
			   rather than exiting, so that our parent
			   gets the right status, but that might cause
			   us to dump core, which would potentially
			   obliterate any core dump left behind by the
			   child. */
			exit(1);
		} else if (WIFSTOPPED(thr_stop_status(thr)) &&
			   WSTOPSIG(thr_stop_status(thr)) == SIGTRAP) {
			switch (thr_stop_status(thr) >> 16) {
			case 0:
				handle_breakpoint(thr);
				break;
			case PTRACE_EVENT_FORK:
				handle_fork(thr);
				break;
			case PTRACE_EVENT_CLONE:
				handle_clone(thr);
				break;
			default:
				fprintf(stderr, "unknown ptrace event %d\n", thr_stop_status(thr) >> 16);
				abort();
			}
		} else if (WIFSTOPPED(thr_stop_status(thr))) {
			if (WSTOPSIG(thr_stop_status(thr)) == SIGSTOP) {
				/* Sometimes get these spuriously when
				 * attaching to a new thread or as a
				 * resule of pause_thread().
				 * Ignore. */
				resume_child(thr);
			} else if (WSTOPSIG(thr_stop_status(thr)) == SIGSEGV) {
				child_got_segv(thr);
			} else if (WSTOPSIG(thr_stop_status(thr)) == (SIGTRAP | 0x80)) {
				child_syscall(child, thr);
			} else {
				msg(20, "Sending signal %d to child %d\n",
				    WSTOPSIG(thr_stop_status(thr)), thr->pid);
				if (ptrace(PTRACE_CONT, thr->pid, NULL,
					   (unsigned long)WSTOPSIG(thr_stop_status(thr))) < 0)
					err(1, "forwarding signal %d to child %d with ptrace",
					    WSTOPSIG(thr_stop_status(thr)), thr->pid);
				thr_resume(thr);
			}
		} else {
			fprintf(stderr, "unexpected waitpid status %x\n", thr_stop_status(thr));
			abort();
		}
	}
	return 0;
}

