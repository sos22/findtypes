#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
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

#define PRELOAD_LIB_NAME "/local/scratch/sos22/findtypes/ft.so"
#define PTRACE_OPTIONS (PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK)

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
	struct breakpoint *bp;
	struct thread new_thr;

	/* Wait for the kernel to attach it to us */
	if (ptrace(PTRACE_GETEVENTMSG, thr->pid, NULL, &new_pid) < 0)
		err(1, "PTRACE_GETEVENTMSG() for fork");
	status = get_stop_status(new_pid, &thr->process->pws);
	if (!WIFSTOPPED(status))
		errx(1, "unexpected status %x for fork", status);

	/* Hack: fake up a thread structure so that we have something
	 * to pass to store_byte */
	bzero(&new_thr, sizeof(new_thr));
	new_thr.pid = new_pid;
	list_foreach(&thr->process->breakpoints, bp, list_process)
		store_byte(&new_thr, bp->addr, bp->old_content);

	/* Detach it and let it go */
	if (ptrace(PTRACE_DETACH, new_pid) < 0)
		err(1, "detaching forked child");

	msg(10, "%d forked %zd, ignoring...\n", thr->pid, new_pid);
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
	resume_child(head_thr);

	/* Get the break address */
	r = read(child->from_child_fd, &child->malloc_root_addr,
		 sizeof(child->malloc_root_addr));
	if (r != sizeof(child->malloc_root_addr))
		err(1, "reading child's malloc root address");

	/* Close out our file descriptors to set it going properly. */
	close(child->from_child_fd);
	close(child->to_child_fd);

	return child;
}

static void
change_investigated_type(struct process *p)
{
	printf("Should change investigated type about now.\n");
}

int
main(int argc, char *argv[])
{
	struct process *child;
	struct thread *head_thr;
	int arg_index;

	on_exit(maybe_dump_debug_ring, NULL);
	signal(SIGABRT, (void (*)(int))dump_debug_ring);

	errno = argp_parse(&argp, argc, argv, 0, &arg_index, NULL);
	if (errno)
		err(1, "parsing arguments");

	child = start_process(argv + arg_index);

	/* Give it a few seconds to get through any initialisation
	 * code. */
	sleep(5);

	/* wait() and friends don't have convenient timeout arguments,
	   and doing it with signals is a pain, so just have a child
	   process which sleeps 60 seconds and then exits. */
	child->timeout_pid = fork();
	if (child->timeout_pid == 0) {
		dsleep(10);
		_exit(0);
	}

	while (1) {
		struct thread *thr;
		bool nothing_ready;

		if (child->timeout_fired) {
			int status;

			head_thr = list_first(&child->threads, struct thread, list);
			status = head_thr->_stop_status;
			if (status == -1)
				pause_child(head_thr);

			change_investigated_type(child);

			if (status == -1)
				unpause_child(head_thr);

			child->timeout_fired = false;
			child->timeout_pid = fork();
			if (child->timeout_pid == 0) {
				dsleep(10);
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
		} else if (WIFSTOPPED(thr_stop_status(thr)) &&
			   WSTOPSIG(thr_stop_status(thr)) == SIGSTOP) {
			/* Sometimes get these spuriously when
			 * attaching to a new thread or as a resule of
			 * pause_thread().  Ignore. */
			resume_child(thr);
		} else if (WIFSTOPPED(thr_stop_status(thr))) {
			msg(20, "Sending signal %d to child %d\n",
			    WSTOPSIG(thr_stop_status(thr)), thr->pid);
			if (ptrace(PTRACE_CONT, thr->pid, NULL,
				   (unsigned long)WSTOPSIG(thr_stop_status(thr))) < 0)
				err(1, "forwarding signal %d to child %d with ptrace",
				    WSTOPSIG(thr_stop_status(thr)), thr->pid);
			thr_resume(thr);
		} else {
			fprintf(stderr, "unexpected waitpid status %x\n", thr_stop_status(thr));
			abort();
		}
	}
	return 0;
}

