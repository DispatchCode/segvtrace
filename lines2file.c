#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char HELP[] =
	"lines2file - Read lines from stdin and write them to a file.\n"
	"Helper for log rotation because it ensures lines are written fully.\n"
	"\n"
	"Usage: lines2file <output-file>\n"
	"\n"
	"Reads lines from standard input and writes them to <output-file>,\n"
	"which is opened in append mode.\n"
	"\n"
	"Signals:\n"
	"  SIGUSR1, SIGHUP  - finish current line, close and reopen the file\n"
	"  SIGINT,  SIGTERM  - finish current line, close the file, exit\n"
	"\n"
	"The current line is always completed before the file descriptor is\n"
	"closed, so the output file never ends with a partial line.\n";


static volatile sig_atomic_t reopen_flag;
static volatile sig_atomic_t exit_flag;

static void handle_reopen(int sig)
{
	(void)sig;
	reopen_flag = 1;
}

static void handle_exit(int sig)
{
	(void)sig;
	exit_flag = 1;
}

/* Write all bytes, retrying on short writes and EINTR. */
static int write_all(int fd, const char *buf, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static int open_output(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (fd < 0)
		fprintf(stderr, "lines2file: open %s: %s\n", path,
			strerror(errno));
	return fd;
}

/*
 * Finish the current (incomplete) line by reading one byte at a time from
 * stdin and writing each byte to outfd.  Returns 0 on success (line
 * completed or EOF reached), -1 on fatal error.
 */
static int finish_line(int outfd)
{
	for (;;) {
		char c;
		ssize_t n = read(STDIN_FILENO, &c, 1);
		if (n == 1) {
			if (write_all(outfd, &c, 1) < 0) {
				fprintf(stderr, "lines2file: write: %s\n",
					strerror(errno));
				return -1;
			}
			if (c == '\n')
				return 0;
		} else if (n == 0) {
			/* EOF — nothing more to read. */
			return 0;
		} else if (errno == EINTR) {
			/* Stay in the loop; we must finish the line. */
			continue;
		} else {
			fprintf(stderr, "lines2file: read: %s\n",
				strerror(errno));
			return -1;
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc == 2 && (strcmp(argv[1], "-h") == 0 ||
			  strcmp(argv[1], "--help") == 0)) {
		fputs(HELP, stdout);
		return 0;
	}
	if (argc != 2) {
		fputs(HELP, stderr);
		return 1;
	}

	const char *path = argv[1];

	/* Install signal handlers without SA_RESTART so that read()
	   returns EINTR when a signal is delivered. */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0; /* no SA_RESTART */

	sa.sa_handler = handle_reopen;
	if (sigaction(SIGUSR1, &sa, NULL) < 0 ||
	    sigaction(SIGHUP, &sa, NULL) < 0) {
		fprintf(stderr, "lines2file: sigaction: %s\n",
			strerror(errno));
		return 1;
	}

	sa.sa_handler = handle_exit;
	if (sigaction(SIGINT, &sa, NULL) < 0 ||
	    sigaction(SIGTERM, &sa, NULL) < 0) {
		fprintf(stderr, "lines2file: sigaction: %s\n",
			strerror(errno));
		return 1;
	}

	int outfd = -1;
	while(!exit_flag)
	{
		outfd = open_output(path);
		if (outfd < 0)
			return 1;

		bool midline = false; /* if the last byte written was not '\n' */
		char buf[4096];

		for (;;) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

			if (n > 0) {
				if (write_all(outfd, buf, (size_t)n) < 0) {
					fprintf(stderr, "lines2file: write: %s\n",
						strerror(errno));
					close(outfd);
					return 1;
				}
				midline = (buf[n - 1] != '\n');
			} else if (n == 0) {
				/* EOF on stdin. */
				exit_flag = 1;
				break;
			} else if (errno != EINTR) {
				fprintf(stderr, "lines2file: read: %s\n",
					strerror(errno));
				close(outfd);
				return 1;
			}
			/* On EINTR (n < 0, errno == EINTR) we fall through to
			   check the signal flags below. */

			if (exit_flag || reopen_flag) {
				// If finish_line hits EOF, we'll hit it again when we read the next time.
				if (midline && finish_line(outfd) < 0) {
					close(outfd);
					return 1;
				}
				if (close(outfd) < 0) {
					fprintf(stderr, "lines2file: close: %s\n",
						strerror(errno));
					return 1;
				}
				outfd = -1;
				reopen_flag = 0;
				break;
			}
		}
	}

	if (outfd != -1 && close(outfd) < 0) {
		fprintf(stderr, "lines2file: close: %s\n", strerror(errno));
		return 1;
	}
	return 0;
}
