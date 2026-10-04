/* SPDX-License-Identifier: GPL-3.0-only
 * Static VM fixture: its ELF constructor performs the first protected open.
 * Never installed as a desktop application or granted access on the host.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int result_path(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    close(fd);
    return 0;
}

static int result(void) { return result_path("/dev/dri/renderD129"); }

__attribute__((constructor)) static void first_open(void)
{
    printf("constructor %d %d\n", getpid(), result());
    fflush(stdout);
}

static void *thread_open(void *unused)
{
    (void)unused;
    printf("thread %d %d\n", getpid(), result());
    fflush(stdout);
    return NULL;
}

static void *thread_exec(void *argument)
{
    char *path = argument;
    execl(path, path, NULL);
    _exit(120);
}

int main(int argc, char **argv)
{
    (void)argc;
    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strcmp(line, "open")) {
            printf("open %d %d\n", getpid(), result());
        } else if (!strncmp(line, "open ", 5)) {
            printf("open %d %d\n", getpid(), result_path(line + 5));
        } else if (!strcmp(line, "fork")) {
            pid_t child = fork();
            if (child == 0) {
                printf("fork %d %d\n", getpid(), result());
                fflush(stdout);
                _exit(0);
            }
            if (child < 0 || waitpid(child, NULL, 0) < 0)
                return 121;
        } else if (!strcmp(line, "thread")) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, thread_open, NULL) || pthread_join(thread, NULL))
                return 122;
        } else if (!strcmp(line, "exec")) {
            execl(argv[0], argv[0], NULL);
            return 123;
        } else if (!strcmp(line, "thread-exec")) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, thread_exec, argv[0]))
                return 124;
            pthread_join(thread, NULL);
            return 125;
        } else if (!strncmp(line, "exec ", 5)) {
            execl(line + 5, line + 5, NULL);
            return 126;
        } else {
            return 127;
        }
        fflush(stdout);
    }
    return 0;
}
