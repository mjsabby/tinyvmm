// dirwalk: walk directory trees in parallel using only readdir (d_type decides
// what to descend into, nothing is stat'ed), and report entries and time.
// Usage: dirwalk <threads> <root>...   Roots are dealt out to threads in turn.
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct job {
    char **roots;
    int nroots;
    long dirs, entries, errors;
};

static void walk(int parent, const char *name, struct job *j) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        j->errors++;
        return;
    }
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        j->errors++;
        return;
    }
    j->dirs++;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' && (e->d_name[1] == 0 || (e->d_name[1] == '.' && e->d_name[2] == 0)))
            continue;
        j->entries++;
        if (e->d_type == DT_DIR)
            walk(dirfd(d), e->d_name, j);
    }
    closedir(d);
}

static void *run(void *arg) {
    struct job *j = arg;
    for (int i = 0; i < j->nroots; i++)
        walk(AT_FDCWD, j->roots[i], j);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: dirwalk <threads> <root>...\n");
        return 2;
    }
    int nthreads = atoi(argv[1]);
    int nroots = argc - 2;
    if (nthreads < 1) nthreads = 1;
    if (nthreads > nroots) nthreads = nroots;
    struct job *jobs = calloc(nthreads, sizeof *jobs);
    for (int t = 0; t < nthreads; t++)
        jobs[t].roots = calloc(nroots, sizeof(char *));
    for (int i = 0; i < nroots; i++) {
        struct job *j = &jobs[i % nthreads];
        j->roots[j->nroots++] = argv[2 + i];
    }
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    pthread_t *th = calloc(nthreads, sizeof *th);
    for (int t = 0; t < nthreads; t++)
        pthread_create(&th[t], NULL, run, &jobs[t]);
    long dirs = 0, entries = 0, errors = 0;
    for (int t = 0; t < nthreads; t++) {
        pthread_join(th[t], NULL);
        dirs += jobs[t].dirs;
        entries += jobs[t].entries;
        errors += jobs[t].errors;
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double ms = (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
    printf("threads=%d dirs=%ld entries=%ld errors=%ld ms=%.1f\n", nthreads, dirs, entries, errors, ms);
    return errors != 0;
}
