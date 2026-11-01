/* emu_native.c -- native (C) hot paths for mocor_emu.py.
 *
 * Unicorn calls these callbacks directly (registered from Python with
 * uclib.uc_hook_add / uc_mmio_map and C function pointers), so no Python
 * frame, ctypes trampoline or GIL hand-off is paid per event unless the
 * access really needs a Python device model. Unicorn's own uc_reg_read /
 * uc_emu_stop are passed in at init as function pointers, so this DLL has no
 * link-time dependency on unicorn.dll.
 *
 * Build: python -m ziglang cc -shared -O2 -target x86_64-windows-gnu
 *            -o emu_native.dll emu_native.c
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

typedef int (*reg_read_fn)(void *uc, int regid, void *value);
typedef int (*emu_stop_fn)(void *uc);
/* Python device-model dispatch (ctypes CFUNCTYPE): returns the read value */
typedef uint64_t (*py_read_fn)(uint64_t addr, uint32_t size);
typedef void (*py_write_fn)(uint64_t addr, uint32_t size, uint64_t value);

/* Shared with Python (ctypes.Structure NativeState - keep in sync). */
typedef struct {
    volatile int32_t gic_waiting;   /* Python: an IRQ is pending, guest masked */
    volatile int32_t stop_cause;    /* C: 1 = stopped at the guest's unmask */
    uint64_t unmask_stops;
    uint64_t insn_now;              /* Python: insn_total at chunk start */
    uint64_t mmio_c_reads;          /* diagnostics: accesses served in C */
    uint64_t mmio_c_writes;
    uint64_t mmio_py_reads;         /* accesses forwarded to Python */
    uint64_t mmio_py_writes;
    uint64_t est;                   /* C: insns executed this chunk (estimate:
                                       2/5 insn per byte of each block run) */
} NativeState;

/* One mmio_map'ed device region. py: 1 = every access goes to the Python
 * models (then echoes the shadow), 0 = pure echo in C. */
typedef struct {
    uint64_t base, size;
    uint8_t *mem;
    int32_t py;
} Region;

#define MAX_REGIONS 64
static Region g_regions[MAX_REGIONS];
static int g_nregions;

static reg_read_fn g_reg_read;
static emu_stop_fn g_emu_stop;
static int g_reg_cpsr;
static NativeState *g_st;
static py_read_fn g_py_read;
static py_write_fn g_py_write;
/* free-running counter pages answered in C: [+4]/[+0xc] = insn_now * scale
 * (counter ticks per insn: SYST 1 MHz, sysfrt 32768 Hz - CTR_REALTIME) */
static uint64_t g_ctr_pages[4];
static double g_ctr_scale[4][2];   /* [page][0: +4, 1: +0xc] */
static int g_nctr;
static int g_ct;                 /* continuous counters on/off */

EXPORT void native_set_ct(int on) { g_ct = on; }

EXPORT void native_init(void *reg_read, void *emu_stop, int reg_cpsr, NativeState *st)
{
    g_reg_read = (reg_read_fn)reg_read;
    g_emu_stop = (emu_stop_fn)emu_stop;
    g_reg_cpsr = reg_cpsr;
    g_st = st;
}

EXPORT void native_set_py(void *rd, void *wr)
{
    g_py_read = (py_read_fn)rd;
    g_py_write = (py_write_fn)wr;
}

EXPORT void native_add_ctr_page(uint64_t page)
{
    if (g_nctr < 4) {
        g_ctr_scale[g_nctr][0] = g_ctr_scale[g_nctr][1] = 1.0;
        g_ctr_pages[g_nctr++] = page;
    }
}

EXPORT void native_set_ctr_scale(uint64_t page, double scale4, double scalec)
{
    for (int i = 0; i < g_nctr; i++)
        if (g_ctr_pages[i] == page) {
            g_ctr_scale[i][0] = scale4;
            g_ctr_scale[i][1] = scalec;
        }
}

/* Allocate a region's shadow; returns its index (user_data for the mmio
 * callbacks) or -1. The shadow pointer is fetched with native_region_mem. */
EXPORT int native_region_add(uint64_t base, uint64_t size, int py)
{
    if (g_nregions >= MAX_REGIONS)
        return -1;
    Region *r = &g_regions[g_nregions];
    r->mem = (uint8_t *)calloc(1, (size_t)size);
    if (!r->mem)
        return -1;
    r->base = base;
    r->size = size;
    r->py = py;
    return g_nregions++;
}

EXPORT uint8_t *native_region_mem(int idx) { return g_regions[idx].mem; }
EXPORT void native_region_set_py(int idx, int py) { g_regions[idx].py = py; }

static inline uint64_t shadow_get(const Region *r, uint64_t off, unsigned size)
{
    uint64_t v = 0;
    if (off + size <= r->size)
        memcpy(&v, r->mem + off, size);
    return v;
}

static inline void shadow_put(Region *r, uint64_t off, unsigned size, uint64_t v)
{
    if (off + size <= r->size)
        memcpy(r->mem + off, &v, size);
}

/* ---------------------------------------------------- C device models
 * Hot registers served without Python (counts per 42M insns before: ADI
 * ~106K, frame timer ~72K, SDHCI ~25K). Each mirrors the Python model it
 * replaces (mocor_emu.py): see the comment at each case. */
static int g_fast;                 /* fast models on/off */
static uint32_t g_adi_rid;         /* ADI doorbell request id */
static double g_wtl_ts_per_insn;   /* WTL_TS_PER_INSN */

EXPORT void native_set_fast(int on, double wtl_ts_per_insn)
{
    g_fast = on;
    g_wtl_ts_per_insn = wtl_ts_per_insn;
}
EXPORT uint32_t native_get_adi_rid(void) { return g_adi_rid; }
EXPORT void native_set_adi_rid(uint32_t rid) { g_adi_rid = rid & 0x7FFF; }

static Region *find_region(uint64_t addr)
{
    for (int i = 0; i < g_nregions; i++)
        if (addr >= g_regions[i].base && addr < g_regions[i].base + g_regions[i].size)
            return &g_regions[i];
    return 0;
}

static uint32_t dev_get32(uint64_t addr)
{
    Region *r = find_region(addr);
    return r ? (uint32_t)shadow_get(r, addr - r->base, 4) : 0;
}

static void dev_put32(uint64_t addr, uint32_t v)
{
    Region *r = find_region(addr);
    if (r)
        shadow_put(r, addr - r->base, 4, v);
}

static uint64_t now_insn(void)
{
    return g_st->insn_now + (g_ct ? g_st->est : 0);
}

/* returns 1 if handled (value in *out) */
static int fast_read(uint64_t addr, unsigned size, uint64_t *out)
{
    if (!g_fast || size != 4)
        return 0;
    /* ADI doorbell response (on_read 0x40600028-0x40600033): +0x2c data =
     * id<<16 | PMIC reg [0x40600000 | id<<2]; +0x30 = id<<16; else id<<2 */
    if (addr >= 0x40600028 && addr < 0x40600034) {
        uint32_t v;
        if (addr == 0x4060002c)
            v = (g_adi_rid << 16) | dev_get32(0x40600000 | ((g_adi_rid << 2) & 0xFFFF));
        else if (addr == 0x40600030)
            v = g_adi_rid << 16;
        else
            v = g_adi_rid << 2;
        *out = v;
        return 1;
    }
    /* LTE frame timer (_wtl_timer_read): lo[18:0] Ts in frame,
     * lo[31:19] frame[12:0], hi[18:0] frame[31:13]; 307200 Ts per frame */
    if (addr == 0xE0020010 || addr == 0xE0020014) {
        uint64_t t = (uint64_t)((double)now_insn() * g_wtl_ts_per_insn);
        uint64_t frame = t / 307200, ts = t % 307200;
        uint32_t lo = (uint32_t)(((frame & 0x1FFF) << 19) | ts);
        uint32_t hi = (uint32_t)((frame >> 13) & 0x7FFFF);
        dev_put32(0xE0020010, lo);
        dev_put32(0xE0020014, hi);
        *out = addr == 0xE0020010 ? lo : hi;
        return 1;
    }
    /* AP DMA channel CHN_PAUSE (0x20101000 + ch*0x40): bit2 PAUSE_STS
     * follows bit0 PAUSE_EN at once (the I2C/UART stop path pauses the
     * channel and polls bit2 forever) */
    if (addr >= 0x20101000 && addr < 0x20102000 && (addr & 0x3F) == 0) {
        uint32_t v = dev_get32(addr);
        v = (v & ~4u) | ((v & 1u) << 2);
        *out = v;
        return 1;
    }
    /* SDHCI CLK_CTRL (+0x2c per slot, _sdhci_read): bit1 stable = bit0 enable */
    if (addr >= 0x20300000 && addr < 0x20700000 && (addr & 0xFFFFF) == 0x2C) {
        uint32_t v = dev_get32(addr);
        v = (v & ~2u) | ((v & 1u) << 1);
        dev_put32(addr, v);
        *out = v;
        return 1;
    }
    return 0;
}

/* returns 1 if handled */
static int fast_write(uint64_t addr, unsigned size, uint64_t value)
{
    if (!g_fast)
        return 0;
    /* ADI doorbell request (on_write 0x40600020-0x4060002f): id = v[16:2] */
    if (addr >= 0x40600020 && addr < 0x40600030 && size == 4) {
        g_adi_rid = (uint32_t)(value >> 2) & 0x7FFF;
        dev_put32(addr, (uint32_t)value);
        return 1;
    }
    /* PMIC registers behind ADI (0x40608000-0x4060ffff): pure store; the
     * Python models own the ADC start register 0x40608404, the RTC
     * update/alarm/INT block 0x40608210-0x4060823f and the ANA int
     * controller 0x406080c0-0x406080cf (RTC_MODEL) */
    if (addr >= 0x40608000 && addr < 0x40610000 && addr != 0x40608404 &&
        !(addr >= 0x40608210 && addr < 0x40608240) &&
        !(addr >= 0x406080C0 && addr < 0x406080D0) && size == 4) {
        dev_put32(addr, (uint32_t)value);
        return 1;
    }
    /* frame-timer latch register: pure echo */
    if (addr == 0xE0020028 && size == 4) {
        dev_put32(addr, (uint32_t)value);
        return 1;
    }
    return 0;
}

/* uc_mmio_map read callback; user_data = (void*)(intptr_t)region index */
EXPORT uint64_t mmio_read_cb(void *uc, uint64_t offset, unsigned size, void *user_data)
{
    Region *r = &g_regions[(intptr_t)user_data];
    uint64_t addr = r->base + offset;
    uint64_t page = addr & ~(uint64_t)0xFFF;
    for (int i = 0; i < g_nctr; i++) {
        if (page == g_ctr_pages[i] && ((addr & 0xFFF) == 4 || (addr & 0xFFF) == 0xC)) {
            g_st->mmio_c_reads++;
            uint64_t t = g_st->insn_now + (g_ct ? g_st->est : 0);
            double sc = g_ctr_scale[i][(addr & 0xFFF) == 0xC];
            if (sc != 1.0)
                t = (uint64_t)((double)t * sc);
            return t & 0xFFFFFFFFu;
        }
    }
    uint64_t fv;
    if (fast_read(addr, size, &fv)) {
        g_st->mmio_c_reads++;
        return fv;
    }
    if (r->py && g_py_read) {
        g_st->mmio_py_reads++;
        return g_py_read(addr, size);
    }
    g_st->mmio_c_reads++;
    return shadow_get(r, offset, size);
}

EXPORT void mmio_write_cb(void *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data)
{
    Region *r = &g_regions[(intptr_t)user_data];
    if (fast_write(r->base + offset, size, value)) {
        g_st->mmio_c_writes++;
        return;
    }
    if (r->py && g_py_write) {
        g_st->mmio_py_writes++;
        g_py_write(r->base + offset, size, value);   /* Python stores + models */
        return;
    }
    g_st->mmio_c_writes++;
    shadow_put(r, offset, size, value);
}

/* Block-address dispatch: one C block hook replaces N bounded Python block
 * hooks (unicorn checks every bounded block hook on every executed block:
 * 24 hooks halved the speed). Sorted table, binary search per block, the
 * Python callback only runs on a match. */
typedef void (*py_block_fn)(uint64_t addr, uint32_t size);
static uint64_t *g_baddr;
static int g_nbaddr, g_cap;
static py_block_fn g_py_block;

EXPORT void native_set_py_block(void *fn) { g_py_block = (py_block_fn)fn; }

EXPORT void native_add_block_addr(uint64_t a)
{
    if (g_nbaddr == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 64;
        g_baddr = (uint64_t *)realloc(g_baddr, sizeof(uint64_t) * g_cap);
    }
    int i = g_nbaddr++;
    while (i > 0 && g_baddr[i - 1] > a) {   /* keep sorted */
        g_baddr[i] = g_baddr[i - 1];
        i--;
    }
    g_baddr[i] = a;
}

static inline int baddr_hit(uint64_t a)
{
    int lo = 0, hi = g_nbaddr - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (g_baddr[mid] == a)
            return 1;
        if (g_baddr[mid] < a)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return 0;
}

/* UC_HOOK_BLOCK over all code. While an IRQ waits for the guest to unmask,
 * stop at the first block that starts with CPSR.I clear (QEMU ends the TB
 * after cpsie / msr cpsr, so this is the instruction after the unmask). */
EXPORT void blk_unmask_cb(void *uc, uint64_t address, uint32_t size, void *user_data)
{
    NativeState *st = (NativeState *)user_data;
    uint32_t cpsr;
    st->est += (size * 2 + 4) / 5;     /* continuous time within a chunk */
    if (g_nbaddr && g_py_block && baddr_hit(address))
        g_py_block(address, size);
    if (!st->gic_waiting)
        return;
    g_reg_read(uc, g_reg_cpsr, &cpsr);
    if (!(cpsr & 0x80)) {
        st->gic_waiting = 0;
        st->stop_cause = 1;
        st->unmask_stops++;
        g_emu_stop(uc);
    }
}
