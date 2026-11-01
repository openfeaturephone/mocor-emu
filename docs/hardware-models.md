# Hardware models

What `mocor_emu.py` models, per block, and how sure I am of each. Every model has a module-level
switch in `mocor_emu.py` (the names in brackets), and the switches are recorded in checkpoints so a
load warns when they differ. VA = physical for everything here: the emulator runs MMU-off with a
flat map.

## Memory map and image loading

- The kernel partition is loaded the way FDL2 loads it: the whole partition, DHTB header included,
  at 0x80a05e00, so file offset F is VA 0x80a05e00 + F (`KBASE` 0x80a05e38 = file 0x38). An early
  version of this used a base 0x70 lower, which broke every absolute pointer in the low SYSRAM blob
  (the two tools in `tools/` still use it, see their headers).
- Reset entry 0x80a061f0 (file 0x3f0). OS main is 0x814c34a5 (Thumb).
- The image-load scatter table at 0x815a937c (10 records `{src, dst, size, handler}`) is executed in
  Python at load (`preload_modules`): 0x81496d48 = LZ decompress (`decomp_lz.py` is a port), 0x81496dac
  = memcpy, 0x81496dc8 = zero-fill. The walker entry 0x81496d14 is then NOPed.
- **mmi_app goes at 0x88000000 with file offset 0**, DHTB header included (`MMI_PRELOAD`). Check:
  42 of the 59 kernel PLT veneer targets (0x80fc46dc-0x80fc4bfc) land on a `push` with that base,
  none with the 0x200 header stripped. Before mmi_app was loaded at all, every veneer ran zeros,
  and a pile of early "cut" hooks (`CELL_CUTS`) existed only to step around that. Run with
  `--no-cell-cuts`.
- On the phone mmi_app 0x88000000-0x88efffff is demand-paged read-only by the kernel's pager. Here it
  is plain RAM. `plat/mmu.py` reads the guest page tables to tell you what the phone would fault on.

## Interrupts and time

- **GIC-400** (`GIC_MODEL`): distributor 0x12001000, CPU interface 0x12002000. Sources set PENDING; an
  IRQ is taken only when CPSR.I is clear. GICC_IAR acks the lowest pending+enabled id, GICC_EOIR ends
  it. While masked, the native block hook stops the chunk at the first block with I clear, so the IRQ
  lands right after the guest's own `cpsie`. Before the kernel programs the GIC
  (`[0x817b1d38+4] == 0`) the dispatcher reads the id from RAM 0x0c and delivery is forced.
- **The OS tick is GIC id 0x3d** (kernel table irq 0x1d, TB_AP_TMR0_INT, handler 0x80a0b3c5), not
  0x20. 0x20 is table irq 0, which is not registered, and the dispatcher runs off its table into a
  garbage handler.
- **AP TMR0** at 0x40220000, 32768 Hz (`AP_TMR_MODEL`): LOAD lo +0 / hi +4, CTRL +0x10 (bit0
  periodic, bit1 run, bit16 64-bit), INT +0x14 (bit0 enable, bit3 clear), value +0x18. ThreadX here
  is tickless: when idle it programs a one-shot up to the next timer (seen: 0x10000 = 2 s) and
  credits the whole period on the IRQ.
- **Virtual time** is instructions at 200 MIPS (`tick_rate` 200000 insns per ms). SYST 0x40230000
  (+4/+0xc) counts milliseconds, sysfrt 0x40040000 counts at 32768 Hz (`CTR_REALTIME`). WFI ends
  the chunk and fast-forwards to the next due IRQ (`WFI_WAKE`).
- LTE frame timer at 0xe0020010/14 (`WTL_TIMER`): lo[18:0] = Ts in frame, lo[31:19] = frame[12:0],
  hi[18:0] = frame[31:13]; 30.72 MHz Ts, 307200 Ts per 10 ms frame.

## Power, clocks, PMIC

- **PMU** (`PMU_MODEL`): PMU_APB 0x402b0000 and AON_APB 0x402e0000 have SET (+0x1000) and CLEAR
  (+0x2000) alias banks that act on the base register. Power status 0x402b00c0/c4/d4 is derived from
  the domain request bits. The reset state (`PMU_RESET`) is what a live phone reads: whale die
  unpowered, every island status field 7 (OFF).
- **ADI / PMIC** (SC2720 behind ADI 0x40600000, PMIC registers at +0x8000): the ADI doorbell and the
  PMIC register store are in C. Doorbell polarity, from the two poll loops: read helper treats
  bit31 set as busy, and the echo in [31:16] must equal the request address [16:2].
- **PMIC ADC** (`PMIC_ADC`): conversions complete at once with a mid-scale value 0x800. Not a real
  battery reading.
- **PMIC eFuse** (`PMIC_EFUSE_READY`): status 0x40608314 reads done; data reads 0 (placeholder).
- **RTC** (`RTC_MODEL`): time/alarm update writes (0x40608210-0x4060822c) complete at once and set
  INT_RAW 0x40608234; INT_CLR 0x40608238 is W1C. The RTC is PMIC interrupt 1 in the ANA controller
  0x406080c0, PMIC dispatcher at GIC id 0x46 (level). Without it the MMI task sat in the RTC
  set-time wait forever.
- **HW spinlock** 0x33000000 (`HWSPINLOCK`): lock n at +0x800+4n. A read returns 0 and takes a free
  lock, 1 while held; writing 0x55aa10c5 releases it.

## Storage and resources

- **SNF/NANDC** 0x21a00000: Python model reading from `nand_full.bin` if you provide it. Early boot
  only; it is the slowest model (about 141K accesses before 20M insns).
- **NV** (`NV_REAL`): the NV container never mounts (the FFS named-device registry is empty in
  emulation), so NV_Init's two loader calls are patched to succeed, and NV_Read (0x80a107e8),
  NV_GetLength (0x80a10b1e) and NV_Write (0x80a107f8) are answered from your nvcal partition first,
  then the RunningNV journal (most common checksum-valid copy). Writes stay in memory.
- **mmi_res** (`RES_MODEL`): the kernel's MMIRES read 0x80c370dc (r0 dst, r1 offset, r2 len) is
  served from `mmi_res.bin`. The resource header is read at about 200M insns, so a checkpoint made
  without it paints a black idle screen forever.
- **SDHCI** 0x20300000 + slot<<20 (`SDHCI_MODEL`): CLK_CTRL +0x2c bit1 (stable) follows bit0;
  present-state stays 0, so no card.

## Display

- **LCDC** 0x20800000 (`LCDC_MODEL`): a run (CTRL bit3 0->1) completes the frame at once: raw
  +0x11c bit0 set, run bit clears, level IRQ at GIC 0x33 while raw & enable (+0x110). Raw bit1 (panel
  TE) reads set, because the LCD ESD task busy-polls it with the IRQ masked and outranks the MMI task.
- `plat/fb.py` composes the layers into PNGs: address registers hold address>>2; OSD1 0x20, OSD2
  0x50, OSD3 0x80, OSD4 0xb0, IMG 0xe0. OSD2 format nibble 3 is ARGB8888 (alpha-blended). Partial
  updates are blitted at the kernel LCD driver's pending rect (0x817ce248+0x15c, u16 left/top/w/h),
  which is in no LCDC register. Frames that start with ctrl 0x19 are skipped; that rule and the
  overlay-only pass are inferred, not checked on the phone.
- `display_model.py` is an older panel/i80 DCS model layered on top of a restored emulator (ST7789
  RDDID 85 85 52 85, LCM 0x20a00000 busy pulses).

## Keypad

`plat/keypad.py`: KPD controller 0x40250000, GIC id 0x44 (table irq 0x24). int_raw +0x08 bit s =
press in slot s, bit 4+s = release; key_status +0x2c byte s = `(B << 4) | A` for keymap index
`A*8+B`. On the real phone key_status is never 0: idle slots read 0x77, a slot keeps its last
scan byte, and bit 7 is set only while the key is down (rest 0x77777731 on mine). The plugin models
that. The ISR is 0x81179eae, the ROM keymap 0x814ccb74. RED/power is on EIC and not modelled.

## Radio side (stubs, not emulation)

No DSP or CM4 core is emulated. The stubs answer the AP's handshakes:

- **Mailbox** 0x400a0000 (`CP_STUB`): AP->CP doorbells are logged as SIPC smsg `{ch, type, flag,
  value}`. An OPEN from the CM4 side channels 4 and 5 gets the peer OPEN and the sbuf attach reply.
  CP->AP FIFO at 0x400a8000, IRQ GIC 0x65.
- **GSM DSP** (`DSP_STUB`): once released (AON 0x402e0254 = 1), polls of the run word
  `0x800e0000+0x19670+0x634` read 1, and the published rf_open/rf_close fields get placeholder values.
- **LTE XDSP** boot: the copy-and-pulse sequence at 0xe047f000/0xe04ff000 completes and the ready
  words are set.
- **LTE ADX rings** (`LTE_ADX_STUB`): DSP->AP response ring at AP IRAM 0xe478 (12 entries of
  `u16 type, u16 len, u32 addr`, data at addr+0xfbec), AP->DSP command ring at 0xe400 (8 entries,
  data at 0xe4e0+offset), doorbell = DSP counter 0x11d08 plus a mailbox message from core 3. A
  version report (type 5) unblocks `LTE_adx_InitInterface`. Requests are auto-confirmed with id+1
  and a zeroed payload. A synthesized cell (EARFCN 1300, PCI 1) gets through the band sweep
  (0x70 -> 0x72) and RRC asks for sync (0x74), whose real reply id/layout I never identified.
  So the phone never camps: the network stays at "Searching".
- **RF transceiver** (`RF_MODEL`): RFTI 0x40070000 serial port to the SR3532 as a register file.
  `RF_CHIP_ID` 0x6c0 is the first id the driver accepts, not a value read from hardware.
- **SIM** (`SIM_MODEL`): controllers SIM0 0x70f00000 (card inserted, GIC 0x2a) and SIM1 0x71000000
  (empty, GIC 0x2d), and a T=0 UICC in `vsim.py` with test identities (IMSI 001010123456789, PLMN
  001-01, PIN off). The full USIM init passes; the card then idles with STATUS polls.
- **I2C** 0x70500000/0x70600000/0x70700000 (`I2C_MODEL`): empty bus, every write NACKed, reads 0.

## MMU (plat/mmu.py)

The page tables, read from a checkpoint at idle: TTBR0 0x81600049, TTBCR 0, DACR 0x55555555 (all
client), SCTLR 0xc5107e (**A = 1**: alignment checking on).

| VA | Phone access |
|---|---|
| 0x00000000-0x00000fff | vectors, read-only |
| 0x00001000-0x000fffff | RW |
| 0x00100000-0x7fffffff | MMIO, strongly ordered |
| 0x80000000-0x809fffff | RW, normal uncached |
| 0x80a00000-0x815fffff | kernel image, read-only |
| 0x81600000-0x816fffff | page tables, RW, XN |
| 0x81700000-0x82ffffff | kernel data, heaps, stacks, loaded apps |
| 0x83000000-0x87ffffff | unmapped |
| 0x88000000-0x88efffff | mmi_app, demand paged, read-only + exec |
| 0x88f00000-0xcfffffff | unmapped (the emulator's scratch at 0x8b03xxxx and 0x8fxxxxxx is here) |
| 0xd0000000-0xefffffff | MMIO |

The phone's data-abort handler (0x80a06544 -> 0x811b7048) accepts only FSR&7 == 7 (pager faults).
Anything else, including an alignment fault, goes to the dump/reset path; a permission fault on a
paged region livelocks in the pager.
