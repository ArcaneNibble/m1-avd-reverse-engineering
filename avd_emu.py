import struct
from unicorn import *
from unicorn.arm_const import *

with open('avd-12.3-lilyD-fw.bin', 'rb') as f:
	FIRMWARE = f.read()

def read_magic_reg():
	print("READ MAGIC REG")
	return 0xdeadc0de

def write_magic_reg(val):
	print(f"WRITE {val:08x} TO MAGIC REG")

def read_magic_reg_2():
	print("READ MAGIC REG 2")
	return 0xcafebabe

def write_magic_reg_2(val):
	print(f"WRITE {val:08x} TO MAGIC REG 2")

MMIOS = {
	0xdeadaa00: (read_magic_reg, write_magic_reg),
	0xdeadaa04: (read_magic_reg_2, write_magic_reg_2),
}

MMIO_BLOCKS = [
	(0x50010000, 0x4000),	# CM3Ctrl
	(0xe000c000, 0x4000),	# SCS
]

emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
emu.mem_map(0, 0x10000)				# IRAM
emu.mem_map(0x10000000, 0x10000)	# DRAM

emu.mem_write(0, FIRMWARE)

def hook_mmio(emu_, access, addr, sz, value, data):
	if addr in MMIOS:
		if access == UC_MEM_READ:
			read_fn = MMIOS[addr][0]
			out_val = read_fn()
			emu_.mem_write(addr, struct.pack("<I", out_val))
		elif access == UC_MEM_WRITE:
			write_fn = MMIOS[addr][1]
			write_fn(value)
	else:
		pc = emu_.reg_read(UC_ARM_REG_PC)
		if access == UC_MEM_READ:
			print(f"UNKNOWN read @ PC {pc:08x} of size {sz} to register {addr:08x}")
		elif access == UC_MEM_WRITE:
			print(f"UNKNOWN write @ PC {pc:08x} of size {sz} to register {addr:08x} with value {value:08x}")

for (addr, len_) in MMIO_BLOCKS:
	emu.mem_map(addr, len_)
	emu.hook_add(UC_HOOK_MEM_READ, hook_mmio, begin=addr, end=addr + len_)
	emu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio, begin=addr, end=addr + len_)

initial_sp = struct.unpack("<I", FIRMWARE[0:4])[0]
initial_pc = struct.unpack("<I", FIRMWARE[4:8])[0]
print(f"Starting @ {initial_pc:08x} with SP {initial_sp:08x}")
emu.reg_write(UC_ARM_REG_SP, initial_sp)
emu.emu_start(initial_pc, 0)


print("~~~~~ HOPEFULLY HIT WFI ~~~~~")

