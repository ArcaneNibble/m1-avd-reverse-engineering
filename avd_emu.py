import struct
from unicorn import *
from unicorn.arm_const import *

code = b"\x4a\xf6\x00\x20\xcd\xf6\xad\x60\x02\xc8\x01\x31\x01\x60"

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

emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
emu.mem_map(0, 0x10000)				# IRAM
emu.mem_map(0x10000000, 0x10000)	# DRAM

emu.mem_write(0, code)

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
		if access == UC_MEM_READ:
			print(f"UNKNOWN read of size {sz} to register {addr:08x}")
		elif access == UC_MEM_WRITE:
			print(f"UNKNOWN write of size {sz} to register {addr:08x} with value {value:08x}")

emu.mem_map(0xdead8000, 0x4000)
emu.hook_add(UC_HOOK_MEM_READ, hook_mmio, begin=0xdead8000, end=0xdeadc000)
emu.hook_add(UC_HOOK_MEM_WRITE, hook_mmio, begin=0xdead8000, end=0xdeadc000)


emu.emu_start(1, len(code))

print(hex(emu.reg_read(UC_ARM_REG_R0)))
