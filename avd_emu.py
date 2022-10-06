from unicorn import *
from unicorn.arm_const import *

code = b"\x4a\xf6\x04\x20\xcd\xf6\xad\x60\x01\x68\x01\x31\x01\x60"

emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
emu.mem_map(0, 0x10000)				# IRAM
emu.mem_map(0x10000000, 0x10000)	# DRAM

emu.mem_write(0, code)

def hook_mmio(emu_, access, addr, sz, value, data):
	if addr == 0xdeadaa00:
		if access == UC_MEM_READ:
			print("READ MAGIC REG")
			emu_.mem_write(0xdeadaa00, b'\xaa\xbb\xcc\xdd')
		elif access == UC_MEM_WRITE:
			print(f"WRITE MAGIC REG {value:08x}")
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
