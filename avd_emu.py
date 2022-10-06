from unicorn import *
from unicorn.arm_const import *

code = b"\x4a\xf6\x00\x20\xcd\xf6\xad\x60\x01\x68\x01\x31\x01\x60"

emu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
emu.mem_map(0, 0x10000)				# IRAM
emu.mem_map(0x10000000, 0x10000)	# DRAM

emu.mem_write(0, code)

def hook_r(emu_, access, addr, sz, value, data):
	print("HOOK R!")
	print(access)
	print(hex(addr))
	print(hex(sz))
	print(hex(value))
	print(data)
	emu_.mem_write(0xdeadaa00, b'\xaa\xbb')
def hook_w(emu_, access, addr, sz, value, data):
	print("HOOK W!")
	print(access)
	print(hex(addr))
	print(hex(sz))
	print(hex(value))
	print(data)
emu.mem_map(0xdead8000, 0x4000)
emu.hook_add(UC_HOOK_MEM_READ, hook_r, begin=0xdead8000, end=0xdeadc000)
emu.hook_add(UC_HOOK_MEM_WRITE, hook_w, begin=0xdead8000, end=0xdeadc000)


emu.emu_start(1, len(code))

print(hex(emu.reg_read(UC_ARM_REG_R0)))
