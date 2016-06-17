import os, sys
import argparse
import distorm3
import struct
import random

# constants

R_EAX = 0
R_ECX = 1
R_EDX = 2
R_EBX = 3
R_ESP = 4
R_EBP = 5
R_ESI = 6
R_EDI = 7

# globals

conf_min_steps = 1
conf_max_steps = 5

# classes

class _instr:
	def __init__(self, bytes, size, is_data):
		self.bytes = bytes
		self.size = size
		self.label = -1
		self.jmp_label = -1
		self.is_data = is_data

# functions

def is_rel_jmp(bytes):
	if len(bytes) >= 2:
		b = ord(bytes[0])
		bb = ord(bytes[1])
		if (b & 0xf0) == 0x70 or (b >= 0xe0 and b <= 0xe3) or b == 0xe8 or b == 0xe9 or b == 0xeb or (b == 0x0f and (bb & 0x80) == 0x80):
			return True
	return False

def get_jmp_bytes(bytes):
	b = ord(bytes[0])
	bb = ord(bytes[1])
	if (b & 0xf0) == 0x70 or (b >= 0xe0 and b <= 0xe3) or b == 0xeb:
		return 1
	elif b == 0xe8 or b == 0xe9 or (b == 0x0f and (bb & 0x80) == 0x80):
		return 4
	return 0

def get_jmp_delta(bytes):
	dl = get_jmp_bytes(bytes)
	if dl == 1:
		d = ord(bytes[1])
		if d >= 0x80:
			return (0x100-d)*(-1)
		else:
			return d
	elif dl == 4:
		fb = 1
		if ord(bytes[0]) == 0x0f:
			fb = 2
		d = int(bytes[fb:fb+4][::-1].encode('hex'), 16)
		if d > 0x80000000:
			return (0x100000000-d)*(-1)
		else:
			return d
	return 0
	
def get_signed_int(imm, nbytes):
	if nbytes == 1:
		d = imm
		if d >= 0x80:
			return (0x100-d)*(-1)
		else:
			return d
	elif nbytes == 2:
		d = imm
		if d >= 0x8000:
			return (0x10000-d)*(-1)
		else:
			return d		
	elif nbytes == 4:
		d = imm
		if d >= 0x80000000:
			return (0x100000000-d)*(-1)
		else:
			return d
	raise	
	
def get_rand_reg(exclude_regs):
	regs = range(R_EAX, R_EDI+1)
	for r in exclude_regs:
		if r in regs:
			regs.remove(r)
	if len(regs) > 0:
		return random.choice(regs)
	else:
		return -1

def mod_jmp_delta(bytes, delta):
	ret_bytes = ''
	js = get_jmp_bytes(bytes)
	dm = 0

	if -128 <= delta <= 127:

		if js == 1:
			ret_bytes += bytes[0]
			ret_bytes += struct.pack('<b', delta)
		elif js == 4:
			if ord(bytes[0]) == 0x0f: # jmp cond r32
				if delta < 0:
					dm = 6-2 # opcode len difference
				ret_bytes += chr( (ord(bytes[1]) & 0x0f) | 0x70)
				ret_bytes += struct.pack('<b', delta+dm)
			elif ord(bytes[0]) == 0xe8: # call
				ret_bytes += bytes[0]
				ret_bytes += struct.pack('<i', delta)
			elif ord(bytes[0]) == 0xe9: # jmp
				if delta < 0:
					dm = 5-2 # opcode len difference
				ret_bytes += chr(0xeb)
				ret_bytes += struct.pack('<b', delta+dm)
			else:
				raise

	else:

		if js == 1:
			if (ord(bytes[0]) & 0xf0) == 0x70: # jmp cond short
				if delta < 0:
					dm = 2-6 # opcode len difference
				ret_bytes += chr(0x0f) + chr( (ord(bytes[0]) & 0x0f) | 0x80)
				ret_bytes += struct.pack('<i', delta+dm)
			elif ord(bytes[0]) == 0xeb: # jmp short
				if delta < 0:
					dm = 2-5
				#print 'dm:', dm
				ret_bytes += chr(0xe9)
				ret_bytes += struct.pack('<i', delta+dm)
			else:
				raise
		elif js == 4:
			if ord(bytes[0]) == 0x0f:
				ret_bytes += chr(0x0f) + bytes[1]
				ret_bytes += struct.pack('<i', delta)
			else:
				ret_bytes += bytes[0]
				ret_bytes += struct.pack('<i', delta)

	return ret_bytes

# parses the instruction bytes and divides them into sections
def parse_instr_bytes(bytes):
	prefix = opcode = modrm = sib = disp = imm = ''
	sib_bytes = 0
	disp_bytes = 0
	
	# prefix
	fl = 0
	for b in bytes:
		if ord(b) in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0x9b, 0xf0, 0xf1, 0xf2, 0xf3]:
			prefix += b
			fl += 1
		else:
			break
			
	# opcode
	if ord(bytes[fl]) == 0x0f: # 2 byte opcode
		opcode = bytes[fl:fl+1]
		fl += 2
	else:
		opcode = bytes[fl]
		fl += 1
		
	# modrm
	modrm = bytes[fl]
	fl += 1
	
	mod = (ord(modrm) & 0xc0) >> 6
	rm = (ord(modrm) & 0x07)
	if mod==0:
		if rm==0x05: # 32-bit displacement only
			disp_bytes = 4
	elif mod==1:
		disp_bytes = 1 # disp8
	elif mod==2:
		disp_bytes = 4 # disp32

	if rm==0x04:
		sib_bytes = 1
		
	#print 'sib_bytes:', sib_bytes
	#print 'disp_bytes:', disp_bytes
	
	# sib	
	if sib_bytes == 1:
		sib = bytes[fl]
		fl += 1
	
	# disp
	if disp_bytes > 0:
		disp = bytes[fl:fl+disp_bytes]
		fl += disp_bytes
	
	# imm
	imm = bytes[fl:]
	
	return prefix, opcode, modrm, sib, disp, imm

# mov reg, imm
def obf_gen_mov_reg_imm(reg, imm, nbytes):
	ret_bytes = ''
	if nbytes == 1:
		opcode = 0xb0
	else:
		opcode = 0xb8

	if nbytes == 2:
		ret_bytes += chr(0x66)
	ret_bytes += chr(opcode + reg)
	if nbytes == 1:
		ret_bytes += struct.pack('<B', imm)
	elif nbytes == 2:
		ret_bytes += struct.pack('<H', imm)
	elif nbytes == 4:
		ret_bytes += struct.pack('<I', imm)
	return ret_bytes
	
# push reg
def obf_gen_push_reg(reg):
	ret_bytes = ''
	opcode = 0x50 # push reg
	ret_bytes += chr(opcode + reg)
	return ret_bytes

# pop reg
def obf_gen_pop_reg(reg):
	ret_bytes = ''
	opcode = 0x58 # pop reg
	ret_bytes += chr(opcode + reg)
	return ret_bytes

# mov reg, [reg+reg]
def obf_gen_mov_reg_reg_disp(reg_dst, reg_src, reg_disp, reg_bytes, prefix):
	ret_bytes = ''
	if reg_bytes==1:
		opcode = 0x8a # mov r8, [reg+reg]
	else:
		opcode = 0x8b # mov r32, [reg+reg]
	modrm = (reg_dst << 3) + 0x04 # sib mode
	sib = reg_src + (reg_disp << 3)
	if reg_bytes == 2:
		ret_bytes += chr(0x66)
	if prefix > 0:
		ret_bytes += chr(prefix)
	ret_bytes += chr(opcode) + chr(modrm) + chr(sib)
	return ret_bytes
	
# mov reg, [reg*X+reg]
def obf_gen_lea_reg_sib_reg(reg_dst, sib_base, sib_index, sib_scale):
	ret_bytes = ''
	opcode = 0x8d # lea r32, mem
	modrm = (reg_dst << 3) + 0x04 # sib mode
	sib = sib_base + (sib_index << 3) + (sib_scale << 6)
	ret_bytes += chr(opcode) + chr(modrm) + chr(sib)
	return ret_bytes

# mov [esp+disp], reg
def obf_gen_mov_esp_disp_reg(disp, reg_src):
	ret_bytes = ''
	opcode = 0x89 # mov mem, reg
	if -128 <= disp <= 127:
		nbytes = 1
		modrm = 0x01 << 6
	else:
		nbytes = 4
		modrm = 0x02 << 6
	modrm += (reg_src << 3) + 0x04 # sib mode
	sib = (R_ESP << 3) + R_ESP # [esp]
	
	ret_bytes += chr(opcode) + chr(modrm) + chr(sib)
	if nbytes == 1:
		ret_bytes += chr(disp)
	elif nbytes == 4:
		ret_bytes += struct.pack('<I', disp)
	return ret_bytes 

def obf_gen_calc_reg_imm(name, reg, imm, nbytes):
	ret_bytes = ''

	opcode = 0x81 # 81 xxx r32, imm32
	modrm = 0
	if nbytes == 1:
		opcode += 1 # 82 xxx r8, imm8
	
	if name == 'add':
		modrm = 0xc0 + reg
	elif name == 'sub':
		modrm = 0xe8 + reg
	elif name == 'xor':
		modrm = 0xf0 + reg

	if nbytes == 2:
		ret_bytes += chr(0x66)
	ret_bytes += chr(opcode) + chr(modrm)
	if nbytes == 1:
		ret_bytes += struct.pack('<B', imm)
	elif nbytes == 2:
		ret_bytes += struct.pack('<H', imm)
	elif nbytes == 4:
		ret_bytes += struct.pack('<I', imm)
	return ret_bytes

def obf_gen_reg_calc(reg, imm, steps, nbytes):
	ret = []
	cimm = imm
	calc = []

	if steps == 0:
		return cimm, ret

	if nbytes == 1:
		mask = 0xff
	elif nbytes == 2:
		mask = 0xffff
	elif nbytes == 4:
		mask = 0xffffffff

	for i in range(0,steps):
		if nbytes == 1:
			rimm = random.randint(0,0xff)
		elif nbytes == 2:
			rimm = random.randint(0,0xffff)
		elif nbytes == 4:
			rimm = random.randint(0,0xffffffff)
		req = random.choice(['add', 'sub', 'xor'])
		if req == 'add':
			cimm = (cimm - rimm) & mask
		elif req == 'sub':
			cimm = (cimm + rimm) & mask
		elif req == 'xor':
			cimm = (cimm ^ rimm) & mask
		calc.insert( 0, (req, reg, rimm) )

	#print 'imm:', hex(imm)
	#print 'cimm', hex(cimm)
	for op in calc:
		#print op[0], op[1], hex(op[2])
		b = obf_gen_calc_reg_imm(op[0], op[1], op[2], nbytes)
		#print_string_hex(b)
		#print ''
		ret.append(b)

	return cimm, ret

def obf_mov_reg_imm(sl, ni):
	imm = 0
	reg = 0
	nbytes = 0
	i = sl[ni]
	if ord(i.bytes[0]) in range(0xb0,0xb8): # mov r8, imm8
		imm = ord(i.bytes[1])
		reg = ord(i.bytes[0]) - 0xb0
		nbytes = 1
	elif ord(i.bytes[0]) == 0x66 and ord(i.bytes[1]) in range(0xb8,0xc0): # mov r16, imm16
		imm = int(i.bytes[1:1+2][::-1].encode('hex'), 16)
		reg = ord(i.bytes[1]) - 0xb8
		nbytes = 2
	elif ord(i.bytes[0]) in range(0xb8,0xc0): # mov r32, imm32
		imm = int(i.bytes[1:1+4][::-1].encode('hex'), 16)
		reg = ord(i.bytes[0]) - 0xb8
		nbytes = 4
	#print 'imm:', imm

	cimm, il = obf_gen_reg_calc(reg, imm, random.randint(conf_min_steps, conf_max_steps), nbytes)
	lbl = i.label

	shell_delete_bytes(sl, ni)
	shell_insert_bytes(sl, ni, obf_gen_mov_reg_imm(reg, cimm, nbytes), lbl)
	of = ni+1
	iadd = 0
	for l in il:
		shell_insert_bytes(sl, of, l)
		of += 1
		iadd += 1
	iadd += 1
	return iadd

def obf_mov_reg_reg_imm_disp(sl, ni):
	disp = reg_dst = reg_dst = reg_index = reg_scale = disp_bytes = -1
	
	i = sl[ni]
	
	reg_bytes = 4
	prefix = 0
	
	fl = 0
	if ord(i.bytes[fl]) == 0x66:
		reg_bytes = 2
		fl += 1
	if ord(i.bytes[fl]) in [0x64, 0x26, 0x2e, 0x36, 0x3e, 0x65, 0xf0, 0xf2, 0xf3]: # known prefixes
		prefix = ord(i.bytes[fl])
		fl += 1
	if ord(i.bytes[fl]) == 0x8a:
		reg_bytes = 1
	
	modrm = ord(i.bytes[fl+1])
	mod = (modrm & 0xc0)
	if mod == 0x80:
		disp_bytes = 4
	elif mod == 0x40:
		disp_bytes = 1
	else:
		raise
	
	reg_dst = (modrm & 0x38) >> 3
	if modrm & 0x07 == 0x04: # sib present
		sib = ord(i.bytes[fl+2])
		reg_src = (sib & 0x07)
		reg_index = (sib & 0x38) >> 3
		reg_scale = (sib & 0xc0) >> 6
		if disp_bytes == 1:
			disp = get_signed_int(ord(i.bytes[fl+3]), 1)
		elif disp_bytes == 4:
			disp = int(i.bytes[fl+3:fl+3+4][::-1].encode('hex'), 16)
	else:
		reg_src = (modrm & 0x07)
		if disp_bytes == 1:
			disp = get_signed_int(ord(i.bytes[fl+2]), 1)
		elif disp_bytes == 4:
			disp = int(i.bytes[fl+2:fl+2+4][::-1].encode('hex'), 16)
			
	#print 'reg_dst:', reg_dst, 'reg_src:', reg_src, 'disp:', disp, 'reg_index:', reg_index, 'reg_scale:', reg_scale
		
	exc_regs = [reg_dst, reg_src, R_ESP, R_EBP]
	if reg_index >= 0:
		exc_regs.append(reg_index)
		
	treg = get_rand_reg(exc_regs)
	#print 'treg:', treg
	if treg == -1:
		raise

	cimm, il = obf_gen_reg_calc(treg, disp, random.randint(conf_min_steps, conf_max_steps), 4)
	lbl = i.label
	
	shell_delete_bytes(sl, ni)
	shell_insert_bytes(sl, ni, obf_gen_push_reg(treg), lbl)
	
	shell_insert_bytes(sl, ni+1, obf_gen_mov_reg_imm(treg, cimm, 4))
	iadd = 1
	of = ni+2
	for l in il:
		shell_insert_bytes(sl, of, l)
		of += 1
		iadd += 1
	
	if reg_index >= 0 and reg_scale >= 0:
		shell_insert_bytes(sl, of, obf_gen_lea_reg_sib_reg(treg, treg, reg_index, reg_scale))
		of += 1
		iadd += 1
	shell_insert_bytes(sl, of, obf_gen_mov_reg_reg_disp(reg_dst, reg_src, treg, reg_bytes, prefix))
	shell_insert_bytes(sl, of+1, obf_gen_pop_reg(treg))
	iadd += 2
	iadd += 1
	return iadd
	
def obf_push_imm(sl, ni):
	imm = 0
	i = sl[ni]
	
	if ord(i.bytes[0]) == 0x6a: # push imm8
		imm = ord(i.bytes[1])
	elif ord(i.bytes[0]) == 0x68: # push imm32
		imm = int(i.bytes[1:1+4][::-1].encode('hex'), 16)
		
	exc_regs = [R_ESP, R_EBP]
	treg = get_rand_reg(exc_regs)

	cimm, il = obf_gen_reg_calc(treg, imm, random.randint(conf_min_steps, conf_max_steps), 4)
	lbl = i.label
	
	shell_delete_bytes(sl, ni)
	shell_insert_bytes(sl, ni, obf_gen_push_reg(get_rand_reg([])), lbl)
	shell_insert_bytes(sl, ni+1, obf_gen_push_reg(treg))

	shell_insert_bytes(sl, ni+2, obf_gen_mov_reg_imm(treg, cimm, 4))
	iadd = 2	
	of = ni+3
	for l in il:
		shell_insert_bytes(sl, of, l)
		of += 1
		iadd += 1

	shell_insert_bytes(sl, of, obf_gen_mov_esp_disp_reg(4, treg))
	shell_insert_bytes(sl, of+1, obf_gen_pop_reg(treg))
	iadd += 2
	iadd += 1
	return iadd

def obf_oper_reg_imm(sl, ni):
	imm = 0
	iadd = 0
	i = sl[ni]
	
	_prefix, _opcode, _modrm, _sib, _disp, _imm = parse_instr_bytes(i.bytes)
	
	exc_regs = [R_ESP, R_EBP]
	if len(_imm) == 1:
		exc_regs.append(R_ESI)
		exc_regs.append(R_EDI)
		
	if len(_sib) > 0:
		exc_regs.append((ord(_sib) & 0x38) >> 3)
		exc_regs.append(ord(_sib) & 0x07)
	else:
		exc_regs.append(ord(_modrm) & 0x07)
	
	treg = get_rand_reg(exc_regs)

	opcode = ord(_opcode)
	mode = (ord(_modrm) & 0x38) >> 3

	if len(_imm) > 0:
		if len(_imm) == 1:
			if opcode == 0x80:
				imm = ord(_imm)
			elif opcode in [0x82, 0x83]:
				imm = get_signed_int(ord(_imm), 1)
			else:
				raise
		else:
			imm = int(_imm[::-1].encode('hex'), 16)
		
		cimm, il = obf_gen_reg_calc(treg, imm, random.randint(conf_min_steps, conf_max_steps), 4)
		lbl = i.label
		
		shell_delete_bytes(sl, ni)
		shell_insert_bytes(sl, ni, obf_gen_push_reg(treg), lbl)
		
		shell_insert_bytes(sl, ni+1, obf_gen_mov_reg_imm(treg, cimm, 4))
		iadd = 1
		of = ni+2
		for l in il:
			shell_insert_bytes(sl, of, l)
			of += 1
			iadd += 1
			
		nopcode = 0
		if mode == 0: # add
			if opcode in [0x80, 0x82]:
				nopcode = 0x00
			elif opcode in [0x81, 0x83]:
				nopcode = 0x01
		elif mode == 1: # or
			if opcode in [0x80, 0x82]:
				nopcode = 0x08
			elif opcode in [0x81, 0x83]:
				nopcode = 0x09
		elif mode == 2: # adc
			if opcode in [0x80, 0x82]:
				nopcode = 0x10
			elif opcode in [0x81, 0x83]:
				nopcode = 0x11
		elif mode == 3: # sbb
			if opcode in [0x80, 0x82]:
				nopcode = 0x18
			elif opcode in [0x81, 0x83]:
				nopcode = 0x19
		elif mode == 4: # and
			if opcode in [0x80, 0x82]:
				nopcode = 0x20
			elif opcode in [0x81, 0x83]:
				nopcode = 0x21
		elif mode == 5: # sub
			if opcode in [0x80, 0x82]:
				nopcode = 0x28
			elif opcode in [0x81, 0x83]:
				nopcode = 0x29
		elif mode == 6: # xor
			if opcode in [0x80, 0x82]:
				nopcode = 0x30
			elif opcode in [0x81, 0x83]:
				nopcode = 0x31
		elif mode == 7: # cmp
			if opcode in [0x80, 0x82]:
				nopcode = 0x38
			elif opcode in [0x81, 0x83]:
				nopcode = 0x39
				
		nmodrm = (ord(_modrm) & 0xc7) | (treg << 3)
		ninstr = _prefix + chr(nopcode) + chr(nmodrm) + _sib + _disp
		shell_insert_bytes(sl, of, ninstr)

		shell_insert_bytes(sl, of+1, obf_gen_pop_reg(treg))
		iadd += 2
		iadd += 1

	return iadd

def obf_instr(sl, ni):
	i = sl[ni]
	fi = 0
	iadd = 0
	for b in i.bytes[fi]:
		if ord(b) in [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0x9b, 0xf0, 0xf1, 0xf2, 0xf3]: # known prefixes
			fi += 1
		else:
			break

	if ord(i.bytes[fi]) >= 0xb0 and ord(i.bytes[fi]) <= 0xbf: # mov reg, imm
		#print 'mov reg,imm:', ni
		iadd = obf_mov_reg_imm(sl, ni)
	elif ord(i.bytes[fi]) == 0x6a or ord(i.bytes[fi]) == 0x68: # push imm
		#print 'push imm:', ni
		iadd = obf_push_imm(sl, ni)
	elif (ord(i.bytes[fi]) == 0x8b or ord(i.bytes[fi]) == 0x8a) and (ord(i.bytes[fi+1]) & 0xC0) in [0x40, 0x80]: # mov reg, [reg+disp]
		#print 'mov reg, [reg+disp]:', ni
		iadd = obf_mov_reg_reg_imm_disp(sl, ni)
	elif ord(i.bytes[fi]) in [0x80, 0x81, 0x82, 0x83]: # <add, or, adc, sbb, and, sub, xor, cmp> reg, imm
		#print '<add/or/adc/sbb/and/sub/xor/cmp> reg, imm:', ni
		iadd = obf_oper_reg_imm(sl, ni)
	return iadd

def do_obfuscate(sl):
	ni = 0
	iadd = 0
	for i in sl:
		if iadd==0 and i.is_data==0:
			iadd += obf_instr(sl, ni) # iadd will receive the number of added instructions that we need to skip afterwards 
		if iadd>0:
			iadd -= 1
		ni += 1

def insert_bad_byte(sl, ni):
	bb = random.choice([0x68, 0x81, 0x83, 0xe8, 0xe9, 0xea, 0xd8, 0xd9, 0xda, 0xdc, 0xde, 0xf7])
	shell_insert_data(sl, ni, chr(bb)) 

def do_mangle_flow(sl, level):
	ret = []
	ni = 0
	ki = 0
	jmps = 0
	jlab = get_next_label(sl)
	for i in sl:
		if i.is_data==0:
			if len(ret)>0 and random.randint(0,10) <= level:
				# do jump
				to_label = i.label
				if to_label == -1:
					to_label = jlab
					jlab += 1
				shell_insert_bytes(ret, ki, '\xeb\x00', -1, to_label)
				insert_bad_byte(ret, ki+1)

				ki = random.randint(0,len(ret)-1)
				while ki<len(ret) and ret[ki].is_data==1: # make sure to not inject jumps where data resides
					ki = random.randint(0,len(ret))

				jmp_label = -1
				ji = ki
				if ki < len(ret):
					jmp_label = ret[ji].label
				if jmp_label == -1:
					jmp_label = jlab
					if ji < len(ret):
						ret[ji].label = jlab
					jlab += 1
				shell_insert_bytes(ret, ki, '\xeb\x00', -1, jmp_label)
				shell_insert_bytes(ret, ki+1, i.bytes, to_label, i.jmp_label)
				ki += 2
				jmps += 1
			else:
				# no jump, just insert an instruction at current position
				shell_insert_bytes(ret, ki, i.bytes, i.label, i.jmp_label)
				ki += 1
		else:
			shell_insert_data(ret, ki, i.bytes)
			ki += 1

	for ni in range(0,len(ret)-1):
		recalc_jmps(ret, ni)

	return ret

def get_instr_i_by_offset(sl, offset):
	off = 0
	ni = 0
	for i in sl:
		if off == offset:
			return ni
		ni+=1
		off+=i.size
	return -1

def get_instr_i_by_label(sl, label_i):
	ni = 0
	for i in sl:
		if i.label == label_i:
			return ni
		ni += 1
	return -1

def get_next_label(sl):
	label_i = -1
	for i in sl:
		if i.label > label_i:
			label_i = i.label
	return label_i+1

def calc_jmp(sl, fromi, toi):
	d = 0
	if fromi < toi:
		mini = fromi+1
		maxi = toi
		dr = 1
	else:
		mini = toi
		maxi = fromi+1
		dr = -1

	for ni in range(mini,maxi):
		d += sl[ni].size
	return d*dr

def parse_shell(sl):
	offset = 0
	si = 0
	label_i = 0
	for i in sl:
		if i.is_data==0 and is_rel_jmp(i.bytes):
			d = get_jmp_delta(i.bytes)
			jmp_off = offset+i.size+d

			ni = get_instr_i_by_offset(sl, jmp_off)
			if ni > -1:
				if sl[ni].label == -1:
					sl[ni].label = label_i
					label_i += 1
				li = sl[ni].label
				i.jmp_label = li

			jmpi = get_instr_i_by_label(sl, i.jmp_label)
			cd = calc_jmp(sl, si, jmpi)
		si += 1
		offset += i.size

def fix_shell(sl):
	# replace problematic instructions
	ni = 0
	for i in sl:
		if i.is_data==0:
			if ord(i.bytes[0]) == 0xe2: # loop
				shell_insert_bytes(sl, ni, '\x49', i.label) # dec ecx
				shell_replace_bytes(sl, ni+1, '\x75\x00', -1, i.jmp_label) # jnz
				fix_jmp(sl, ni+1)
			if ord(i.bytes[0]) == 0xe3: # jecxz
				shell_insert_bytes(sl, ni, '\x85\xc9', i.label) # text ecx, ecx
				shell_replace_bytes(sl, ni+1, '\x74\x00', -1, i.jmp_label) # jz
				fix_jmp(sl, ni+1)
			if ord(i.bytes[0]) in [0xe0, 0xe1]:
				li = i.label
				jmpi = i.jmp_label
				nextl = get_next_label(sl)

				fjmp = '\x75\x00'
				if ord(i.bytes[0]) == 0xe1:
					fjmp = '\x74\x00'

				shell_delete_bytes(sl, ni)

				jlab = nextl+1

				shell_insert_bytes(sl, ni, '\x75\x00', li, nextl)
				shell_insert_bytes(sl, ni+1, '\x49')
				shell_insert_bytes(sl, ni+2, '\x74\x00', -1, jlab)
				shell_insert_bytes(sl, ni+3, '\xe9\x00\x00\x00\x00', -1, jmpi)
				shell_insert_bytes(sl, ni+4, '\x49', nextl)
				shell_insert_bytes(sl, ni+5, '\x90', jlab)

				fix_jmp(sl, ni)
				fix_jmp(sl, ni+2)
				fix_jmp(sl, ni+3)

		ni += 1

def shell_insert_bytes(sl, ni, bytes, label = -1, jmp_label = -1):
	l = distorm3.Decode(0, bytes, distorm3.Decode32Bits)
	tsize = 0
	for (offset, size, instr, hexdump) in l:
		i = _instr(bytes[offset:offset+size], size, 0)
		i.label = label
		i.jmp_label = jmp_label

		sl.insert(ni, i)
		ni += 1
		tsize += size
	recalc_jmps(sl, ni)

def shell_insert_data(sl, ni, bytes):
	i = _instr(bytes[:], len(bytes), 1)
	sl.insert(ni, i)
	recalc_jmps(sl, ni)

def shell_replace_bytes(sl, ni, bytes, label = -1, jmp_label = -1):
	i = sl[ni]
	i.bytes = bytes
	i.size = len(bytes)
	i.label = label
	i.jmp_label = jmp_label
	recalc_jmps(sl, ni)

def shell_delete_bytes(sl, ni):
	sl.remove(sl[ni])
	recalc_jmps(sl, ni)

def fix_jmp(sl, ni):
	i = sl[ni]
	if is_rel_jmp(i.bytes):
		jmpi = get_instr_i_by_label(sl, i.jmp_label)
		if jmpi >= 0:
			cd = calc_jmp(sl, ni, jmpi)
			rd = get_jmp_delta(i.bytes)
			#print 'cd:', cd, 'rd:', rd
			if cd != rd:
				nbytes = mod_jmp_delta(i.bytes, cd)
				ldiff = len(i.bytes)-len(nbytes)
				i.bytes = nbytes
				i.size = len(nbytes)
				if ldiff != 0:
					recalc_jmps(sl, ni)

def recalc_jmps(sl, ni):
	nni = 0
	for i in sl:
		if i.jmp_label >= 0:
			jmpi = get_instr_i_by_label(sl, i.jmp_label)
			if jmpi >= 0:
				#print 'jmpi:', jmpi, 'ni:', ni, 'nni:', nni
				if (jmpi <= ni and ni <= nni) or (jmpi >= ni and ni >= nni):
					cd = calc_jmp(sl, nni, jmpi)
					rd = get_jmp_delta(i.bytes)
					if cd != rd:
						nbytes = mod_jmp_delta(i.bytes, cd)
						ldiff = len(i.bytes)-len(nbytes)
						i.bytes = nbytes
						i.size = len(nbytes)
						if ldiff != 0:
							recalc_jmps(sl, nni)
		nni += 1

def load_shell(bin, range):
	ret = []

	rbin = []
	ibin = []

	if range != '':
		cr = 0
		for r in range.split(','):
			rr = r.split('-')
			br = int(rr[0])
			er = int(rr[1])
			if br > cr:
				rbin.append( bin[cr:br] )
				ibin.append(1)
			rbin.append(bin[br:er])
			ibin.append(0)
			cr = er
		if cr == 0:
			rbin.append(bin[:])
			ibin.append(0)
		elif cr < len(bin):
			rbin.append(bin[cr:])
			ibin.append(1)
	else:
		rbin.append(bin[:])
		ibin.append(0)

	i=0
	for t in rbin:
		i+=1

	i=0
	for rb in rbin:
		if ibin[i]==0:
			l = distorm3.Decode(0, rb, distorm3.Decode32Bits)
			for (offset, size, instr, hexdump) in l:
				ret.append( _instr(rb[offset:offset+size], size, 0) )
		else:
			ret.append( _instr(rb[:], len(rb), 1) )
		i+=1

	parse_shell(ret)
	return ret[:]

def write_shell(sl):
	ret = ''
	for i in sl:
		ret += i.bytes
	return ret

def print_disasm(sl):

	ni = 0
	ioff = 0
	for i in sl:
		if i.is_data == 0:
			#if i.label >= 0 or i.jmp_label >= 0:
			#	print 'label:', i.label, 'jmp_label:', i.jmp_label
			l = distorm3.Decode(ioff, i.bytes, distorm3.Decode32Bits)
			for (offset, size, instr, hexdump) in l:
				print '%-4i %.8x: %-32s %s' % (ni, offset, hexdump, instr)
				ni += 1
				ioff += size
		else:
			print '%-4i %.8x:' % (ni, ioff),
			print_string_hex(i.bytes)
			print ''
			ioff += i.size

def print_debug(sl):

	offset = 0
	for i in sl:
		print '%08x:' % (offset),
		print_string_hex(i.bytes)
		if i.label > -1:
			print 'label:', i.label
		if i.jmp_label > -1:
			print 'jmp_to:', i.jmp_label,
		print ''
		offset += i.size

def print_string_hex(str):
	for c in str:
		print "%02x" % ord(c),

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--input", help="Input binary shellcode file", default='', required=True)
	parser.add_argument("-o", "--output", help="Output obfuscated binary shellcode file", default='', required=True)
	parser.add_argument("-r", "--range", help="Ranges where code instructions reside (e.g. 0-184,188-204)", default='')
	parser.add_argument("-p", "--passes", help="How many passes should the obfuscation process go through (def. 1)", default=1, type=int)
	parser.add_argument("-f", "--mixflow", help="Specify level of execution flow mixing (0-10) (def. 5)", default=5, type=int)
	return parser.parse_args()

def main():
	args = parse_args()

	with open(args.input, 'rb') as f:
		shbin = f.read()

	sl = load_shell(shbin, args.range)
	print_disasm(sl)
	fix_shell(sl)
	print ''
	for i in range(1,args.passes+1):
		print 'Obfuscation pass:', i
		do_obfuscate(sl)
	
	if args.mixflow > 0:
		sl = do_mangle_flow(sl, args.mixflow)

	print ''
	print_disasm(sl)

	obin = write_shell(sl)
	with open(args.output, 'wb') as f:
		f.write(obin)

if __name__ == '__main__':
	main()
