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

# classes

class _instr:
	def __init__(self, bytes, size, is_data):
		self.bytes = bytes
		self.size = size
		self.label = -1
		self.jmp_label = -1
		self.is_data = is_data

# functions

def print_string_hex(str):
	for c in str:
		print "%02x" % ord(c),

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Input binary shellcode file", default='', required=True)
    parser.add_argument("-o", "--output", help="Output obfuscated binary shellcode file", default='', required=True)
    parser.add_argument("-r", "--range", help="Ranges where code instructions reside (e.g. 0-184,188-204)", default='')
    return parser.parse_args()

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

	cimm, il = obf_gen_reg_calc(reg, imm, random.randint(1,5), nbytes)
	lbl = i.label

	shell_delete_bytes(sl, ni)
	shell_insert_bytes(sl, ni, obf_gen_mov_reg_imm(reg, cimm, nbytes), lbl)
	of = ni+1
	for l in il:
		shell_insert_bytes(sl, of, l)
		lbl = -1
		of += 1

def obf_instr(sl, ni):
	i = sl[ni]
	fi = 0
	if ord(i.bytes[0]) == 0x66: # 16bit
		fi = 1

	if ord(i.bytes[fi]) >= 0xb0 and ord(i.bytes[fi]) <= 0xbf: # mov reg, imm
		print 'mov reg,imm:', ni
		obf_mov_reg_imm(sl, ni)
	if ord(i.bytes[fi]) == 0x6a or ord(i.bytes[fi]) == 0x68: # push imm
		print 'push imm:', ni

def do_obfuscate(sl):
	ni = 0
	for i in sl:
		if i.is_data==0:
			obf_instr(sl, ni)
		ni += 1	

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

				#jlab = -1
				#if len(sl) > ni:
				#	jlab = sl[ni].label
				#if jlab == -1: jlab = nextl+1
				jlab = nextl+1

				shell_insert_bytes(sl, ni, '\x75\x00', li, nextl)
				shell_insert_bytes(sl, ni+1, '\x49')
				shell_insert_bytes(sl, ni+2, '\x74\x00', -1, jlab)
				shell_insert_bytes(sl, ni+3, '\xe9\x00\x00\x00\x00', -1, jmpi)
				shell_insert_bytes(sl, ni+4, '\x49', nextl)
				shell_insert_bytes(sl, ni+5, '\x90', jlab)

				#sl[ni+5].label = jlab

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
			#print 'from', int(rr[0]), 'to', int(rr[1])
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
		#print len(t), ':', ibin[i]
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


def main():
	args = parse_args()

	with open(args.input, 'r') as f:
		shbin = f.read()

	sl = load_shell(shbin, args.range)
	print_disasm(sl)
	fix_shell(sl)
	do_obfuscate(sl)

	print ''
	print_disasm(sl)

	obin = write_shell(sl)
	with open(args.output, 'w') as f:
		f.write(obin)

if __name__ == '__main__':
	main()
