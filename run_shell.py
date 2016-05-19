#!/usr/bin/python
import ctypes
import argparse
 
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Path to binary shellcode file", default='', required=True)
    return parser.parse_args()

def main():
  args = parse_args()

  with open(args.input, 'rb') as f:
    shbin = f.read()

  shellcode = bytearray()
  shellcode.extend(shbin)

  ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
  buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
  ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))

  ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
   
  ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

if __name__ == '__main__':
  main()
