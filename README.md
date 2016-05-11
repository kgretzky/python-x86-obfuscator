## X86 Shellcode Obfuscator

This is a **WIP** tool that performs shellcode obfuscation in x86 instruction set.
If you want to learn more, check out my blog where I explain how it works:

[X86 Shellcode Obfuscation - Part 1](https://breakdev.org/)

#### Requirements

Tool requires distorm3 library, which you can easily install with `pip`:
```
pip install distorm3
```

#### Usage

```
usage: x86obf.py [-h] -i INPUT -o OUTPUT [-r RANGE]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input binary shellcode file
  -o OUTPUT, --output OUTPUT
                        Output obfuscated binary shellcode file
  -r RANGE, --range RANGE
                        Ranges where code instructions reside (e.g.
                        0-184,188-204)
```

**Example 1:**
```
python x86obf.py -i shellcode\test1.bin -o output.bin
```

**Example 2:**
```
python x86obf.py -i shellcode\exec_calc.bin -o output.bin -r 0-184
```

**Example 3:**
```
python x86obf.py -i shellcode\msg_box.bin -o output.bin -r 0-196
```

If you want to run and test any obfuscated or not obfuscated shellcode, you can use the attached `run_shell.py` script:
```
python run_shell.py -i shellcode\exec_calc.bin
```
