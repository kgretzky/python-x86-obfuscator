## X86 Shellcode Obfuscator

This is a **WIP** tool that performs shellcode obfuscation in x86 instruction set.
If you want to learn more, check out my blog where I explain how it works:

[X86 Shellcode Obfuscation - Part 1](https://breakdev.org/x86-shellcode-obfuscation-part-1/)

[X86 Shellcode Obfuscation - Part 2](https://breakdev.org/x86-shellcode-obfuscation-part-2/)

[X86 Shellcode Obfuscation - Part 3](https://breakdev.org/x86-shellcode-obfuscation-part-3/)

#### Requirements

Tool requires distorm3 library, which you can easily install with `pip`:
```
pip install distorm3
```

#### Usage

```
usage: x86obf.py [-h] -i INPUT -o OUTPUT [-r RANGE] [-p PASSES] [-f MIXFLOW]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input binary shellcode file
  -o OUTPUT, --output OUTPUT
                        Output obfuscated binary shellcode file
  -r RANGE, --range RANGE
                        Ranges where code instructions reside (e.g.
                        0-184,188-204)
  -p PASSES, --passes PASSES
                        How many passes should the obfuscation process go
                        through (def. 1)
  -f MIXFLOW, --mixflow MIXFLOW
                        Specify level of execution flow mixing (0-10) (def. 5)
```

**Example 1:**
```
python x86obf.py -i shellcode\test1.bin -o output.bin
```

**Example 2:**
```
python x86obf.py -i shellcode\exec_calc.bin -o output.bin -r 0-184
python x86obf.py -i shellcode\exec_calc.bin -o output.bin -r 0-184 -p 4
python x86obf.py -i shellcode\exec_calc.bin -o output.bin -r 0-184 -p 2 -f 10
```

**Example 3:**
```
python x86obf.py -i shellcode\msg_box.bin -o output.bin -r 0-196
```

If you want to run and test any obfuscated or not obfuscated shellcode, you can use the attached `run_shell.py` script:
```
python run_shell.py -i shellcode\exec_calc.bin
```
