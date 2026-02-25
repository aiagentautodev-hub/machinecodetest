NASM = /c/Users/User/AppData/Local/bin/NASM/nasm.exe
GOLINK = /c/Users/User/AppData/Local/bin/GoLink/GoLink.exe

all: pe2.exe

pe2.obj: pe2.asm
	$(NASM) -f win32 pe2.asm -o pe2.obj

pe2.exe: pe2.obj
	$(GOLINK) /console /entry Start pe2.obj kernel32.dll user32.dll
	python3 -c "import struct; f=open('pe2.exe','r+b'); f.seek(0x3C); o=struct.unpack('<I',f.read(4))[0]; f.seek(o+0x5C); f.write(struct.pack('<H',3)); f.close(); print('Patched to Console subsystem')"

clean:
	rm -f pe2.obj pe2.exe
