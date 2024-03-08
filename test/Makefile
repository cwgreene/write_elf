exit_9.exe: exit_9.asm
	nasm -f bin exit_9.asm
	python3 ../write_elf.py --assembly exit_9 exit_9.exe
	chmod +x exit_9.exe
