Yixuan Wang(yixua003) Qicheng Shi(shixx752) Ruoyan Kong (kong0135)

1. What mistakes in the source code bcmta.c make the exploit possible?
	In the process_local_rcpt function, if the user has a .forward file, it will use all of the entries in it as recipient without checking what's actually in it. And the function just take the content of the .forward file (after symbol |) as the recipients' address(path).	
	And in the delivery_msg function, At the beginning, the dropped_priv is initialized to 0. But After this part:	
	
	if (type == RCPT_CMD && !dropped_priv) {
	    assert(rcpts[i].uid != 0 && rcpts[i].uid != -1);
	    if (drop_priv_temp(rcpts[i].uid) != -1)
		dropped_priv = 1;
	}
	the dropped_priv is triggered but never reseted in the any other part of this program, which means the following process who
	send email to RCPT_CMD type recipient who can not be able to run the drop_priv_temp to set its euid. And there the euid (effective uid) will be reset to 0 (root) in this part:
	if (dropped_priv) {
	    int res = restore_priv();
	    assert(res != -1);
	}
Then this part can run the 2nd /bin/rootshell in .forward as root:
	} else if (type == RCPT_CMD) {
	    mbox_fp = popen(rcpts[i].path, "w");
fprintf(mbox_fp, "%s\n", msg_lines[line]);



2. explain how you constructed your inputs
Out input: 
	1.  echo $'|/bin/rootshell\n|/bin/rootshell' > ~/.forward
	2.  (echo -e ".")| bcmta -f student -t student@localhost
	
	1:	Create a .forward file under the home directory and write '|/bin/rootshell\n|/bin/rootshell' into this file.
	2:	bcmta -f student -t student@localhost : Send an email from student to local user. (echo -e ".")  : input

3. Explain step-by-step what happens when an ordinary user runs exploit.sh.
Firstly, a .forward file will be created under home directory with the context "|/bin/rootshell\n|/bin/rootshell" .
Then the bcmta program is run to send email from student to student@localhost and, since there is a .forward file, the program will use all of the entries in it as recipient.
So it will send "/bin/rootshell" twice to the studen@loca. For the first time, since the euid is set to the user's uid, it cannot run the rootshell.
For the second time, because the dropped_priv is not reseted, the euid remains to 0(root). Therefore, the program can access the rootshell successfully.

