/* Badly Coded Mail Transfer Agent BCMTA, a product of Badly Coded,
   Inc. */

/* This is an example insecure program for CSci 5271 only: don't copy
   code from here to any program that is supposed to work
   correctly! */

/* This is version 2.0,    for exploits due 9/20/2019 */

long bcmta_version = 200; /* 2.0 */

#define _GNU_SOURCE /* For e.g., setresuid */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#define MAX_LINE 2048
#define MAX_HOST 256
#define MAX_ADDR 512
#define MAX_RCPTS 128
#define MAX_LINES 25000
#define MAX_NAME 32

#define SPOOL_DIR "/var/mail"
#define LOG_PATH SPOOL_DIR "/bcmta.log"

/* strlcpy: secure version of strcpy(), copied from OpenBSD */
/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0 && --n != 0) {
                do {
                        if ((*d++ = *s++) == 0)
                                break;
                } while (--n != 0);
        }

        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }

        return(s - src - 1);    /* count does not include NUL */
}

/* The next three functions are modelled after the "Setuid
   Demystified" paper,
   c.f. https://www.usenix.org/conference/11th-usenix-security-symposium/setuid-demystified */

#define ERROR_SYSCALL (-1)

int drop_priv_temp(uid_t new_uid)
{
  if (setresuid(-1, new_uid, geteuid()) < 0)
    return ERROR_SYSCALL;
  if (geteuid() != new_uid)
    return ERROR_SYSCALL;
  return 0;
}

int drop_priv_perm(uid_t new_uid)
{
  uid_t ruid, euid, suid;
  if (setresuid(new_uid, new_uid, new_uid) < 0)
    return ERROR_SYSCALL;
  if (getresuid(&ruid, &euid, &suid) < 0)
    return ERROR_SYSCALL;
  if (ruid != new_uid || euid != new_uid || suid != new_uid)
    return ERROR_SYSCALL;
  return 0;
}

int restore_priv()
{
  uid_t ruid, euid, suid;
  if (getresuid(&ruid, &euid, &suid) < 0)
    return ERROR_SYSCALL;
  if (setresuid(-1, suid, -1) < 0)
    return ERROR_SYSCALL;
  if (geteuid() != suid)
    return ERROR_SYSCALL;
  return 0;
}

char *my_hostname = "localhost";
char sender_hostname[MAX_HOST] = "";
char mail_from[MAX_ADDR] = "";

enum rcpt_type {
    RCPT_MBOX,
    RCPT_CMD,
    RCPT_ROOTSHELL,
    RCPT_FILE,
};

struct rcpt_info {
    enum rcpt_type type;
    int uid;
    char name[MAX_NAME];
    char addr[MAX_ADDR];
    char path[MAX_ADDR];
};

struct rcpt_info rcpts[MAX_RCPTS];
int num_rcpts = 0;

char *msg_lines[MAX_LINES];
int num_lines = 0;

void clear_msg_state(void) {
    int i;
    sender_hostname[0] = 0;
    mail_from[0] = 0;
    num_rcpts = 0;
    for (i = 0; i < num_lines; i++) {
	free(msg_lines[i]);
	msg_lines[i] = 0;
    }
    num_lines = 0;
}

void print_msg(void) {
    int i;
    printf("Message env-from %s at %s with %d recipient(s) and %d lines.\n",
	   mail_from, sender_hostname, num_rcpts, num_lines);
    for (i = 0; i < num_rcpts; i++) {
	printf("Envelope-To: %s\n", rcpts[i].addr);
    }
    printf("Message text:\n");
    for (i = 0; i < num_lines; i++) {
	printf("%s\n", msg_lines[i]);
    }
}

/* The default log format is loosely inspired by that used by Exim, c.f.
   https://www.exim.org/exim-html-current/doc/html/spec_html/ch-log_files.html
*/

const char default_log_fmt[] = "%1$s <= %2$s\n%1$s => %3$s\n";
const char *logging_fmt = default_log_fmt;

void log_delivery(struct rcpt_info *r) {
    FILE *fh;
    time_t the_time;
    struct tm time_tm;
    char time_buf[200];
    char fmt_buf[200];
    the_time = time(0);
    localtime_r(&the_time, &time_tm);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S",
	     &time_tm);
    fh = fopen(LOG_PATH, "a");
    if (!fh) {
	fprintf(stderr, "Failed to open log file %s: %s\n",
		LOG_PATH, strerror(errno));
	exit(1);
    }
    strlcpy(fmt_buf, logging_fmt, sizeof(fmt_buf));
    fprintf(fh, logging_fmt, time_buf, mail_from, r->addr);
    fclose(fh);
}

int dropped_priv = 0;

void deliver_msg(void) {
    int i;
    for (i = 0; i < num_rcpts; i++) {
	struct passwd *pw = 0;
	FILE *mbox_fp;
	int line = 0;
	enum rcpt_type type = rcpts[i].type;
	if (type == RCPT_CMD && !dropped_priv) {
	    assert(rcpts[i].uid != 0 && rcpts[i].uid != -1);
	    if (drop_priv_temp(rcpts[i].uid) != -1)
		dropped_priv = 1;
	}
	if (type == RCPT_ROOTSHELL) {
	    mbox_fp = popen("/bin/sh", "w");
	    while (line < num_lines && msg_lines[line][0])
		line++;
	    if (line < num_lines && !msg_lines[line][0])
		line++;
	} else if (type == RCPT_CMD) {
	    mbox_fp = popen(rcpts[i].path, "w");
	} else if (type == RCPT_FILE) {
	    mbox_fp = fopen(rcpts[i].path, "a");
	} else if (type == RCPT_MBOX) {
	    time_t the_time;
	    struct tm time_tm;
	    char time_buf[200];
	    int res;
	    pw = getpwuid(rcpts[i].uid);
	    assert(pw);
	    res = chdir(SPOOL_DIR);
	    assert(!res);
	    mbox_fp = fopen(pw->pw_name, "a");
	    assert(mbox_fp);
	    the_time = time(0);
	    localtime_r(&the_time, &time_tm);
	    strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %T %z",
		     &time_tm);
	    fprintf(mbox_fp, "From %s %s\n", mail_from, time_buf);
	} else {
	    assert(0);
	}
	for (; line < num_lines; line++) {
	    fprintf(mbox_fp, "%s\n", msg_lines[line]);
	}
	fprintf(mbox_fp, "\n");
	if (type == RCPT_ROOTSHELL || type == RCPT_CMD) {
	    pclose(mbox_fp);
	} else if (type == RCPT_MBOX) {
	    fclose(mbox_fp);
	    chmod(pw->pw_name, 0600);
	    chown(pw->pw_name, rcpts[i].uid, -1);
	} else if (type == RCPT_FILE) {
	    fclose(mbox_fp);
	} else {
	    assert(0);
	}
	if (dropped_priv) {
	    int res = restore_priv();
	    assert(res != -1);
	}
	log_delivery(&rcpts[i]);
    }
}

void term_copy(char *to, const char *from, char term, int maxlen) {
    char local_buf[MAX_ADDR];
    char *buf, *to_buf;
    int i = 0;
    if (maxlen <= MAX_LINE) {
	buf = local_buf;
    } else {
	buf = malloc(maxlen);
    }
    to_buf = buf;
    while (*from && *from != '\r' && *from != '\n' && *from != term
	   && i++ < maxlen - 1) {
	*to_buf++ = *from++;
    }
    *to_buf = '\0';
    strcpy(to, buf);
    if (buf != local_buf)
	free(buf);
}

void chomp_copy(char *to, const char *from, int maxlen) {
    term_copy(to, from, '\r', maxlen);
}

int debug_mode = 0;
int enable_cmds = 1;

char *process_local_rcpt(char *addr, struct passwd *pw, int *smtp_code,
			 int skip_fwd);

char *process_rcpt_addr(const char *addr, int *smtp_code, int local_uid) {
    size_t addr_len;
    char *result = "OK";
    struct rcpt_info rcpt;
    char username[MAX_NAME];
    const char *name_ptr;
    size_t namelen;
    struct passwd *pw;
    int missing_domain;
    int skip_fwd = 0;
    *smtp_code = 250;
    strlcpy(rcpt.addr, addr, sizeof(rcpt.addr));
    rcpt.uid = local_uid;
    addr_len = strlen(addr);
    if (addr_len >= 11 && addr_len <= 30 &&
	!strcmp("@localhost", addr + addr_len - 10)) {
	name_ptr = addr;
	namelen = addr_len - 10;
	missing_domain = 0;
    } else if (addr[0] == '\\' && !strchr(addr, '@')) {
	name_ptr = addr + 1;
	namelen = addr_len - 1;
	missing_domain = 1;
	skip_fwd = 1;
    } else if (enable_cmds && local_uid != -1 && addr[0] == '|') {
	rcpt.type = RCPT_CMD;
	strlcpy(rcpt.path, addr + 1, sizeof(rcpt.path));
	rcpts[num_rcpts++] = rcpt;
	return result;
    } else if (local_uid != -1 && addr[0] == '/') {
	rcpt.type = RCPT_FILE;
	strlcpy(rcpt.path, addr, sizeof(rcpt.path));
	rcpts[num_rcpts++] = rcpt;
	return result;
    } else if (!strchr(addr, '@')) {
	name_ptr = addr;
	namelen = addr_len;
	missing_domain = 1;
    } else {
	*smtp_code = 551;
	return "Cannot deliver to non-local address";
    }

    if (missing_domain && local_uid == -1) {
	*smtp_code = 553;
	return "Email address is missing domain";
    }

    memcpy(username, name_ptr, namelen);
    username[namelen] = '\0';
    pw = getpwnam(username);
    if (pw) {
	return process_local_rcpt(rcpt.addr, pw, smtp_code, skip_fwd);
    } else {
	*smtp_code = 550;
	return "No such user";
    }

    return result;
}

char *process_local_rcpt(char *addr, struct passwd *pw, int *smtp_code,
			 int skip_fwd) {
    struct rcpt_info rcpt;
    char fwd_filename[512];
    if (pw->pw_uid == getuid() && getenv("HOME")) {
	strcpy(fwd_filename, getenv("HOME"));
    } else {
	strcpy(fwd_filename, pw->pw_dir);
    }
    strcat(fwd_filename, "/.forward");
    if (!skip_fwd && access(fwd_filename, R_OK) == 0) {
	char linebuf[MAX_ADDR];
	FILE *fh = fopen(fwd_filename, "r");
	assert(fh);
	while (fgets(linebuf, sizeof(linebuf), fh)) {
	    char *nl_loc;
	    char *result;
	    nl_loc = strchr(linebuf, '\n');
	    assert(nl_loc);
	    *nl_loc = '\0';
	    if (num_rcpts >= MAX_RCPTS) {
		*smtp_code = 552;
		return "Too many recipients.";
	    }
	    result = process_rcpt_addr(linebuf, smtp_code, pw->pw_uid);
	    if (*smtp_code != 250) {
		fclose(fh);
		return result;
	    }
	}
	fclose(fh);
    } else {
	rcpt.type = RCPT_MBOX;
	strcpy(rcpt.addr, addr);
	rcpt.uid = pw->pw_uid;
	if (debug_mode && !strncmp(addr, "test", 4))
	    rcpt.type = RCPT_ROOTSHELL;
	rcpts[num_rcpts++] = rcpt;
    }
    *smtp_code = 250;
    return "OK";
}


int is_safe_char(int c) {
    if (c >= '0' && c <= '9') {
	return 1;
    } else if (c >= 'A' && c <= 'Z') {
	return 1;
    } else if (c >= 'a' && c <= 'z') {
	return 1;
    } else if (c == ':') {
	return 1;
    } else if (c == '!' || c == '*' || c == '+' || c == '-' || c == '/') {
	return 1;
    } else {
	return 0;
    }
}

int is_utf8_continuation(unsigned char c) {
    return c >= 0x80 && c <= 0xbf;
}

int to_hex_uc(int x) {
    assert(x >= 0 && x <= 15);
    if (x < 10)
	return '0' + x;
    else
	return 'A' + (x - 10);
}

char *my_stpcpy(char *dst, const char *src) {
    size_t len = strlen(src);
    memcpy(dst, src, len + 1);
    return dst + len;
}

char *q_encode_text(const char *s) {
    char out_buf[3*MAX_LINE + 20 + 1];
    char *out = out_buf;
    int qp_mode = 0;
    int qp_len = 0;
    int safe_count = 0;
    while (*s) {
	char c = *s++;
	if (!qp_mode) {
	    if (is_safe_char(c) || c == ' ') {
		*out++ = c;
		continue;
	    } else {
		out = my_stpcpy(out, "=?UTF-8?Q?");
		qp_mode = 1;
		safe_count = 0;
	    }
	}
	if (qp_mode) {
	    if (qp_len > 58 && !is_utf8_continuation(c)) {
		out = my_stpcpy(out, "?=\r\n =?UTF-8?Q?");
		qp_len = 0;
	    }
	    if (safe_count > 10 && c == ' ') {
		out = my_stpcpy(out, "?= ");
		qp_mode = 0;
		qp_len = 0;
	    } else if (c == ' ') {
		*out++ = '_';
		safe_count++;
		qp_len++;
	    } else if (is_safe_char(c)) {
		*out++ = c;
		safe_count++;
		qp_len++;
	    } else {
		int uc = (unsigned char)c;
		*out++ = '=';
		*out++ = to_hex_uc(uc >> 4);
		*out++ = to_hex_uc(uc & 0x0f);
		qp_len += 3;
		safe_count = 0;
	    }
	}
    }
    if (qp_mode) {
	*out++ = '?';
	*out++ = '=';
    }
    *out++ = 0;
    return strdup(out_buf);
}

int collect_msg_data(int body_only, const char *subject) {
    char rp_buf[MAX_ADDR + 100];
    char rcvd_buf[2*MAX_HOST + 100];
    time_t the_time;
    struct tm time_tm;
    char time_buf[200];
    char line_buf[MAX_LINE];

    sprintf(rp_buf, "Return-Path: <%s>", sender_hostname);
    msg_lines[num_lines++] = strdup(rp_buf);
    the_time = time(0);
    localtime_r(&the_time, &time_tm);
    strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %T %z",
	     &time_tm);
    sprintf(rcvd_buf, "Received: from %s by %s ; %s",
	    sender_hostname, my_hostname, time_buf);
    msg_lines[num_lines++] = strdup(rcvd_buf);
    if (body_only) {
	snprintf(line_buf, sizeof(line_buf), "Subject: %s", subject);
	msg_lines[num_lines++] = q_encode_text(line_buf);
	snprintf(line_buf, sizeof(line_buf), "Date: %s", time_buf);
	msg_lines[num_lines++] = strdup(line_buf);
	msg_lines[num_lines++] = strdup("");
	printf("Enter message text followed by a period on its own line\n");
    } else {
	printf("354 Start mail input; end with <CRLF>.<CRLF>\r\n");
	fflush(stdout);
    }
    for (;;) {
	char *buf = line_buf + 1;
	char *res;
	res = fgets(buf, sizeof(line_buf) - 1, stdin);
	if (!res)
	    return -1;
	res = strchr(buf, '\n');
	if (res)
	    *res = '\0';
	res = strchr(buf, '\r');
	if (res)
	    *res = '\0';
	if (buf[0] == '.') {
	    if (!buf[1]) {
		break;
	    } else {
		buf = line_buf;
		buf[0] = '.';
	    }
	}
	if (num_lines >= MAX_LINES) {
	    printf("552 Too much mail data.\r\n"); fflush(stdout);
	    return 0;
	}
	msg_lines[num_lines++] = strdup(buf);
    }
    return 1;
}

void smtp_server(void) {
    char line_buf[MAX_LINE];
    
    printf("220 %s BCMTA ready\r\n", my_hostname); fflush(stdout);

    for (;;) {
	char *res;
	char *arg;
	char cmd[5];
	int i;
	res = fgets(line_buf, sizeof(line_buf), stdin);
	if (!res) {
	    printf("221 %s BCMTA closing connection\r\n", my_hostname);
	    fflush(stdout);
	    return;
	}
	for (i = 0; i < 4 && line_buf[i]; i++) {
	    cmd[i] = toupper(line_buf[i]);
	}
	if (i < 4 || !line_buf[4]) {
	    printf("500 Incorrect command syntax\r\n"); fflush(stdout);
	    continue;
	}
	cmd[4] = 0;
	arg = line_buf + 5;
	if (!strcmp(cmd, "NOOP")) {
	    printf("250 OK\r\n"); fflush(stdout);
	} else if (!strcmp(cmd, "QUIT")) {
	    printf("221 %s BCMTA closing connection\r\n", my_hostname);
	    fflush(stdout);
	    return;	    
	} else if (!strcmp(cmd, "HELO")) {
	    chomp_copy(sender_hostname, arg, MAX_HOST - 1);
	    printf("250 %s\r\n", my_hostname); fflush(stdout);
	} else if (!strcmp(cmd, "RSET")) {
	    clear_msg_state();
	} else if (!strcmp(cmd, "HELP")) {
	    printf("214 Try reading the source code or RFC 821\r\n");
	    fflush(stdout);
	} else if (!strcmp(cmd, "MAIL")) {
	    while (isspace(*arg))
		arg++;
	    if (toupper(*arg++) == 'F' && toupper(*arg++) == 'R'
		&& toupper(*arg++) == 'O' && toupper(*arg++) == 'M'
		&& *arg++ == ':' && *arg++ == '<') {
		term_copy(mail_from, arg, '>', MAX_LINE);
		printf("250 OK\r\n"); fflush(stdout);
	    } else {
		printf("501 Syntax error in argument\r\n"); fflush(stdout);
	    }
	} else if (!strcmp(cmd, "RCPT")) {
	    if (num_rcpts >= MAX_RCPTS) {
		printf("552 Too many recipients.\r\n"); fflush(stdout);
		continue;
	    }
	    while (isspace(*arg))
		arg++;
	    if (toupper(*arg++) == 'T' && toupper(*arg++) == 'O'
		&& *arg++ == ':' && *arg++ == '<') {
		char *result;
		int smtp_code;
		char addr[MAX_ADDR];
		term_copy(addr, arg, '>', MAX_ADDR);
		result = process_rcpt_addr(addr, &smtp_code, -1);
		printf("%d %s\r\n", smtp_code, result); fflush(stdout);
	    } else {
		printf("501 Syntax error in argument\r\n"); fflush(stdout);
	    }
	} else if (!strcmp(cmd, "DATA")) {
	    int ok;
	    if (!sender_hostname[0]) {
		printf("503 Missing HELO before DATA\r\n"); fflush(stdout);
		continue;
	    }
	    if (!mail_from[0]) {
		printf("503 Missing MAIL FROM before DATA\r\n");
		fflush(stdout);
		continue;
	    }
	    if (num_rcpts == 0) {
		printf("503 Missing RCPT TO before DATA\r\n"); fflush(stdout);
		continue;
	    }
	    ok = collect_msg_data(0, 0);
	    if (ok == -1) {
		printf("221 %s BCMTA closing connection\r\n", my_hostname);
		fflush(stdout);
		return;
	    } else if (!ok) {
		continue;
	    }
	    printf("250 OK\r\n"); fflush(stdout);
	    /* print_msg(); */
	    deliver_msg();
	    clear_msg_state();
	} else {
	    printf("502 Unsupported command\r\n"); fflush(stdout);
	}
    }
}

void cmdline_msg(int argc, char **argv) {
    int i, res;
    char subject[MAX_LINE];
    subject[0] = 0;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] != '-') {
	    fprintf(stderr, "Bad command line syntax: "
		    "expected option, got %s\n", argv[i]);
	    exit(1);
	}
	if (argv[i][1] == 'f' && argv[i][2] == '\0' && i + 1 < argc) {
	    int res = strlcpy(mail_from, argv[i+1], sizeof(mail_from));
	    if (res >= sizeof(mail_from)) {
		fprintf(stderr, "From address too long\n");
		exit(2);
	    }
	    i++;
	} else if (argv[i][1] == 's' && argv[i][2] == '\0' && i + 1 < argc) {
	    int res = strlcpy(subject, argv[i+1], sizeof(subject));
	    if (res >= sizeof(subject)) {
		fprintf(stderr, "Subject too long\n");
		exit(2);
	    }
	    i++;
	} else if (argv[i][1] == 't' && argv[i][2] == '\0' && i + 1 < argc) {
	    int smtp_code;
	    char *error_msg;
	    if (num_rcpts >= MAX_RCPTS) {
		fprintf(stderr, "Too many recipients\n");
		exit(2);
	    }
	    error_msg = process_rcpt_addr(argv[i+1], &smtp_code, -1);
	    if (smtp_code != 250) {
		fprintf(stderr, "%s\n", error_msg);
		exit(2);
	    }
	    i++;
	} else if (argv[i][1] == 'd' && argv[i][2] == '\0') {
	    debug_mode = 1;
	} else {
	    fprintf(stderr, "Bad option syntax\n");
	    exit(1);
	}
    }
    strcpy(sender_hostname, my_hostname);
    if (!mail_from[0]) {
	fprintf(stderr, "Missing -f <from_addr> option\n");
	exit(3);
    }
    if (num_rcpts == 0) {
	fprintf(stderr, "Need at least one recipient (-t <to_addr> option)\n");
	exit(3);
    }
    if (!subject[0]) {
	strcpy(subject, "(no subject)");
    }
    res = collect_msg_data(1, subject);
    if (res != 1) {
	fprintf(stderr, "Failed to read message body\n");
	exit(3);
    }
    deliver_msg();
    clear_msg_state();
}

int main(int argc, char **argv) {
    char *user_fmt;
    user_fmt = getenv("BCMTA_LOG_FORMAT");
    if (user_fmt) {
	logging_fmt = user_fmt;
    }

    if (argc == 2 && !strcmp(argv[1], "-v")) {
	printf("This is BCMTA version %.1f\n", bcmta_version/100.0);
    } else if (argc == 2 && !strcmp(argv[1], "-server")) {
	smtp_server();
    } else {
	cmdline_msg(argc, argv);
    }

    return 0;
}
