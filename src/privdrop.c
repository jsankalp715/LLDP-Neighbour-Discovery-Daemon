/*
 * privdrop.c - shed root after start-up, keeping only CAP_NET_RAW
 *
 * Uses the raw capset(2) system call so there is no libcap dependency.
 */
#include "privdrop.h"

#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int privdrop(const char *user)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];
	struct passwd *pw;

	errno = 0;
	pw = getpwnam(user);
	if (!pw) {
		fprintf(stderr, "privdrop: unknown user '%s'\n", user);
		return -1;
	}
	if (pw->pw_uid == 0) {
		fprintf(stderr, "privdrop: refusing to 'drop' to uid 0 (%s)\n", user);
		return -1;
	}
	/* keep the permitted set across setuid(), then trim it with capset */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 ||
	    setgroups(0, NULL) < 0 ||
	    setgid(pw->pw_gid) < 0 ||
	    setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "privdrop: switching to %s: %s\n", user, strerror(errno));
		return -1;
	}

	memset(&hdr, 0, sizeof hdr);
	memset(data, 0, sizeof data);
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;
	data[0].permitted = data[0].effective = 1u << CAP_NET_RAW;
	if (syscall(SYS_capset, &hdr, data) < 0) {
		fprintf(stderr, "privdrop: capset: %s\n", strerror(errno));
		return -1;
	}
	if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		fprintf(stderr, "privdrop: prctl: %s\n", strerror(errno));
		return -1;
	}
	/* paranoia: it must now be impossible to become root again */
	if (setuid(0) == 0 || seteuid(0) == 0) {
		fprintf(stderr, "privdrop: still able to regain root, aborting\n");
		return -1;
	}
	return 0;
}
