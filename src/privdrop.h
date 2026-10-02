/*
 * privdrop.h - shed root after start-up, keeping only CAP_NET_RAW
 *
 * The raw sockets are already open, but an interface that disappears and
 * comes back needs a new AF_PACKET socket, so CAP_NET_RAW is retained. Every
 * other capability, supplementary group and the root uid are dropped, and
 * PR_SET_NO_NEW_PRIVS prevents regaining them via exec.
 */
#ifndef LLDP_PRIVDROP_H
#define LLDP_PRIVDROP_H

/* Returns 0, or -1 with a message on stderr. */
int privdrop(const char *user);

#endif
