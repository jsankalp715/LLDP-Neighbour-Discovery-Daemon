/*
 * ctl.h - local control socket (AF_UNIX stream) for querying the daemon
 *
 * Protocol: the client sends one command line ("show", "json", "stats",
 * "local", "help"), the daemon writes the reply and closes the connection.
 * Fully non-blocking inside the daemon's epoll loop; a client that stalls
 * can only occupy one of a few slots, and the oldest is evicted when a new
 * client needs one.
 */
#ifndef LLDP_CTL_H
#define LLDP_CTL_H

#include <stdint.h>
#include <stdio.h>

#include "agent.h"

#define CTL_DEFAULT_PATH "/run/lldpnd.sock"

struct ctl;

/* Called with the command (no newline); writes the reply to out. */
typedef void (*ctl_fn)(const char *cmd, FILE *out, void *ctx);

/*
 * Create the socket at path (mode 0600) and register it with epfd.
 * Refuses to replace a socket another live daemon is listening on.
 */
struct ctl *ctl_open(const char *path, int epfd, ctl_fn fn, void *ctx);

/* Dispatch an epoll event whose data.ptr is an ev with kind EV_CTL. */
void ctl_event(struct ctl *c, struct ev *e, uint32_t events);

/* Close all clients and the listener, and unlink the socket if possible. */
void ctl_close(struct ctl *c);

#endif
