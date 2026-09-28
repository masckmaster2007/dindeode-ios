#ifndef _SYS_FILEPORT_H_
#define _SYS_FILEPORT_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <mach/mach.h>

__BEGIN_DECLS

int fileport_makeport(int fd, mach_port_t *portp);
int fileport_makefd(mach_port_t port);

__END_DECLS

#endif /* _SYS_FILEPORT_H_ */