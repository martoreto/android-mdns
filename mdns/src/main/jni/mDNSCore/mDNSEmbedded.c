#include <stdio.h>          // For printf()
#include <stdlib.h>         // For exit() etc.
#include <string.h>         // For strlen() etc.
#include <unistd.h>         // For select()
#include <errno.h>          // For errno, EINTR
#include <netinet/in.h>     // For INADDR_NONE
#include <arpa/inet.h>      // For inet_addr()
#include <netdb.h>          // For gethostbyname()
#include <signal.h>         // For SIGINT, etc.

#include "mDNSEmbeddedAPI.h"  // Defines the interface to the client layer above
#include "mDNSPosix.h"      // Defines the specific types needed to run mDNS on this platform

// Globals
mDNS mDNSStorage;       // mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;  // Stores this platform's globals
#define RR_CACHE_SIZE 500
static CacheEntity gRRCache[RR_CACHE_SIZE];

const char ProgramName[] = "mDNSClientPosix";

static int state = 0;

mDNSexport int embedded_mDNSInit() {
	mStatus status;
	status = mDNS_Init(&mDNSStorage, &PlatformStorage, gRRCache, RR_CACHE_SIZE,
	mDNS_Init_AdvertiseLocalAddresses,
	mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
	return status;
}

mDNSexport void embedded_mDNSExit() {
	mDNS* m = &mDNSStorage;
	mDNS_StartExit(&mDNSStorage);
}

mDNSexport void embedded_mDNSLoop() {
	mDNS* m = &mDNSStorage;
	state = 1;
	while (1) {
		mDNSs32 now = mDNS_TimeNow(m);

		if (m->ShutdownTime)
		{
			if (mDNSStorage.ResourceRecords)
			{
				AuthRecord *rr;
				for (rr = mDNSStorage.ResourceRecords; rr; rr=rr->next)
				{
					LogInfo("Cannot exit yet; Resource Record still exists: %s", ARDisplayString(m, rr));
					if (mDNS_LoggingEnabled) usleep(10000);     // Sleep 10ms so that we don't flood syslog with too many messages
				}
			}
			if (mDNS_ExitNow(m, now))
			{
				break;
			}
		}

		//LogMsg("embedded_mDNSLoop 1");
		int nfds = 0;
		fd_set readfds;
		struct timeval timeout;
		int result;

		// 1. Set up the fd_set as usual here.
		// This example client has no file descriptors of its own,
		// but a real application would call FD_SET to add them to the set here
		FD_ZERO(&readfds);

		// 2. Set up the timeout.
		// This example client has no other work it needs to be doing,
		// so we set an effectively infinite timeout
		timeout.tv_sec = 0x1;
		timeout.tv_usec = 0;

		//LogMsg("mDNSPosixGetFDSet");
		// 3. Give the mDNSPosix layer a chance to add its information to the fd_set and timeout
		mDNSPosixGetFDSet(m, &nfds, &readfds, &timeout);

		// 4. Call select as normal
		//verbosedebugf( "select(%d, %d.%06d)", nfds, timeout.tv_sec, timeout.tv_usec);
		result = select(nfds, &readfds, NULL, NULL, &timeout);

		if (result < 0) {
			//verbosedebugf( "select() returned %d errno %d", result, errno);
			if (errno != EINTR) {
				LogMsg("Select failed: %s", strerror(errno));
				break;
			}
		} else {
			//LogMsg("mDNSPosixProcessFDSet");
			// 5. Call mDNSPosixProcessFDSet to let the mDNSPosix layer do its work
			mDNSPosixProcessFDSet(m, &readfds);

			// 6. This example client has no other work it needs to be doing,
			// but a real client would do its work here
			// ... (do work) ...
		}
		//LogMsg("embedded_mDNSLoop 2");
	    sigset_t signals;
		mDNSBool gotSomething;
		mDNSPosixRunEventLoopOnce(m, &timeout, &signals, &gotSomething);
	}
	state = 0;

	LogInfo("mDNS_FinalExit");
	mDNS_FinalExit(&mDNSStorage);
	usleep(1000);       // Little 1ms pause before exiting, so we don't lose our final syslog messages
}
