LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_BIN_PATH := $(LOCAL_PATH)/../bin
LOCAL_CLASS_PATH := $(LOCAL_PATH)/../../../build/intermediates/classes/$(APP_OPTIM)

LOCAL_MODULE    := jdns_sd

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/mDNSShared \
	$(LOCAL_PATH)/mDNSPosix \
	$(LOCAL_PATH)/mDNSCore 
	
LOCAL_CFLAGS :=  \
	-DAUTO_CALLBACKS=1 \
	-DTARGET_OS_ANDROID \
	-DmDNS_REQUEST_UNICAST_RESPONSE \
	-DHAVE_IPV6 \
	-DHAVE_LINUX \
	-DNOT_HAVE_SA_LEN -DUSES_NETLINK \
	-Wno-address-of-packed-member

ifeq ($(APP_OPTIM),debug)
LOCAL_CFLAGS += -DMDNS_DEBUGMSGS=0
else
LOCAL_CFLAGS += -DMDNS_DEBUGMSGS=0
endif

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog

setup := $(shell javah -force -classpath $(LOCAL_CLASS_PATH) -o $(LOCAL_PATH)/mDNSShared/Java/DNSSD.java.h \
	com.apple.dnssd.AppleDNSSD \
	com.apple.dnssd.AppleBrowser \
	com.apple.dnssd.AppleResolver \
	com.apple.dnssd.AppleRegistration \
	com.apple.dnssd.AppleQuery \
	com.apple.dnssd.AppleDomainEnum \
	com.apple.dnssd.AppleService \
	com.apple.dnssd.AppleDNSRecord \
	com.apple.dnssd.AppleRecordRegistrar \
	com.apple.dnssd.DNSSDEmbedded \
	)
		
$(setup)

LOCAL_SRC_FILES := \
    mDNSPosix/mDNSPosix.c \
    mDNSPosix/mDNSUNP.c \
    mDNSShared/mDNSDebug.c \
    mDNSShared/GenLinkedList.c \
    mDNSCore/DNSDigest.c \
    mDNSCore/uDNS.c \
    mDNSCore/DNSCommon.c \
    mDNSShared/PlatformCommon.c \
    mDNSCore/CryptoAlg.c \
    mDNSCore/anonymous.c \
    mDNSCore/mDNS.c \
    mDNSShared/dnssd_clientlib.c \
    mDNSShared/dnssd_clientshim.c \
    mDNSShared/Java/JNISupport.c \
    mDNSCore/mDNSEmbedded.c

include $(BUILD_SHARED_LIBRARY)
