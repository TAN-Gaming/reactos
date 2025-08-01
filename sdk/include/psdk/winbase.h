#ifndef _WINBASE_
#define _WINBASE_

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_ADVAPI32_)
#define WINADVAPI DECLSPEC_IMPORT
#else
#define WINADVAPI
#endif

#if !defined(_KERNEL32_)
#define WINBASEAPI DECLSPEC_IMPORT
#else
#define WINBASEAPI
#endif

#include <minwinbase.h>
#include <ioapiset.h>
#include <sysinfoapi.h>
#include <threadpoolapiset.h>
#include <libloaderapi.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4201)
#pragma warning(disable:4214)
#pragma warning(disable:4820)
#endif

#define PROCESS_NAME_NATIVE      1

#define FILE_ENCRYPTABLE         0
#define FILE_IS_ENCRYPTED        1
#define FILE_SYSTEM_ATTR         2
#define FILE_ROOT_DIR            3
#define FILE_SYSTEM_DIR          4
#define FILE_UNKNOWN             5
#define FILE_SYSTEM_NOT_SUPPORT  6
#define FILE_USER_DISALLOWED     7
#define FILE_READ_ONLY           8
#define FILE_DIR_DISALLOWED      9

#define COMMPROP_INITIALIZED 0xE73CF52E
#define SP_SERIALCOMM 1
#define PST_UNSPECIFIED	0
#define PST_RS232	1
#define PST_PARALLELPORT	2
#define PST_RS422	3
#define PST_RS423	4
#define PST_RS449	5
#define PST_MODEM	6
#define PST_FAX	0x21
#define PST_SCANNER	0x22
#define PST_NETWORK_BRIDGE	0x100
#define PST_LAT	0x101
#define PST_TCPIP_TELNET	0x102
#define PST_X25	0x103
#define BAUD_075	1
#define BAUD_110	2
#define BAUD_134_5	4
#define BAUD_150	8
#define BAUD_300	16
#define BAUD_600	32
#define BAUD_1200	64
#define BAUD_1800	128
#define BAUD_2400	256
#define BAUD_4800	512
#define BAUD_7200	1024
#define BAUD_9600	2048
#define BAUD_14400	4096
#define BAUD_19200	8192
#define BAUD_38400	16384
#define BAUD_56K	32768
#define BAUD_128K	65536
#define BAUD_115200	131072
#define BAUD_57600	262144
#define BAUD_USER	0x10000000
#define PCF_DTRDSR	1
#define PCF_RTSCTS	2
#define PCF_RLSD	4
#define PCF_PARITY_CHECK	8
#define PCF_XONXOFF	16
#define PCF_SETXCHAR	32
#define PCF_TOTALTIMEOUTS	64
#define PCF_INTTIMEOUTS	128
#define PCF_SPECIALCHARS	256
#define PCF_16BITMODE	512
#define SP_PARITY	1
#define SP_BAUD	2
#define SP_DATABITS	4
#define SP_STOPBITS	8
#define SP_HANDSHAKING	16
#define SP_PARITY_CHECK	32
#define SP_RLSD	64
#define DATABITS_5	1
#define DATABITS_6	2
#define DATABITS_7	4
#define DATABITS_8	8
#define DATABITS_16	16
#define DATABITS_16X	32
#define STOPBITS_10	1
#define STOPBITS_15	2
#define STOPBITS_20	4
#define PARITY_NONE	256
#define PARITY_ODD	512
#define PARITY_EVEN	1024
#define PARITY_MARK	2048
#define PARITY_SPACE	4096
#define HFILE_ERROR ((HFILE)-1)
#define FILE_BEGIN	0
#define FILE_CURRENT	1
#define FILE_END	2
#define INVALID_SET_FILE_POINTER	((DWORD)-1)
#define OF_READ 0
#define OF_READWRITE	2
#define OF_WRITE	1
#define OF_SHARE_COMPAT	0
#define OF_SHARE_DENY_NONE	64
#define OF_SHARE_DENY_READ	48
#define OF_SHARE_DENY_WRITE	32
#define OF_SHARE_EXCLUSIVE	16
#define OF_CANCEL	2048
#define OF_CREATE	4096
#define OF_DELETE	512
#define OF_EXIST	16384
#define OF_PARSE	256
#define OF_PROMPT	8192
#define OF_REOPEN	32768
#define OF_VERIFY	1024
#define NMPWAIT_NOWAIT	1
#define NMPWAIT_WAIT_FOREVER	((DWORD)-1)
#define NMPWAIT_USE_DEFAULT_WAIT	0
#define CE_BREAK	16
#define CE_DNS	2048
#define CE_FRAME	8
#define CE_IOE	1024
#define CE_MODE	32768
#define CE_OOP	4096
#define CE_OVERRUN	2
#define CE_PTO	512
#define CE_RXOVER	1
#define CE_RXPARITY	4
#define CE_TXFULL	256
#define PROGRESS_CONTINUE	0
#define PROGRESS_CANCEL	1
#define PROGRESS_STOP	2
#define PROGRESS_QUIET	3
#define CALLBACK_CHUNK_FINISHED	0
#define CALLBACK_STREAM_SWITCH	1
#define OFS_MAXPATHNAME 128
#define FILE_MAP_COPY SECTION_QUERY
#define FILE_MAP_WRITE SECTION_MAP_WRITE
#define FILE_MAP_READ SECTION_MAP_READ
#define FILE_MAP_ALL_ACCESS SECTION_ALL_ACCESS
#define FILE_MAP_EXECUTE SECTION_MAP_EXECUTE_EXPLICIT
#define MUTEX_ALL_ACCESS	0x1f0001
#define MUTEX_MODIFY_STATE	1
#define SEMAPHORE_ALL_ACCESS	0x1f0003
#define SEMAPHORE_MODIFY_STATE	2
#define EVENT_ALL_ACCESS	0x1f0003
#define EVENT_MODIFY_STATE	2
#define PIPE_ACCESS_DUPLEX      3
#define PIPE_ACCESS_INBOUND     1
#define PIPE_ACCESS_OUTBOUND    2
#define PIPE_TYPE_BYTE	0
#define PIPE_TYPE_MESSAGE	4
#define PIPE_READMODE_BYTE	0
#define PIPE_READMODE_MESSAGE	2
#define PIPE_WAIT	0
#define PIPE_NOWAIT	1
#define PIPE_CLIENT_END 0
#define PIPE_SERVER_END 1
#define PIPE_UNLIMITED_INSTANCES 255

/* CreateProcess() dwCreationFlags values */
#define DEBUG_PROCESS                     0x00000001
#define DEBUG_ONLY_THIS_PROCESS           0x00000002
#define CREATE_SUSPENDED                  0x00000004
#define DETACHED_PROCESS                  0x00000008
#define CREATE_NEW_CONSOLE                0x00000010
#define NORMAL_PRIORITY_CLASS             0x00000020
#define IDLE_PRIORITY_CLASS               0x00000040
#define HIGH_PRIORITY_CLASS               0x00000080
#define REALTIME_PRIORITY_CLASS           0x00000100
#define CREATE_NEW_PROCESS_GROUP          0x00000200
#define CREATE_UNICODE_ENVIRONMENT        0x00000400
#define CREATE_SEPARATE_WOW_VDM           0x00000800
#define CREATE_SHARED_WOW_VDM             0x00001000
#define CREATE_FORCEDOS                   0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS       0x00008000

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define INHERIT_PARENT_AFFINITY           0x00010000
#endif // _WIN32_WINNT_WIN7

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define INHERIT_CALLER_PRIORITY           0x00020000 // Deprecated
#define CREATE_PROTECTED_PROCESS          0x00040000
#define EXTENDED_STARTUPINFO_PRESENT      0x00080000
#define PROCESS_MODE_BACKGROUND_BEGIN     0x00100000
#define PROCESS_MODE_BACKGROUND_END       0x00200000
#endif // _WIN32_WINNT_VISTA

#if (NTDDI_VERSION >= NTDDI_WIN10_RS4)
#define CREATE_SECURE_PROCESS             0x00400000
#endif // NTDDI_WIN10_RS4

#define CREATE_BREAKAWAY_FROM_JOB         0x01000000
#define CREATE_PRESERVE_CODE_AUTHZ_LEVEL  0x02000000
#define CREATE_DEFAULT_ERROR_MODE         0x04000000
#define CREATE_NO_WINDOW                  0x08000000
#define PROFILE_USER                      0x10000000
#define PROFILE_KERNEL                    0x20000000
#define PROFILE_SERVER                    0x40000000
#define CREATE_IGNORE_SYSTEM_DEFAULT      0x80000000

/* CreateThread()/CreateRemoteThread() dwCreationFlags values */
// #define CREATE_SUSPENDED 0x00000004 // See above
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000

#define CREATE_NEW	1
#define CREATE_ALWAYS	2
#define OPEN_EXISTING	3
#define OPEN_ALWAYS	4
#define TRUNCATE_EXISTING	5

#define COPY_FILE_FAIL_IF_EXISTS                0x00000001
#define COPY_FILE_RESTARTABLE                   0x00000002
#define COPY_FILE_OPEN_SOURCE_FOR_WRITE         0x00000004
#define COPY_FILE_ALLOW_DECRYPTED_DESTINATION   0x00000008

#define FILE_FLAG_WRITE_THROUGH                 0x80000000
#define FILE_FLAG_OVERLAPPED                    0x40000000
#define FILE_FLAG_NO_BUFFERING                  0x20000000
#define FILE_FLAG_RANDOM_ACCESS                 0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN               0x08000000
#define FILE_FLAG_DELETE_ON_CLOSE               0x04000000
#define FILE_FLAG_BACKUP_SEMANTICS              0x02000000
#define FILE_FLAG_POSIX_SEMANTICS               0x01000000
#define FILE_FLAG_OPEN_REPARSE_POINT            0x00200000
#define FILE_FLAG_OPEN_NO_RECALL                0x00100000
#if (_WIN32_WINNT >= 0x0500)
#define FILE_FLAG_FIRST_PIPE_INSTANCE           0x00080000
#endif

#define CLRDTR 6
#define CLRRTS 4
#define SETDTR 5
#define SETRTS 3
#define SETXOFF 1
#define SETXON 2
#define RESETDEV 7
#define SETBREAK 8
#define CLRBREAK 9
#define SCS_32BIT_BINARY 0
#define SCS_64BIT_BINARY 6
#define SCS_DOS_BINARY 1
#define SCS_OS216_BINARY 5
#define SCS_PIF_BINARY 3
#define SCS_POSIX_BINARY 4
#define SCS_WOW_BINARY 2
#define MAX_COMPUTERNAME_LENGTH 15
#define HW_PROFILE_GUIDLEN	39
#define MAX_PROFILE_LEN	80
#define DOCKINFO_UNDOCKED	1
#define DOCKINFO_DOCKED	2
#define DOCKINFO_USER_SUPPLIED	4
#define DOCKINFO_USER_UNDOCKED	(DOCKINFO_USER_SUPPLIED|DOCKINFO_UNDOCKED)
#define DOCKINFO_USER_DOCKED	(DOCKINFO_USER_SUPPLIED|DOCKINFO_DOCKED)
#define DRIVE_REMOVABLE 2
#define DRIVE_FIXED 3
#define DRIVE_REMOTE 4
#define DRIVE_CDROM 5
#define DRIVE_RAMDISK 6
#define DRIVE_UNKNOWN 0
#define DRIVE_NO_ROOT_DIR 1
#define FILE_TYPE_UNKNOWN 0
#define FILE_TYPE_DISK 1
#define FILE_TYPE_CHAR 2
#define FILE_TYPE_PIPE 3
#define FILE_TYPE_REMOTE 0x8000
/* also in ddk/ntapi.h */
#define HANDLE_FLAG_INHERIT		0x01
#define HANDLE_FLAG_PROTECT_FROM_CLOSE	0x02
/* end ntapi.h */
#define STD_INPUT_HANDLE (DWORD)(0xfffffff6)
#define STD_OUTPUT_HANDLE (DWORD)(0xfffffff5)
#define STD_ERROR_HANDLE (DWORD)(0xfffffff4)
#define INVALID_HANDLE_VALUE (HANDLE)(-1)
#define GET_TAPE_MEDIA_INFORMATION 0
#define GET_TAPE_DRIVE_INFORMATION 1
#define SET_TAPE_MEDIA_INFORMATION 0
#define SET_TAPE_DRIVE_INFORMATION 1
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_HIGHEST 2
#define THREAD_PRIORITY_IDLE (-15)
#define THREAD_PRIORITY_LOWEST (-2)
#define THREAD_PRIORITY_NORMAL 0
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define THREAD_PRIORITY_ERROR_RETURN 2147483647
#define TIME_ZONE_ID_UNKNOWN 0
#define TIME_ZONE_ID_STANDARD 1
#define TIME_ZONE_ID_DAYLIGHT 2
#define TIME_ZONE_ID_INVALID 0xFFFFFFFF
#define FS_CASE_IS_PRESERVED 2
#define FS_CASE_SENSITIVE 1
#define FS_UNICODE_STORED_ON_DISK 4
#define FS_PERSISTENT_ACLS 8
#define FS_FILE_COMPRESSION 16
#define FS_VOL_IS_COMPRESSED 32768
#define GMEM_FIXED 0
#define GMEM_MOVEABLE 2
#define GMEM_MODIFY 128
#define GPTR 64
#define GHND 66
#define GMEM_DDESHARE 8192
#define GMEM_DISCARDABLE 256
#define GMEM_LOWER 4096
#define GMEM_NOCOMPACT 16
#define GMEM_NODISCARD 32
#define GMEM_NOT_BANKED 4096
#define GMEM_NOTIFY 16384
#define GMEM_SHARE 8192
#define GMEM_ZEROINIT 64
#define GMEM_DISCARDED 16384
#define GMEM_INVALID_HANDLE 32768
#define GMEM_LOCKCOUNT 255
#define GMEM_VALID_FLAGS 32626

// LoadLibraryEx() dwFlags.
#define DONT_RESOLVE_DLL_REFERENCES                 0x00000001
#define LOAD_LIBRARY_AS_DATAFILE                    0x00000002
// #define LOAD_PACKAGED_LIBRARY                       0x00000004 // Internal use only.
#define LOAD_WITH_ALTERED_SEARCH_PATH               0x00000008
#define LOAD_IGNORE_CODE_AUTHZ_LEVEL                0x00000010
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE              0x00000020
#define LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE          0x00000040
#define LOAD_LIBRARY_REQUIRE_SIGNED_TARGET          0x00000080
#define LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR            0x00000100
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR         0x00000200
#define LOAD_LIBRARY_SEARCH_USER_DIRS               0x00000400
#define LOAD_LIBRARY_SEARCH_SYSTEM32                0x00000800
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS            0x00001000
#endif // _WIN32_WINNT_VISTA
#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
#define LOAD_LIBRARY_SAFE_CURRENT_DIRS              0x00002000
#define LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER   0x00004000
#else // NTDDI_WIN10_RS1
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
#define LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER   LOAD_LIBRARY_SEARCH_SYSTEM32
#endif // _WIN32_WINNT_VISTA
#endif // NTDDI_WIN10_RS1
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
#define LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY        0x00008000
#endif // NTDDI_WIN10_RS2

#define LOGON32_PROVIDER_DEFAULT	0
#define LOGON32_PROVIDER_WINNT35	1
#define LOGON32_PROVIDER_WINNT40	2
#define LOGON32_PROVIDER_WINNT50	3
#define LOGON32_LOGON_INTERACTIVE	2
#define LOGON32_LOGON_NETWORK	3
#define LOGON32_LOGON_BATCH	4
#define LOGON32_LOGON_SERVICE	5
#define LOGON32_LOGON_UNLOCK	7
#define LOGON32_LOGON_NETWORK_CLEARTEXT	8
#define LOGON32_LOGON_NEW_CREDENTIALS	9
#define MOVEFILE_REPLACE_EXISTING 1
#define MOVEFILE_COPY_ALLOWED 2
#define MOVEFILE_DELAY_UNTIL_REBOOT 4
#define MOVEFILE_WRITE_THROUGH 8
#define MOVEFILE_CREATE_HARDLINK 16
#define MOVEFILE_FAIL_IF_NOT_TRACKABLE 32
#define MAXIMUM_WAIT_OBJECTS 64
#define MAXIMUM_SUSPEND_COUNT 0x7F
#define WAIT_OBJECT_0 0
#define WAIT_ABANDONED_0 128
#ifndef WAIT_TIMEOUT /* also in winerror.h */
#define WAIT_TIMEOUT 258
#endif
#define WAIT_IO_COMPLETION 0xC0
#define WAIT_ABANDONED 128
#define WAIT_FAILED ((DWORD)0xFFFFFFFF)
#define PURGE_TXABORT 1
#define PURGE_RXABORT 2
#define PURGE_TXCLEAR 4
#define PURGE_RXCLEAR 8

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 256
#define FORMAT_MESSAGE_IGNORE_INSERTS 512
#define FORMAT_MESSAGE_FROM_STRING 1024
#define FORMAT_MESSAGE_FROM_HMODULE 2048
#define FORMAT_MESSAGE_FROM_SYSTEM 4096
#define FORMAT_MESSAGE_ARGUMENT_ARRAY 8192
#define FORMAT_MESSAGE_MAX_WIDTH_MASK 255
#define EV_BREAK 64
#define EV_CTS 8
#define EV_DSR 16
#define EV_ERR 128
#define EV_EVENT1 2048
#define EV_EVENT2 4096
#define EV_PERR 512
#define EV_RING 256
#define EV_RLSD 32
#define EV_RX80FULL 1024
#define EV_RXCHAR 1
#define EV_RXFLAG 2
#define EV_TXEMPTY 4
/* also in ddk/ntapi.h */
#define SEM_FAILCRITICALERRORS		0x0001
#define SEM_NOGPFAULTERRORBOX		0x0002
#define SEM_NOALIGNMENTFAULTEXCEPT	0x0004
#define SEM_NOOPENFILEERRORBOX		0x8000
/* end ntapi.h */
#define SLE_ERROR 1
#define SLE_MINORERROR 2
#define SLE_WARNING 3
#define SHUTDOWN_NORETRY 1
#define MAXINTATOM 0xC000
#define INVALID_ATOM ((ATOM)0)
#define IGNORE	0
#define INFINITE	0xFFFFFFFF
#define NOPARITY	0
#define ODDPARITY	1
#define EVENPARITY	2
#define MARKPARITY	3
#define SPACEPARITY	4
#define ONESTOPBIT	0
#define ONE5STOPBITS	1
#define TWOSTOPBITS	2
#define CBR_110	110
#define CBR_300	300
#define CBR_600	600
#define CBR_1200	1200
#define CBR_2400	2400
#define CBR_4800	4800
#define CBR_9600	9600
#define CBR_14400	14400
#define CBR_19200	19200
#define CBR_38400	38400
#define CBR_56000	56000
#define CBR_57600	57600
#define CBR_115200	115200
#define CBR_128000	128000
#define CBR_256000	256000
#define BACKUP_INVALID	0
#define BACKUP_DATA 1
#define BACKUP_EA_DATA 2
#define BACKUP_SECURITY_DATA 3
#define BACKUP_ALTERNATE_DATA 4
#define BACKUP_LINK 5
#define BACKUP_PROPERTY_DATA 6
#define BACKUP_OBJECT_ID 7
#define BACKUP_REPARSE_DATA 8
#define BACKUP_SPARSE_BLOCK 9
#define STREAM_NORMAL_ATTRIBUTE 0
#define STREAM_MODIFIED_WHEN_READ 1
#define STREAM_CONTAINS_SECURITY 2
#define STREAM_CONTAINS_PROPERTIES 4

#define STARTF_USESHOWWINDOW    0x00000001
#define STARTF_USESIZE          0x00000002
#define STARTF_USEPOSITION      0x00000004
#define STARTF_USECOUNTCHARS    0x00000008
#define STARTF_USEFILLATTRIBUTE 0x00000010
#define STARTF_RUNFULLSCREEN    0x00000020
#define STARTF_FORCEONFEEDBACK  0x00000040
#define STARTF_FORCEOFFFEEDBACK 0x00000080
#define STARTF_USESTDHANDLES    0x00000100
#if (WINVER >= 0x400)
#define STARTF_USEHOTKEY        0x00000200
#define STARTF_TITLEISLINKNAME  0x00000800
#define STARTF_TITLEISAPPID     0x00001000
#define STARTF_PREVENTPINNING   0x00002000
#endif /* (WINVER >= 0x400) */
#if (WINVER >= 0x0600)
#define STARTF_UNTRUSTEDSOURCE  0x00008000
#endif /* (WINVER >= 0x0600) */

#define TC_NORMAL 0
#define TC_HARDERR 1
#define TC_GP_TRAP 2
#define TC_SIGNAL 3
#define AC_LINE_OFFLINE 0
#define AC_LINE_ONLINE 1
#define AC_LINE_BACKUP_POWER 2
#define AC_LINE_UNKNOWN 255
#define BATTERY_FLAG_HIGH 1
#define BATTERY_FLAG_LOW 2
#define BATTERY_FLAG_CRITICAL 4
#define BATTERY_FLAG_CHARGING 8
#define BATTERY_FLAG_NO_BATTERY 128
#define BATTERY_FLAG_UNKNOWN 255
#define BATTERY_PERCENTAGE_UNKNOWN 255
#define BATTERY_LIFE_UNKNOWN 0xFFFFFFFF
#define DDD_RAW_TARGET_PATH 1
#define DDD_REMOVE_DEFINITION 2
#define DDD_EXACT_MATCH_ON_REMOVE 4
#define DDD_NO_BROADCAST_SYSTEM 8
#define DDD_LUID_BROADCAST_DRIVE 16
#define HINSTANCE_ERROR 32
#define MS_CTS_ON 16
#define MS_DSR_ON 32
#define MS_RING_ON 64
#define MS_RLSD_ON 128
#define DTR_CONTROL_DISABLE 0
#define DTR_CONTROL_ENABLE 1
#define DTR_CONTROL_HANDSHAKE 2
#define RTS_CONTROL_DISABLE 0
#define RTS_CONTROL_ENABLE 1
#define RTS_CONTROL_HANDSHAKE 2
#define RTS_CONTROL_TOGGLE 3
#define SECURITY_ANONYMOUS (SecurityAnonymous<<16)
#define SECURITY_IDENTIFICATION (SecurityIdentification<<16)
#define SECURITY_IMPERSONATION (SecurityImpersonation<<16)
#define SECURITY_DELEGATION (SecurityDelegation<<16)
#define SECURITY_CONTEXT_TRACKING 0x40000
#define SECURITY_EFFECTIVE_ONLY 0x80000
#define SECURITY_SQOS_PRESENT 0x100000
#define SECURITY_VALID_SQOS_FLAGS 0x1F0000
#define INVALID_FILE_SIZE 0xFFFFFFFF
#define TLS_OUT_OF_INDEXES (DWORD)0xFFFFFFFF
#if (_WIN32_WINNT >= 0x0501)
#define ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID 0x00000001
#define ACTCTX_FLAG_LANGID_VALID 0x00000002
#define ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID 0x00000004
#define ACTCTX_FLAG_RESOURCE_NAME_VALID 0x00000008
#define ACTCTX_FLAG_SET_PROCESS_DEFAULT 0x00000010
#define ACTCTX_FLAG_APPLICATION_NAME_VALID 0x00000020
#define ACTCTX_FLAG_SOURCE_IS_ASSEMBLYREF 0x00000040
#define ACTCTX_FLAG_HMODULE_VALID 0x00000080
#define DEACTIVATE_ACTCTX_FLAG_FORCE_EARLY_DEACTIVATION 0x00000001
#define FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX 0x00000001
#define QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX 0x00000004
#define QUERY_ACTCTX_FLAG_ACTCTX_IS_HMODULE 0x00000008
#define QUERY_ACTCTX_FLAG_ACTCTX_IS_ADDRESS 0x00000010
#define QUERY_ACTCTX_FLAG_NO_ADDREF 0x80000000
#if (_WIN32_WINNT >= 0x0600)
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#endif /* (_WIN32_WINNT >= 0x0501) */
#if (_WIN32_WINNT >= 0x0500)
#define REPLACEFILE_WRITE_THROUGH 0x00000001
#define REPLACEFILE_IGNORE_MERGE_ERRORS 0x00000002
#endif /* (_WIN32_WINNT >= 0x0500) */
#if (_WIN32_WINNT >= 0x0400)
#define FIBER_FLAG_FLOAT_SWITCH 0x1
#endif
#define FLS_OUT_OF_INDEXES 0xFFFFFFFF
#if (_WIN32_WINNT >= 0x0600)
#define MAX_RESTART_CMD_LINE 0x800
#define RESTART_CYCLICAL 0x1
#define RESTART_NOTIFY_SOLUTION 0x2
#define RESTART_NOTIFY_FAULT 0x4
#define VOLUME_NAME_DOS 0x0
#define VOLUME_NAME_GUID 0x1
#define VOLUME_NAME_NT 0x2
#define VOLUME_NAME_NONE 0x4
#define FILE_NAME_NORMALIZED 0x0
#define FILE_NAME_OPENED 0x8
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif
#if (_WIN32_WINNT >= 0x0500)
#define GET_MODULE_HANDLE_EX_FLAG_PIN 0x1
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x2
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 0x4
#endif
#if (_WIN32_WINNT >= 0x0600)
#define CREATE_EVENT_MANUAL_RESET   0x1
#define CREATE_EVENT_INITIAL_SET    0x2
#define CREATE_MUTEX_INITIAL_OWNER  0x1
#define CREATE_WAITABLE_TIMER_MANUAL_RESET  0x1
#define SRWLOCK_INIT    RTL_SRWLOCK_INIT
#define CONDITION_VARIABLE_INIT RTL_CONDITION_VARIABLE_INIT
#define CONDITION_VARIABLE_LOCKMODE_SHARED  RTL_CONDITION_VARIABLE_LOCKMODE_SHARED
#endif

#define BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE  0x00001
#define BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE 0x10000
#define BASE_SEARCH_PATH_PERMANENT               0x08000
#define BASE_SEARCH_PATH_INVALID_FLAGS           (~0x18001)

#define INIT_ONCE_STATIC_INIT RTL_RUN_ONCE_INIT

#if (_WIN32_WINNT >= 0x0600)
#define PROCESS_DEP_ENABLE 0x00000001
#define PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION 0x00000002
#endif

#define LOGON_WITH_PROFILE        0x00000001
#define LOGON_NETCREDENTIALS_ONLY 0x00000002

#ifndef RC_INVOKED

typedef struct _BY_HANDLE_FILE_INFORMATION {
	DWORD	dwFileAttributes;
	FILETIME	ftCreationTime;
	FILETIME	ftLastAccessTime;
	FILETIME	ftLastWriteTime;
	DWORD	dwVolumeSerialNumber;
	DWORD	nFileSizeHigh;
	DWORD	nFileSizeLow;
	DWORD	nNumberOfLinks;
	DWORD	nFileIndexHigh;
	DWORD	nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION,*PBY_HANDLE_FILE_INFORMATION,*LPBY_HANDLE_FILE_INFORMATION;

typedef struct _DCB {
	DWORD DCBlength;
	DWORD BaudRate;
	DWORD fBinary:1;
	DWORD fParity:1;
	DWORD fOutxCtsFlow:1;
	DWORD fOutxDsrFlow:1;
	DWORD fDtrControl:2;
	DWORD fDsrSensitivity:1;
	DWORD fTXContinueOnXoff:1;
	DWORD fOutX:1;
	DWORD fInX:1;
	DWORD fErrorChar:1;
	DWORD fNull:1;
	DWORD fRtsControl:2;
	DWORD fAbortOnError:1;
	DWORD fDummy2:17;
	WORD wReserved;
	WORD XonLim;
	WORD XoffLim;
	BYTE ByteSize;
	BYTE Parity;
	BYTE StopBits;
	char XonChar;
	char XoffChar;
	char ErrorChar;
	char EofChar;
	char EvtChar;
	WORD wReserved1;
} DCB,*LPDCB;

typedef struct _COMM_CONFIG {
	DWORD dwSize;
	WORD  wVersion;
	WORD  wReserved;
	DCB   dcb;
	DWORD dwProviderSubType;
	DWORD dwProviderOffset;
	DWORD dwProviderSize;
	WCHAR wcProviderData[1];
} COMMCONFIG,*LPCOMMCONFIG;

typedef struct _COMMPROP {
	WORD	wPacketLength;
	WORD	wPacketVersion;
	DWORD	dwServiceMask;
	DWORD	dwReserved1;
	DWORD	dwMaxTxQueue;
	DWORD	dwMaxRxQueue;
	DWORD	dwMaxBaud;
	DWORD	dwProvSubType;
	DWORD	dwProvCapabilities;
	DWORD	dwSettableParams;
	DWORD	dwSettableBaud;
	WORD	wSettableData;
	WORD	wSettableStopParity;
	DWORD	dwCurrentTxQueue;
	DWORD	dwCurrentRxQueue;
	DWORD	dwProvSpec1;
	DWORD	dwProvSpec2;
	WCHAR	wcProvChar[1];
} COMMPROP,*LPCOMMPROP;

typedef struct _COMMTIMEOUTS {
	DWORD ReadIntervalTimeout;
	DWORD ReadTotalTimeoutMultiplier;
	DWORD ReadTotalTimeoutConstant;
	DWORD WriteTotalTimeoutMultiplier;
	DWORD WriteTotalTimeoutConstant;
} COMMTIMEOUTS,*LPCOMMTIMEOUTS;

typedef struct _COMSTAT {
	DWORD fCtsHold:1;
	DWORD fDsrHold:1;
	DWORD fRlsdHold:1;
	DWORD fXoffHold:1;
	DWORD fXoffSent:1;
	DWORD fEof:1;
	DWORD fTxim:1;
	DWORD fReserved:25;
	DWORD cbInQue;
	DWORD cbOutQue;
} COMSTAT,*LPCOMSTAT;

#ifndef MIDL_PASS
typedef PEXCEPTION_RECORD LPEXCEPTION_RECORD;
typedef PEXCEPTION_POINTERS LPEXCEPTION_POINTERS;
#endif

typedef struct _STARTUPINFOA {
	DWORD	cb;
	LPSTR	lpReserved;
	LPSTR	lpDesktop;
	LPSTR	lpTitle;
	DWORD	dwX;
	DWORD	dwY;
	DWORD	dwXSize;
	DWORD	dwYSize;
	DWORD	dwXCountChars;
	DWORD	dwYCountChars;
	DWORD	dwFillAttribute;
	DWORD	dwFlags;
	WORD	wShowWindow;
	WORD	cbReserved2;
	PBYTE	lpReserved2;
	HANDLE	hStdInput;
	HANDLE	hStdOutput;
	HANDLE	hStdError;
} STARTUPINFOA,*LPSTARTUPINFOA;

typedef struct _STARTUPINFOW {
	DWORD	cb;
	LPWSTR	lpReserved;
	LPWSTR	lpDesktop;
	LPWSTR	lpTitle;
	DWORD	dwX;
	DWORD	dwY;
	DWORD	dwXSize;
	DWORD	dwYSize;
	DWORD	dwXCountChars;
	DWORD	dwYCountChars;
	DWORD	dwFillAttribute;
	DWORD	dwFlags;
	WORD	wShowWindow;
	WORD	cbReserved2;
	PBYTE	lpReserved2;
	HANDLE	hStdInput;
	HANDLE	hStdOutput;
	HANDLE	hStdError;
} STARTUPINFOW,*LPSTARTUPINFOW;

typedef struct _PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
} PROCESS_INFORMATION,*PPROCESS_INFORMATION,*LPPROCESS_INFORMATION;

#if (_WIN32_WINNT >= 0x0500)
typedef WAITORTIMERCALLBACKFUNC WAITORTIMERCALLBACK ;
#endif
typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
	DWORD	dwFileAttributes;
	FILETIME	ftCreationTime;
	FILETIME	ftLastAccessTime;
	FILETIME	ftLastWriteTime;
	DWORD	nFileSizeHigh;
	DWORD	nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA,*LPWIN32_FILE_ATTRIBUTE_DATA;

#if (_WIN32_WINNT >= 0x0501)
typedef enum _STREAM_INFO_LEVELS {
	FindStreamInfoStandard
} STREAM_INFO_LEVELS;

typedef struct _WIN32_FIND_STREAM_DATA {
	LARGE_INTEGER StreamSize;
	WCHAR cStreamName[MAX_PATH + 36];
} WIN32_FIND_STREAM_DATA, *PWIN32_FIND_STREAM_DATA;
#endif

typedef struct _WIN32_STREAM_ID {
	DWORD dwStreamId;
	DWORD dwStreamAttributes;
	LARGE_INTEGER Size;
	DWORD dwStreamNameSize;
	WCHAR cStreamName[ANYSIZE_ARRAY];
} WIN32_STREAM_ID, *LPWIN32_STREAM_ID;

#if (_WIN32_WINNT >= 0x0600)

typedef enum _FILE_ID_TYPE {
    FileIdType,
    ObjectIdType,
    ExtendedFileIdType,
    MaximumFileIdType
} FILE_ID_TYPE, *PFILE_ID_TYPE;

typedef struct _FILE_ID_DESCRIPTOR {
    DWORD        dwSize;
    FILE_ID_TYPE Type;
    union {
        LARGE_INTEGER FileId;
        GUID          ObjectId;
    } DUMMYUNIONNAME;
} FILE_ID_DESCRIPTOR, *LPFILE_ID_DESCRIPTOR;

typedef struct _FILE_ID_BOTH_DIR_INFO {
    DWORD         NextEntryOffset;
    DWORD         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    DWORD         FileAttributes;
    DWORD         FileNameLength;
    DWORD         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFO, *PFILE_ID_BOTH_DIR_INFO;

typedef struct _FILE_BASIC_INFO {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    DWORD FileAttributes;
} FILE_BASIC_INFO, *PFILE_BASIC_INFO;

typedef struct _FILE_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    DWORD NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFO, *PFILE_STANDARD_INFO;

typedef struct _FILE_NAME_INFO {
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFO, *PFILE_NAME_INFO;

typedef enum _PRIORITY_HINT {
    IoPriorityHintVeryLow,
    IoPriorityHintLow,
    IoPriorityHintNormal,
    MaximumIoPriorityHintType
} PRIORITY_HINT;

typedef struct _FILE_IO_PRIORITY_HINT_INFO {
    PRIORITY_HINT PriorityHint;
} FILE_IO_PRIORITY_HINT_INFO;

typedef struct _FILE_ALLOCATION_INFO {
    LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFO, *PFILE_ALLOCATION_INFO;

typedef struct _FILE_DISPOSITION_INFO {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFO, *PFILE_DISPOSITION_INFO;

typedef struct _FILE_END_OF_FILE_INFO {
    LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFO, *PFILE_END_OF_FILE_INFO;

typedef struct _FILE_RENAME_INFO {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFO, *PFILE_RENAME_INFO;

typedef struct _FILE_ATTRIBUTE_TAG_INFO {
    DWORD FileAttributes;
    DWORD ReparseTag;
} FILE_ATTRIBUTE_TAG_INFO, *PFILE_ATTRIBUTE_TAG_INFO;

typedef struct _FILE_COMPRESSION_INFO {
    LARGE_INTEGER CompressedFileSize;
    WORD CompressionFormat;
    UCHAR CompressionUnitShift;
    UCHAR ChunkShift;
    UCHAR ClusterShift;
    UCHAR Reserved[3];
} FILE_COMPRESSION_INFO, *PFILE_COMPRESSION_INFO;

typedef struct _FILE_REMOTE_PROTOCOL_INFO {
    USHORT StructureVersion;
    USHORT StructureSize;
    ULONG Protocol;
    USHORT ProtocolMajorVersion;
    USHORT ProtocolMinorVersion;
    USHORT ProtocolRevision;
    USHORT Reserved;
    ULONG Flags;
    struct {
        ULONG Reserved[8];
    } GenericReserved;
    struct {
        ULONG Reserved[16];
    } ProtocolSpecificReserved;
} FILE_REMOTE_PROTOCOL_INFO, *PFILE_REMOTE_PROTOCOL_INFO;

#endif



typedef struct tagHW_PROFILE_INFOA {
	DWORD dwDockInfo;
	CHAR szHwProfileGuid[HW_PROFILE_GUIDLEN];
	CHAR szHwProfileName[MAX_PROFILE_LEN];
} HW_PROFILE_INFOA,*LPHW_PROFILE_INFOA;

typedef struct tagHW_PROFILE_INFOW {
	DWORD dwDockInfo;
	WCHAR szHwProfileGuid[HW_PROFILE_GUIDLEN];
	WCHAR szHwProfileName[MAX_PROFILE_LEN];
} HW_PROFILE_INFOW,*LPHW_PROFILE_INFOW;

/* Event Logging */

#define EVENTLOG_FULL_INFO          0

typedef struct _EVENTLOG_FULL_INFORMATION {
    DWORD dwFull;
} EVENTLOG_FULL_INFORMATION, *LPEVENTLOG_FULL_INFORMATION;

typedef struct _SYSTEM_INFO {
	_ANONYMOUS_UNION union {
		DWORD dwOemId;
		_ANONYMOUS_STRUCT struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
	DWORD dwPageSize;
	PVOID lpMinimumApplicationAddress;
	PVOID lpMaximumApplicationAddress;
	DWORD_PTR dwActiveProcessorMask;
	DWORD dwNumberOfProcessors;
	DWORD dwProcessorType;
	DWORD dwAllocationGranularity;
	WORD wProcessorLevel;
	WORD wProcessorRevision;
} SYSTEM_INFO,*LPSYSTEM_INFO;

typedef struct _SYSTEM_POWER_STATUS {
	BYTE ACLineStatus;
	BYTE BatteryFlag;
	BYTE BatteryLifePercent;
	BYTE SystemStatusFlag;
	DWORD BatteryLifeTime;
	DWORD BatteryFullLifeTime;
} SYSTEM_POWER_STATUS,*LPSYSTEM_POWER_STATUS;

typedef struct _TIME_DYNAMIC_ZONE_INFORMATION {
  LONG Bias;
  WCHAR StandardName[32];
  SYSTEMTIME StandardDate;
  LONG StandardBias;
  WCHAR DaylightName[32];
  SYSTEMTIME DaylightDate;
  LONG DaylightBias;
  WCHAR TimeZoneKeyName[128];
  BOOLEAN DynamicDaylightTimeDisabled;
} DYNAMIC_TIME_ZONE_INFORMATION, *PDYNAMIC_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[32];
	SYSTEMTIME StandardDate;
	LONG StandardBias;
	WCHAR DaylightName[32];
	SYSTEMTIME DaylightDate;
	LONG DaylightBias;
} TIME_ZONE_INFORMATION,*PTIME_ZONE_INFORMATION,*LPTIME_ZONE_INFORMATION;

typedef struct _MEMORYSTATUS {
	DWORD dwLength;
	DWORD dwMemoryLoad;
	SIZE_T dwTotalPhys;
	SIZE_T dwAvailPhys;
	SIZE_T dwTotalPageFile;
	SIZE_T dwAvailPageFile;
	SIZE_T dwTotalVirtual;
	SIZE_T dwAvailVirtual;
} MEMORYSTATUS,*LPMEMORYSTATUS;

#if (_WIN32_WINNT >= 0x0500)
typedef struct _MEMORYSTATUSEX {
	DWORD dwLength;
	DWORD dwMemoryLoad;
	DWORDLONG ullTotalPhys;
	DWORDLONG ullAvailPhys;
	DWORDLONG ullTotalPageFile;
	DWORDLONG ullAvailPageFile;
	DWORDLONG ullTotalVirtual;
	DWORDLONG ullAvailVirtual;
	DWORDLONG ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
#endif

#ifndef _LDT_ENTRY_DEFINED
#define _LDT_ENTRY_DEFINED
typedef struct _LDT_ENTRY {
	WORD LimitLow;
	WORD BaseLow;
	union {
		struct {
			BYTE BaseMid;
			BYTE Flags1;
			BYTE Flags2;
			BYTE BaseHi;
		} Bytes;
		struct {
			DWORD BaseMid:8;
			DWORD Type:5;
			DWORD Dpl:2;
			DWORD Pres:1;
			DWORD LimitHi:4;
			DWORD Sys:1;
			DWORD Reserved_0:1;
			DWORD Default_Big:1;
			DWORD Granularity:1;
			DWORD BaseHi:8;
		} Bits;
	} HighWord;
} LDT_ENTRY,*PLDT_ENTRY,*LPLDT_ENTRY;
#endif

typedef struct _OFSTRUCT {
	BYTE cBytes;
	BYTE fFixedDisk;
	WORD nErrCode;
	WORD Reserved1;
	WORD Reserved2;
	CHAR szPathName[OFS_MAXPATHNAME];
} OFSTRUCT,*LPOFSTRUCT,*POFSTRUCT;

#if (_WIN32_WINNT >= 0x0501)
typedef struct tagACTCTXA {
	ULONG cbSize;
	DWORD dwFlags;
	LPCSTR lpSource;
	USHORT wProcessorArchitecture;
	LANGID wLangId;
	LPCSTR lpAssemblyDirectory;
	LPCSTR lpResourceName;
	LPCSTR lpApplicationName;
	HMODULE hModule;
} ACTCTXA,*PACTCTXA;
typedef const ACTCTXA *PCACTCTXA;

typedef struct tagACTCTXW {
	ULONG cbSize;
	DWORD dwFlags;
	LPCWSTR lpSource;
	USHORT wProcessorArchitecture;
	LANGID wLangId;
	LPCWSTR lpAssemblyDirectory;
	LPCWSTR lpResourceName;
	LPCWSTR lpApplicationName;
	HMODULE hModule;
} ACTCTXW,*PACTCTXW;
typedef const ACTCTXW *PCACTCTXW;

typedef struct tagACTCTX_SECTION_KEYED_DATA_2600 {
	ULONG  cbSize;
	ULONG  ulDataFormatVersion;
	PVOID  lpData;
	ULONG  ulLength;
	PVOID  lpSectionGlobalData;
	ULONG  ulSectionGlobalDataLength;
	PVOID  lpSectionBase;
	ULONG  ulSectionTotalLength;
	HANDLE hActCtx;
	ULONG  ulAssemblyRosterIndex;
} ACTCTX_SECTION_KEYED_DATA_2600, *PACTCTX_SECTION_KEYED_DATA_2600;
typedef const ACTCTX_SECTION_KEYED_DATA_2600 *PCACTCTX_SECTION_KEYED_DATA_2600;

typedef struct tagACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA {
	PVOID lpInformation;
	PVOID lpSectionBase;
	ULONG ulSectionLength;
	PVOID lpSectionGlobalDataBase;
	ULONG ulSectionGlobalDataLength;
} ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA, *PACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA;
typedef const ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA *PCACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA;

typedef struct tagACTCTX_SECTION_KEYED_DATA {
	ULONG cbSize;
	ULONG ulDataFormatVersion;
	PVOID lpData;
	ULONG ulLength;
	PVOID lpSectionGlobalData;
	ULONG ulSectionGlobalDataLength;
	PVOID lpSectionBase;
	ULONG ulSectionTotalLength;
	HANDLE hActCtx;
	ULONG ulAssemblyRosterIndex;
	/* Non 2600 extra fields */
	ULONG ulFlags;
	ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA AssemblyMetadata;
} ACTCTX_SECTION_KEYED_DATA,*PACTCTX_SECTION_KEYED_DATA;

typedef const ACTCTX_SECTION_KEYED_DATA *PCACTCTX_SECTION_KEYED_DATA;

typedef struct _ACTIVATION_CONTEXT_BASIC_INFORMATION {
	HANDLE hActCtx;
	DWORD  dwFlags;
} ACTIVATION_CONTEXT_BASIC_INFORMATION, *PACTIVATION_CONTEXT_BASIC_INFORMATION;
typedef const struct _ACTIVATION_CONTEXT_BASIC_INFORMATION *PCACTIVATION_CONTEXT_BASIC_INFORMATION;

typedef BOOL
(WINAPI *PQUERYACTCTXW_FUNC)(
  _In_ DWORD dwFlags,
  _In_ HANDLE hActCtx,
  _In_opt_ PVOID pvSubInstance,
  _In_ ULONG ulInfoClass,
  _Out_writes_bytes_to_opt_(cbBuffer, *pcbWrittenOrRequired) PVOID pvBuffer,
  _In_ SIZE_T cbBuffer,
  _Out_opt_ SIZE_T *pcbWrittenOrRequired);

typedef enum {
	LowMemoryResourceNotification ,
	HighMemoryResourceNotification
} MEMORY_RESOURCE_NOTIFICATION_TYPE;
#endif /* (_WIN32_WINNT >= 0x0501) */

#if (_WIN32_WINNT >= 0x0500)
typedef enum _COMPUTER_NAME_FORMAT {
	ComputerNameNetBIOS,
	ComputerNameDnsHostname,
	ComputerNameDnsDomain,
	ComputerNameDnsFullyQualified,
	ComputerNamePhysicalNetBIOS,
	ComputerNamePhysicalDnsHostname,
	ComputerNamePhysicalDnsDomain,
	ComputerNamePhysicalDnsFullyQualified,
	ComputerNameMax
} COMPUTER_NAME_FORMAT;
#endif /* (_WIN32_WINNT >= 0x0500) */

typedef enum _DEP_SYSTEM_POLICY_TYPE
{
    DEPPolicyAlwaysOff = 0,
    DEPPolicyAlwaysOn,
    DEPPolicyOptIn,
    DEPPolicyOptOut,
    DEPTotalPolicyCount
} DEP_SYSTEM_POLICY_TYPE;

#if (_WIN32_WINNT >= 0x0600)
typedef RTL_SRWLOCK SRWLOCK, *PSRWLOCK;
typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;
#endif

typedef struct _PROC_THREAD_ATTRIBUTE_LIST *PPROC_THREAD_ATTRIBUTE_LIST, *LPPROC_THREAD_ATTRIBUTE_LIST;

#define PROC_THREAD_ATTRIBUTE_NUMBER 0x0000ffff
#define PROC_THREAD_ATTRIBUTE_THREAD 0x00010000
#define PROC_THREAD_ATTRIBUTE_INPUT 0x00020000
#define PROC_THREAD_ATTRIBUTE_ADDITIVE 0x00040000

typedef enum _PROC_THREAD_ATTRIBUTE_NUM {
  ProcThreadAttributeParentProcess = 0,
  ProcThreadAttributeHandleList = 2,
  ProcThreadAttributeGroupAffinity = 3,
  ProcThreadAttributeIdealProcessor = 5,
  ProcThreadAttributeUmsThread = 6,
  ProcThreadAttributeMitigationPolicy = 7,
  ProcThreadAttributeSecurityCapabilities = 9,
  ProcThreadAttributeProtectionLevel = 11,
  ProcThreadAttributeJobList = 13,
  ProcThreadAttributeChildProcessPolicy = 14,
  ProcThreadAttributeAllApplicationPackagesPolicy = 15,
  ProcThreadAttributeWin32kFilter = 16,
  ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
} PROC_THREAD_ATTRIBUTE_NUM;

#define PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR (ProcThreadAttributeIdealProcessor | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST (ProcThreadAttributeHandleList | PROC_THREAD_ATTRIBUTE_INPUT)
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (ProcThreadAttributeParentProcess | PROC_THREAD_ATTRIBUTE_INPUT)

typedef DWORD
(WINAPI *PFE_EXPORT_FUNC)(
  _In_reads_bytes_(ulLength) PBYTE pbData,
  _In_opt_ PVOID pvCallbackContext,
  _In_ ULONG ulLength);

typedef DWORD(WINAPI *LPPROGRESS_ROUTINE)(_In_ LARGE_INTEGER, _In_ LARGE_INTEGER, _In_ LARGE_INTEGER, _In_ LARGE_INTEGER, _In_ DWORD, _In_ DWORD, _In_ HANDLE, _In_ HANDLE, _In_opt_ LPVOID);

typedef VOID (WINAPI *PFIBER_START_ROUTINE)( LPVOID lpFiberParameter );
typedef PFIBER_START_ROUTINE LPFIBER_START_ROUTINE;

typedef VOID (WINAPI *PFLS_CALLBACK_FUNCTION)(PVOID);
typedef BOOL(CALLBACK *ENUMRESLANGPROCA)(HMODULE,LPCSTR,LPCSTR,WORD,LONG_PTR);
typedef BOOL(CALLBACK *ENUMRESLANGPROCW)(HMODULE,LPCWSTR,LPCWSTR,WORD,LONG_PTR);
typedef BOOL(CALLBACK *ENUMRESNAMEPROCA)(HMODULE,LPCSTR,LPSTR,LONG_PTR);
typedef BOOL(CALLBACK *ENUMRESNAMEPROCW)(HMODULE,LPCWSTR,LPWSTR,LONG_PTR);
typedef BOOL(CALLBACK *ENUMRESTYPEPROCA)(HMODULE,LPSTR,LONG_PTR);
typedef BOOL(CALLBACK *ENUMRESTYPEPROCW)(HMODULE,LPWSTR,LONG_PTR);
typedef LONG(CALLBACK *PTOP_LEVEL_EXCEPTION_FILTER)(LPEXCEPTION_POINTERS);
typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;
typedef void(APIENTRY *PAPCFUNC)(ULONG_PTR);
typedef void(CALLBACK *PTIMERAPCROUTINE)(PVOID,DWORD,DWORD);
#if (_WIN32_WINNT >= 0x0600)
typedef DWORD (WINAPI *APPLICATION_RECOVERY_CALLBACK)(PVOID);
#endif

#ifdef WINE_NO_UNICODE_MACROS /* force using a cast */
#define MAKEINTATOM(atom)   ((ULONG_PTR)((WORD)(atom)))
#else
#define MAKEINTATOM(i) (LPTSTR)((ULONG_PTR)((WORD)(i)))
#endif

typedef DWORD
(WINAPI *PFE_IMPORT_FUNC)(
  _Out_writes_bytes_to_(*ulLength, *ulLength) PBYTE pbData,
  _In_opt_ PVOID pvCallbackContext,
  _Inout_ PULONG ulLength);

/* Functions */
#ifndef UNDER_CE
int APIENTRY WinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ LPSTR, _In_ int);
#else
int APIENTRY WinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int);
#endif
int APIENTRY wWinMain(_In_ HINSTANCE, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int);

long
WINAPI
_hread(
  _In_ HFILE hFile,
  _Out_writes_bytes_to_(lBytes, return) LPVOID lpBuffer,
  _In_ long lBytes);

long
WINAPI
_hwrite(
  _In_ HFILE hFile,
  _In_reads_bytes_(lBytes) LPCCH lpBuffer,
  _In_ long lBytes);

HFILE WINAPI _lclose(_In_ HFILE);
HFILE WINAPI _lcreat(_In_ LPCSTR, _In_ int);
LONG WINAPI _llseek(_In_ HFILE, _In_ LONG, _In_ int);
HFILE WINAPI _lopen(_In_ LPCSTR, _In_ int);

UINT
WINAPI
_lread(
  _In_ HFILE hFile,
  _Out_writes_bytes_to_(uBytes, return) LPVOID lpBuffer,
  _In_ UINT uBytes);

UINT
WINAPI
_lwrite(
  _In_ HFILE hFile,
  _In_reads_bytes_(uBytes) LPCCH lpBuffer,
  _In_ UINT uBytes);

BOOL WINAPI AccessCheck(PSECURITY_DESCRIPTOR,HANDLE,DWORD,PGENERIC_MAPPING,PPRIVILEGE_SET,PDWORD,PDWORD,PBOOL);

BOOL
WINAPI
AccessCheckAndAuditAlarmA(
  _In_ LPCSTR SubsystemName,
  _In_opt_ LPVOID HandleId,
  _In_ LPSTR ObjectTypeName,
  _In_opt_ LPSTR ObjectName,
  _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
  _In_ DWORD DesiredAccess,
  _In_ PGENERIC_MAPPING GenericMapping,
  _In_ BOOL ObjectCreation,
  _Out_ LPDWORD GrantedAccess,
  _Out_ LPBOOL AccessStatus,
  _Out_ LPBOOL pfGenerateOnClose);

BOOL WINAPI AccessCheckAndAuditAlarmW(LPCWSTR,LPVOID,LPWSTR,LPWSTR,PSECURITY_DESCRIPTOR,DWORD,PGENERIC_MAPPING,BOOL,PDWORD,PBOOL,PBOOL);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI AcquireSRWLockExclusive(PSRWLOCK);
VOID WINAPI AcquireSRWLockShared(PSRWLOCK);
#endif
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI ActivateActCtx(_Inout_opt_ HANDLE, _Out_ ULONG_PTR*);
#endif
BOOL WINAPI AddAccessAllowedAce(PACL,DWORD,DWORD,PSID);
BOOL WINAPI AddAccessDeniedAce(PACL,DWORD,DWORD,PSID);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI AddAccessAllowedAceEx(PACL,DWORD,DWORD,DWORD,PSID);
BOOL WINAPI AddAccessDeniedAceEx(PACL,DWORD,DWORD,DWORD,PSID);
BOOL WINAPI AddAccessAllowedObjectAce(PACL,DWORD,DWORD,DWORD,GUID*,GUID*,PSID);
BOOL WINAPI AddAccessDeniedObjectAce(PACL,DWORD,DWORD,DWORD,GUID*,GUID*,PSID);
#endif
BOOL WINAPI AddAce(PACL,DWORD,DWORD,PVOID,DWORD);
ATOM WINAPI AddAtomA(_In_opt_ LPCSTR);
ATOM WINAPI AddAtomW(_In_opt_ LPCWSTR);
BOOL WINAPI AddAuditAccessAce(PACL,DWORD,DWORD,PSID,BOOL,BOOL);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI AddAuditAccessObjectAce(PACL,DWORD,DWORD,DWORD,GUID*,GUID*,PSID,BOOL,BOOL);
#endif
#if (_WIN32_WINNT >= 0x0501)
void WINAPI AddRefActCtx(_Inout_ HANDLE);
#endif
#if (_WIN32_WINNT >= 0x0500)
_Ret_maybenull_ PVOID WINAPI AddVectoredExceptionHandler(_In_ ULONG, _In_ PVECTORED_EXCEPTION_HANDLER);
_Ret_maybenull_ PVOID WINAPI AddVectoredContinueHandler(_In_ ULONG, _In_ PVECTORED_EXCEPTION_HANDLER);
#endif

BOOL
WINAPI
AccessCheckByType(
  _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _In_opt_ PSID PrincipalSelfSid,
  _In_ HANDLE ClientToken,
  _In_ DWORD DesiredAccess,
  _In_reads_opt_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
  _In_ DWORD ObjectTypeListLength,
  _In_ PGENERIC_MAPPING GenericMapping,
  _Out_writes_bytes_(*PrivilegeSetLength)PPRIVILEGE_SET PrivilegeSet,
  _Inout_ LPDWORD PrivilegeSetLength,
  _Out_ LPDWORD GrantedAccess,
  _Out_ LPBOOL AccessStatus);

BOOL
WINAPI
AccessCheckByTypeResultList(
  _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _In_opt_ PSID PrincipalSelfSid,
  _In_ HANDLE ClientToken,
  _In_ DWORD DesiredAccess,
  _In_reads_(ObjectTypeListLength) POBJECT_TYPE_LIST ObjectTypeList,
  _In_ DWORD ObjectTypeListLength,
  _In_ PGENERIC_MAPPING GenericMapping,
  _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
  _Inout_ LPDWORD PrivilegeSetLength,
  _Out_writes_(ObjectTypeListLength) LPDWORD GrantedAccess,
  _Out_writes_(ObjectTypeListLength) LPBOOL AccessStatus);

BOOL WINAPI AdjustTokenGroups(HANDLE,BOOL,PTOKEN_GROUPS,DWORD,PTOKEN_GROUPS,PDWORD);
BOOL WINAPI AdjustTokenPrivileges(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
BOOL WINAPI AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY,BYTE,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,PSID*);
BOOL WINAPI CheckTokenMembership(HANDLE,PSID,PBOOL);
BOOL WINAPI AllocateLocallyUniqueId(PLUID);
BOOL WINAPI AreAllAccessesGranted(DWORD,DWORD);
BOOL WINAPI AreAnyAccessesGranted(DWORD,DWORD);
BOOL WINAPI AreFileApisANSI(void);
BOOL WINAPI BackupEventLogA(_In_ HANDLE, _In_ LPCSTR);
BOOL WINAPI BackupEventLogW(_In_ HANDLE, _In_ LPCWSTR);

BOOL
WINAPI
BackupRead(
  _In_ HANDLE hFile,
  _Out_writes_bytes_to_(nNumberOfBytesToRead, *lpNumberOfBytesRead) LPBYTE lpBuffer,
  _In_ DWORD nNumberOfBytesToRead,
  _Out_ LPDWORD lpNumberOfBytesRead,
  _In_ BOOL bAbort,
  _In_ BOOL bProcessSecurity,
  _Inout_ LPVOID *lpContext);

BOOL WINAPI BackupSeek(_In_ HANDLE, _In_ DWORD, _In_ DWORD, _Out_ LPDWORD, _Out_ LPDWORD, _Inout_ LPVOID*);

BOOL
WINAPI
BackupWrite(
  _In_ HANDLE hFile,
  _In_reads_bytes_(nNumberOfBytesToWrite) LPBYTE lpBuffer,
  _In_ DWORD nNumberOfBytesToWrite,
  _Out_ LPDWORD lpNumberOfBytesWritten,
  _In_ BOOL bAbort,
  _In_ BOOL bProcessSecurity,
  _Inout_ LPVOID *lpContext);

BOOL WINAPI Beep(DWORD,DWORD);
HANDLE WINAPI BeginUpdateResourceA(_In_ LPCSTR, _In_ BOOL);
HANDLE WINAPI BeginUpdateResourceW(_In_ LPCWSTR, _In_ BOOL);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI BindIoCompletionCallback(_In_ HANDLE, _In_ LPOVERLAPPED_COMPLETION_ROUTINE, _In_ ULONG);
#endif
BOOL WINAPI BuildCommDCBA(_In_ LPCSTR, _Out_ LPDCB);
BOOL WINAPI BuildCommDCBW(_In_ LPCWSTR, _Out_ LPDCB);
BOOL WINAPI BuildCommDCBAndTimeoutsA(_In_ LPCSTR, _Out_ LPDCB, _Out_ LPCOMMTIMEOUTS);
BOOL WINAPI BuildCommDCBAndTimeoutsW(_In_ LPCWSTR, _Out_ LPDCB, _Out_ LPCOMMTIMEOUTS);

BOOL
WINAPI
CallNamedPipeA(
  _In_ LPCSTR lpNamedPipeName,
  _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
  _In_ DWORD nInBufferSize,
  _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesRead) LPVOID lpOutBuffer,
  _In_ DWORD nOutBufferSize,
  _Out_ LPDWORD lpBytesRead,
  _In_ DWORD nTimeOut);

BOOL
WINAPI
CallNamedPipeW(
  _In_ LPCWSTR lpNamedPipeName,
  _In_reads_bytes_opt_(nInBufferSize) LPVOID lpInBuffer,
  _In_ DWORD nInBufferSize,
  _Out_writes_bytes_to_opt_(nOutBufferSize, *lpBytesRead) LPVOID lpOutBuffer,
  _In_ DWORD nOutBufferSize,
  _Out_ LPDWORD lpBytesRead,
  _In_ DWORD nTimeOut);

BOOL WINAPI CancelDeviceWakeupRequest(_In_ HANDLE);
BOOL WINAPI CancelWaitableTimer(HANDLE);

#if (_WIN32_WINNT >= 0x0501)

BOOL
WINAPI
CheckNameLegalDOS8Dot3A(
  _In_ LPCSTR lpName,
  _Out_writes_opt_(OemNameSize) LPSTR lpOemName,
  _In_ DWORD OemNameSize,
  _Out_opt_ PBOOL pbNameContainsSpaces,
  _Out_ PBOOL pbNameLegal);

BOOL
WINAPI
CheckNameLegalDOS8Dot3W(
  _In_ LPCWSTR lpName,
  _Out_writes_opt_(OemNameSize) LPSTR lpOemName,
  _In_ DWORD OemNameSize,
  _Out_opt_ PBOOL pbNameContainsSpaces,
  _Out_ PBOOL pbNameLegal);

BOOL WINAPI CheckRemoteDebuggerPresent(_In_ HANDLE, _Out_ PBOOL);
#endif

BOOL WINAPI ClearCommBreak(_In_ HANDLE);
BOOL WINAPI ClearCommError(_In_ HANDLE, _Out_opt_ PDWORD, _Out_opt_ LPCOMSTAT);
BOOL WINAPI ClearEventLogA(_In_ HANDLE, _In_opt_ LPCSTR);
BOOL WINAPI ClearEventLogW(_In_ HANDLE, _In_opt_ LPCWSTR);
BOOL WINAPI CloseEventLog(_In_ HANDLE);
BOOL WINAPI CloseHandle(HANDLE);
BOOL WINAPI CommConfigDialogA(_In_ LPCSTR, _In_opt_ HWND, _Inout_ LPCOMMCONFIG);
BOOL WINAPI CommConfigDialogW(_In_ LPCWSTR, _In_opt_ HWND, _Inout_ LPCOMMCONFIG);
LONG WINAPI CompareFileTime(CONST FILETIME*,CONST FILETIME*);
BOOL WINAPI ConnectNamedPipe(HANDLE,LPOVERLAPPED);
BOOL WINAPI ContinueDebugEvent(DWORD,DWORD,DWORD);
#if (_WIN32_WINNT >= 0x0400)
BOOL WINAPI ConvertFiberToThread(void);
#endif
_Ret_maybenull_ PVOID WINAPI ConvertThreadToFiber(_In_opt_ PVOID);
BOOL WINAPI CopyFileA(_In_ LPCSTR, _In_ LPCSTR, _In_ BOOL);
BOOL WINAPI CopyFileW(_In_ LPCWSTR lpExistingFileName, _In_ LPCWSTR lpNewFileName, _In_ BOOL bFailIfExists);
BOOL WINAPI CopyFileExA(_In_ LPCSTR, _In_ LPCSTR, _In_opt_ LPPROGRESS_ROUTINE, _In_opt_ LPVOID, _In_opt_ LPBOOL, _In_ DWORD);
BOOL WINAPI CopyFileExW(_In_ LPCWSTR, _In_ LPCWSTR, _In_opt_ LPPROGRESS_ROUTINE, _In_opt_ LPVOID, _In_opt_ LPBOOL, _In_ DWORD);
#define SecureZeroMemory RtlSecureZeroMemory
BOOL WINAPI CopySid(DWORD,PSID,PSID);
#if (_WIN32_WINNT >= 0x0501)
HANDLE WINAPI CreateActCtxA(_In_ PCACTCTXA);
HANDLE WINAPI CreateActCtxW(_In_ PCACTCTXW);
#endif
BOOL WINAPI CreateDirectoryA(LPCSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI CreateDirectoryW(LPCWSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI CreateDirectoryExA(_In_ LPCSTR, _In_ LPCSTR, _In_opt_ LPSECURITY_ATTRIBUTES);
BOOL WINAPI CreateDirectoryExW(_In_ LPCWSTR, _In_ LPCWSTR, _In_opt_ LPSECURITY_ATTRIBUTES);
HANDLE WINAPI CreateEventA(_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ LPCSTR lpName);
HANDLE WINAPI CreateEventW(_In_opt_ LPSECURITY_ATTRIBUTES,_In_ BOOL bManualReset, _In_ BOOL bInitialState,_In_opt_ LPCWSTR lpName);
#if (_WIN32_WINNT >= 0x0600)
HANDLE WINAPI CreateEventExA(LPSECURITY_ATTRIBUTES,LPCSTR,DWORD,DWORD);
HANDLE WINAPI CreateEventExW(LPSECURITY_ATTRIBUTES,LPCWSTR,DWORD,DWORD);
#endif
_Ret_maybenull_ LPVOID WINAPI CreateFiber(_In_ SIZE_T, _In_ LPFIBER_START_ROUTINE, _In_opt_ LPVOID);
#if (_WIN32_WINNT >= 0x0400)
_Ret_maybenull_ LPVOID WINAPI CreateFiberEx(_In_ SIZE_T, _In_ SIZE_T, _In_ DWORD, _In_ LPFIBER_START_ROUTINE, _In_opt_ LPVOID);
#endif
HANDLE WINAPI CreateFileA(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
HANDLE WINAPI CreateFileW(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
_Ret_maybenull_ HANDLE WINAPI CreateFileMappingA(_In_ HANDLE, _In_opt_ LPSECURITY_ATTRIBUTES, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_opt_ LPCSTR);
HANDLE WINAPI CreateFileMappingW(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI CreateHardLinkA(_In_ LPCSTR, _In_ LPCSTR, _Reserved_ LPSECURITY_ATTRIBUTES);
BOOL WINAPI CreateHardLinkW(_In_ LPCWSTR, _In_ LPCWSTR, _Reserved_ LPSECURITY_ATTRIBUTES);
#endif
#if (_WIN32_WINNT >= 0x0500)
_Ret_maybenull_ HANDLE WINAPI CreateJobObjectA(_In_opt_ LPSECURITY_ATTRIBUTES, _In_opt_ LPCSTR);
_Ret_maybenull_ HANDLE WINAPI CreateJobObjectW(_In_opt_ LPSECURITY_ATTRIBUTES, _In_opt_ LPCWSTR);
BOOL WINAPI TerminateJobObject(_In_ HANDLE, _In_ UINT);
BOOL WINAPI AssignProcessToJobObject(_In_ HANDLE, _In_ HANDLE);
#endif
HANDLE WINAPI CreateMailslotA(_In_ LPCSTR, _In_ DWORD, _In_ DWORD, _In_opt_ LPSECURITY_ATTRIBUTES);
HANDLE WINAPI CreateMailslotW(_In_ LPCWSTR, _In_ DWORD, _In_ DWORD, _In_opt_ LPSECURITY_ATTRIBUTES);
#if (_WIN32_WINNT >= 0x0501)
HANDLE WINAPI CreateMemoryResourceNotification(MEMORY_RESOURCE_NOTIFICATION_TYPE);
#endif
HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES,BOOL,LPCSTR);
HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES,BOOL,LPCWSTR);
#if (_WIN32_WINNT >= 0x0600)
HANDLE WINAPI CreateMutexExA(LPSECURITY_ATTRIBUTES,LPCSTR,DWORD,DWORD);
HANDLE WINAPI CreateMutexExW(LPSECURITY_ATTRIBUTES,LPCWSTR,DWORD,DWORD);
#endif
HANDLE WINAPI CreateNamedPipeA(_In_ LPCSTR, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_opt_ LPSECURITY_ATTRIBUTES);
HANDLE WINAPI CreateNamedPipeW(_In_ LPCWSTR, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_opt_ LPSECURITY_ATTRIBUTES);
BOOL WINAPI CreatePipe(PHANDLE,PHANDLE,LPSECURITY_ATTRIBUTES,DWORD);
BOOL WINAPI CreatePrivateObjectSecurity(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR*,BOOL,HANDLE,PGENERIC_MAPPING);
BOOL WINAPI CreateProcessA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessW(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);

BOOL
WINAPI
CreateProcessAsUserA(
  _In_opt_ HANDLE,
  _In_opt_ LPCSTR,
  _Inout_opt_ LPSTR,
  _In_opt_ LPSECURITY_ATTRIBUTES,
  _In_opt_ LPSECURITY_ATTRIBUTES,
  _In_ BOOL,
  _In_ DWORD,
  _In_opt_ PVOID,
  _In_opt_ LPCSTR,
  _In_ LPSTARTUPINFOA,
  _Out_ LPPROCESS_INFORMATION);

BOOL WINAPI CreateProcessAsUserW(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessWithLogonW(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
BOOL WINAPI CreateProcessWithTokenW(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
HANDLE WINAPI CreateRemoteThread(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);

BOOL
WINAPI
CreateRestrictedToken(
  _In_ HANDLE ExistingTokenHandle,
  _In_ DWORD Flags,
  _In_ DWORD DisableSidCount,
  _In_reads_opt_(DisableSidCount) PSID_AND_ATTRIBUTES SidsToDisable,
  _In_ DWORD DeletePrivilegeCount,
  _In_reads_opt_(DeletePrivilegeCount) PLUID_AND_ATTRIBUTES PrivilegesToDelete,
  _In_ DWORD RestrictedSidCount,
  _In_reads_opt_(RestrictedSidCount) PSID_AND_ATTRIBUTES SidsToRestrict,
  _Outptr_ PHANDLE NewTokenHandle);

_Ret_maybenull_ HANDLE WINAPI CreateSemaphoreA(_In_opt_ LPSECURITY_ATTRIBUTES, _In_ LONG, _In_ LONG, _In_opt_ LPCSTR);
_Ret_maybenull_ HANDLE WINAPI CreateSemaphoreW(_In_opt_ LPSECURITY_ATTRIBUTES, _In_ LONG, _In_ LONG, _In_opt_ LPCWSTR);
#if (_WIN32_WINNT >= 0x0600)
_Ret_maybenull_ HANDLE WINAPI CreateSemaphoreExA(_In_opt_ LPSECURITY_ATTRIBUTES, _In_ LONG, _In_ LONG, _In_opt_ LPCSTR, _Reserved_ DWORD, _In_ DWORD);
HANDLE WINAPI CreateSemaphoreExW(LPSECURITY_ATTRIBUTES,LONG,LONG,LPCWSTR,DWORD,DWORD);
#endif
DWORD WINAPI CreateTapePartition(_In_ HANDLE, _In_ DWORD, _In_ DWORD, _In_ DWORD);

#if (_WIN32_WINNT >= 0x0500)

HANDLE WINAPI CreateTimerQueue(void);

BOOL
WINAPI
CreateTimerQueueTimer(
  _Outptr_ PHANDLE,
  _In_opt_ HANDLE,
  _In_ WAITORTIMERCALLBACK,
  _In_opt_ PVOID,
  _In_ DWORD,
  _In_ DWORD,
  _In_ ULONG);

_Must_inspect_result_
BOOL
WINAPI
ChangeTimerQueueTimer(
  _In_opt_ HANDLE TimerQueue,
  _Inout_ HANDLE Timer,
  _In_ ULONG DueTime,
  _In_ ULONG Period);

#endif /* (_WIN32_WINNT >= 0x0500) */

HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES,DWORD,LPTHREAD_START_ROUTINE,PVOID,DWORD,PDWORD);
_Ret_maybenull_ HANDLE WINAPI CreateWaitableTimerA(_In_opt_ LPSECURITY_ATTRIBUTES, _In_ BOOL, _In_opt_ LPCSTR);
_Ret_maybenull_ HANDLE WINAPI CreateWaitableTimerW(_In_opt_ LPSECURITY_ATTRIBUTES, _In_ BOOL, _In_opt_ LPCWSTR);
#if (_WIN32_WINNT >= 0x0600)
_Ret_maybenull_ HANDLE WINAPI CreateWaitableTimerExA(_In_opt_ LPSECURITY_ATTRIBUTES, _In_opt_ LPCSTR, _In_ DWORD, _In_ DWORD);
HANDLE WINAPI CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES,LPCWSTR,DWORD,DWORD);
#endif
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI CreateWellKnownSid(WELL_KNOWN_SID_TYPE,PSID,PSID,DWORD*);
BOOL WINAPI DeactivateActCtx(_In_ DWORD, _In_ ULONG_PTR);
#endif
BOOL WINAPI DebugActiveProcess(DWORD);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI DebugActiveProcessStop(DWORD);
#endif
void WINAPI DebugBreak(void);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI DebugBreakProcess(_In_ HANDLE);
BOOL WINAPI DebugSetProcessKillOnExit(_In_ BOOL);
#endif
PVOID WINAPI DecodePointer(PVOID);
PVOID WINAPI DecodeSystemPointer(PVOID);
BOOL WINAPI DecryptFileA(_In_ LPCSTR, _Reserved_ DWORD);
BOOL WINAPI DecryptFileW(_In_ LPCWSTR, _Reserved_ DWORD);
BOOL WINAPI DefineDosDeviceA(_In_ DWORD, _In_ LPCSTR, _In_opt_ LPCSTR);
BOOL WINAPI DefineDosDeviceW(DWORD,LPCWSTR,LPCWSTR);
#define DefineHandleTable(w) ((w),TRUE)
BOOL WINAPI DeleteAce(PACL,DWORD);
ATOM WINAPI DeleteAtom(_In_ ATOM);
void WINAPI DeleteCriticalSection(PCRITICAL_SECTION);
void WINAPI DeleteFiber(_In_ PVOID);
BOOL WINAPI DeleteFileA(LPCSTR);
BOOL WINAPI DeleteFileW(LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
_Must_inspect_result_ BOOL WINAPI DeleteTimerQueue(_In_ HANDLE);
BOOL WINAPI DeleteTimerQueueEx(HANDLE,HANDLE);
BOOL WINAPI DeleteTimerQueueTimer(HANDLE,HANDLE,HANDLE);
BOOL WINAPI DeleteVolumeMountPointA(_In_ LPCSTR);
BOOL WINAPI DeleteVolumeMountPointW(LPCWSTR);
#endif
BOOL WINAPI DeregisterEventSource(_In_ HANDLE);
BOOL WINAPI DestroyPrivateObjectSecurity(PSECURITY_DESCRIPTOR*);
BOOL WINAPI DisableThreadLibraryCalls(HMODULE);

#if (_WIN32_WINNT >= 0x0500)

_Success_(return != FALSE)
BOOL
WINAPI
DnsHostnameToComputerNameA(
  _In_ LPCSTR Hostname,
  _Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR ComputerName,
  _Inout_ LPDWORD nSize);

_Success_(return != FALSE)
BOOL
WINAPI
DnsHostnameToComputerNameW(
  _In_ LPCWSTR Hostname,
  _Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR ComputerName,
  _Inout_ LPDWORD nSize);

#endif

BOOL WINAPI DisconnectNamedPipe(HANDLE);
BOOL WINAPI DosDateTimeToFileTime(_In_ WORD, _In_ WORD, _Out_ LPFILETIME);
BOOL WINAPI DuplicateHandle(HANDLE,HANDLE,HANDLE,PHANDLE,DWORD,BOOL,DWORD);
BOOL WINAPI DuplicateToken(HANDLE,SECURITY_IMPERSONATION_LEVEL,PHANDLE);
BOOL WINAPI DuplicateTokenEx(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
PVOID WINAPI EncodePointer(PVOID);
PVOID WINAPI EncodeSystemPointer(PVOID);
BOOL WINAPI EncryptFileA(_In_ LPCSTR);
BOOL WINAPI EncryptFileW(_In_ LPCWSTR);
BOOL WINAPI EndUpdateResourceA(_In_ HANDLE, _In_ BOOL);
BOOL WINAPI EndUpdateResourceW(_In_ HANDLE, _In_ BOOL);
void WINAPI EnterCriticalSection(LPCRITICAL_SECTION);
BOOL WINAPI EnumResourceLanguagesA(_In_opt_ HMODULE, _In_ LPCSTR, _In_ LPCSTR, _In_ ENUMRESLANGPROCA, _In_ LONG_PTR);
BOOL WINAPI EnumResourceLanguagesW(_In_opt_ HMODULE, _In_ LPCWSTR, _In_ LPCWSTR, _In_ ENUMRESLANGPROCW, _In_ LONG_PTR);
BOOL WINAPI EnumResourceNamesA(_In_opt_ HMODULE, _In_ LPCSTR, _In_ ENUMRESNAMEPROCA, _In_ LONG_PTR);
BOOL WINAPI EnumResourceNamesW(_In_opt_ HMODULE, _In_ LPCWSTR, _In_ ENUMRESNAMEPROCW, _In_ LONG_PTR);
BOOL WINAPI EnumResourceTypesA(_In_opt_ HMODULE, _In_ ENUMRESTYPEPROCA, _In_ LONG_PTR);
BOOL WINAPI EnumResourceTypesW(_In_opt_ HMODULE, _In_ ENUMRESTYPEPROCW, _In_ LONG_PTR);
BOOL WINAPI EqualPrefixSid(PSID,PSID);
BOOL WINAPI EqualSid(PSID,PSID);
DWORD WINAPI EraseTape(_In_ HANDLE, _In_ DWORD, _In_ BOOL);
BOOL WINAPI EscapeCommFunction(_In_ HANDLE, _In_ DWORD);
DECLSPEC_NORETURN void WINAPI ExitProcess(UINT);
DECLSPEC_NORETURN void WINAPI ExitThread(_In_ DWORD dwExitCode);
DWORD WINAPI ExpandEnvironmentStringsA(LPCSTR,LPSTR,DWORD);
DWORD WINAPI ExpandEnvironmentStringsW(LPCWSTR,LPWSTR,DWORD);
void WINAPI FatalAppExitA(UINT,LPCSTR);
void WINAPI FatalAppExitW(UINT,LPCWSTR);
__analysis_noreturn void WINAPI FatalExit(_In_ int);
BOOL WINAPI FileEncryptionStatusA(_In_ LPCSTR, _Out_ LPDWORD);
BOOL WINAPI FileEncryptionStatusW(_In_ LPCWSTR, _Out_ LPDWORD);
BOOL WINAPI FileTimeToDosDateTime(_In_ CONST FILETIME *, _Out_ LPWORD, _Out_ LPWORD);
BOOL WINAPI FileTimeToLocalFileTime(CONST FILETIME *,LPFILETIME);
BOOL WINAPI FileTimeToSystemTime(CONST FILETIME *,LPSYSTEMTIME);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI FindActCtxSectionGuid(_In_ DWORD, _Reserved_ const GUID*, _In_ ULONG, _In_opt_ const GUID*, _Out_ PACTCTX_SECTION_KEYED_DATA);
BOOL WINAPI FindActCtxSectionStringA(_In_ DWORD, _Reserved_ const GUID*, _In_ ULONG, _In_ LPCSTR, _Out_ PACTCTX_SECTION_KEYED_DATA);
BOOL WINAPI FindActCtxSectionStringW(_In_ DWORD, _Reserved_ const GUID*, _In_ ULONG, _In_ LPCWSTR, _Out_ PACTCTX_SECTION_KEYED_DATA);
#endif
ATOM WINAPI FindAtomA(_In_opt_ LPCSTR);
ATOM WINAPI FindAtomW(_In_opt_ LPCWSTR);
BOOL WINAPI FindClose(HANDLE);
BOOL WINAPI FindCloseChangeNotification(HANDLE);
HANDLE WINAPI FindFirstChangeNotificationA(LPCSTR,BOOL,DWORD);
HANDLE WINAPI FindFirstChangeNotificationW(LPCWSTR,BOOL,DWORD);
HANDLE WINAPI FindFirstFileA(LPCSTR,LPWIN32_FIND_DATAA);
HANDLE WINAPI FindFirstFileW(LPCWSTR,LPWIN32_FIND_DATAW);
HANDLE WINAPI FindFirstFileExA(LPCSTR,FINDEX_INFO_LEVELS,PVOID,FINDEX_SEARCH_OPS,PVOID,DWORD);
HANDLE WINAPI FindFirstFileExW(LPCWSTR,FINDEX_INFO_LEVELS,PVOID,FINDEX_SEARCH_OPS,PVOID,DWORD);
#if (_WIN32_WINNT >= 0x0501)
HANDLE WINAPI FindFirstStreamW(_In_ LPCWSTR, _In_ STREAM_INFO_LEVELS, _Out_ LPVOID, _Reserved_ DWORD);
#endif
BOOL WINAPI FindFirstFreeAce(PACL,PVOID*);

#if (_WIN32_WINNT >= 0x0500)

HANDLE
WINAPI
FindFirstVolumeA(
  _Out_writes_(cchBufferLength) LPSTR lpszVolumeName,
  _In_ DWORD cchBufferLength);

HANDLE WINAPI FindFirstVolumeW(LPWSTR,DWORD);

HANDLE
WINAPI
FindFirstVolumeMountPointA(
  _In_ LPCSTR lpszRootPathName,
  _Out_writes_(cchBufferLength) LPSTR lpszVolumeMountPoint,
  _In_ DWORD cchBufferLength);

HANDLE
WINAPI
FindFirstVolumeMountPointW(
  _In_ LPCWSTR lpszRootPathName,
  _Out_writes_(cchBufferLength) LPWSTR lpszVolumeMountPoint,
  _In_ DWORD cchBufferLength);

#endif

BOOL WINAPI FindNextChangeNotification(HANDLE);
BOOL WINAPI FindNextFileA(HANDLE,LPWIN32_FIND_DATAA);
BOOL WINAPI FindNextFileW(HANDLE,LPWIN32_FIND_DATAW);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI FindNextStreamW(_In_ HANDLE, _Out_ LPVOID);
#endif

#if (_WIN32_WINNT >= 0x0500)

BOOL
WINAPI
FindNextVolumeA(
  _Inout_ HANDLE hFindVolume,
  _Out_writes_(cchBufferLength) LPSTR lpszVolumeName,
  _In_ DWORD cchBufferLength);

BOOL WINAPI FindNextVolumeW(HANDLE,LPWSTR,DWORD);

BOOL
WINAPI
FindNextVolumeMountPointA(
  _In_ HANDLE hFindVolumeMountPoint,
  _Out_writes_(cchBufferLength) LPSTR lpszVolumeMountPoint,
  _In_ DWORD cchBufferLength);

BOOL
WINAPI
FindNextVolumeMountPointW(
  _In_ HANDLE hFindVolumeMountPoint,
  _Out_writes_(cchBufferLength) LPWSTR lpszVolumeMountPoint,
  _In_ DWORD cchBufferLength);

BOOL WINAPI FindVolumeClose(HANDLE);
BOOL WINAPI FindVolumeMountPointClose(_In_ HANDLE);

#endif

_Ret_maybenull_ HRSRC WINAPI FindResourceA(_In_opt_ HMODULE,_In_ LPCSTR, _In_ LPCSTR);
_Ret_maybenull_ HRSRC WINAPI FindResourceW(_In_opt_ HMODULE,_In_ LPCWSTR, _In_ LPCWSTR);
_Ret_maybenull_ HRSRC WINAPI FindResourceExA(_In_opt_ HMODULE, _In_ LPCSTR, _In_ LPCSTR, _In_ WORD);
HRSRC WINAPI FindResourceExW(HINSTANCE,LPCWSTR,LPCWSTR,WORD);

BOOL WINAPI FlushFileBuffers(HANDLE);
BOOL WINAPI FlushInstructionCache(HANDLE,LPCVOID,SIZE_T);
BOOL WINAPI FlushViewOfFile(LPCVOID,SIZE_T);
DWORD WINAPI FlsAlloc(PFLS_CALLBACK_FUNCTION);
PVOID WINAPI FlsGetValue(DWORD);
BOOL WINAPI FlsSetValue(DWORD,PVOID);
BOOL WINAPI FlsFree(DWORD);
DWORD WINAPI FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list* Arguments);
DWORD WINAPI FormatMessageW(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list* Arguments);
BOOL WINAPI FreeEnvironmentStringsA(LPSTR);
BOOL WINAPI FreeEnvironmentStringsW(LPWSTR);
BOOL WINAPI FreeLibrary(HMODULE);
DECLSPEC_NORETURN void WINAPI FreeLibraryAndExitThread(HMODULE,DWORD);
#define FreeModule(m) FreeLibrary(m)
#define FreeProcInstance(p) (void)(p)
BOOL WINAPI FreeResource(HGLOBAL);
PVOID WINAPI FreeSid(PSID);
BOOL WINAPI GetAce(PACL,DWORD,LPVOID*);
BOOL WINAPI GetAclInformation(PACL,PVOID,DWORD,ACL_INFORMATION_CLASS);
#if (_WIN32_WINNT >= 0x0600)
HRESULT WINAPI GetApplicationRecoveryCallback(_In_ HANDLE, _Out_ APPLICATION_RECOVERY_CALLBACK*, _Outptr_opt_result_maybenull_ PVOID*, _Out_opt_ DWORD*, _Out_opt_ DWORD*);
HRESULT WINAPI GetApplicationRestart(HANDLE,PWSTR,PDWORD,PDWORD);
#endif

UINT
WINAPI
GetAtomNameA(
  _In_ ATOM nAtom,
  _Out_writes_to_(nSize, return + 1) LPSTR lpBuffer,
  _In_ int nSize);

UINT
WINAPI
GetAtomNameW(
  _In_ ATOM nAtom,
  _Out_writes_to_(nSize, return + 1) LPWSTR lpBuffer,
  _In_ int nSize);

BOOL WINAPI GetBinaryTypeA(_In_ LPCSTR, _Out_ PDWORD);
BOOL WINAPI GetBinaryTypeW(_In_ LPCWSTR, _Out_ PDWORD);
LPSTR WINAPI GetCommandLineA(VOID);
LPWSTR WINAPI GetCommandLineW(VOID);

_Success_(return != FALSE)
BOOL
WINAPI
GetCommConfig(
  _In_ HANDLE hCommDev,
  _Out_writes_bytes_opt_(*lpdwSize) LPCOMMCONFIG lpCC,
  _Inout_ LPDWORD lpdwSize);

BOOL WINAPI GetCommMask(_In_ HANDLE, _Out_ PDWORD);
BOOL WINAPI GetCommModemStatus(_In_ HANDLE, _Out_ PDWORD);
BOOL WINAPI GetCommProperties(_In_ HANDLE, _Inout_ LPCOMMPROP);
BOOL WINAPI GetCommState(_In_ HANDLE, _Out_ LPDCB);
BOOL WINAPI GetCommTimeouts(_In_ HANDLE, _Out_ LPCOMMTIMEOUTS);
DWORD WINAPI GetCompressedFileSizeA(_In_ LPCSTR, _Out_opt_ PDWORD);
DWORD WINAPI GetCompressedFileSizeW(_In_ LPCWSTR, _Out_opt_ PDWORD);

_Success_(return != 0)
BOOL
WINAPI
GetComputerNameA(
  _Out_writes_to_opt_(*nSize, *nSize + 1) LPSTR lpBuffer,
  _Inout_ LPDWORD nSize);

_Success_(return != 0)
BOOL
WINAPI
GetComputerNameW(
  _Out_writes_to_opt_(*nSize, *nSize + 1) LPWSTR lpBuffer,
  _Inout_ LPDWORD nSize);

#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI GetComputerNameExA(COMPUTER_NAME_FORMAT,LPSTR,LPDWORD);
BOOL WINAPI GetComputerNameExW(COMPUTER_NAME_FORMAT,LPWSTR,LPDWORD);
#endif
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI GetCurrentActCtx( _Outptr_ HANDLE*);
#endif
DWORD WINAPI GetCurrentDirectoryA(DWORD,LPSTR);
DWORD WINAPI GetCurrentDirectoryW(DWORD,LPWSTR);
BOOL WINAPI GetCurrentHwProfileA(_Out_ LPHW_PROFILE_INFOA);
BOOL WINAPI GetCurrentHwProfileW(_Out_ LPHW_PROFILE_INFOW);
HANDLE WINAPI GetCurrentProcess(void);
DWORD WINAPI GetCurrentProcessId(void);
HANDLE WINAPI GetCurrentThread(void);
DWORD WINAPI GetCurrentThreadId(void);
#define GetCurrentTime GetTickCount

BOOL
WINAPI
GetDefaultCommConfigA(
  _In_ LPCSTR lpszName,
  _Out_writes_bytes_to_(*lpdwSize, *lpdwSize) LPCOMMCONFIG lpCC,
  _Inout_ LPDWORD lpdwSize);

BOOL
WINAPI
GetDefaultCommConfigW(
  _In_ LPCWSTR lpszName,
  _Out_writes_bytes_to_(*lpdwSize, *lpdwSize) LPCOMMCONFIG lpCC,
  _Inout_ LPDWORD lpdwSize);

BOOL WINAPI GetDiskFreeSpaceA(LPCSTR,PDWORD,PDWORD,PDWORD,PDWORD);
BOOL WINAPI GetDiskFreeSpaceW(LPCWSTR,PDWORD,PDWORD,PDWORD,PDWORD);
BOOL WINAPI GetDiskFreeSpaceExA(LPCSTR,PULARGE_INTEGER,PULARGE_INTEGER,PULARGE_INTEGER);
BOOL WINAPI GetDiskFreeSpaceExW(LPCWSTR,PULARGE_INTEGER,PULARGE_INTEGER,PULARGE_INTEGER);

#if (_WIN32_WINNT >= 0x0502)

_Success_(return != 0 && return < nBufferLength)
DWORD
WINAPI
GetDllDirectoryA(
  _In_ DWORD nBufferLength,
  _Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer);

_Success_(return != 0 && return < nBufferLength)
DWORD
WINAPI
GetDllDirectoryW(
  _In_ DWORD nBufferLength,
  _Out_writes_to_opt_(nBufferLength, return + 1) LPWSTR lpBuffer);

#endif

UINT WINAPI GetDriveTypeA(LPCSTR);
UINT WINAPI GetDriveTypeW(LPCWSTR);
LPSTR WINAPI GetEnvironmentStrings(void);
LPWSTR WINAPI GetEnvironmentStringsW(void);
DWORD WINAPI GetEnvironmentVariableA(LPCSTR,LPSTR,DWORD);
DWORD WINAPI GetEnvironmentVariableW(LPCWSTR,LPWSTR,DWORD);
BOOL WINAPI GetExitCodeProcess(HANDLE,PDWORD);
BOOL WINAPI GetExitCodeThread(HANDLE,PDWORD);
DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName);
#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI GetFileAttributesByHandle(HANDLE,LPDWORD,DWORD);
DWORD WINAPI GetFinalPathNameByHandleA(HANDLE,LPSTR,DWORD,DWORD);
DWORD WINAPI GetFinalPathNameByHandleW(HANDLE,LPWSTR,DWORD,DWORD);
#endif
DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
BOOL WINAPI GetFileAttributesExA(LPCSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, PVOID lpFileInformation);
BOOL WINAPI GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, PVOID lpFileInformation);
#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI GetFileBandwidthReservation(_In_ HANDLE, _Out_ LPDWORD, _Out_ LPDWORD, _Out_ LPBOOL, _Out_ LPDWORD, _Out_ LPDWORD);
#endif
BOOL WINAPI GetFileInformationByHandle(HANDLE,LPBY_HANDLE_FILE_INFORMATION);

#if (_WIN32_WINNT >= 0x0600)
BOOL
WINAPI
GetFileInformationByHandleEx(
  _In_ HANDLE hFile,
  _In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
  _Out_writes_bytes_(dwBufferSize) LPVOID lpFileInformation,
  _In_ DWORD dwBufferSize);
#endif

BOOL
WINAPI
GetFileSecurityA(
  _In_ LPCSTR lpFileName,
  _In_ SECURITY_INFORMATION RequestedInformation,
  _Out_writes_bytes_to_opt_(nLength, *lpnLengthNeeded) PSECURITY_DESCRIPTOR pSecurityDescriptor,
  _In_ DWORD nLength,
  _Out_ LPDWORD lpnLengthNeeded);

BOOL WINAPI GetFileSecurityW(LPCWSTR,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR,DWORD,PDWORD);
DWORD WINAPI GetFileSize(HANDLE,PDWORD);
BOOL WINAPI GetFileSizeEx(HANDLE,PLARGE_INTEGER);
BOOL WINAPI GetFileTime(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME);
DWORD WINAPI GetFileType(HANDLE);
#define GetFreeSpace(w) (0x100000L)
DWORD WINAPI GetFullPathNameA(LPCSTR,DWORD,LPSTR,LPSTR*);
DWORD WINAPI GetFullPathNameW(LPCWSTR,DWORD,LPWSTR,LPWSTR*);
BOOL WINAPI GetHandleInformation(HANDLE,PDWORD);
BOOL WINAPI GetKernelObjectSecurity(HANDLE,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR,DWORD,PDWORD);
DWORD WINAPI GetLastError(void);
DWORD WINAPI GetLengthSid(PSID);
void WINAPI GetLocalTime(LPSYSTEMTIME);
DWORD WINAPI GetLogicalDrives(void);

_Success_(return != 0 && return <= nBufferLength)
DWORD
WINAPI
GetLogicalDriveStringsA(
  _In_ DWORD nBufferLength,
  _Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer);

DWORD WINAPI GetLogicalDriveStringsW(DWORD,LPWSTR);
#if (_WIN32_WINNT >= 0x0500 || _WIN32_WINDOWS >= 0x0410)
DWORD WINAPI GetLongPathNameA(LPCSTR,LPSTR,DWORD);
DWORD WINAPI GetLongPathNameW(LPCWSTR,LPWSTR,DWORD);
#endif
BOOL WINAPI GetMailslotInfo(_In_ HANDLE, _Out_opt_ PDWORD, _Out_opt_ PDWORD, _Out_opt_ PDWORD, _Out_opt_ PDWORD);
DWORD WINAPI GetModuleFileNameA(HINSTANCE hModule,LPSTR lpFilename,DWORD nSize);
DWORD WINAPI GetModuleFileNameW(HINSTANCE hModule,LPWSTR lpFilename,DWORD nSize);
HMODULE WINAPI GetModuleHandleA(LPCSTR);
HMODULE WINAPI GetModuleHandleW(LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI GetModuleHandleExA(DWORD,LPCSTR,HMODULE*);
BOOL WINAPI GetModuleHandleExW(DWORD,LPCWSTR,HMODULE*);
#endif

#if _WIN32_WINNT >= 0x0502
WINBASEAPI BOOL WINAPI NeedCurrentDirectoryForExePathA(LPCSTR ExeName);
WINBASEAPI BOOL WINAPI NeedCurrentDirectoryForExePathW(LPCWSTR ExeName);
#endif

BOOL
WINAPI
GetNamedPipeHandleStateA(
  _In_ HANDLE hNamedPipe,
  _Out_opt_ LPDWORD lpState,
  _Out_opt_ LPDWORD lpCurInstances,
  _Out_opt_ LPDWORD lpMaxCollectionCount,
  _Out_opt_ LPDWORD lpCollectDataTimeout,
  _Out_writes_opt_(nMaxUserNameSize) LPSTR lpUserName,
  _In_ DWORD nMaxUserNameSize);

BOOL
WINAPI
GetNamedPipeHandleStateW(
  _In_ HANDLE hNamedPipe,
  _Out_opt_ LPDWORD lpState,
  _Out_opt_ LPDWORD lpCurInstances,
  _Out_opt_ LPDWORD lpMaxCollectionCount,
  _Out_opt_ LPDWORD lpCollectDataTimeout,
  _Out_writes_opt_(nMaxUserNameSize) LPWSTR lpUserName,
  _In_ DWORD nMaxUserNameSize);

BOOL WINAPI GetNamedPipeInfo(_In_ HANDLE, _Out_opt_ PDWORD, _Out_opt_ PDWORD, _Out_opt_ PDWORD, _Out_opt_ PDWORD);
#if (_WIN32_WINNT >= 0x0501)
VOID WINAPI GetNativeSystemInfo(LPSYSTEM_INFO);
#endif

BOOL
WINAPI
GetEventLogInformation(
  _In_ HANDLE hEventLog,
  _In_ DWORD dwInfoLevel,
  _Out_writes_bytes_to_(cbBufSize, *pcbBytesNeeded) LPVOID lpBuffer,
  _In_ DWORD cbBufSize,
  _Out_ LPDWORD pcbBytesNeeded);

BOOL WINAPI GetNumberOfEventLogRecords(_In_ HANDLE, _Out_ PDWORD);
BOOL WINAPI GetOldestEventLogRecord(_In_ HANDLE, _Out_ PDWORD);
DWORD WINAPI GetPriorityClass(HANDLE);
BOOL WINAPI GetPrivateObjectSecurity(PSECURITY_DESCRIPTOR,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR,DWORD,PDWORD);
UINT WINAPI GetPrivateProfileIntA(_In_ LPCSTR, _In_ LPCSTR, _In_ INT, _In_opt_ LPCSTR);
UINT WINAPI GetPrivateProfileIntW(_In_ LPCWSTR, _In_ LPCWSTR, _In_ INT, _In_opt_ LPCWSTR);

DWORD
WINAPI
GetPrivateProfileSectionA(
  _In_ LPCSTR lpAppName,
  _Out_writes_to_opt_(nSize, return + 1) LPSTR lpReturnedString,
  _In_ DWORD nSize,
  _In_opt_ LPCSTR lpFileName);

DWORD
WINAPI
GetPrivateProfileSectionW(
  _In_ LPCWSTR lpAppName,
  _Out_writes_to_opt_(nSize, return + 1) LPWSTR lpReturnedString,
  _In_ DWORD nSize,
  _In_opt_ LPCWSTR lpFileName);

DWORD
WINAPI
GetPrivateProfileSectionNamesA(
  _Out_writes_to_opt_(nSize, return + 1) LPSTR lpszReturnBuffer,
  _In_ DWORD nSize,
  _In_opt_ LPCSTR lpFileName);

DWORD
WINAPI
GetPrivateProfileSectionNamesW(
  _Out_writes_to_opt_(nSize, return + 1) LPWSTR lpszReturnBuffer,
  _In_ DWORD nSize,
  _In_opt_ LPCWSTR lpFileName);

DWORD
WINAPI
GetPrivateProfileStringA(
  _In_opt_ LPCSTR lpAppName,
  _In_opt_ LPCSTR lpKeyName,
  _In_opt_ LPCSTR lpDefault,
  _Out_writes_to_opt_(nSize, return + 1) LPSTR lpReturnedString,
  _In_ DWORD nSize,
  _In_opt_ LPCSTR lpFileName);

DWORD
WINAPI
GetPrivateProfileStringW(
  _In_opt_ LPCWSTR lpAppName,
  _In_opt_ LPCWSTR lpKeyName,
  _In_opt_ LPCWSTR lpDefault,
  _Out_writes_to_opt_(nSize, return + 1) LPWSTR lpReturnedString,
  _In_ DWORD nSize,
  _In_opt_ LPCWSTR lpFileName);

BOOL
WINAPI
GetPrivateProfileStructA(
  _In_ LPCSTR lpszSection,
  _In_ LPCSTR lpszKey,
  _Out_writes_bytes_opt_(uSizeStruct) LPVOID lpStruct,
  _In_ UINT uSizeStruct,
  _In_opt_ LPCSTR szFile);

BOOL
WINAPI
GetPrivateProfileStructW(
  _In_ LPCWSTR lpszSection,
  _In_ LPCWSTR lpszKey,
  _Out_writes_bytes_opt_(uSizeStruct) LPVOID lpStruct,
  _In_ UINT uSizeStruct,
  _In_opt_ LPCWSTR szFile);

FARPROC WINAPI GetProcAddress(HINSTANCE,LPCSTR);
BOOL WINAPI GetProcessAffinityMask(_In_ HANDLE, _Out_ PDWORD_PTR, _Out_ PDWORD_PTR);
#if (_WIN32_WINNT >= 0x0502)
BOOL WINAPI GetProcessHandleCount(_In_ HANDLE, _Out_ PDWORD);
#endif
HANDLE WINAPI GetProcessHeap(VOID);
DWORD WINAPI GetProcessHeaps(DWORD,PHANDLE);
#if (_WIN32_WINNT >= 0x0502)
DWORD WINAPI GetProcessId(HANDLE);
DWORD WINAPI GetProcessIdOfThread(HANDLE);
#endif
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI GetProcessIoCounters(_In_ HANDLE, _Out_ PIO_COUNTERS);
#endif
BOOL WINAPI GetProcessPriorityBoost(_In_ HANDLE, _Out_ PBOOL);
BOOL WINAPI GetProcessShutdownParameters(_Out_ PDWORD, _Out_ PDWORD);
BOOL WINAPI GetProcessTimes(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME,LPFILETIME);
DWORD WINAPI GetProcessVersion(DWORD);
HWINSTA WINAPI GetProcessWindowStation(void);
BOOL WINAPI GetProcessWorkingSetSize(_In_ HANDLE, _Out_ PSIZE_T, _Out_ PSIZE_T);
UINT WINAPI GetProfileIntA(_In_ LPCSTR, _In_ LPCSTR, _In_ INT);
UINT WINAPI GetProfileIntW(_In_ LPCWSTR, _In_ LPCWSTR, _In_ INT);

DWORD
WINAPI
GetProfileSectionA(
  _In_ LPCSTR lpAppName,
  _Out_writes_to_opt_(nSize, return + 1) LPSTR lpReturnedString,
  _In_ DWORD nSize);

DWORD
WINAPI
GetProfileSectionW(
  _In_ LPCWSTR lpAppName,
  _Out_writes_to_opt_(nSize, return + 1) LPWSTR lpReturnedString,
  _In_ DWORD nSize);

DWORD
WINAPI
GetProfileStringA(
  _In_opt_ LPCSTR lpAppName,
  _In_opt_ LPCSTR lpKeyName,
  _In_opt_ LPCSTR lpDefault,
  _Out_writes_to_opt_(nSize, return + 1) LPSTR lpReturnedString,
  _In_ DWORD nSize);

DWORD
WINAPI
GetProfileStringW(
  _In_opt_ LPCWSTR lpAppName,
  _In_opt_ LPCWSTR lpKeyName,
  _In_opt_ LPCWSTR lpDefault,
  _Out_writes_to_opt_(nSize, return + 1) LPWSTR lpReturnedString,
  _In_ DWORD nSize);

BOOL WINAPI GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR_CONTROL,PDWORD);
BOOL WINAPI GetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR,LPBOOL,PACL*,LPBOOL);
BOOL WINAPI GetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR,PSID*,LPBOOL);
DWORD WINAPI GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR);
BOOL WINAPI GetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR,PSID*,LPBOOL);
DWORD WINAPI GetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR,PUCHAR);
BOOL WINAPI GetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR,LPBOOL,PACL*,LPBOOL);

_Success_(return != 0 && return < cchBuffer)
DWORD
WINAPI
GetShortPathNameA(
  _In_ LPCSTR lpszLongPath,
  _Out_writes_to_opt_(cchBuffer, return + 1) LPSTR  lpszShortPath,
  _In_ DWORD cchBuffer);

DWORD WINAPI GetShortPathNameW(LPCWSTR,LPWSTR,DWORD);
PSID_IDENTIFIER_AUTHORITY WINAPI GetSidIdentifierAuthority(PSID);
DWORD WINAPI GetSidLengthRequired(UCHAR);
PDWORD WINAPI GetSidSubAuthority(PSID,DWORD);
PUCHAR WINAPI GetSidSubAuthorityCount(PSID);
VOID WINAPI GetStartupInfoA(_Out_ LPSTARTUPINFOA);
VOID WINAPI GetStartupInfoW(LPSTARTUPINFOW);
HANDLE WINAPI GetStdHandle(_In_ DWORD);
UINT WINAPI GetSystemDirectoryA(LPSTR,UINT);
UINT WINAPI GetSystemDirectoryW(LPWSTR,UINT);

VOID WINAPI GetSystemInfo(LPSYSTEM_INFO);
BOOL WINAPI GetSystemPowerStatus(_Out_ LPSYSTEM_POWER_STATUS);
#if (_WIN32_WINNT >= 0x0502)
BOOL WINAPI GetSystemRegistryQuota(_Out_opt_ PDWORD, _Out_opt_ PDWORD);
#endif
VOID WINAPI GetSystemTime(LPSYSTEMTIME lpSystemTime);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI GetSystemTimes(_Out_opt_ LPFILETIME, _Out_opt_ LPFILETIME, _Out_opt_ LPFILETIME);
#endif
BOOL WINAPI GetSystemTimeAdjustment(PDWORD,PDWORD,PBOOL);
void WINAPI GetSystemTimeAsFileTime(LPFILETIME);
#if (_WIN32_WINNT >= 0x0500)
UINT WINAPI GetSystemWindowsDirectoryA(LPSTR,UINT);
UINT WINAPI GetSystemWindowsDirectoryW(LPWSTR,UINT);
#endif

#if (_WIN32_WINNT >= 0x0501)

_Success_(return != 0 && return < uSize)
UINT
WINAPI
GetSystemWow64DirectoryA(
  _Out_writes_to_opt_(uSize, return + 1) LPSTR lpBuffer,
  _In_ UINT uSize);

_Success_(return != 0 && return < uSize)
UINT
WINAPI
GetSystemWow64DirectoryW(
  _Out_writes_to_opt_(uSize, return + 1) LPWSTR lpBuffer,
  _In_ UINT uSize);

#endif

DWORD
WINAPI
GetTapeParameters(
  _In_ HANDLE hDevice,
  _In_ DWORD dwOperation,
  _Inout_ LPDWORD lpdwSize,
  _Out_writes_bytes_(*lpdwSize) LPVOID lpTapeInformation);

DWORD WINAPI GetTapePosition(_In_ HANDLE, _In_ DWORD, _Out_ PDWORD, _Out_ PDWORD, _Out_ PDWORD);
DWORD WINAPI GetTapeStatus(_In_ HANDLE);

UINT
WINAPI
GetTempFileNameA(
  _In_ LPCSTR lpPathName,
  _In_ LPCSTR lpPrefixString,
  _In_ UINT uUnique,
  _Out_writes_(MAX_PATH) LPSTR lpTempFileName);

UINT WINAPI GetTempFileNameW(LPCWSTR,LPCWSTR,UINT,LPWSTR);

DWORD
WINAPI
GetTempPathA(
  _In_ DWORD nBufferLength,
  _Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer);

DWORD WINAPI GetTempPathW(DWORD,LPWSTR);
BOOL WINAPI GetThreadContext(HANDLE,LPCONTEXT);
#if (_WIN32_WINNT >= 0x0502)
BOOL WINAPI GetThreadIOPendingFlag(_In_ HANDLE, _Out_ PBOOL);
#endif
int WINAPI GetThreadPriority(HANDLE);
BOOL WINAPI GetThreadPriorityBoost(HANDLE,PBOOL);
BOOL WINAPI GetThreadSelectorEntry(_In_ HANDLE, _In_ DWORD, _Out_ LPLDT_ENTRY);
BOOL WINAPI GetThreadTimes(HANDLE,LPFILETIME,LPFILETIME,LPFILETIME,LPFILETIME);
DWORD WINAPI GetTickCount(VOID);
#if (_WIN32_WINNT >= 0x0600)
ULONGLONG WINAPI GetTickCount64(VOID);
#endif
DWORD WINAPI GetThreadId(HANDLE);
DWORD WINAPI GetTimeZoneInformation(LPTIME_ZONE_INFORMATION);
BOOL WINAPI GetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,PVOID,DWORD,PDWORD);

BOOL
WINAPI
GetUserNameA(
  _Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPSTR lpBuffer,
  _Inout_ LPDWORD pcbBuffer);

BOOL
WINAPI
GetUserNameW(
  _Out_writes_to_opt_(*pcbBuffer, *pcbBuffer) LPWSTR lpBuffer,
  _Inout_ LPDWORD pcbBuffer);

DWORD WINAPI GetVersion(void);
BOOL WINAPI GetVersionExA(LPOSVERSIONINFOA);
BOOL WINAPI GetVersionExW(LPOSVERSIONINFOW);

BOOL
WINAPI
GetVolumeInformationA(
  _In_opt_ LPCSTR lpRootPathName,
  _Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
  _In_ DWORD nVolumeNameSize,
  _Out_opt_ LPDWORD lpVolumeSerialNumber,
  _Out_opt_ LPDWORD lpMaximumComponentLength,
  _Out_opt_ LPDWORD lpFileSystemFlags,
  _Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
  _In_ DWORD nFileSystemNameSize);

BOOL WINAPI GetVolumeInformationW(LPCWSTR,LPWSTR,DWORD,PDWORD,PDWORD,PDWORD,LPWSTR,DWORD);

#if (_WIN32_WINNT >= 0x0500)

BOOL
WINAPI
GetVolumeNameForVolumeMountPointA(
  _In_ LPCSTR lpszVolumeMountPoint,
  _Out_writes_(cchBufferLength) LPSTR lpszVolumeName,
  _In_ DWORD cchBufferLength);

BOOL WINAPI GetVolumeNameForVolumeMountPointW(LPCWSTR,LPWSTR,DWORD);

BOOL
WINAPI
GetVolumePathNameA(
  _In_ LPCSTR lpszFileName,
  _Out_writes_(cchBufferLength) LPSTR lpszVolumePathName,
  _In_ DWORD cchBufferLength);

BOOL WINAPI GetVolumePathNameW(LPCWSTR,LPWSTR,DWORD);

#endif

#if (_WIN32_WINNT >= 0x0501)

BOOL
WINAPI
GetVolumePathNamesForVolumeNameA(
  _In_ LPCSTR lpszVolumeName,
  _Out_writes_to_opt_(cchBufferLength, *lpcchReturnLength) _Post_ _NullNull_terminated_ LPCH lpszVolumePathNames,
  _In_ DWORD cchBufferLength,
  _Out_ PDWORD lpcchReturnLength);

BOOL WINAPI GetVolumePathNamesForVolumeNameW(LPCWSTR,LPWSTR,DWORD,PDWORD);

#endif

UINT WINAPI GetWindowsDirectoryA(LPSTR,UINT);
UINT WINAPI GetWindowsDirectoryW(LPWSTR,UINT);
DWORD WINAPI GetWindowThreadProcessId(HWND hWnd,PDWORD lpdwProcessId);
UINT WINAPI GetWriteWatch(DWORD,PVOID,SIZE_T,PVOID*,PULONG_PTR,PULONG);
ATOM WINAPI GlobalAddAtomA(_In_opt_ LPCSTR);
ATOM WINAPI GlobalAddAtomW(_In_opt_ LPCWSTR);
HGLOBAL WINAPI GlobalAlloc(UINT,SIZE_T);
SIZE_T WINAPI GlobalCompact(_In_ DWORD); /* Obsolete: Has no effect. */
ATOM WINAPI GlobalDeleteAtom(_In_ ATOM);
#define GlobalDiscard(m) GlobalReAlloc((m),0,GMEM_MOVEABLE)
ATOM WINAPI GlobalFindAtomA(_In_opt_ LPCSTR);
ATOM WINAPI GlobalFindAtomW(_In_opt_ LPCWSTR);
VOID WINAPI GlobalFix(_In_ HGLOBAL); /* Obsolete: Has no effect. */
UINT WINAPI GlobalFlags(_In_ HGLOBAL); /* Obsolete: Has no effect. */
HGLOBAL WINAPI GlobalFree(HGLOBAL);

UINT
WINAPI
GlobalGetAtomNameA(
  _In_ ATOM nAtom,
  _Out_writes_to_(nSize, return + 1) LPSTR lpBuffer,
  _In_ int nSize);

UINT
WINAPI
GlobalGetAtomNameW(
  _In_ ATOM nAtom,
  _Out_writes_to_(nSize, return + 1) LPWSTR lpBuffer,
  _In_ int nSize);

_Ret_maybenull_ HGLOBAL WINAPI GlobalHandle(_In_ LPCVOID);
_Ret_maybenull_ LPVOID WINAPI GlobalLock(_In_ HGLOBAL);
VOID WINAPI GlobalMemoryStatus(_Out_ LPMEMORYSTATUS);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI GlobalMemoryStatusEx(LPMEMORYSTATUSEX);
#endif
HGLOBAL WINAPI GlobalReAlloc(HGLOBAL,SIZE_T,UINT);
SIZE_T WINAPI GlobalSize(_In_ HGLOBAL);
VOID WINAPI GlobalUnfix(_In_ HGLOBAL); /* Obsolete: Has no effect. */
BOOL WINAPI GlobalUnlock(_In_ HGLOBAL);
BOOL WINAPI GlobalUnWire(_In_ HGLOBAL); /* Obsolete: Has no effect. */
PVOID WINAPI GlobalWire(_In_ HGLOBAL); /* Obsolete: Has no effect. */
#define HasOverlappedIoCompleted(lpOverlapped)  ((lpOverlapped)->Internal != STATUS_PENDING)
PVOID WINAPI HeapAlloc(HANDLE,DWORD,SIZE_T);
SIZE_T WINAPI HeapCompact(HANDLE,DWORD);
HANDLE WINAPI HeapCreate(DWORD,SIZE_T,SIZE_T);
BOOL WINAPI HeapDestroy(HANDLE);
BOOL WINAPI HeapFree(HANDLE,DWORD,PVOID);
BOOL WINAPI HeapLock(HANDLE);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI HeapQueryInformation(HANDLE,HEAP_INFORMATION_CLASS,PVOID,SIZE_T,PSIZE_T);
#endif
PVOID WINAPI HeapReAlloc(HANDLE,DWORD,PVOID,SIZE_T);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI HeapSetInformation(HANDLE,HEAP_INFORMATION_CLASS,PVOID,SIZE_T);
#endif
SIZE_T WINAPI HeapSize(HANDLE,DWORD,LPCVOID);
BOOL WINAPI HeapUnlock(HANDLE);
BOOL WINAPI HeapValidate(HANDLE,DWORD,LPCVOID);
BOOL WINAPI HeapWalk(HANDLE,LPPROCESS_HEAP_ENTRY);
BOOL WINAPI ImpersonateAnonymousToken(HANDLE);
BOOL WINAPI ImpersonateLoggedOnUser(HANDLE);
BOOL WINAPI ImpersonateNamedPipeClient(HANDLE);
BOOL WINAPI ImpersonateSelf(SECURITY_IMPERSONATION_LEVEL);
BOOL WINAPI InitAtomTable(_In_ DWORD);
BOOL WINAPI InitializeAcl(PACL,DWORD,DWORD);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI InitializeConditionVariable(PCONDITION_VARIABLE);
#endif
VOID WINAPI InitializeCriticalSection(LPCRITICAL_SECTION);
BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION,DWORD);
DWORD WINAPI SetCriticalSectionSpinCount(LPCRITICAL_SECTION,DWORD);
BOOL WINAPI InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR,DWORD);
BOOL WINAPI InitializeSid (PSID,PSID_IDENTIFIER_AUTHORITY,BYTE);

#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI InitializeSRWLock(PSRWLOCK);
#endif

BOOL WINAPI IsBadCodePtr(_In_opt_ FARPROC);
BOOL WINAPI IsBadHugeReadPtr(_In_opt_ CONST VOID*, _In_ UINT_PTR);
BOOL WINAPI IsBadHugeWritePtr(_In_opt_ PVOID, _In_ UINT_PTR);
BOOL WINAPI IsBadReadPtr(_In_opt_ CONST VOID*, _In_ UINT_PTR);
BOOL WINAPI IsBadStringPtrA(_In_opt_ LPCSTR, _In_ UINT_PTR);
BOOL WINAPI IsBadStringPtrW(_In_opt_ LPCWSTR, _In_ UINT_PTR);
BOOL WINAPI IsBadWritePtr(_In_opt_ PVOID, _In_ UINT_PTR);
BOOL WINAPI IsDebuggerPresent(void);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI IsProcessInJob(HANDLE,HANDLE,PBOOL);
#endif
BOOL WINAPI IsProcessorFeaturePresent(DWORD);
BOOL WINAPI IsSystemResumeAutomatic(void);

BOOL
WINAPI
IsTextUnicode(
  _In_reads_bytes_(iSize) CONST VOID *lpv,
  _In_ int iSize,
  _Inout_opt_ LPINT lpiResult);

#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI IsThreadAFiber(VOID);
#endif
BOOL WINAPI IsValidAcl(PACL);
BOOL WINAPI IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR);
BOOL WINAPI IsValidSid(PSID);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI IsWellKnownSid(PSID,WELL_KNOWN_SID_TYPE);
BOOL WINAPI IsWow64Process(HANDLE,PBOOL);
#endif
void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION);
#define LimitEmsPages(n)
_Ret_maybenull_ HINSTANCE WINAPI LoadLibraryA(_In_ LPCSTR);
_Ret_maybenull_ HINSTANCE WINAPI LoadLibraryW(_In_ LPCWSTR);
HINSTANCE WINAPI LoadLibraryExA(LPCSTR,HANDLE,DWORD);
HINSTANCE WINAPI LoadLibraryExW(LPCWSTR,HANDLE,DWORD);
DWORD WINAPI LoadModule(_In_ LPCSTR, _In_ PVOID);
HGLOBAL WINAPI LoadResource(HINSTANCE,HRSRC);
HLOCAL WINAPI LocalAlloc(UINT,SIZE_T);
SIZE_T WINAPI LocalCompact(_In_ UINT); /* Obsolete: Has no effect. */
BOOL WINAPI LocalFileTimeToFileTime(CONST FILETIME *,LPFILETIME);
UINT WINAPI LocalFlags(_In_ HLOCAL); /* Obsolete: Has no effect. */
HLOCAL WINAPI LocalFree(HLOCAL);
_Ret_maybenull_ HLOCAL WINAPI LocalHandle(_In_ LPCVOID);
PVOID WINAPI LocalLock(HLOCAL);
HLOCAL WINAPI LocalReAlloc(HLOCAL,SIZE_T,UINT);
SIZE_T WINAPI LocalShrink(_In_ HLOCAL, _In_ UINT);  /* Obsolete: Has no effect. */
SIZE_T WINAPI LocalSize(_In_ HLOCAL);
BOOL WINAPI LocalUnlock(HLOCAL);
BOOL WINAPI LockFile(HANDLE,DWORD,DWORD,DWORD,DWORD);
BOOL WINAPI LockFileEx(HANDLE,DWORD,DWORD,DWORD,DWORD,LPOVERLAPPED);
PVOID WINAPI LockResource(HGLOBAL);
#define LockSegment(w) GlobalFix((HANDLE)(w)) /* Obsolete: Has no effect. */
BOOL WINAPI LogonUserA(_In_ LPSTR, _In_opt_ LPSTR, _In_opt_ LPSTR, _In_ DWORD, _In_ DWORD, _Outptr_ PHANDLE);
BOOL WINAPI LogonUserW(_In_ LPWSTR, _In_opt_ LPWSTR, _In_opt_ LPWSTR, _In_ DWORD, _In_ DWORD, _Outptr_ PHANDLE);

_Success_(return != FALSE)
BOOL
WINAPI
LogonUserExA(
  _In_ LPSTR lpszUsername,
  _In_opt_ LPSTR lpszDomain,
  _In_opt_ LPSTR lpszPassword,
  _In_ DWORD dwLogonType,
  _In_ DWORD dwLogonProvider,
  _Out_opt_ PHANDLE phToken,
  _Out_opt_ PSID *ppLogonSid,
  _Out_opt_ PVOID *ppProfileBuffer,
  _Out_opt_ LPDWORD pdwProfileLength,
  _Out_opt_ PQUOTA_LIMITS pQuotaLimits);

_Success_(return != FALSE)
BOOL
WINAPI
LogonUserExW(
  _In_ LPWSTR lpszUsername,
  _In_opt_ LPWSTR lpszDomain,
  _In_opt_ LPWSTR lpszPassword,
  _In_ DWORD dwLogonType,
  _In_ DWORD dwLogonProvider,
  _Out_opt_ PHANDLE phToken,
  _Out_opt_ PSID *ppLogonSid,
  _Out_opt_ PVOID *ppProfileBuffer,
  _Out_opt_ LPDWORD pdwProfileLength,
  _Out_opt_ PQUOTA_LIMITS pQuotaLimits);

_Success_(return != FALSE)
BOOL
WINAPI
LookupAccountNameA(
  _In_opt_ LPCSTR lpSystemName,
  _In_ LPCSTR lpAccountName,
  _Out_writes_bytes_to_opt_(*cbSid, *cbSid) PSID Sid,
  _Inout_ LPDWORD cbSid,
  _Out_writes_to_opt_(*cchReferencedDomainName, *cchReferencedDomainName + 1) LPSTR ReferencedDomainName,
  _Inout_ LPDWORD cchReferencedDomainName,
  _Out_ PSID_NAME_USE peUse);

_Success_(return != FALSE)
BOOL
WINAPI
LookupAccountNameW(
  _In_opt_ LPCWSTR lpSystemName,
  _In_ LPCWSTR lpAccountName,
  _Out_writes_bytes_to_opt_(*cbSid, *cbSid) PSID Sid,
  _Inout_ LPDWORD cbSid,
  _Out_writes_to_opt_(*cchReferencedDomainName, *cchReferencedDomainName + 1) LPWSTR ReferencedDomainName,
  _Inout_ LPDWORD cchReferencedDomainName,
  _Out_ PSID_NAME_USE peUse);

_Success_(return != FALSE)
BOOL
WINAPI
LookupAccountSidA(
  _In_opt_ LPCSTR lpSystemName,
  _In_ PSID Sid,
  _Out_writes_to_opt_(*cchName, *cchName + 1) LPSTR Name,
  _Inout_ LPDWORD cchName,
  _Out_writes_to_opt_(*cchReferencedDomainName, *cchReferencedDomainName + 1) LPSTR ReferencedDomainName,
  _Inout_ LPDWORD cchReferencedDomainName,
  _Out_ PSID_NAME_USE peUse);

_Success_(return != FALSE)
BOOL
WINAPI
LookupAccountSidW(
  _In_opt_ LPCWSTR lpSystemName,
  _In_ PSID Sid,
  _Out_writes_to_opt_(*cchName, *cchName + 1) LPWSTR Name,
  _Inout_  LPDWORD cchName,
  _Out_writes_to_opt_(*cchReferencedDomainName, *cchReferencedDomainName + 1) LPWSTR ReferencedDomainName,
  _Inout_ LPDWORD cchReferencedDomainName,
  _Out_ PSID_NAME_USE peUse);

_Success_(return != FALSE)
BOOL
WINAPI
LookupPrivilegeDisplayNameA(
  _In_opt_ LPCSTR lpSystemName,
  _In_ LPCSTR lpName,
  _Out_writes_to_opt_(*cchDisplayName, *cchDisplayName + 1) LPSTR lpDisplayName,
  _Inout_ LPDWORD cchDisplayName,
  _Out_ LPDWORD lpLanguageId);

_Success_(return != FALSE)
BOOL
WINAPI
LookupPrivilegeDisplayNameW(
  _In_opt_ LPCWSTR lpSystemName,
  _In_ LPCWSTR lpName,
  _Out_writes_to_opt_(*cchDisplayName, *cchDisplayName + 1) LPWSTR lpDisplayName,
  _Inout_ LPDWORD cchDisplayName,
  _Out_ LPDWORD lpLanguageId);

_Success_(return != FALSE)
BOOL
WINAPI
LookupPrivilegeNameA(
  _In_opt_ LPCSTR lpSystemName,
  _In_ PLUID lpLuid,
  _Out_writes_to_opt_(*cchName, *cchName + 1) LPSTR lpName,
  _Inout_ LPDWORD cchName);

_Success_(return != FALSE)
BOOL
WINAPI
LookupPrivilegeNameW(
  _In_opt_ LPCWSTR lpSystemName,
  _In_ PLUID lpLuid,
  _Out_writes_to_opt_(*cchName, *cchName + 1) LPWSTR lpName,
  _Inout_ LPDWORD cchName);

BOOL WINAPI LookupPrivilegeValueA(_In_opt_ LPCSTR, _In_ LPCSTR, _Out_ PLUID);
BOOL WINAPI LookupPrivilegeValueW(_In_opt_ LPCWSTR, _In_ LPCWSTR, _Out_ PLUID);

LPSTR
WINAPI
lstrcatA(
  _Inout_updates_z_(_String_length_(lpString1) + _String_length_(lpString2) + 1) LPSTR lpString1,
  _In_ LPCSTR lpString2);

LPWSTR
WINAPI
lstrcatW(
  _Inout_updates_z_(_String_length_(lpString1) + _String_length_(lpString2) + 1) LPWSTR lpString1,
  _In_ LPCWSTR lpString2);

int WINAPI lstrcmpA(LPCSTR,LPCSTR);
int WINAPI lstrcmpiA(LPCSTR,LPCSTR);
int WINAPI lstrcmpiW( LPCWSTR,LPCWSTR);
int WINAPI lstrcmpW(LPCWSTR,LPCWSTR);

LPSTR
WINAPI
lstrcpyA(
  _Out_writes_(_String_length_(lpString2) + 1) LPSTR lpString1,
  _In_ LPCSTR lpString2);

LPWSTR
WINAPI
lstrcpyW(
  _Out_writes_(_String_length_(lpString2) + 1) LPWSTR lpString1,
  _In_ LPCWSTR lpString2);

LPSTR WINAPI lstrcpynA(LPSTR,LPCSTR,int);
LPWSTR WINAPI lstrcpynW(LPWSTR,LPCWSTR,int);
int WINAPI lstrlenA(LPCSTR);
int WINAPI lstrlenW(LPCWSTR);
BOOL WINAPI MakeAbsoluteSD(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR,PDWORD,PACL,PDWORD,PACL,PDWORD,PSID,PDWORD,PSID,PDWORD);
#define MakeProcInstance(p,i) (p)
BOOL WINAPI MakeSelfRelativeSD(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR,PDWORD);
VOID WINAPI MapGenericMask(PDWORD,PGENERIC_MAPPING);
PVOID WINAPI MapViewOfFile(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
PVOID WINAPI MapViewOfFileEx(HANDLE,DWORD,DWORD,DWORD,SIZE_T,PVOID);
BOOL WINAPI MoveFileA(_In_ LPCSTR, _In_ LPCSTR);
BOOL WINAPI MoveFileW(_In_ LPCWSTR, _In_ LPCWSTR);
BOOL WINAPI MoveFileExA(_In_ LPCSTR, _In_opt_ LPCSTR, _In_ DWORD);
BOOL WINAPI MoveFileExW(_In_ LPCWSTR, _In_opt_ LPCWSTR, _In_ DWORD);
BOOL WINAPI MoveFileWithProgressA(_In_ LPCSTR, _In_opt_ LPCSTR, _In_opt_ LPPROGRESS_ROUTINE, _In_opt_ LPVOID, _In_ DWORD);
BOOL WINAPI MoveFileWithProgressW(_In_ LPCWSTR, _In_opt_ LPCWSTR, _In_opt_ LPPROGRESS_ROUTINE, _In_opt_ LPVOID, _In_ DWORD);
int WINAPI MulDiv(_In_ int, _In_ int, _In_ int);
BOOL WINAPI NotifyChangeEventLog(_In_ HANDLE, _In_ HANDLE);
BOOL WINAPI ObjectCloseAuditAlarmA(_In_ LPCSTR, _In_ PVOID, _In_ BOOL);
BOOL WINAPI ObjectCloseAuditAlarmW(LPCWSTR,PVOID,BOOL);
BOOL WINAPI ObjectDeleteAuditAlarmA(_In_ LPCSTR, _In_ PVOID, _In_ BOOL);
BOOL WINAPI ObjectDeleteAuditAlarmW(LPCWSTR,PVOID,BOOL);
BOOL WINAPI ObjectOpenAuditAlarmA(_In_ LPCSTR, _In_ PVOID, _In_ LPSTR, _In_opt_ LPSTR, _In_ PSECURITY_DESCRIPTOR, _In_ HANDLE, _In_ DWORD, _In_ DWORD, _In_opt_ PPRIVILEGE_SET, _In_ BOOL, _In_ BOOL, _Out_ PBOOL);
BOOL WINAPI ObjectOpenAuditAlarmW(LPCWSTR,PVOID,LPWSTR,LPWSTR,PSECURITY_DESCRIPTOR,HANDLE,DWORD,DWORD,PPRIVILEGE_SET,BOOL,BOOL,PBOOL);
BOOL WINAPI ObjectPrivilegeAuditAlarmA(_In_ LPCSTR, _In_ PVOID, _In_ HANDLE, _In_ DWORD, _In_ PPRIVILEGE_SET, _In_ BOOL);
BOOL WINAPI ObjectPrivilegeAuditAlarmW(LPCWSTR,PVOID,HANDLE,DWORD,PPRIVILEGE_SET,BOOL);
HANDLE WINAPI OpenBackupEventLogA(_In_opt_ LPCSTR, _In_ LPCSTR);
HANDLE WINAPI OpenBackupEventLogW(_In_opt_ LPCWSTR, _In_ LPCWSTR);
HANDLE WINAPI OpenEventA(DWORD,BOOL,LPCSTR);
HANDLE WINAPI OpenEventLogA(_In_opt_ LPCSTR, _In_ LPCSTR);
HANDLE WINAPI OpenEventLogW(_In_opt_ LPCWSTR, _In_ LPCWSTR);
HANDLE WINAPI OpenEventW(DWORD,BOOL,LPCWSTR);
HFILE WINAPI OpenFile(_In_ LPCSTR, _Inout_ LPOFSTRUCT, _In_ UINT);
#if (_WIN32_WINNT >= 0x0600)
HANDLE WINAPI OpenFileById(_In_ HANDLE, _In_ LPFILE_ID_DESCRIPTOR, _In_ DWORD, _In_ DWORD, _In_opt_ LPSECURITY_ATTRIBUTES, _In_ DWORD);
#endif
HANDLE WINAPI OpenFileMappingA(_In_ DWORD, _In_ BOOL, _In_ LPCSTR);
HANDLE WINAPI OpenFileMappingW(DWORD,BOOL,LPCWSTR);
_Ret_maybenull_ HANDLE WINAPI OpenMutexA(_In_ DWORD, _In_ BOOL, _In_ LPCSTR);
HANDLE WINAPI OpenMutexW(DWORD,BOOL,LPCWSTR);
HANDLE WINAPI OpenProcess(DWORD,BOOL,DWORD);
BOOL WINAPI OpenProcessToken(HANDLE,DWORD,PHANDLE);
_Ret_maybenull_ HANDLE WINAPI OpenSemaphoreA(_In_ DWORD, _In_ BOOL, _In_ LPCSTR);
HANDLE WINAPI OpenSemaphoreW(DWORD,BOOL,LPCWSTR);
#if (_WIN32_WINNT >= 0x0500) || (_WIN32_WINDOWS >= 0x0490)
HANDLE WINAPI OpenThread(DWORD,BOOL,DWORD);
#endif
BOOL WINAPI OpenThreadToken(HANDLE,DWORD,BOOL,PHANDLE);
_Ret_maybenull_ HANDLE WINAPI OpenWaitableTimerA(_In_ DWORD, _In_ BOOL, _In_ LPCSTR);
HANDLE WINAPI OpenWaitableTimerW(DWORD,BOOL,LPCWSTR);
WINBASEAPI void WINAPI OutputDebugStringA(LPCSTR);
WINBASEAPI void WINAPI OutputDebugStringW(LPCWSTR);
BOOL WINAPI PeekNamedPipe(HANDLE,PVOID,DWORD,PDWORD,PDWORD,PDWORD);
DWORD WINAPI PrepareTape(_In_ HANDLE, _In_ DWORD, _In_ BOOL);
BOOL WINAPI PrivilegeCheck (HANDLE,PPRIVILEGE_SET,PBOOL);
BOOL WINAPI PrivilegedServiceAuditAlarmA(_In_ LPCSTR, _In_ LPCSTR, _In_ HANDLE, _In_ PPRIVILEGE_SET, _In_ BOOL);
BOOL WINAPI PrivilegedServiceAuditAlarmW(LPCWSTR,LPCWSTR,HANDLE,PPRIVILEGE_SET,BOOL);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI ProcessIdToSessionId(DWORD,DWORD*);
#endif
BOOL WINAPI PulseEvent(HANDLE);
BOOL WINAPI PurgeComm(_In_ HANDLE, _In_ DWORD);

#if (_WIN32_WINNT >= 0x0501)
BOOL
WINAPI
QueryActCtxW(
  _In_ DWORD dwFlags,
  _In_ HANDLE hActCtx,
  _In_opt_ PVOID pvSubInstance,
  _In_ ULONG ulInfoClass,
  _Out_writes_bytes_to_opt_(cbBuffer, *pcbWrittenOrRequired) PVOID pvBuffer,
  _In_ SIZE_T cbBuffer,
  _Out_opt_ SIZE_T *pcbWrittenOrRequired);
#endif

DWORD
WINAPI
QueryDosDeviceA(
  _In_opt_ LPCSTR lpDeviceName,
  _Out_writes_to_opt_(ucchMax, return) LPSTR lpTargetPath,
  _In_ DWORD ucchMax);

DWORD WINAPI QueryDosDeviceW(LPCWSTR,LPWSTR,DWORD);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI QueryMemoryResourceNotification(HANDLE,PBOOL);
#endif
BOOL WINAPI QueryPerformanceCounter(PLARGE_INTEGER);
BOOL WINAPI QueryPerformanceFrequency(PLARGE_INTEGER);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI QuerySecurityAccessMask(SECURITY_INFORMATION,LPDWORD);
#endif
DWORD WINAPI QueueUserAPC(PAPCFUNC,HANDLE,ULONG_PTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI QueueUserWorkItem(LPTHREAD_START_ROUTINE,PVOID,ULONG);
#endif
void WINAPI RaiseException(DWORD,DWORD,DWORD,const ULONG_PTR*);

BOOL
WINAPI
QueryInformationJobObject(
  _In_opt_ HANDLE hJob,
  _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
  _Out_writes_bytes_to_(cbJobObjectInformationLength, *lpReturnLength) LPVOID lpJobObjectInformation,
  _In_ DWORD cbJobObjectInformationLength,
  _Out_opt_ LPDWORD lpReturnLength);

BOOL
WINAPI
ReadDirectoryChangesW(
  _In_ HANDLE hDirectory,
  _Out_writes_bytes_to_(nBufferLength, *lpBytesReturned) LPVOID lpBuffer,
  _In_ DWORD nBufferLength,
  _In_ BOOL bWatchSubtree,
  _In_ DWORD dwNotifyFilter,
  _Out_opt_ LPDWORD lpBytesReturned,
  _Inout_opt_ LPOVERLAPPED lpOverlapped,
  _In_opt_ LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

BOOL
WINAPI
ReadEventLogA(
  _In_ HANDLE hEventLog,
  _In_ DWORD dwReadFlags,
  _In_ DWORD dwRecordOffset,
  _Out_writes_bytes_to_(nNumberOfBytesToRead, *pnBytesRead) LPVOID lpBuffer,
  _In_ DWORD nNumberOfBytesToRead,
  _Out_ DWORD *pnBytesRead,
  _Out_ DWORD *pnMinNumberOfBytesNeeded);

BOOL
WINAPI
ReadEventLogW(
  _In_ HANDLE hEventLog,
  _In_ DWORD dwReadFlags,
  _In_ DWORD dwRecordOffset,
  _Out_writes_bytes_to_(nNumberOfBytesToRead, *pnBytesRead) LPVOID lpBuffer,
  _In_ DWORD nNumberOfBytesToRead,
  _Out_ DWORD *pnBytesRead,
  _Out_ DWORD *pnMinNumberOfBytesNeeded);

BOOL WINAPI ReadFile(HANDLE,PVOID,DWORD,PDWORD,LPOVERLAPPED);
BOOL WINAPI ReadFileEx(HANDLE,PVOID,DWORD,LPOVERLAPPED,LPOVERLAPPED_COMPLETION_ROUTINE);
BOOL WINAPI ReadFileScatter(HANDLE,FILE_SEGMENT_ELEMENT*,DWORD,LPDWORD,LPOVERLAPPED);
BOOL WINAPI ReadProcessMemory(HANDLE,LPCVOID,LPVOID,SIZE_T,PSIZE_T);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI RecoveryFinished(BOOL);
HRESULT WINAPI RecoveryInProgress(OUT PBOOL);
HRESULT WINAPI RegisterApplicationRecoveryCallback(_In_ APPLICATION_RECOVERY_CALLBACK, _In_opt_ PVOID, _In_ DWORD, _In_ DWORD);
HRESULT WINAPI RegisterApplicationRestart(_In_opt_ PCWSTR, _In_ DWORD);
#endif
HANDLE WINAPI RegisterEventSourceA(_In_opt_ LPCSTR, _In_ LPCSTR);
HANDLE WINAPI RegisterEventSourceW(_In_opt_ LPCWSTR, _In_ LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI RegisterWaitForSingleObject(_Outptr_ PHANDLE, _In_ HANDLE, _In_ WAITORTIMERCALLBACK, _In_opt_ PVOID, _In_ ULONG, _In_ ULONG);
HANDLE WINAPI RegisterWaitForSingleObjectEx(HANDLE,WAITORTIMERCALLBACK,PVOID,ULONG,ULONG);
#endif
#if (_WIN32_WINNT >= 0x0501)
void WINAPI ReleaseActCtx(_Inout_ HANDLE);
#endif
BOOL WINAPI ReleaseMutex(HANDLE);
BOOL WINAPI ReleaseSemaphore(HANDLE,LONG,LPLONG);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI ReleaseSRWLockExclusive(PSRWLOCK);
VOID WINAPI ReleaseSRWLockShared(PSRWLOCK);
#endif
BOOL WINAPI RemoveDirectoryA(LPCSTR);
BOOL WINAPI RemoveDirectoryW(LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
ULONG WINAPI RemoveVectoredExceptionHandler(_In_ PVOID);
ULONG WINAPI RemoveVectoredContinueHandler(_In_ PVOID);
#endif
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI ReplaceFileA(_In_ LPCSTR, _In_ LPCSTR, _In_opt_ LPCSTR, _In_ DWORD, _Reserved_ LPVOID, _Reserved_ LPVOID);
BOOL WINAPI ReplaceFileW(_In_ LPCWSTR, _In_ LPCWSTR, _In_opt_ LPCWSTR, _In_ DWORD, _Reserved_ LPVOID, _Reserved_ LPVOID);
#endif

BOOL
WINAPI
ReportEventA(
  _In_ HANDLE hEventLog,
  _In_ WORD wType,
  _In_ WORD wCategory,
  _In_ DWORD dwEventID,
  _In_opt_ PSID lpUserSid,
  _In_ WORD wNumStrings,
  _In_ DWORD dwDataSize,
  _In_reads_opt_(wNumStrings) LPCSTR *lpStrings,
  _In_reads_bytes_opt_(dwDataSize) LPVOID lpRawData);

BOOL
WINAPI
ReportEventW(
  _In_ HANDLE hEventLog,
  _In_ WORD wType,
  _In_ WORD wCategory,
  _In_ DWORD dwEventID,
  _In_opt_ PSID lpUserSid,
  _In_ WORD wNumStrings,
  _In_ DWORD dwDataSize,
  _In_reads_opt_(wNumStrings) LPCWSTR *lpStrings,
  _In_reads_bytes_opt_(dwDataSize) LPVOID lpRawData);

BOOL WINAPI ResetEvent(HANDLE);
UINT WINAPI ResetWriteWatch(LPVOID,SIZE_T);
#if (_WIN32_WINNT >= 0x0510)
VOID WINAPI RestoreLastError(_In_ DWORD);
#endif
DWORD WINAPI ResumeThread(HANDLE);
BOOL WINAPI RevertToSelf(void);

_Success_(return != 0 && return < nBufferLength)
DWORD
WINAPI
SearchPathA(
  _In_opt_ LPCSTR lpPath,
  _In_ LPCSTR lpFileName,
  _In_opt_ LPCSTR lpExtension,
  _In_ DWORD nBufferLength,
  _Out_writes_to_opt_(nBufferLength, return + 1) LPSTR lpBuffer,
  _Out_opt_ LPSTR *lpFilePart);

DWORD WINAPI
SearchPathW(
    _In_opt_ LPCWSTR lpPath,
    _In_ LPCWSTR lpFileName,
    _In_opt_ LPCWSTR lpExtension,
    _In_ DWORD nBufferLength,
    _Out_writes_to_opt_(nBufferLength, return +1) LPWSTR lpBuffer,
    _Out_opt_ LPWSTR *lpFilePart);
BOOL WINAPI SetAclInformation(PACL,PVOID,DWORD,ACL_INFORMATION_CLASS);
BOOL WINAPI SetCommBreak(_In_ HANDLE);

BOOL
WINAPI
SetCommConfig(
  _In_ HANDLE hCommDev,
  _In_reads_bytes_(dwSize) LPCOMMCONFIG lpCC,
  _In_ DWORD dwSize);

BOOL WINAPI SetCommMask(_In_ HANDLE, _In_ DWORD);
BOOL WINAPI SetCommState(_In_ HANDLE, _In_ LPDCB);
BOOL WINAPI SetCommTimeouts(_In_ HANDLE, _In_ LPCOMMTIMEOUTS);
BOOL WINAPI SetComputerNameA(_In_ LPCSTR);
BOOL WINAPI SetComputerNameW(_In_ LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI SetComputerNameExA(_In_ COMPUTER_NAME_FORMAT, _In_ LPCSTR);
BOOL WINAPI SetComputerNameExW(COMPUTER_NAME_FORMAT,LPCWSTR);
#endif
BOOL WINAPI SetCurrentDirectoryA(LPCSTR);
BOOL WINAPI SetCurrentDirectoryW(LPCWSTR);

BOOL
WINAPI
SetDefaultCommConfigA(
  _In_ LPCSTR lpszName,
  _In_reads_bytes_(dwSize) LPCOMMCONFIG lpCC,
  _In_ DWORD dwSize);

BOOL
WINAPI
SetDefaultCommConfigW(
  _In_ LPCWSTR lpszName,
  _In_reads_bytes_(dwSize) LPCOMMCONFIG lpCC,
  _In_ DWORD dwSize);

#if (_WIN32_WINNT >= 0x0502)
BOOL WINAPI SetDllDirectoryA(_In_opt_ LPCSTR);
BOOL WINAPI SetDllDirectoryW(_In_opt_ LPCWSTR);
#endif
BOOL WINAPI SetEndOfFile(HANDLE);
BOOL WINAPI SetEnvironmentVariableA(LPCSTR,LPCSTR);
BOOL WINAPI SetEnvironmentVariableW(LPCWSTR,LPCWSTR);
UINT WINAPI SetErrorMode(UINT);
BOOL WINAPI SetEvent(HANDLE);
VOID WINAPI SetFileApisToANSI(void);
VOID WINAPI SetFileApisToOEM(void);
BOOL WINAPI SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI SetFileAttributesByHandle(HANDLE,DWORD,DWORD);
#endif
BOOL WINAPI SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);
#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI SetFileBandwidthReservation(_In_ HANDLE, _In_ DWORD, _In_ DWORD, _In_ BOOL, _Out_ LPDWORD, _Out_ LPDWORD);
BOOL WINAPI SetFileCompletionNotificationModes(_In_ HANDLE, _In_ UCHAR);
#endif
DWORD WINAPI SetFilePointer(HANDLE,LONG,PLONG,DWORD);
BOOL WINAPI SetFilePointerEx(HANDLE,LARGE_INTEGER,PLARGE_INTEGER,DWORD);
BOOL WINAPI SetFileSecurityA(_In_ LPCSTR, _In_ SECURITY_INFORMATION, _In_ PSECURITY_DESCRIPTOR);
BOOL WINAPI SetFileSecurityW(LPCWSTR,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI SetFileShortNameA(_In_ HANDLE, _In_ LPCSTR);
BOOL WINAPI SetFileShortNameW(_In_ HANDLE, _In_ LPCWSTR);
#endif
BOOL WINAPI SetFileTime(HANDLE,const FILETIME*,const FILETIME*,const FILETIME*);
#if (_WIN32_WINNT >= 0x0501)
BOOL WINAPI SetFileValidData(HANDLE,LONGLONG);
#endif

#if (_WIN32_WINNT >= 0x0502)

WINBASEAPI
UINT
WINAPI
EnumSystemFirmwareTables(
    _In_ DWORD FirmwareTableProviderSignature,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableEnumBuffer,
    _In_ DWORD BufferSize);

WINBASEAPI
UINT
WINAPI
GetSystemFirmwareTable(
    _In_ DWORD FirmwareTableProviderSignature,
    _In_ DWORD FirmwareTableID,
    _Out_writes_bytes_to_opt_(BufferSize, return) PVOID pFirmwareTableBuffer,
    _In_ DWORD BufferSize);

_Success_(return > 0)
WINBASEAPI
DWORD
WINAPI
GetFirmwareEnvironmentVariableA(
    _In_ LPCSTR lpName,
    _In_ LPCSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize);

_Success_(return > 0)
WINBASEAPI
DWORD
WINAPI
GetFirmwareEnvironmentVariableW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize);

#ifdef UNICODE
#define GetFirmwareEnvironmentVariable GetFirmwareEnvironmentVariableW
#else
#define GetFirmwareEnvironmentVariable GetFirmwareEnvironmentVariableA
#endif

WINBASEAPI
BOOL
WINAPI
SetFirmwareEnvironmentVariableA(
  _In_ LPCSTR lpName,
  _In_ LPCSTR lpGuid,
  _In_reads_bytes_opt_(nSize) PVOID pValue,
  _In_ DWORD nSize);

WINBASEAPI
BOOL
WINAPI
SetFirmwareEnvironmentVariableW(
  _In_ LPCWSTR lpName,
  _In_ LPCWSTR lpGuid,
  _In_reads_bytes_opt_(nSize) PVOID pValue,
  _In_ DWORD nSize);

#ifdef UNICODE
#define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableW
#else
#define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableA
#endif

#endif /* _WIN32_WINNT >= 0x0502 */

#if (_WIN32_WINNT >= 0x0602)

_Success_(return > 0)
WINBASEAPI
DWORD
WINAPI
GetFirmwareEnvironmentVariableExW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize,
    _Out_opt_ PDWORD pdwAttribubutes);

_Success_(return > 0)
WINBASEAPI
DWORD
WINAPI
GetFirmwareEnvironmentVariableExA(
    _In_ LPCSTR lpName,
    _In_ LPCSTR lpGuid,
    _Out_writes_bytes_to_opt_(nSize, return) PVOID pBuffer,
    _In_ DWORD nSize,
    _Out_opt_ PDWORD pdwAttribubutes);

#ifdef UNICODE
#define GetFirmwareEnvironmentVariableEx GetFirmwareEnvironmentVariableExW
#else
#define GetFirmwareEnvironmentVariableEx GetFirmwareEnvironmentVariableExA
#endif

WINBASEAPI
BOOL
WINAPI
SetFirmwareEnvironmentVariableExW(
    _In_ LPCWSTR lpName,
    _In_ LPCWSTR lpGuid,
    _In_reads_bytes_opt_(nSize) PVOID pValue,
    _In_ DWORD nSize,
    _In_ DWORD dwAttributes);

WINBASEAPI
BOOL
WINAPI
SetFirmwareEnvironmentVariableExA(
    _In_ LPCSTR lpName,
    _In_ LPCSTR lpGuid,
    _In_reads_bytes_opt_(nSize) PVOID pValue,
    _In_ DWORD nSize,
    _In_ DWORD dwAttributes);

#ifdef UNICODE
#define SetFirmwareEnvironmentVariableEx SetFirmwareEnvironmentVariableExW
#else
#define SetFirmwareEnvironmentVariableEx SetFirmwareEnvironmentVariableExA
#endif

_Success_(return)
WINBASEAPI
BOOL
WINAPI
GetFirmwareType(
    _Out_ PFIRMWARE_TYPE FirmwareType);

#endif /* _WIN32_WINNT >= 0x0602 */

UINT WINAPI SetHandleCount(UINT);
BOOL WINAPI SetHandleInformation(HANDLE,DWORD,DWORD);

BOOL
WINAPI
SetInformationJobObject(
  _In_ HANDLE hJob,
  _In_ JOBOBJECTINFOCLASS JobObjectInformationClass,
  _In_reads_bytes_(cbJobObjectInformationLength) LPVOID lpJobObjectInformation,
  _In_ DWORD cbJobObjectInformationLength);

BOOL WINAPI SetKernelObjectSecurity(HANDLE,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR);
void WINAPI SetLastError(DWORD);
void WINAPI SetLastErrorEx(DWORD,DWORD);
BOOL WINAPI SetLocalTime(const SYSTEMTIME*);
BOOL WINAPI SetMailslotInfo(_In_ HANDLE, _In_ DWORD);
BOOL WINAPI SetNamedPipeHandleState(HANDLE,PDWORD,PDWORD,PDWORD);
BOOL WINAPI SetPriorityClass(HANDLE,DWORD);
BOOL WINAPI SetPrivateObjectSecurity(SECURITY_INFORMATION,PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR *,PGENERIC_MAPPING,HANDLE);
BOOL WINAPI SetProcessAffinityMask(_In_ HANDLE, _In_ DWORD_PTR);
BOOL WINAPI SetProcessPriorityBoost(_In_ HANDLE, _In_ BOOL);
BOOL WINAPI SetProcessShutdownParameters(DWORD,DWORD);
BOOL WINAPI SetProcessWorkingSetSize(_In_ HANDLE, _In_ SIZE_T, _In_ SIZE_T);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI SetSecurityAccessMask(SECURITY_INFORMATION,LPDWORD);
#endif
BOOL WINAPI SetSecurityDescriptorControl(PSECURITY_DESCRIPTOR,SECURITY_DESCRIPTOR_CONTROL,SECURITY_DESCRIPTOR_CONTROL);
BOOL WINAPI SetSecurityDescriptorDacl(PSECURITY_DESCRIPTOR,BOOL,PACL,BOOL);
BOOL WINAPI SetSecurityDescriptorGroup(PSECURITY_DESCRIPTOR,PSID,BOOL);
BOOL WINAPI SetSecurityDescriptorOwner(PSECURITY_DESCRIPTOR,PSID,BOOL);
DWORD WINAPI SetSecurityDescriptorRMControl(PSECURITY_DESCRIPTOR,PUCHAR);
BOOL WINAPI SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR,BOOL,PACL,BOOL);
BOOL WINAPI SetStdHandle(_In_ DWORD, _In_ HANDLE);
#define SetSwapAreaSize(w) (w)
BOOL WINAPI SetSystemPowerState(_In_ BOOL, _In_ BOOL);
BOOL WINAPI SetSystemTime(const SYSTEMTIME*);
BOOL WINAPI SetSystemTimeAdjustment(_In_ DWORD, _In_ BOOL);
DWORD WINAPI SetTapeParameters(_In_ HANDLE, _In_ DWORD, _In_ PVOID);
DWORD WINAPI SetTapePosition(_In_ HANDLE, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ DWORD, _In_ BOOL);
DWORD_PTR WINAPI SetThreadAffinityMask(_In_ HANDLE, _In_ DWORD_PTR);
BOOL WINAPI SetThreadContext(HANDLE,const CONTEXT*);
DWORD WINAPI SetThreadIdealProcessor(_In_ HANDLE, _In_ DWORD);
BOOL WINAPI SetThreadPriority(HANDLE,int);
BOOL WINAPI SetThreadPriorityBoost(HANDLE,BOOL);
BOOL WINAPI SetThreadToken (PHANDLE,HANDLE);
BOOL WINAPI SetTimeZoneInformation(const TIME_ZONE_INFORMATION *);
BOOL WINAPI SetTokenInformation(HANDLE,TOKEN_INFORMATION_CLASS,PVOID,DWORD);
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);
BOOL WINAPI SetupComm(_In_ HANDLE, _In_ DWORD, _In_ DWORD);
BOOL WINAPI SetVolumeLabelA(_In_opt_ LPCSTR, _In_opt_ LPCSTR);
BOOL WINAPI SetVolumeLabelW(_In_opt_ LPCWSTR, _In_opt_ LPCWSTR);
#if (_WIN32_WINNT >= 0x0500)
BOOL WINAPI SetVolumeMountPointA(_In_ LPCSTR, _In_ LPCSTR);
BOOL WINAPI SetVolumeMountPointW(_In_ LPCWSTR, _In_ LPCWSTR);
#endif
BOOL WINAPI SetWaitableTimer(HANDLE,const LARGE_INTEGER*,LONG,PTIMERAPCROUTINE,PVOID,BOOL);
DWORD WINAPI SignalObjectAndWait(_In_ HANDLE, _In_ HANDLE, _In_ DWORD, _In_ BOOL);
DWORD WINAPI SizeofResource(HINSTANCE,HRSRC);
WINBASEAPI void WINAPI Sleep(DWORD);
#if (_WIN32_WINNT >= 0x0600)
BOOL WINAPI SleepConditionVariableCS(PCONDITION_VARIABLE,PCRITICAL_SECTION,DWORD);
BOOL WINAPI SleepConditionVariableSRW(PCONDITION_VARIABLE,PSRWLOCK,DWORD,ULONG);
#endif
DWORD WINAPI SleepEx(DWORD,BOOL);
DWORD WINAPI SuspendThread(HANDLE);
void WINAPI SwitchToFiber(_In_ PVOID);
BOOL WINAPI SwitchToThread(void);
BOOL WINAPI SystemTimeToFileTime(const SYSTEMTIME*,LPFILETIME);
BOOL WINAPI SystemTimeToTzSpecificLocalTime(CONST TIME_ZONE_INFORMATION*,CONST SYSTEMTIME*,LPSYSTEMTIME);
BOOL WINAPI TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL WINAPI TerminateThread(HANDLE hThread,DWORD dwExitCode);
DWORD WINAPI TlsAlloc(VOID);
BOOL WINAPI TlsFree(DWORD);
PVOID WINAPI TlsGetValue(DWORD);
BOOL WINAPI TlsSetValue(DWORD,PVOID);
BOOL WINAPI TransactNamedPipe(HANDLE,PVOID,DWORD,PVOID,DWORD,PDWORD,LPOVERLAPPED);
BOOL WINAPI TransmitCommChar(_In_ HANDLE, _In_ char);
BOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION);
BOOL WINAPI TzSpecificLocalTimeToSystemTime(LPTIME_ZONE_INFORMATION,LPSYSTEMTIME,LPSYSTEMTIME);
LONG WINAPI UnhandledExceptionFilter(LPEXCEPTION_POINTERS);
BOOL WINAPI UnlockFile(HANDLE,DWORD,DWORD,DWORD,DWORD);
BOOL WINAPI UnlockFileEx(HANDLE,DWORD,DWORD,DWORD,LPOVERLAPPED);
#define UnlockResource(handle) ((handle), 0)
#define UnlockSegment(w) GlobalUnfix((HANDLE)(w)) /* Obsolete: Has no effect. */
BOOL WINAPI UnmapViewOfFile(LPCVOID);
#if (_WIN32_WINNT >= 0x0500)
_Must_inspect_result_ BOOL WINAPI UnregisterWait(_In_ HANDLE);
BOOL WINAPI UnregisterWaitEx(HANDLE,HANDLE);
#endif

BOOL
WINAPI
UpdateResourceA(
  _In_ HANDLE hUpdate,
  _In_ LPCSTR lpType,
  _In_ LPCSTR lpName,
  _In_ WORD wLanguage,
  _In_reads_bytes_opt_(cb) LPVOID lpData,
  _In_ DWORD cb);

BOOL
WINAPI
UpdateResourceW(
  _In_ HANDLE hUpdate,
  _In_ LPCWSTR lpType,
  _In_ LPCWSTR lpName,
  _In_ WORD wLanguage,
  _In_reads_bytes_opt_(cb) LPVOID lpData,
  _In_ DWORD cb);

BOOL WINAPI VerifyVersionInfoA(_Inout_ LPOSVERSIONINFOEXA, _In_ DWORD, _In_ DWORDLONG);
BOOL WINAPI VerifyVersionInfoW(_Inout_ LPOSVERSIONINFOEXW, _In_ DWORD, _In_ DWORDLONG);
PVOID WINAPI VirtualAlloc(PVOID,SIZE_T,DWORD,DWORD);
PVOID WINAPI VirtualAllocEx(HANDLE,PVOID,SIZE_T,DWORD,DWORD);
BOOL WINAPI VirtualFree(PVOID,SIZE_T,DWORD);
BOOL WINAPI VirtualFreeEx(HANDLE,PVOID,SIZE_T,DWORD);
BOOL WINAPI VirtualLock(PVOID,SIZE_T);
BOOL WINAPI VirtualProtect(PVOID,SIZE_T,DWORD,PDWORD);
BOOL WINAPI VirtualProtectEx(HANDLE,PVOID,SIZE_T,DWORD,PDWORD);
SIZE_T WINAPI VirtualQuery(LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
SIZE_T WINAPI VirtualQueryEx(HANDLE,LPCVOID,PMEMORY_BASIC_INFORMATION,SIZE_T);
BOOL WINAPI VirtualUnlock(PVOID,SIZE_T);
BOOL WINAPI WaitCommEvent(_In_ HANDLE, _Inout_ PDWORD, _Inout_opt_ LPOVERLAPPED);
BOOL WINAPI WaitForDebugEvent(LPDEBUG_EVENT,DWORD);

DWORD
WINAPI
WaitForMultipleObjects(
  _In_ DWORD nCount,
  _In_reads_(nCount) CONST HANDLE *lpHandles,
  _In_ BOOL bWaitAll,
  _In_ DWORD dwMilliseconds);

DWORD WINAPI WaitForMultipleObjectsEx(DWORD,const HANDLE*,BOOL,DWORD,BOOL);
DWORD WINAPI WaitForSingleObject(_In_ HANDLE hHandle, _In_ DWORD dwMilliseconds);
DWORD WINAPI WaitForSingleObjectEx(HANDLE,DWORD,BOOL);
BOOL WINAPI WaitNamedPipeA(_In_ LPCSTR, _In_ DWORD);
BOOL WINAPI WaitNamedPipeW(_In_ LPCWSTR, _In_ DWORD);
#if (_WIN32_WINNT >= 0x0600)
VOID WINAPI WakeConditionVariable(PCONDITION_VARIABLE);
VOID WINAPI WakeAllConditionVariable(PCONDITION_VARIABLE);
#endif
BOOL WINAPI WinLoadTrustProvider(GUID*);
BOOL WINAPI Wow64DisableWow64FsRedirection(PVOID*);
BOOLEAN WINAPI Wow64EnableWow64FsRedirection(_In_ BOOLEAN);
BOOL WINAPI Wow64RevertWow64FsRedirection(PVOID);
DWORD WINAPI WriteEncryptedFileRaw(_In_ PFE_IMPORT_FUNC, _In_opt_ PVOID, _In_ PVOID);
BOOL WINAPI WriteFile(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
BOOL WINAPI WriteFileEx(HANDLE,LPCVOID,DWORD,LPOVERLAPPED,LPOVERLAPPED_COMPLETION_ROUTINE);
BOOL WINAPI WriteFileGather(HANDLE,FILE_SEGMENT_ELEMENT*,DWORD,LPDWORD,LPOVERLAPPED);
BOOL WINAPI WritePrivateProfileSectionA(_In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_opt_ LPCSTR);
BOOL WINAPI WritePrivateProfileSectionW(_In_opt_ LPCWSTR, _In_opt_ LPCWSTR, _In_opt_ LPCWSTR);
BOOL WINAPI WritePrivateProfileStringA(_In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_opt_ LPCSTR);
BOOL WINAPI WritePrivateProfileStringW(_In_opt_ LPCWSTR, _In_opt_ LPCWSTR, _In_opt_ LPCWSTR, _In_opt_ LPCWSTR);

BOOL
WINAPI
WritePrivateProfileStructA(
  _In_ LPCSTR lpszSection,
  _In_ LPCSTR lpszKey,
  _In_reads_bytes_opt_(uSizeStruct) LPVOID lpStruct,
  _In_ UINT uSizeStruct,
  _In_opt_ LPCSTR szFile);

BOOL
WINAPI
WritePrivateProfileStructW(
  _In_ LPCWSTR lpszSection,
  _In_ LPCWSTR lpszKey,
  _In_reads_bytes_opt_(uSizeStruct) LPVOID lpStruct,
  _In_ UINT uSizeStruct,
  _In_opt_ LPCWSTR szFile);

BOOL WINAPI WriteProcessMemory(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
BOOL WINAPI WriteProfileSectionA(_In_ LPCSTR, _In_ LPCSTR);
BOOL WINAPI WriteProfileSectionW(_In_ LPCWSTR, _In_ LPCWSTR);
BOOL WINAPI WriteProfileStringA(_In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_opt_ LPCSTR);
BOOL WINAPI WriteProfileStringW(_In_opt_ LPCWSTR, _In_opt_ LPCWSTR, _In_opt_ LPCWSTR);
DWORD WINAPI WriteTapemark(_In_ HANDLE, _In_ DWORD, _In_ DWORD, _In_ BOOL);

#define Yield()

#if (_WIN32_WINNT >= 0x0501)
DWORD WINAPI WTSGetActiveConsoleSessionId(VOID);
BOOL WINAPI ZombifyActCtx(_Inout_ HANDLE);
#endif

#if (_WIN32_WINNT >= 0x0500)

BOOL
WINAPI
AllocateUserPhysicalPages(
  _In_ HANDLE hProcess,
  _Inout_ PULONG_PTR NumberOfPages,
  _Out_writes_to_(*NumberOfPages, *NumberOfPages) PULONG_PTR PageArray);

BOOL
WINAPI
FreeUserPhysicalPages(
  _In_ HANDLE hProcess,
  _Inout_ PULONG_PTR NumberOfPages,
  _In_reads_(*NumberOfPages) PULONG_PTR PageArray);

BOOL
WINAPI
MapUserPhysicalPages(
  _In_ PVOID VirtualAddress,
  _In_ ULONG_PTR NumberOfPages,
  _In_reads_opt_(NumberOfPages) PULONG_PTR PageArray);

BOOL
WINAPI
MapUserPhysicalPagesScatter(
  _In_reads_(NumberOfPages) PVOID *VirtualAddresses,
  _In_ ULONG_PTR NumberOfPages,
  _In_reads_opt_(NumberOfPages) PULONG_PTR PageArray);

#endif

#ifdef UNICODE
typedef STARTUPINFOW STARTUPINFO,*LPSTARTUPINFO;
typedef HW_PROFILE_INFOW HW_PROFILE_INFO,*LPHW_PROFILE_INFO;
typedef ENUMRESLANGPROCW ENUMRESLANGPROC;
typedef ENUMRESNAMEPROCW ENUMRESNAMEPROC;
typedef ENUMRESTYPEPROCW ENUMRESTYPEPROC;
#if (_WIN32_WINNT >= 0x0501)
typedef ACTCTXW ACTCTX,*PACTCTX;
typedef PCACTCTXW PCACTCTX;
#endif
#define AccessCheckAndAuditAlarm AccessCheckAndAuditAlarmW
#define AddAtom AddAtomW
#define BackupEventLog BackupEventLogW
#define BeginUpdateResource BeginUpdateResourceW
#define BuildCommDCB BuildCommDCBW
#define BuildCommDCBAndTimeouts BuildCommDCBAndTimeoutsW
#define CallNamedPipe CallNamedPipeW
#if (_WIN32_WINNT >= 0x0501)
#define CheckNameLegalDOS8Dot3 CheckNameLegalDOS8Dot3W
#endif
#define ClearEventLog ClearEventLogW
#define CommConfigDialog CommConfigDialogW
#define CopyFile CopyFileW
#define CopyFileEx CopyFileExW
#if (_WIN32_WINNT >= 0x0501)
#define CreateActCtx CreateActCtxW
#endif
#define CreateDirectory CreateDirectoryW
#define CreateDirectoryEx CreateDirectoryExW
#define CreateEvent CreateEventW
#define CreateFile CreateFileW
#define CreateFileMapping CreateFileMappingW
#if (_WIN32_WINNT >= 0x0500)
#define CreateHardLink CreateHardLinkW
#define CreateJobObject CreateJobObjectW
#endif
#define CreateMailslot CreateMailslotW
#define CreateMutex CreateMutexW
#define CreateNamedPipe CreateNamedPipeW
#define CreateProcess CreateProcessW
#define CreateProcessAsUser CreateProcessAsUserW
#define CreateSemaphore CreateSemaphoreW
#define CreateWaitableTimer CreateWaitableTimerW
#define DecryptFile DecryptFileW
#define DefineDosDevice DefineDosDeviceW
#define DeleteFile DeleteFileW
#if (_WIN32_WINNT >= 0x0500)
#define DeleteVolumeMountPoint DeleteVolumeMountPointW
#define DnsHostnameToComputerName DnsHostnameToComputerNameW
#endif
#define EncryptFile EncryptFileW
#define EndUpdateResource EndUpdateResourceW
#define EnumResourceLanguages EnumResourceLanguagesW
#define EnumResourceNames EnumResourceNamesW
#define EnumResourceTypes EnumResourceTypesW
#define ExpandEnvironmentStrings ExpandEnvironmentStringsW
#define FatalAppExit FatalAppExitW
#define FileEncryptionStatus FileEncryptionStatusW
#if (_WIN32_WINNT >= 0x0501)
#define FindActCtxSectionString FindActCtxSectionStringW
#endif
#define FindAtom FindAtomW
#define FindFirstChangeNotification FindFirstChangeNotificationW
#define FindFirstFile FindFirstFileW
#define FindFirstFileEx FindFirstFileExW
#if (_WIN32_WINNT >= 0x0500)
#define FindFirstVolume FindFirstVolumeW
#define FindFirstVolumeMountPoint FindFirstVolumeMountPointW
#endif
#define FindNextFile FindNextFileW
#if (_WIN32_WINNT >= 0x0500)
#define FindNextVolume FindNextVolumeW
#define FindNextVolumeMountPoint  FindNextVolumeMountPointW
#endif
#define FindResource FindResourceW
#define FindResourceEx FindResourceExW
#define FormatMessage FormatMessageW
#define FreeEnvironmentStrings FreeEnvironmentStringsW
#define GetAtomName GetAtomNameW
#define GetBinaryType GetBinaryTypeW
#define GetCommandLine GetCommandLineW
#define GetCompressedFileSize GetCompressedFileSizeW
#define GetComputerName GetComputerNameW
#if (_WIN32_WINNT >= 0x0500)
#define GetComputerNameEx GetComputerNameExW
#endif
#define GetCurrentDirectory GetCurrentDirectoryW
#define GetDefaultCommConfig GetDefaultCommConfigW
#define GetDiskFreeSpace GetDiskFreeSpaceW
#define GetDiskFreeSpaceEx GetDiskFreeSpaceExW
#if (_WIN32_WINNT >= 0x0502)
#define GetDllDirectory GetDllDirectoryW
#endif
#define GetDriveType GetDriveTypeW
#define GetEnvironmentStrings GetEnvironmentStringsW
#define GetEnvironmentVariable GetEnvironmentVariableW
#define GetFileAttributes GetFileAttributesW
#define GetFileAttributesEx GetFileAttributesExW
#define GetFileSecurity GetFileSecurityW
#if (_WIN32_WINNT >= 0x0600)
#define GetFinalPathNameByHandle GetFinalPathNameByHandleW
#endif
#define GetFullPathName GetFullPathNameW
#define GetLogicalDriveStrings GetLogicalDriveStringsW
#if (_WIN32_WINNT >= 0x0500 || _WIN32_WINDOWS >= 0x0410)
#define GetLongPathName GetLongPathNameW
#endif
#define GetModuleFileName GetModuleFileNameW
#define GetModuleHandle GetModuleHandleW
#if (_WIN32_WINNT >= 0x0500)
#define GetModuleHandleEx GetModuleHandleExW
#endif
#define GetNamedPipeHandleState GetNamedPipeHandleStateW
#define GetPrivateProfileInt GetPrivateProfileIntW
#define GetPrivateProfileSection GetPrivateProfileSectionW
#define GetPrivateProfileSectionNames GetPrivateProfileSectionNamesW
#define GetPrivateProfileString GetPrivateProfileStringW
#define GetPrivateProfileStruct GetPrivateProfileStructW
#define GetProfileInt GetProfileIntW
#define GetProfileSection GetProfileSectionW
#define GetProfileString GetProfileStringW
#define GetShortPathName GetShortPathNameW
#define GetStartupInfo GetStartupInfoW
#define GetSystemDirectory GetSystemDirectoryW
#if (_WIN32_WINNT >= 0x0500)
#define GetSystemWindowsDirectory GetSystemWindowsDirectoryW
#endif
#if (_WIN32_WINNT >= 0x0501)
#define GetSystemWow64Directory GetSystemWow64DirectoryW
#endif
#define GetTempFileName GetTempFileNameW
#define GetTempPath GetTempPathW
#define GetUserName GetUserNameW
#define GetVersionEx GetVersionExW
#define GetVolumeInformation GetVolumeInformationW
#define GetVolumeNameForVolumeMountPoint GetVolumeNameForVolumeMountPointW
#define GetVolumePathName GetVolumePathNameW
#define GetVolumePathNamesForVolumeName GetVolumePathNamesForVolumeNameW
#define GetWindowsDirectory GetWindowsDirectoryW
#define GlobalAddAtom GlobalAddAtomW
#define GlobalFindAtom GlobalFindAtomW
#define GlobalGetAtomName GlobalGetAtomNameW
#define IsBadStringPtr IsBadStringPtrW
#define LoadLibrary LoadLibraryW
#define LoadLibraryEx LoadLibraryExW
#define LogonUser LogonUserW
#define LogonUserEx LogonUserExW
#define LookupAccountName LookupAccountNameW
#define LookupAccountSid LookupAccountSidW
#define LookupPrivilegeDisplayName LookupPrivilegeDisplayNameW
#define LookupPrivilegeName LookupPrivilegeNameW
#define LookupPrivilegeValue LookupPrivilegeValueW
#define lstrcat lstrcatW
#define lstrcmp lstrcmpW
#define lstrcmpi lstrcmpiW
#define lstrcpy lstrcpyW
#define lstrcpyn lstrcpynW
#define lstrlen lstrlenW
#define MoveFile MoveFileW
#define MoveFileEx MoveFileExW
#define MoveFileWithProgress MoveFileWithProgressW
#define ObjectCloseAuditAlarm ObjectCloseAuditAlarmW
#define ObjectDeleteAuditAlarm ObjectDeleteAuditAlarmW
#define ObjectOpenAuditAlarm ObjectOpenAuditAlarmW
#define ObjectPrivilegeAuditAlarm ObjectPrivilegeAuditAlarmW
#define OpenBackupEventLog OpenBackupEventLogW
#define OpenEvent OpenEventW
#define OpenEventLog OpenEventLogW
#define OpenFileMapping OpenFileMappingW
#define OpenMutex OpenMutexW
#define OpenSemaphore OpenSemaphoreW
#define OutputDebugString OutputDebugStringW
#define PrivilegedServiceAuditAlarm PrivilegedServiceAuditAlarmW
#define QueryDosDevice QueryDosDeviceW
#define ReadEventLog ReadEventLogW
#define RegisterEventSource RegisterEventSourceW
#define RemoveDirectory RemoveDirectoryW
#if (_WIN32_WINNT >= 0x0500)
#define ReplaceFile ReplaceFileW
#endif
#define ReportEvent ReportEventW
#define SearchPath SearchPathW
#define SetComputerName SetComputerNameW
#define SetComputerNameEx SetComputerNameExW
#define SetCurrentDirectory SetCurrentDirectoryW
#define SetDefaultCommConfig SetDefaultCommConfigW
#if (_WIN32_WINNT >= 0x0502)
#define SetDllDirectory SetDllDirectoryW
#endif
#define SetEnvironmentVariable SetEnvironmentVariableW
#define SetFileAttributes SetFileAttributesW
#define SetFileSecurity SetFileSecurityW
#if (_WIN32_WINNT >= 0x0501)
#define SetFileShortName SetFileShortNameW
#endif
#if (_WIN32_WINNT >= 0x0502)
#define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableW
#endif
#define SetVolumeLabel SetVolumeLabelW
#define SetVolumeMountPoint SetVolumeMountPointW
#define UpdateResource UpdateResourceW
#define VerifyVersionInfo VerifyVersionInfoW
#define WaitNamedPipe WaitNamedPipeW
#define WritePrivateProfileSection WritePrivateProfileSectionW
#define WritePrivateProfileString WritePrivateProfileStringW
#define WritePrivateProfileStruct WritePrivateProfileStructW
#define WriteProfileSection WriteProfileSectionW
#define WriteProfileString WriteProfileStringW
#else
typedef STARTUPINFOA STARTUPINFO,*LPSTARTUPINFO;
typedef HW_PROFILE_INFOA HW_PROFILE_INFO,*LPHW_PROFILE_INFO;
#if (_WIN32_WINNT >= 0x0501)
typedef ACTCTXA ACTCTX,*PACTCTX;
typedef PCACTCTXA PCACTCTX;
#endif
typedef ENUMRESLANGPROCA ENUMRESLANGPROC;
typedef ENUMRESNAMEPROCA ENUMRESNAMEPROC;
typedef ENUMRESTYPEPROCA ENUMRESTYPEPROC;
#define AccessCheckAndAuditAlarm AccessCheckAndAuditAlarmA
#define AddAtom AddAtomA
#define BackupEventLog BackupEventLogA
#define BeginUpdateResource BeginUpdateResourceA
#define BuildCommDCB BuildCommDCBA
#define BuildCommDCBAndTimeouts BuildCommDCBAndTimeoutsA
#define CallNamedPipe CallNamedPipeA
#if (_WIN32_WINNT >= 0x0501)
#define CheckNameLegalDOS8Dot3 CheckNameLegalDOS8Dot3A
#endif
#define ClearEventLog ClearEventLogA
#define CommConfigDialog CommConfigDialogA
#define CopyFile CopyFileA
#define CopyFileEx CopyFileExA
#if (_WIN32_WINNT >= 0x0501)
#define CreateActCtx CreateActCtxA
#endif
#define CreateDirectory CreateDirectoryA
#define CreateDirectoryEx CreateDirectoryExA
#define CreateEvent CreateEventA
#define CreateFile CreateFileA
#define CreateFileMapping CreateFileMappingA
#if (_WIN32_WINNT >= 0x0500)
#define CreateHardLink CreateHardLinkA
#define CreateJobObject CreateJobObjectA
#endif
#define CreateMailslot CreateMailslotA
#define CreateMutex CreateMutexA
#define CreateNamedPipe CreateNamedPipeA
#define CreateProcess CreateProcessA
#define CreateProcessAsUser CreateProcessAsUserA
#define CreateSemaphore CreateSemaphoreA
#define CreateWaitableTimer CreateWaitableTimerA
#define DecryptFile DecryptFileA
#define DefineDosDevice DefineDosDeviceA
#define DeleteFile DeleteFileA
#if (_WIN32_WINNT >= 0x0500)
#define DeleteVolumeMountPoint DeleteVolumeMountPointA
#define DnsHostnameToComputerName DnsHostnameToComputerNameA
#endif
#define EncryptFile EncryptFileA
#define EndUpdateResource EndUpdateResourceA
#define EnumResourceLanguages EnumResourceLanguagesA
#define EnumResourceNames EnumResourceNamesA
#define EnumResourceTypes EnumResourceTypesA
#define ExpandEnvironmentStrings ExpandEnvironmentStringsA
#define FatalAppExit FatalAppExitA
#define FileEncryptionStatus FileEncryptionStatusA
#if (_WIN32_WINNT >= 0x0501)
#define FindActCtxSectionString FindActCtxSectionStringA
#endif
#define FindAtom FindAtomA
#define FindFirstChangeNotification FindFirstChangeNotificationA
#define FindFirstFile FindFirstFileA
#define FindFirstFileEx FindFirstFileExA
#if (_WIN32_WINNT >= 0x0500)
#define FindFirstVolume FindFirstVolumeA
#define FindFirstVolumeMountPoint FindFirstVolumeMountPointA
#endif
#define FindNextFile FindNextFileA
#if (_WIN32_WINNT >= 0x0500)
#define FindNextVolume FindNextVolumeA
#define FindNextVolumeMountPoint FindNextVolumeMountPointA
#endif
#define FindResource FindResourceA
#define FindResourceEx FindResourceExA
#define FormatMessage FormatMessageA
#define FreeEnvironmentStrings FreeEnvironmentStringsA
#define GetAtomName GetAtomNameA
#define GetBinaryType GetBinaryTypeA
#define GetCommandLine GetCommandLineA
#define GetComputerName GetComputerNameA
#if (_WIN32_WINNT >= 0x0500)
#define GetComputerNameEx GetComputerNameExA
#endif
#define GetCompressedFileSize GetCompressedFileSizeA
#define GetCurrentDirectory GetCurrentDirectoryA
#define GetDefaultCommConfig GetDefaultCommConfigA
#define GetDiskFreeSpace GetDiskFreeSpaceA
#define GetDiskFreeSpaceEx GetDiskFreeSpaceExA
#if (_WIN32_WINNT >= 0x0502)
#define GetDllDirectory GetDllDirectoryA
#endif
#define GetDriveType GetDriveTypeA
#define GetEnvironmentStringsA GetEnvironmentStrings
#define GetEnvironmentVariable GetEnvironmentVariableA
#define GetFileAttributes GetFileAttributesA
#define GetFileAttributesEx GetFileAttributesExA
#define GetFileSecurity GetFileSecurityA
#if (_WIN32_WINNT >= 0x0600)
#define GetFinalPathNameByHandle GetFinalPathNameByHandleA
#endif
#define GetFullPathName GetFullPathNameA
#define GetLogicalDriveStrings GetLogicalDriveStringsA
#if (_WIN32_WINNT >= 0x0500 || _WIN32_WINDOWS >= 0x0410)
#define GetLongPathName GetLongPathNameA
#endif
#define GetNamedPipeHandleState GetNamedPipeHandleStateA
#define GetModuleHandle GetModuleHandleA
#if (_WIN32_WINNT >= 0x0500)
#define GetModuleHandleEx GetModuleHandleExA
#endif
#define GetModuleFileName GetModuleFileNameA
#define GetPrivateProfileInt GetPrivateProfileIntA
#define GetPrivateProfileSection GetPrivateProfileSectionA
#define GetPrivateProfileSectionNames GetPrivateProfileSectionNamesA
#define GetPrivateProfileString GetPrivateProfileStringA
#define GetPrivateProfileStruct GetPrivateProfileStructA
#define GetProfileInt GetProfileIntA
#define GetProfileSection GetProfileSectionA
#define GetProfileString GetProfileStringA
#define GetShortPathName GetShortPathNameA
#define GetStartupInfo GetStartupInfoA
#define GetSystemDirectory GetSystemDirectoryA
#if (_WIN32_WINNT >= 0x0500)
#define GetSystemWindowsDirectory GetSystemWindowsDirectoryA
#endif
#if (_WIN32_WINNT >= 0x0501)
#define GetSystemWow64Directory GetSystemWow64DirectoryA
#endif
#define GetTempFileName GetTempFileNameA
#define GetTempPath GetTempPathA
#define GetUserName GetUserNameA
#define GetVersionEx GetVersionExA
#define GetVolumeInformation GetVolumeInformationA
#define GetVolumeNameForVolumeMountPoint GetVolumeNameForVolumeMountPointA
#define GetVolumePathName GetVolumePathNameA
#define GetVolumePathNamesForVolumeName GetVolumePathNamesForVolumeNameA
#define GetWindowsDirectory GetWindowsDirectoryA
#define GlobalAddAtom GlobalAddAtomA
#define GlobalFindAtom GlobalFindAtomA
#define GlobalGetAtomName GlobalGetAtomNameA
#define IsBadStringPtr IsBadStringPtrA
#define LoadLibrary LoadLibraryA
#define LoadLibraryEx LoadLibraryExA
#define LogonUser LogonUserA
#define LogonUserEx LogonUserExA
#define LookupAccountName LookupAccountNameA
#define LookupAccountSid LookupAccountSidA
#define LookupPrivilegeDisplayName LookupPrivilegeDisplayNameA
#define LookupPrivilegeName LookupPrivilegeNameA
#define LookupPrivilegeValue LookupPrivilegeValueA
#define lstrcat lstrcatA
#define lstrcmp lstrcmpA
#define lstrcmpi lstrcmpiA
#define lstrcpy lstrcpyA
#define lstrcpyn lstrcpynA
#define lstrlen lstrlenA
#define MoveFile MoveFileA
#define MoveFileEx MoveFileExA
#define MoveFileWithProgress MoveFileWithProgressA
#define ObjectCloseAuditAlarm ObjectCloseAuditAlarmA
#define ObjectDeleteAuditAlarm ObjectDeleteAuditAlarmA
#define ObjectOpenAuditAlarm ObjectOpenAuditAlarmA
#define ObjectPrivilegeAuditAlarm ObjectPrivilegeAuditAlarmA
#define OpenBackupEventLog OpenBackupEventLogA
#define OpenEvent OpenEventA
#define OpenEventLog OpenEventLogA
#define OpenFileMapping OpenFileMappingA
#define OpenMutex OpenMutexA
#define OpenSemaphore OpenSemaphoreA
#define OutputDebugString OutputDebugStringA
#define PrivilegedServiceAuditAlarm PrivilegedServiceAuditAlarmA
#define QueryDosDevice QueryDosDeviceA
#define ReadEventLog ReadEventLogA
#define RegisterEventSource RegisterEventSourceA
#define RemoveDirectory RemoveDirectoryA
#if (_WIN32_WINNT >= 0x0500)
#define ReplaceFile ReplaceFileA
#endif
#define ReportEvent ReportEventA
#define SearchPath SearchPathA
#define SetComputerName SetComputerNameA
#define SetComputerNameEx SetComputerNameExA
#define SetCurrentDirectory SetCurrentDirectoryA
#define SetDefaultCommConfig SetDefaultCommConfigA
#if (_WIN32_WINNT >= 0x0502)
#define SetDllDirectory SetDllDirectoryA
#endif
#define SetEnvironmentVariable SetEnvironmentVariableA
#define SetFileAttributes SetFileAttributesA
#define SetFileSecurity SetFileSecurityA
#if (_WIN32_WINNT >= 0x0501)
#define SetFileShortName SetFileShortNameA
#endif
#if (_WIN32_WINNT >= 0x0502)
#define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableA
#endif
#define SetVolumeLabel SetVolumeLabelA
#define SetVolumeMountPoint SetVolumeMountPointA
#define UpdateResource UpdateResourceA
#define VerifyVersionInfo VerifyVersionInfoA
#define WaitNamedPipe WaitNamedPipeA
#define WritePrivateProfileSection WritePrivateProfileSectionA
#define WritePrivateProfileString WritePrivateProfileStringA
#define WritePrivateProfileStruct WritePrivateProfileStructA
#define WriteProfileSection WriteProfileSectionA
#define WriteProfileString WriteProfileStringA
#endif
#endif

/* one-time initialisation API */
typedef RTL_RUN_ONCE INIT_ONCE;
typedef PRTL_RUN_ONCE PINIT_ONCE;
typedef PRTL_RUN_ONCE LPINIT_ONCE;

#define INIT_ONCE_CHECK_ONLY RTL_RUN_ONCE_CHECK_ONLY
#define INIT_ONCE_ASYNC RTL_RUN_ONCE_ASYNC
#define INIT_ONCE_INIT_FAILED RTL_RUN_ONCE_INIT_FAILED

#define INIT_ONCE_CTX_RESERVED_BITS RTL_RUN_ONCE_CTX_RESERVED_BITS

typedef BOOL
(WINAPI *PINIT_ONCE_FN)(
  _Inout_ PINIT_ONCE InitOnce,
  _Inout_opt_ PVOID Parameter,
  _Outptr_opt_result_maybenull_ PVOID *Context);

#if _WIN32_WINNT >= 0x0601

#define COPYFILE2_MESSAGE_COPY_OFFLOAD 0x00000001L

typedef enum _COPYFILE2_MESSAGE_TYPE {
  COPYFILE2_CALLBACK_NONE = 0,
  COPYFILE2_CALLBACK_CHUNK_STARTED,
  COPYFILE2_CALLBACK_CHUNK_FINISHED,
  COPYFILE2_CALLBACK_STREAM_STARTED,
  COPYFILE2_CALLBACK_STREAM_FINISHED,
  COPYFILE2_CALLBACK_POLL_CONTINUE,
  COPYFILE2_CALLBACK_ERROR,
  COPYFILE2_CALLBACK_MAX,
} COPYFILE2_MESSAGE_TYPE;

typedef enum _COPYFILE2_MESSAGE_ACTION {
  COPYFILE2_PROGRESS_CONTINUE = 0,
  COPYFILE2_PROGRESS_CANCEL,
  COPYFILE2_PROGRESS_STOP,
  COPYFILE2_PROGRESS_QUIET,
  COPYFILE2_PROGRESS_PAUSE,
} COPYFILE2_MESSAGE_ACTION;

typedef enum _COPYFILE2_COPY_PHASE {
  COPYFILE2_PHASE_NONE = 0,
  COPYFILE2_PHASE_PREPARE_SOURCE,
  COPYFILE2_PHASE_PREPARE_DEST,
  COPYFILE2_PHASE_READ_SOURCE,
  COPYFILE2_PHASE_WRITE_DESTINATION,
  COPYFILE2_PHASE_SERVER_COPY,
  COPYFILE2_PHASE_NAMEGRAFT_COPY,
  COPYFILE2_PHASE_MAX,
} COPYFILE2_COPY_PHASE;

typedef struct COPYFILE2_MESSAGE {
  COPYFILE2_MESSAGE_TYPE Type;
  DWORD dwPadding;
  union {
    struct {
      DWORD dwStreamNumber;
      DWORD dwReserved;
      HANDLE hSourceFile;
      HANDLE hDestinationFile;
      ULARGE_INTEGER uliChunkNumber;
      ULARGE_INTEGER uliChunkSize;
      ULARGE_INTEGER uliStreamSize;
      ULARGE_INTEGER uliTotalFileSize;
    } ChunkStarted;
    struct {
      DWORD dwStreamNumber;
      DWORD dwFlags;
      HANDLE hSourceFile;
      HANDLE hDestinationFile;
      ULARGE_INTEGER uliChunkNumber;
      ULARGE_INTEGER uliChunkSize;
      ULARGE_INTEGER uliStreamSize;
      ULARGE_INTEGER uliStreamBytesTransferred;
      ULARGE_INTEGER uliTotalFileSize;
      ULARGE_INTEGER uliTotalBytesTransferred;
    } ChunkFinished;
    struct {
      DWORD dwStreamNumber;
      DWORD dwReserved;
      HANDLE hSourceFile;
      HANDLE hDestinationFile;
      ULARGE_INTEGER uliStreamSize;
      ULARGE_INTEGER uliTotalFileSize;
    } StreamStarted;
    struct {
      DWORD dwStreamNumber;
      DWORD dwReserved;
      HANDLE hSourceFile;
      HANDLE hDestinationFile;
      ULARGE_INTEGER uliStreamSize;
      ULARGE_INTEGER uliStreamBytesTransferred;
      ULARGE_INTEGER uliTotalFileSize;
      ULARGE_INTEGER uliTotalBytesTransferred;
    } StreamFinished;
    struct {
      DWORD dwReserved;
    } PollContinue;
    struct {
      COPYFILE2_COPY_PHASE CopyPhase;
      DWORD dwStreamNumber;
      HRESULT hrFailure;
      DWORD dwReserved;
      ULARGE_INTEGER uliChunkNumber;
      ULARGE_INTEGER uliStreamSize;
      ULARGE_INTEGER uliStreamBytesTransferred;
      ULARGE_INTEGER uliTotalFileSize;
      ULARGE_INTEGER uliTotalBytesTransferred;
    } Error;
  } Info;
} COPYFILE2_MESSAGE;

typedef COPYFILE2_MESSAGE_ACTION
(CALLBACK *PCOPYFILE2_PROGRESS_ROUTINE)(
  _In_ const COPYFILE2_MESSAGE *pMessage,
  _In_opt_ PVOID pvCallbackContext);

typedef struct COPYFILE2_EXTENDED_PARAMETERS {
  DWORD dwSize;
  DWORD dwCopyFlags;
  BOOL *pfCancel;
  PCOPYFILE2_PROGRESS_ROUTINE pProgressRoutine;
  PVOID pvCallbackContext;
} COPYFILE2_EXTENDED_PARAMETERS;

WINBASEAPI
HRESULT
WINAPI
CopyFile2(
  _In_ PCWSTR pwszExistingFileName,
  _In_ PCWSTR pwszNewFileName,
  _In_opt_ COPYFILE2_EXTENDED_PARAMETERS *pExtendedParameters);

#endif /* _WIN32_WINNT >= 0x0601 */

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA) || (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA)

WINBASEAPI
VOID
WINAPI
InitOnceInitialize(
    _Out_ PINIT_ONCE InitOnce);

WINBASEAPI
BOOL
WINAPI
InitOnceBeginInitialize(
    _Inout_ LPINIT_ONCE lpInitOnce,
    _In_ DWORD dwFlags,
    _Out_ PBOOL fPending,
    _Outptr_opt_result_maybenull_ LPVOID *lpContext);

WINBASEAPI
BOOL
WINAPI
InitOnceComplete(
    _Inout_ LPINIT_ONCE lpInitOnce,
    _In_ DWORD dwFlags,
    _In_opt_ LPVOID lpContext);

#endif /* (_WIN32_WINNT >= _WIN32_WINNT_VISTA) || (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA) */

WINBASEAPI
BOOL
WINAPI
InitOnceExecuteOnce(
    _Inout_ PINIT_ONCE InitOnce,
    _In_ __callback PINIT_ONCE_FN InitFn,
    _Inout_opt_ PVOID Parameter,
    _Outptr_opt_result_maybenull_ LPVOID *Context);

typedef VOID (NTAPI *PTP_WIN32_IO_CALLBACK)(PTP_CALLBACK_INSTANCE,PVOID,PVOID,ULONG,ULONG_PTR,PTP_IO);

#if defined(_SLIST_HEADER_) && !defined(_NTOS_) && !defined(_NTOSP_)

WINBASEAPI
VOID
WINAPI
InitializeSListHead(
  _Out_ PSLIST_HEADER ListHead);

WINBASEAPI
PSLIST_ENTRY
WINAPI
InterlockedPopEntrySList(
  _Inout_ PSLIST_HEADER ListHead);

WINBASEAPI
PSLIST_ENTRY
WINAPI
InterlockedPushEntrySList(
  _Inout_ PSLIST_HEADER ListHead,
  _Inout_ PSLIST_ENTRY ListEntry);

WINBASEAPI
PSLIST_ENTRY
WINAPI
InterlockedFlushSList(
  _Inout_ PSLIST_HEADER ListHead);

WINBASEAPI
USHORT
WINAPI
QueryDepthSList(
  _In_ PSLIST_HEADER ListHead);

#endif /* _SLIST_HEADER_ */

#ifdef __WINESRC__
/* Wine specific. Basically MultiByteToWideChar for us. */
WCHAR * CDECL wine_get_dos_file_name(LPCSTR str);
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#ifdef __cplusplus
}
#endif

#include <synchapi.h>
#include <processthreadsapi.h>

#endif /* _WINBASE_ */
