# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   SYSTEM Errors from [MS-ERREF]. Ideally all the files
#   should grab the error codes from here 
#

ERROR_MESSAGES = {
        0x00000000: ("ERROR_SUCCESS", "The operation completed successfully."),
        0x00000001: ("ERROR_INVALID_FUNCTION", "Incorrect function."),
        0x00000002: ("ERROR_FILE_NOT_FOUND", "The system cannot find the file specified."),
        0x00000003: ("ERROR_PATH_NOT_FOUND", "The system cannot find the path specified."),
        0x00000004: ("ERROR_TOO_MANY_OPEN_FILES", "The system cannot open the file."),
        0x00000005: ("ERROR_ACCESS_DENIED", "Access is denied."),
        0x00000006: ("ERROR_INVALID_HANDLE", "The handle is invalid."),
        0x00000007: ("ERROR_ARENA_TRASHED", "The storage control blocks were destroyed."),
        0x00000008: ("ERROR_NOT_ENOUGH_MEMORY", "Not enough storage is available to process this command."),
        0x00000009: ("ERROR_INVALID_BLOCK", "The storage control block address is invalid."),
        0x0000000a: ("ERROR_BAD_ENVIRONMENT", "The environment is incorrect."),
        0x0000000b: ("ERROR_BAD_FORMAT", "An attempt was made to load a program with an incorrect format."),
        0x0000000c: ("ERROR_INVALID_ACCESS", "The access code is invalid."),
        0x0000000d: ("ERROR_INVALID_DATA", "The data is invalid."),
        0x0000000e: ("ERROR_OUTOFMEMORY", "Not enough storage is available to complete this operation."),
        0x0000000f: ("ERROR_INVALID_DRIVE", "The system cannot find the drive specified."),
        0x00000010: ("ERROR_CURRENT_DIRECTORY", "The directory cannot be removed."),
        0x00000011: ("ERROR_NOT_SAME_DEVICE", "The system cannot move the file to a different disk drive."),
        0x00000012: ("ERROR_NO_MORE_FILES", "There are no more files."),
        0x00000013: ("ERROR_WRITE_PROTECT", "The media is write protected."),
        0x00000014: ("ERROR_BAD_UNIT", "The system cannot find the device specified."),
        0x00000015: ("ERROR_NOT_READY", "The device is not ready."),
        0x00000016: ("ERROR_BAD_COMMAND", "The device does not recognize the command."),
        0x00000017: ("ERROR_CRC", "Data error (cyclic redundancy check)."),
        0x00000018: ("ERROR_BAD_LENGTH", "The program issued a command but the command length is incorrect."),
        0x00000019: ("ERROR_SEEK", "The drive cannot locate a specific area or track on the disk."),
        0x0000001a: ("ERROR_NOT_DOS_DISK", "The specified disk or diskette cannot be accessed."),
        0x0000001b: ("ERROR_SECTOR_NOT_FOUND", "The drive cannot find the sector requested."),
        0x0000001c: ("ERROR_OUT_OF_PAPER", "The printer is out of paper."),
        0x0000001d: ("ERROR_WRITE_FAULT", "The system cannot write to the specified device."),
        0x0000001e: ("ERROR_READ_FAULT", "The system cannot read from the specified device."),
        0x0000001f: ("ERROR_GEN_FAILURE", "A device attached to the system is not functioning."),
        0x00000020: ("ERROR_SHARING_VIOLATION", "The process cannot access the file because it is being used by another process."),
        0x00000021: ("ERROR_LOCK_VIOLATION", "The process cannot access the file because another process has locked a portion of the file."),
        0x00000022: ("ERROR_WRONG_DISK", "The wrong diskette is in the drive."),
        0x00000024: ("ERROR_SHARING_BUFFER_EXCEEDED", "Too many files opened for sharing."),
        0x00000026: ("ERROR_HANDLE_EOF", "Reached the end of the file."),
        0x00000027: ("ERROR_HANDLE_DISK_FULL", "The disk is full."),
        0x00000032: ("ERROR_NOT_SUPPORTED", "The request is not supported."),
        0x00000033: ("ERROR_REM_NOT_LIST", "Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator."),
        0x00000034: ("ERROR_DUP_NAME", "You were not connected because a duplicate name exists on the network. If joining a domain, go to System in Control Panel to change the computer name and try again. If joining a workgroup, choose another workgroup name."),
        0x00000035: ("ERROR_BAD_NETPATH", "The network path was not found."),
        0x00000036: ("ERROR_NETWORK_BUSY", "The network is busy."),
        0x00000037: ("ERROR_DEV_NOT_EXIST", "The specified network resource or device is no longer available."),
        0x00000038: ("ERROR_TOO_MANY_CMDS", "The network BIOS command limit has been reached."),
        0x00000039: ("ERROR_ADAP_HDW_ERR", "A network adapter hardware error occurred."),
        0x0000003a: ("ERROR_BAD_NET_RESP", "The specified server cannot perform the requested operation."),
        0x0000003b: ("ERROR_UNEXP_NET_ERR", "An unexpected network error occurred."),
        0x0000003c: ("ERROR_BAD_REM_ADAP", "The remote adapter is not compatible."),
        0x0000003d: ("ERROR_PRINTQ_FULL", "The printer queue is full."),
        0x0000003e: ("ERROR_NO_SPOOL_SPACE", "Space to store the file waiting to be printed is not available on the server."),
        0x0000003f: ("ERROR_PRINT_CANCELLED", "Your file waiting to be printed was deleted."),
        0x00000040: ("ERROR_NETNAME_DELETED", "The specified network name is no longer available."),
        0x00000041: ("ERROR_NETWORK_ACCESS_DENIED", "Network access is denied."),
        0x00000042: ("ERROR_BAD_DEV_TYPE", "The network resource type is not correct."),
        0x00000043: ("ERROR_BAD_NET_NAME", "The network name cannot be found."),
        0x00000044: ("ERROR_TOO_MANY_NAMES", "The name limit for the local computer network adapter card was exceeded."),
        0x00000045: ("ERROR_TOO_MANY_SESS", "The network BIOS session limit was exceeded."),
        0x00000046: ("ERROR_SHARING_PAUSED", "The remote server has been paused or is in the process of being started."),
        0x00000047: ("ERROR_REQ_NOT_ACCEP", "No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept."),
        0x00000048: ("ERROR_REDIR_PAUSED", "The specified printer or disk device has been paused."),
        0x00000050: ("ERROR_FILE_EXISTS", "The file exists."),
        0x00000052: ("ERROR_CANNOT_MAKE", "The directory or file cannot be created."),
        0x00000053: ("ERROR_FAIL_I24", "Fail on INT 24."),
        0x00000054: ("ERROR_OUT_OF_STRUCTURES", "Storage to process this request is not available."),
        0x00000055: ("ERROR_ALREADY_ASSIGNED", "The local device name is already in use."),
        0x00000056: ("ERROR_INVALID_PASSWORD", "The specified network password is not correct."),
        0x00000057: ("ERROR_INVALID_PARAMETER", "The parameter is incorrect."),
        0x00000058: ("ERROR_NET_WRITE_FAULT", "A write fault occurred on the network."),
        0x00000059: ("ERROR_NO_PROC_SLOTS", "The system cannot start another process at this time."),
        0x00000064: ("ERROR_TOO_MANY_SEMAPHORES", "Cannot create another system semaphore."),
        0x00000065: ("ERROR_EXCL_SEM_ALREADY_OWNED", "The exclusive semaphore is owned by another process."),
        0x00000066: ("ERROR_SEM_IS_SET", "The semaphore is set and cannot be closed."),
        0x00000067: ("ERROR_TOO_MANY_SEM_REQUESTS", "The semaphore cannot be set again."),
        0x00000068: ("ERROR_INVALID_AT_INTERRUPT_TIME", "Cannot request exclusive semaphores at interrupt time."),
        0x00000069: ("ERROR_SEM_OWNER_DIED", "The previous ownership of this semaphore has ended."),
        0x0000006a: ("ERROR_SEM_USER_LIMIT", "Insert the diskette for drive %1."),
        0x0000006b: ("ERROR_DISK_CHANGE", "The program stopped because an alternate diskette was not inserted."),
        0x0000006c: ("ERROR_DRIVE_LOCKED", "The disk is in use or locked by another process."),
        0x0000006d: ("ERROR_BROKEN_PIPE", "The pipe has been ended."),
        0x0000006e: ("ERROR_OPEN_FAILED", "The system cannot open the device or file specified."),
        0x0000006f: ("ERROR_BUFFER_OVERFLOW", "The file name is too long."),
        0x00000070: ("ERROR_DISK_FULL", "There is not enough space on the disk."),
        0x00000071: ("ERROR_NO_MORE_SEARCH_HANDLES", "No more internal file identifiers available."),
        0x00000072: ("ERROR_INVALID_TARGET_HANDLE", "The target internal file identifier is incorrect."),
        0x00000075: ("ERROR_INVALID_CATEGORY", "The IOCTL call made by the application program is not correct."),
        0x00000076: ("ERROR_INVALID_VERIFY_SWITCH", "The verify-on-write switch parameter value is not correct."),
        0x00000077: ("ERROR_BAD_DRIVER_LEVEL", "The system does not support the command requested."),
        0x00000078: ("ERROR_CALL_NOT_IMPLEMENTED", "This function is not supported on this system."),
        0x00000079: ("ERROR_SEM_TIMEOUT", "The semaphore timeout period has expired."),
        0x0000007a: ("ERROR_INSUFFICIENT_BUFFER", "The data area passed to a system call is too small."),
        0x0000007b: ("ERROR_INVALID_NAME", "The filename, directory name, or volume label syntax is incorrect."),
        0x0000007c: ("ERROR_INVALID_LEVEL", "The system call level is not correct."),
        0x0000007d: ("ERROR_NO_VOLUME_LABEL", "The disk has no volume label."),
        0x0000007e: ("ERROR_MOD_NOT_FOUND", "The specified module could not be found."),
        0x0000007f: ("ERROR_PROC_NOT_FOUND", "The specified procedure could not be found."),
        0x00000080: ("ERROR_WAIT_NO_CHILDREN", "There are no child processes to wait for."),
        0x00000081: ("ERROR_CHILD_NOT_COMPLETE", "The %1 application cannot be run in Win32 mode."),
        0x00000082: ("ERROR_DIRECT_ACCESS_HANDLE", "Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O."),
        0x00000083: ("ERROR_NEGATIVE_SEEK", "An attempt was made to move the file pointer before the beginning of the file."),
        0x00000084: ("ERROR_SEEK_ON_DEVICE", "The file pointer cannot be set on the specified device or file."),
        0x00000085: ("ERROR_IS_JOIN_TARGET", "A JOIN or SUBST command cannot be used for a drive that contains previously joined drives."),
        0x00000086: ("ERROR_IS_JOINED", "An attempt was made to use a JOIN or SUBST command on a drive that has already been joined."),
        0x00000087: ("ERROR_IS_SUBSTED", "An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted."),
        0x00000088: ("ERROR_NOT_JOINED", "The system tried to delete the JOIN of a drive that is not joined."),
        0x00000089: ("ERROR_NOT_SUBSTED", "The system tried to delete the substitution of a drive that is not substituted."),
        0x0000008a: ("ERROR_JOIN_TO_JOIN", "The system tried to join a drive to a directory on a joined drive."),
        0x0000008b: ("ERROR_SUBST_TO_SUBST", "The system tried to substitute a drive to a directory on a substituted drive."),
        0x0000008c: ("ERROR_JOIN_TO_SUBST", "The system tried to join a drive to a directory on a substituted drive."),
        0x0000008d: ("ERROR_SUBST_TO_JOIN", "The system tried to SUBST a drive to a directory on a joined drive."),
        0x0000008e: ("ERROR_BUSY_DRIVE", "The system cannot perform a JOIN or SUBST at this time."),
        0x0000008f: ("ERROR_SAME_DRIVE", "The system cannot join or substitute a drive to or for a directory on the same drive."),
        0x00000090: ("ERROR_DIR_NOT_ROOT", "The directory is not a subdirectory of the root directory."),
        0x00000091: ("ERROR_DIR_NOT_EMPTY", "The directory is not empty."),
        0x00000092: ("ERROR_IS_SUBST_PATH", "The path specified is being used in a substitute."),
        0x00000093: ("ERROR_IS_JOIN_PATH", "Not enough resources are available to process this command."),
        0x00000094: ("ERROR_PATH_BUSY", "The path specified cannot be used at this time."),
        0x00000095: ("ERROR_IS_SUBST_TARGET", "An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute."),
        0x00000096: ("ERROR_SYSTEM_TRACE", "System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed."),
        0x00000097: ("ERROR_INVALID_EVENT_COUNT", "The number of specified semaphore events for DosMuxSemWait is not correct."),
        0x00000098: ("ERROR_TOO_MANY_MUXWAITERS", "DosMuxSemWait did not execute; too many semaphores are already set."),
        0x00000099: ("ERROR_INVALID_LIST_FORMAT", "The DosMuxSemWait list is not correct."),
        0x0000009a: ("ERROR_LABEL_TOO_LONG", "The volume label you entered exceeds the label character limit of the target file system."),
        0x0000009b: ("ERROR_TOO_MANY_TCBS", "Cannot create another thread."),
        0x0000009c: ("ERROR_SIGNAL_REFUSED", "The recipient process has refused the signal."),
        0x0000009d: ("ERROR_DISCARDED", "The segment is already discarded and cannot be locked."),
        0x0000009e: ("ERROR_NOT_LOCKED", "The segment is already unlocked."),
        0x0000009f: ("ERROR_BAD_THREADID_ADDR", "The address for the thread ID is not correct."),
        0x000000a0: ("ERROR_BAD_ARGUMENTS", "One or more arguments are not correct."),
        0x000000a1: ("ERROR_BAD_PATHNAME", "The specified path is invalid."),
        0x000000a2: ("ERROR_SIGNAL_PENDING", "A signal is already pending."),
        0x000000a4: ("ERROR_MAX_THRDS_REACHED", "No more threads can be created in the system."),
        0x000000a7: ("ERROR_LOCK_FAILED", "Unable to lock a region of a file."),
        0x000000aa: ("ERROR_BUSY", "The requested resource is in use."),
        0x000000ab: ("ERROR_DEVICE_SUPPORT_IN_PROGRESS", "Device's command support detection is in progress."),
        0x000000ad: ("ERROR_CANCEL_VIOLATION", "A lock request was not outstanding for the supplied cancel region."),
        0x000000ae: ("ERROR_ATOMIC_LOCKS_NOT_SUPPORTED", "The file system does not support atomic changes to the lock type."),
        0x000000b4: ("ERROR_INVALID_SEGMENT_NUMBER", "The system detected a segment number that was not correct."),
        0x000000b6: ("ERROR_INVALID_ORDINAL", "The operating system cannot run %1."),
        0x000000b7: ("ERROR_ALREADY_EXISTS", "Cannot create a file when that file already exists."),
        0x000000ba: ("ERROR_INVALID_FLAG_NUMBER", "The flag passed is not correct."),
        0x000000bb: ("ERROR_SEM_NOT_FOUND", "The specified system semaphore name was not found."),
        0x000000bc: ("ERROR_INVALID_STARTING_CODESEG", "The operating system cannot run %1."),
        0x000000bd: ("ERROR_INVALID_STACKSEG", "The operating system cannot run %1."),
        0x000000be: ("ERROR_INVALID_MODULETYPE", "The operating system cannot run %1."),
        0x000000bf: ("ERROR_INVALID_EXE_SIGNATURE", "Cannot run %1 in Win32 mode."),
        0x000000c0: ("ERROR_EXE_MARKED_INVALID", "The operating system cannot run %1."),
        0x000000c1: ("ERROR_BAD_EXE_FORMAT", "%1 is not a valid Win32 application."),
        0x000000c2: ("ERROR_ITERATED_DATA_EXCEEDS_64k", "The operating system cannot run %1."),
        0x000000c3: ("ERROR_INVALID_MINALLOCSIZE", "The operating system cannot run %1."),
        0x000000c4: ("ERROR_DYNLINK_FROM_INVALID_RING", "The operating system cannot run this application program."),
        0x000000c5: ("ERROR_IOPL_NOT_ENABLED", "The operating system is not presently configured to run this application."),
        0x000000c6: ("ERROR_INVALID_SEGDPL", "The operating system cannot run %1."),
        0x000000c7: ("ERROR_AUTODATASEG_EXCEEDS_64k", "The operating system cannot run this application program."),
        0x000000c8: ("ERROR_RING2SEG_MUST_BE_MOVABLE", "The code segment cannot be greater than or equal to 64K."),
        0x000000c9: ("ERROR_RELOC_CHAIN_XEEDS_SEGLIM", "The operating system cannot run %1."),
        0x000000ca: ("ERROR_INFLOOP_IN_RELOC_CHAIN", "The operating system cannot run %1."),
        0x000000cb: ("ERROR_ENVVAR_NOT_FOUND", "The system could not find the environment option that was entered."),
        0x000000cd: ("ERROR_NO_SIGNAL_SENT", "No process in the command subtree has a signal handler."),
        0x000000ce: ("ERROR_FILENAME_EXCED_RANGE", "The filename or extension is too long."),
        0x000000cf: ("ERROR_RING2_STACK_IN_USE", "The ring 2 stack is in use."),
        0x000000d0: ("ERROR_META_EXPANSION_TOO_LONG", "The global filename characters, * or ?, are entered incorrectly or too many global filename characters are specified."),
        0x000000d1: ("ERROR_INVALID_SIGNAL_NUMBER", "The signal being posted is not correct."),
        0x000000d2: ("ERROR_THREAD_1_INACTIVE", "The signal handler cannot be set."),
        0x000000d4: ("ERROR_LOCKED", "The segment is locked and cannot be reallocated."),
        0x000000d6: ("ERROR_TOO_MANY_MODULES", "Too many dynamic-link modules are attached to this program or dynamic-link module."),
        0x000000d7: ("ERROR_NESTING_NOT_ALLOWED", "Cannot nest calls to LoadModule."),
        0x000000d8: ("ERROR_EXE_MACHINE_TYPE_MISMATCH", "This version of %1 is not compatible with the version of Windows you're running. Check your computer's system information and then contact the software publisher."),
        0x000000d9: ("ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY", "The image file %1 is signed, unable to modify."),
        0x000000da: ("ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY", "The image file %1 is strong signed, unable to modify."),
        0x000000dc: ("ERROR_FILE_CHECKED_OUT", "This file is checked out or locked for editing by another user."),
        0x000000dd: ("ERROR_CHECKOUT_REQUIRED", "The file must be checked out before saving changes."),
        0x000000de: ("ERROR_BAD_FILE_TYPE", "The file type being saved or retrieved has been blocked."),
        0x000000df: ("ERROR_FILE_TOO_LARGE", "The file size exceeds the limit allowed and cannot be saved."),
        0x000000e0: ("ERROR_FORMS_AUTH_REQUIRED", "Access Denied. Before opening files in this location, you must first add the web site to your trusted sites list, browse to the web site, and select the option to login automatically."),
        0x000000e1: ("ERROR_VIRUS_INFECTED", "Operation did not complete successfully because the file contains a virus or potentially unwanted software."),
        0x000000e2: ("ERROR_VIRUS_DELETED", "This file contains a virus or potentially unwanted software and cannot be opened. Due to the nature of this virus or potentially unwanted software, the file has been removed from this location."),
        0x000000e5: ("ERROR_PIPE_LOCAL", "The pipe is local."),
        0x000000e6: ("ERROR_BAD_PIPE", "The pipe state is invalid."),
        0x000000e7: ("ERROR_PIPE_BUSY", "All pipe instances are busy."),
        0x000000e8: ("ERROR_NO_DATA", "The pipe is being closed."),
        0x000000e9: ("ERROR_PIPE_NOT_CONNECTED", "No process is on the other end of the pipe."),
        0x000000ea: ("ERROR_MORE_DATA", "More data is available."),
        0x000000f0: ("ERROR_VC_DISCONNECTED", "The session was canceled."),
        0x000000fe: ("ERROR_INVALID_EA_NAME", "The specified extended attribute name was invalid."),
        0x000000ff: ("ERROR_EA_LIST_INCONSISTENT", "The extended attributes are inconsistent."),
        0x00000102: ("WAIT_TIMEOUT", "The wait operation timed out."),
        0x00000103: ("ERROR_NO_MORE_ITEMS", "No more data is available."),
        0x0000010a: ("ERROR_CANNOT_COPY", "The copy functions cannot be used."),
        0x0000010b: ("ERROR_DIRECTORY", "The directory name is invalid."),
        0x00000113: ("ERROR_EAS_DIDNT_FIT", "The extended attributes did not fit in the buffer."),
        0x00000114: ("ERROR_EA_FILE_CORRUPT", "The extended attribute file on the mounted file system is corrupt."),
        0x00000115: ("ERROR_EA_TABLE_FULL", "The extended attribute table file is full."),
        0x00000116: ("ERROR_INVALID_EA_HANDLE", "The specified extended attribute handle is invalid."),
        0x0000011a: ("ERROR_EAS_NOT_SUPPORTED", "The mounted file system does not support extended attributes."),
        0x00000120: ("ERROR_NOT_OWNER", "Attempt to release mutex not owned by caller."),
        0x0000012a: ("ERROR_TOO_MANY_POSTS", "Too many posts were made to a semaphore."),
        0x0000012b: ("ERROR_PARTIAL_COPY", "Only part of a ReadProcessMemory or WriteProcessMemory request was completed."),
        0x0000012c: ("ERROR_OPLOCK_NOT_GRANTED", "The oplock request is denied."),
        0x0000012d: ("ERROR_INVALID_OPLOCK_PROTOCOL", "An invalid oplock acknowledgment was received by the system."),
        0x0000012e: ("ERROR_DISK_TOO_FRAGMENTED", "The volume is too fragmented to complete this operation."),
        0x0000012f: ("ERROR_DELETE_PENDING", "The file cannot be opened because it is in the process of being deleted."),
        0x00000130: ("ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING", "Short name settings may not be changed on this volume due to the global registry setting."),
        0x00000131: ("ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME", "Short names are not enabled on this volume."),
        0x00000132: ("ERROR_SECURITY_STREAM_IS_INCONSISTENT", "The security stream for the given volume is in an inconsistent state."),
        0x00000133: ("ERROR_INVALID_LOCK_RANGE", "A requested file lock operation cannot be processed due to an invalid byte range."),
        0x00000134: ("ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT", "The subsystem needed to support the image type is not present."),
        0x00000135: ("ERROR_NOTIFICATION_GUID_ALREADY_DEFINED", "The specified file already has a notification GUID associated with it."),
        0x00000136: ("ERROR_INVALID_EXCEPTION_HANDLER", "An invalid exception handler routine has been detected."),
        0x00000137: ("ERROR_DUPLICATE_PRIVILEGES", "Duplicate privileges were specified for the token."),
        0x00000138: ("ERROR_NO_RANGES_PROCESSED", "No ranges for the specified operation were able to be processed."),
        0x00000139: ("ERROR_NOT_ALLOWED_ON_SYSTEM_FILE", "Operation is not allowed on a file system internal file."),
        0x0000013a: ("ERROR_DISK_RESOURCES_EXHAUSTED", "The physical resources of this disk have been exhausted."),
        0x0000013b: ("ERROR_INVALID_TOKEN", "The token representing the data is invalid."),
        0x0000013c: ("ERROR_DEVICE_FEATURE_NOT_SUPPORTED", "The device does not support the command feature."),
        0x0000013d: ("ERROR_MR_MID_NOT_FOUND", "The system cannot find message text for message number 0x%1 in the message file for %2."),
        0x0000013e: ("ERROR_SCOPE_NOT_FOUND", "The scope specified was not found."),
        0x0000013f: ("ERROR_UNDEFINED_SCOPE", "The Central Access Policy specified is not defined on the target machine."),
        0x00000140: ("ERROR_INVALID_CAP", "The Central Access Policy obtained from Active Directory is invalid."),
        0x00000141: ("ERROR_DEVICE_UNREACHABLE", "The device is unreachable."),
        0x00000142: ("ERROR_DEVICE_NO_RESOURCES", "The target device has insufficient resources to complete the operation."),
        0x00000143: ("ERROR_DATA_CHECKSUM_ERROR", "A data integrity checksum error occurred. Data in the file stream is corrupt."),
        0x00000144: ("ERROR_INTERMIXED_KERNEL_EA_OPERATION", "An attempt was made to modify both a KERNEL and normal Extended Attribute (EA) in the same operation."),
        0x00000146: ("ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED", "Device does not support file-level TRIM."),
        0x00000147: ("ERROR_OFFSET_ALIGNMENT_VIOLATION", "The command specified a data offset that does not align to the device's granularity/alignment."),
        0x00000148: ("ERROR_INVALID_FIELD_IN_PARAMETER_LIST", "The command specified an invalid field in its parameter list."),
        0x00000149: ("ERROR_OPERATION_IN_PROGRESS", "An operation is currently in progress with the device."),
        0x0000014a: ("ERROR_BAD_DEVICE_PATH", "An attempt was made to send down the command via an invalid path to the target device."),
        0x0000014b: ("ERROR_TOO_MANY_DESCRIPTORS", "The command specified a number of descriptors that exceeded the maximum supported by the device."),
        0x0000014c: ("ERROR_SCRUB_DATA_DISABLED", "Scrub is disabled on the specified file."),
        0x0000014d: ("ERROR_NOT_REDUNDANT_STORAGE", "The storage device does not provide redundancy."),
        0x0000014e: ("ERROR_RESIDENT_FILE_NOT_SUPPORTED", "An operation is not supported on a resident file."),
        0x0000014f: ("ERROR_COMPRESSED_FILE_NOT_SUPPORTED", "An operation is not supported on a compressed file."),
        0x00000150: ("ERROR_DIRECTORY_NOT_SUPPORTED", "An operation is not supported on a directory."),
        0x00000151: ("ERROR_NOT_READ_FROM_COPY", "The specified copy of the requested data could not be read."),
        0x00000152: ("ERROR_FT_WRITE_FAILURE", "The specified data could not be written to any of the copies."),
        0x00000153: ("ERROR_FT_DI_SCAN_REQUIRED", "One or more copies of data on this device may be out of sync. No writes may be performed until a data integrity scan is completed."),
        0x00000154: ("ERROR_INVALID_KERNEL_INFO_VERSION", "The supplied kernel information version is invalid."),
        0x00000155: ("ERROR_INVALID_PEP_INFO_VERSION", "The supplied PEP information version is invalid."),
        0x0000015e: ("ERROR_FAIL_NOACTION_REBOOT", "No action was taken as a system reboot is required."),
        0x0000015f: ("ERROR_FAIL_SHUTDOWN", "The shutdown operation failed."),
        0x00000160: ("ERROR_FAIL_RESTART", "The restart operation failed."),
        0x00000161: ("ERROR_MAX_SESSIONS_REACHED", "The maximum number of sessions has been reached."),
        0x00000190: ("ERROR_THREAD_MODE_ALREADY_BACKGROUND", "The thread is already in background processing mode."),
        0x00000191: ("ERROR_THREAD_MODE_NOT_BACKGROUND", "The thread is not in background processing mode."),
        0x00000192: ("ERROR_PROCESS_MODE_ALREADY_BACKGROUND", "The process is already in background processing mode."),
        0x00000193: ("ERROR_PROCESS_MODE_NOT_BACKGROUND", "The process is not in background processing mode."),
        0x000001e7: ("ERROR_INVALID_ADDRESS", "Attempt to access invalid address."),
        0x000001f4: ("ERROR_USER_PROFILE_LOAD", "User profile cannot be loaded."),
        0x00000216: ("ERROR_ARITHMETIC_OVERFLOW", "Arithmetic result exceeded 32 bits."),
        0x00000217: ("ERROR_PIPE_CONNECTED", "There is a process on other end of the pipe."),
        0x00000218: ("ERROR_PIPE_LISTENING", "Waiting for a process to open the other end of the pipe."),
        0x00000219: ("ERROR_VERIFIER_STOP", "Application verifier has found an error in the current process."),
        0x0000021a: ("ERROR_ABIOS_ERROR", "An error occurred in the ABIOS subsystem."),
        0x0000021b: ("ERROR_WX86_WARNING", "A warning occurred in the WX86 subsystem."),
        0x0000021c: ("ERROR_WX86_ERROR", "An error occurred in the WX86 subsystem."),
        0x0000021d: ("ERROR_TIMER_NOT_CANCELED", "An attempt was made to cancel or set a timer that has an associated APC and the subject thread is not the thread that originally set the timer with an associated APC routine."),
        0x0000021e: ("ERROR_UNWIND", "Unwind exception code."),
        0x0000021f: ("ERROR_BAD_STACK", "An invalid or unaligned stack was encountered during an unwind operation."),
        0x00000220: ("ERROR_INVALID_UNWIND_TARGET", "An invalid unwind target was encountered during an unwind operation."),
        0x00000221: ("ERROR_INVALID_PORT_ATTRIBUTES", "Invalid Object Attributes specified to NtCreatePort or invalid Port Attributes specified to NtConnectPort"),
        0x00000222: ("ERROR_PORT_MESSAGE_TOO_LONG", "Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port."),
        0x00000223: ("ERROR_INVALID_QUOTA_LOWER", "An attempt was made to lower a quota limit below the current usage."),
        0x00000224: ("ERROR_DEVICE_ALREADY_ATTACHED", "An attempt was made to attach to a device that was already attached to another device."),
        0x00000225: ("ERROR_INSTRUCTION_MISALIGNMENT", "An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references."),
        0x00000226: ("ERROR_PROFILING_NOT_STARTED", "Profiling not started."),
        0x00000227: ("ERROR_PROFILING_NOT_STOPPED", "Profiling not stopped."),
        0x00000228: ("ERROR_COULD_NOT_INTERPRET", "The passed ACL did not contain the minimum required information."),
        0x00000229: ("ERROR_PROFILING_AT_LIMIT", "The number of active profiling objects is at the maximum and no more may be started."),
        0x0000022a: ("ERROR_CANT_WAIT", "Used to indicate that an operation cannot continue without blocking for I/O."),
        0x0000022b: ("ERROR_CANT_TERMINATE_SELF", "Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process."),
        0x0000022c: ("ERROR_UNEXPECTED_MM_CREATE_ERR", "If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter."),
        0x0000022d: ("ERROR_UNEXPECTED_MM_MAP_ERROR", "If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter."),
        0x0000022e: ("ERROR_UNEXPECTED_MM_EXTEND_ERR", "If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter."),
        0x0000022f: ("ERROR_BAD_FUNCTION_TABLE", "A malformed function table was encountered during an unwind operation."),
        0x00000230: ("ERROR_NO_GUID_TRANSLATION", "Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system."),
        0x00000231: ("ERROR_INVALID_LDT_SIZE", "Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors."),
        0x00000233: ("ERROR_INVALID_LDT_OFFSET", "Indicates that the starting value for the LDT information was not an integral multiple of the selector size."),
        0x00000234: ("ERROR_INVALID_LDT_DESCRIPTOR", "Indicates that the user supplied an invalid descriptor when trying to set up Ldt descriptors."),
        0x00000235: ("ERROR_TOO_MANY_THREADS", "Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads."),
        0x00000236: ("ERROR_THREAD_NOT_IN_PROCESS", "An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified."),
        0x00000237: ("ERROR_PAGEFILE_QUOTA_EXCEEDED", "Page file quota was exceeded."),
        0x00000238: ("ERROR_LOGON_SERVER_CONFLICT", "The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role."),
        0x00000239: ("ERROR_SYNCHRONIZATION_REQUIRED", "The SAM database on a Windows Server is significantly out of synchronization with the copy on the Domain Controller. A complete synchronization is required."),
        0x0000023a: ("ERROR_NET_OPEN_FAILED", "The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows Lan Manager Redirector to use in its internal error mapping routines."),
        0x0000023b: ("ERROR_IO_PRIVILEGE_FAILED", "{Privilege Failed}"),
        0x0000023c: ("ERROR_CONTROL_C_EXIT", "{Application Exit by CTRL+C}"),
        0x0000023d: ("ERROR_MISSING_SYSTEMFILE", "{Missing System File}"),
        0x0000023e: ("ERROR_UNHANDLED_EXCEPTION", "{Application Error}"),
        0x0000023f: ("ERROR_APP_INIT_FAILURE", "{Application Error}"),
        0x00000240: ("ERROR_PAGEFILE_CREATE_FAILED", "{Unable to Create Paging File}"),
        0x00000241: ("ERROR_INVALID_IMAGE_HASH", "Windows cannot verify the digital signature for this file. A recent hardware or software change might have installed a file that is signed incorrectly or damaged, or that might be malicious software from an unknown source."),
        0x00000242: ("ERROR_NO_PAGEFILE", "{No Paging File Specified}"),
        0x00000243: ("ERROR_ILLEGAL_FLOAT_CONTEXT", "{EXCEPTION}"),
        0x00000244: ("ERROR_NO_EVENT_PAIR", "An event pair synchronization operation was performed using the thread specific client/server event pair object, but no event pair object was associated with the thread."),
        0x00000245: ("ERROR_DOMAIN_CTRLR_CONFIG_ERROR", "A Windows Server has an incorrect configuration."),
        0x00000246: ("ERROR_ILLEGAL_CHARACTER", "An illegal character was encountered. For a multi-byte character set this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE."),
        0x00000247: ("ERROR_UNDEFINED_CHARACTER", "The Unicode character is not defined in the Unicode character set installed on the system."),
        0x00000248: ("ERROR_FLOPPY_VOLUME", "The paging file cannot be created on a floppy diskette."),
        0x00000249: ("ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT", "The system BIOS failed to connect a system interrupt to the device or bus for which the device is connected."),
        0x0000024a: ("ERROR_BACKUP_CONTROLLER", "This operation is only allowed for the Primary Domain Controller of the domain."),
        0x0000024b: ("ERROR_MUTANT_LIMIT_EXCEEDED", "An attempt was made to acquire a mutant such that its maximum count would have been exceeded."),
        0x0000024c: ("ERROR_FS_DRIVER_REQUIRED", "A volume has been accessed for which a file system driver is required that has not yet been loaded."),
        0x0000024d: ("ERROR_CANNOT_LOAD_REGISTRY_FILE", "{Registry File Failure}"),
        0x0000024e: ("ERROR_DEBUG_ATTACH_FAILED", "{Unexpected Failure in DebugActiveProcess}"),
        0x0000024f: ("ERROR_SYSTEM_PROCESS_TERMINATED", "{Fatal System Error}"),
        0x00000250: ("ERROR_DATA_NOT_ACCEPTED", "{Data Not Accepted}"),
        0x00000251: ("ERROR_VDM_HARD_ERROR", "NTVDM encountered a hard error."),
        0x00000252: ("ERROR_DRIVER_CANCEL_TIMEOUT", "{Cancel Timeout}"),
        0x00000253: ("ERROR_REPLY_MESSAGE_MISMATCH", "{Reply Message Mismatch}"),
        0x00000254: ("ERROR_LOST_WRITEBEHIND_DATA", "{Delayed Write Failed}"),
        0x00000255: ("ERROR_CLIENT_SERVER_PARAMETERS_INVALID", "The parameter(s) passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window."),
        0x00000256: ("ERROR_NOT_TINY_STREAM", "The stream is not a tiny stream."),
        0x00000257: ("ERROR_STACK_OVERFLOW_READ", "The request must be handled by the stack overflow code."),
        0x00000258: ("ERROR_CONVERT_TO_LARGE", "Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing onode is moved or the extent stream is converted to a large stream."),
        0x00000259: ("ERROR_FOUND_OUT_OF_SCOPE", "The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation."),
        0x0000025a: ("ERROR_ALLOCATE_BUCKET", "The bucket array must be grown. Retry transaction after doing so."),
        0x0000025b: ("ERROR_MARSHALL_OVERFLOW", "The user/kernel marshalling buffer has overflowed."),
        0x0000025c: ("ERROR_INVALID_VARIANT", "The supplied variant structure contains invalid data."),
        0x0000025d: ("ERROR_BAD_COMPRESSION_BUFFER", "The specified buffer contains ill-formed data."),
        0x0000025e: ("ERROR_AUDIT_FAILED", "{Audit Failed}"),
        0x0000025f: ("ERROR_TIMER_RESOLUTION_NOT_SET", "The timer resolution was not previously set by the current process."),
        0x00000260: ("ERROR_INSUFFICIENT_LOGON_INFO", "There is insufficient account information to log you on."),
        0x00000261: ("ERROR_BAD_DLL_ENTRYPOINT", "{Invalid DLL Entrypoint}"),
        0x00000262: ("ERROR_BAD_SERVICE_ENTRYPOINT", "{Invalid Service Callback Entrypoint}"),
        0x00000263: ("ERROR_IP_ADDRESS_CONFLICT1", "There is an IP address conflict with another system on the network"),
        0x00000264: ("ERROR_IP_ADDRESS_CONFLICT2", "There is an IP address conflict with another system on the network"),
        0x00000265: ("ERROR_REGISTRY_QUOTA_LIMIT", "{Low On Registry Space}"),
        0x00000266: ("ERROR_NO_CALLBACK_ACTIVE", "A callback return system service cannot be executed when no callback is active."),
        0x00000267: ("ERROR_PWD_TOO_SHORT", "The password provided is too short to meet the policy of your user account."),
        0x00000268: ("ERROR_PWD_TOO_RECENT", "The policy of your user account does not allow you to change passwords too frequently."),
        0x00000269: ("ERROR_PWD_HISTORY_CONFLICT", "You have attempted to change your password to one that you have used in the past."),
        0x0000026a: ("ERROR_UNSUPPORTED_COMPRESSION", "The specified compression format is unsupported."),
        0x0000026b: ("ERROR_INVALID_HW_PROFILE", "The specified hardware profile configuration is invalid."),
        0x0000026c: ("ERROR_INVALID_PLUGPLAY_DEVICE_PATH", "The specified Plug and Play registry device path is invalid."),
        0x0000026d: ("ERROR_QUOTA_LIST_INCONSISTENT", "The specified quota list is internally inconsistent with its descriptor."),
        0x0000026e: ("ERROR_EVALUATION_EXPIRATION", "{Windows Evaluation Notification}"),
        0x0000026f: ("ERROR_ILLEGAL_DLL_RELOCATION", "{Illegal System DLL Relocation}"),
        0x00000270: ("ERROR_DLL_INIT_FAILED_LOGOFF", "{DLL Initialization Failed}"),
        0x00000271: ("ERROR_VALIDATE_CONTINUE", "The validation process needs to continue on to the next step."),
        0x00000272: ("ERROR_NO_MORE_MATCHES", "There are no more matches for the current index enumeration."),
        0x00000273: ("ERROR_RANGE_LIST_CONFLICT", "The range could not be added to the range list because of a conflict."),
        0x00000274: ("ERROR_SERVER_SID_MISMATCH", "The server process is running under a SID different than that required by client."),
        0x00000275: ("ERROR_CANT_ENABLE_DENY_ONLY", "A group marked use for deny only cannot be enabled."),
        0x00000276: ("ERROR_FLOAT_MULTIPLE_FAULTS", "{EXCEPTION}"),
        0x00000277: ("ERROR_FLOAT_MULTIPLE_TRAPS", "{EXCEPTION}"),
        0x00000278: ("ERROR_NOINTERFACE", "The requested interface is not supported."),
        0x00000279: ("ERROR_DRIVER_FAILED_SLEEP", "{System Standby Failed}"),
        0x0000027a: ("ERROR_CORRUPT_SYSTEM_FILE", "The system file %1 has become corrupt and has been replaced."),
        0x0000027b: ("ERROR_COMMITMENT_MINIMUM", "{Virtual Memory Minimum Too Low}"),
        0x0000027c: ("ERROR_PNP_RESTART_ENUMERATION", "A device was removed so enumeration must be restarted."),
        0x0000027d: ("ERROR_SYSTEM_IMAGE_BAD_SIGNATURE", "{Fatal System Error}"),
        0x0000027e: ("ERROR_PNP_REBOOT_REQUIRED", "Device will not start without a reboot."),
        0x0000027f: ("ERROR_INSUFFICIENT_POWER", "There is not enough power to complete the requested operation."),
        0x00000280: ("ERROR_MULTIPLE_FAULT_VIOLATION", " ERROR_MULTIPLE_FAULT_VIOLATION"),
        0x00000281: ("ERROR_SYSTEM_SHUTDOWN", "The system is in the process of shutting down."),
        0x00000282: ("ERROR_PORT_NOT_SET", "An attempt to remove a processes DebugPort was made, but a port was not already associated with the process."),
        0x00000283: ("ERROR_DS_VERSION_CHECK_FAILURE", "This version of Windows is not compatible with the behavior version of directory forest, domain or domain controller."),
        0x00000284: ("ERROR_RANGE_NOT_FOUND", "The specified range could not be found in the range list."),
        0x00000286: ("ERROR_NOT_SAFE_MODE_DRIVER", "The driver was not loaded because the system is booting into safe mode."),
        0x00000287: ("ERROR_FAILED_DRIVER_ENTRY", "The driver was not loaded because it failed its initialization call."),
        0x00000288: ("ERROR_DEVICE_ENUMERATION_ERROR", "The '%hs' encountered an error while applying power or reading the device configuration."),
        0x00000289: ("ERROR_MOUNT_POINT_NOT_RESOLVED", "The create operation failed because the name contained at least one mount point which resolves to a volume to which the specified device object is not attached."),
        0x0000028a: ("ERROR_INVALID_DEVICE_OBJECT_PARAMETER", "The device object parameter is either not a valid device object or is not attached to the volume specified by the file name."),
        0x0000028b: ("ERROR_MCA_OCCURED", "A Machine Check Error has occurred. Please check the system eventlog for additional information."),
        0x0000028c: ("ERROR_DRIVER_DATABASE_ERROR", "There was error [%2] processing the driver database."),
        0x0000028d: ("ERROR_SYSTEM_HIVE_TOO_LARGE", "System hive size has exceeded its limit."),
        0x0000028e: ("ERROR_DRIVER_FAILED_PRIOR_UNLOAD", "The driver could not be loaded because a previous version of the driver is still in memory."),
        0x0000028f: ("ERROR_VOLSNAP_PREPARE_HIBERNATE", "{Volume Shadow Copy Service}"),
        0x00000290: ("ERROR_HIBERNATION_FAILURE", "The system has failed to hibernate (The error code is %hs). Hibernation will be disabled until the system is restarted."),
        0x00000291: ("ERROR_PWD_TOO_LONG", "The password provided is too long to meet the policy of your user account."),
        0x00000299: ("ERROR_FILE_SYSTEM_LIMITATION", "The requested operation could not be completed due to a file system limitation"),
        0x0000029c: ("ERROR_ASSERTION_FAILURE", "An assertion failure has occurred."),
        0x0000029d: ("ERROR_ACPI_ERROR", "An error occurred in the ACPI subsystem."),
        0x0000029e: ("ERROR_WOW_ASSERTION", "WOW Assertion Error."),
        0x0000029f: ("ERROR_PNP_BAD_MPS_TABLE", "A device is missing in the system BIOS MPS table. This device will not be used."),
        0x000002a0: ("ERROR_PNP_TRANSLATION_FAILED", "A translator failed to translate resources."),
        0x000002a1: ("ERROR_PNP_IRQ_TRANSLATION_FAILED", "A IRQ translator failed to translate resources."),
        0x000002a2: ("ERROR_PNP_INVALID_ID", "Driver %2 returned invalid ID for a child device (%3)."),
        0x000002a3: ("ERROR_WAKE_SYSTEM_DEBUGGER", "{Kernel Debugger Awakened}"),
        0x000002a4: ("ERROR_HANDLES_CLOSED", "{Handles Closed}"),
        0x000002a5: ("ERROR_EXTRANEOUS_INFORMATION", "{Too Much Information}"),
        0x000002a6: ("ERROR_RXACT_COMMIT_NECESSARY", "This warning level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted."),
        0x000002a7: ("ERROR_MEDIA_CHECK", "{Media Changed}"),
        0x000002a8: ("ERROR_GUID_SUBSTITUTION_MADE", "{GUID Substitution}"),
        0x000002a9: ("ERROR_STOPPED_ON_SYMLINK", "The create operation stopped after reaching a symbolic link"),
        0x000002aa: ("ERROR_LONGJUMP", "A long jump has been executed."),
        0x000002ab: ("ERROR_PLUGPLAY_QUERY_VETOED", "The Plug and Play query operation was not successful."),
        0x000002ac: ("ERROR_UNWIND_CONSOLIDATE", "A frame consolidation has been executed."),
        0x000002ad: ("ERROR_REGISTRY_HIVE_RECOVERED", "{Registry Hive Recovered}"),
        0x000002ae: ("ERROR_DLL_MIGHT_BE_INSECURE", "The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?"),
        0x000002af: ("ERROR_DLL_MIGHT_BE_INCOMPATIBLE", "The application is loading executable code from the module %hs. This is secure, but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?"),
        0x000002b0: ("ERROR_DBG_EXCEPTION_NOT_HANDLED", "Debugger did not handle the exception."),
        0x000002b1: ("ERROR_DBG_REPLY_LATER", "Debugger will reply later."),
        0x000002b2: ("ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE", "Debugger cannot provide handle."),
        0x000002b3: ("ERROR_DBG_TERMINATE_THREAD", "Debugger terminated thread."),
        0x000002b4: ("ERROR_DBG_TERMINATE_PROCESS", "Debugger terminated process."),
        0x000002b5: ("ERROR_DBG_CONTROL_C", "Debugger got control C."),
        0x000002b6: ("ERROR_DBG_PRINTEXCEPTION_C", "Debugger printed exception on control C."),
        0x000002b7: ("ERROR_DBG_RIPEXCEPTION", "Debugger received RIP exception."),
        0x000002b8: ("ERROR_DBG_CONTROL_BREAK", "Debugger received control break."),
        0x000002b9: ("ERROR_DBG_COMMAND_EXCEPTION", "Debugger command communication exception."),
        0x000002ba: ("ERROR_OBJECT_NAME_EXISTS", "{Object Exists}"),
        0x000002bb: ("ERROR_THREAD_WAS_SUSPENDED", "{Thread Suspended}"),
        0x000002bc: ("ERROR_IMAGE_NOT_AT_BASE", "{Image Relocated}"),
        0x000002bd: ("ERROR_RXACT_STATE_CREATED", "This informational level status indicates that a specified registry sub-tree transaction state did not yet exist and had to be created."),
        0x000002be: ("ERROR_SEGMENT_NOTIFICATION", "{Segment Load}"),
        0x000002bf: ("ERROR_BAD_CURRENT_DIRECTORY", "{Invalid Current Directory}"),
        0x000002c0: ("ERROR_FT_READ_RECOVERY_FROM_BACKUP", "{Redundant Read}"),
        0x000002c1: ("ERROR_FT_WRITE_RECOVERY", "{Redundant Write}"),
        0x000002c2: ("ERROR_IMAGE_MACHINE_TYPE_MISMATCH", "{Machine Type Mismatch}"),
        0x000002c3: ("ERROR_RECEIVE_PARTIAL", "{Partial Data Received}"),
        0x000002c4: ("ERROR_RECEIVE_EXPEDITED", "{Expedited Data Received}"),
        0x000002c5: ("ERROR_RECEIVE_PARTIAL_EXPEDITED", "{Partial Expedited Data Received}"),
        0x000002c6: ("ERROR_EVENT_DONE", "{TDI Event Done}"),
        0x000002c7: ("ERROR_EVENT_PENDING", "{TDI Event Pending}"),
        0x000002c8: ("ERROR_CHECKING_FILE_SYSTEM", "Checking file system on %wZ"),
        0x000002c9: ("ERROR_FATAL_APP_EXIT", "{Fatal Application Exit}"),
        0x000002ca: ("ERROR_PREDEFINED_HANDLE", "The specified registry key is referenced by a predefined handle."),
        0x000002cb: ("ERROR_WAS_UNLOCKED", "{Page Unlocked}"),
        0x000002cc: ("ERROR_SERVICE_NOTIFICATION", "%hs"),
        0x000002cd: ("ERROR_WAS_LOCKED", "{Page Locked}"),
        0x000002ce: ("ERROR_LOG_HARD_ERROR", "Application popup: %1 : %2"),
        0x000002cf: ("ERROR_ALREADY_WIN32", " ERROR_ALREADY_WIN32"),
        0x000002d0: ("ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE", "{Machine Type Mismatch}"),
        0x000002d1: ("ERROR_NO_YIELD_PERFORMED", "A yield execution was performed and no thread was available to run."),
        0x000002d2: ("ERROR_TIMER_RESUME_IGNORED", "The resumable flag to a timer API was ignored."),
        0x000002d3: ("ERROR_ARBITRATION_UNHANDLED", "The arbiter has deferred arbitration of these resources to its parent"),
        0x000002d4: ("ERROR_CARDBUS_NOT_SUPPORTED", "The inserted CardBus device cannot be started because of a configuration error on '%hs'."),
        0x000002d5: ("ERROR_MP_PROCESSOR_MISMATCH", "The CPUs in this multiprocessor system are not all the same revision level. To use all processors the operating system restricts itself to the features of the least capable processor in the system. Should problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported."),
        0x000002d6: ("ERROR_HIBERNATED", "The system was put into hibernation."),
        0x000002d7: ("ERROR_RESUME_HIBERNATION", "The system was resumed from hibernation."),
        0x000002d8: ("ERROR_FIRMWARE_UPDATED", "Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3]."),
        0x000002d9: ("ERROR_DRIVERS_LEAKING_LOCKED_PAGES", "A device driver is leaking locked I/O pages causing system degradation. The system has automatically enabled tracking code in order to try and catch the culprit."),
        0x000002da: ("ERROR_WAKE_SYSTEM", "The system has awoken"),
        0x000002db: ("ERROR_WAIT_1", " ERROR_WAIT_1"),
        0x000002dc: ("ERROR_WAIT_2", " ERROR_WAIT_2"),
        0x000002dd: ("ERROR_WAIT_3", " ERROR_WAIT_3"),
        0x000002de: ("ERROR_WAIT_63", " ERROR_WAIT_63"),
        0x000002df: ("ERROR_ABANDONED_WAIT_0", " ERROR_ABANDONED_WAIT_0"),
        0x000002e0: ("ERROR_ABANDONED_WAIT_63", " ERROR_ABANDONED_WAIT_63"),
        0x000002e1: ("ERROR_USER_APC", " ERROR_USER_APC"),
        0x000002e2: ("ERROR_KERNEL_APC", " ERROR_KERNEL_APC"),
        0x000002e3: ("ERROR_ALERTED", " ERROR_ALERTED"),
        0x000002e4: ("ERROR_ELEVATION_REQUIRED", "The requested operation requires elevation."),
        0x000002e5: ("ERROR_REPARSE", "A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link."),
        0x000002e6: ("ERROR_OPLOCK_BREAK_IN_PROGRESS", "An open/create operation completed while an oplock break is underway."),
        0x000002e7: ("ERROR_VOLUME_MOUNTED", "A new volume has been mounted by a file system."),
        0x000002e8: ("ERROR_RXACT_COMMITTED", "This success level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted."),
        0x000002e9: ("ERROR_NOTIFY_CLEANUP", "This indicates that a notify change request has been completed due to closing the handle which made the notify change request."),
        0x000002ea: ("ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED", "{Connect Failure on Primary Transport}"),
        0x000002eb: ("ERROR_PAGE_FAULT_TRANSITION", "Page fault was a transition fault."),
        0x000002ec: ("ERROR_PAGE_FAULT_DEMAND_ZERO", "Page fault was a demand zero fault."),
        0x000002ed: ("ERROR_PAGE_FAULT_COPY_ON_WRITE", "Page fault was a demand zero fault."),
        0x000002ee: ("ERROR_PAGE_FAULT_GUARD_PAGE", "Page fault was a demand zero fault."),
        0x000002ef: ("ERROR_PAGE_FAULT_PAGING_FILE", "Page fault was satisfied by reading from a secondary storage device."),
        0x000002f0: ("ERROR_CACHE_PAGE_LOCKED", "Cached page was locked during operation."),
        0x000002f1: ("ERROR_CRASH_DUMP", "Crash dump exists in paging file."),
        0x000002f2: ("ERROR_BUFFER_ALL_ZEROS", "Specified buffer contains all zeros."),
        0x000002f3: ("ERROR_REPARSE_OBJECT", "A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link."),
        0x000002f4: ("ERROR_RESOURCE_REQUIREMENTS_CHANGED", "The device has succeeded a query-stop and its resource requirements have changed."),
        0x000002f5: ("ERROR_TRANSLATION_COMPLETE", "The translator has translated these resources into the global space and no further translations should be performed."),
        0x000002f6: ("ERROR_NOTHING_TO_TERMINATE", "A process being terminated has no threads to terminate."),
        0x000002f7: ("ERROR_PROCESS_NOT_IN_JOB", "The specified process is not part of a job."),
        0x000002f8: ("ERROR_PROCESS_IN_JOB", "The specified process is part of a job."),
        0x000002f9: ("ERROR_VOLSNAP_HIBERNATE_READY", "{Volume Shadow Copy Service}"),
        0x000002fa: ("ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY", "A file system or file system filter driver has successfully completed an FsFilter operation."),
        0x000002fb: ("ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED", "The specified interrupt vector was already connected."),
        0x000002fc: ("ERROR_INTERRUPT_STILL_CONNECTED", "The specified interrupt vector is still connected."),
        0x000002fd: ("ERROR_WAIT_FOR_OPLOCK", "An operation is blocked waiting for an oplock."),
        0x000002fe: ("ERROR_DBG_EXCEPTION_HANDLED", "Debugger handled exception"),
        0x000002ff: ("ERROR_DBG_CONTINUE", "Debugger continued"),
        0x00000300: ("ERROR_CALLBACK_POP_STACK", "An exception occurred in a user mode callback and the kernel callback frame should be removed."),
        0x00000301: ("ERROR_COMPRESSION_DISABLED", "Compression is disabled for this volume."),
        0x00000302: ("ERROR_CANTFETCHBACKWARDS", "The data provider cannot fetch backwards through a result set."),
        0x00000303: ("ERROR_CANTSCROLLBACKWARDS", "The data provider cannot scroll backwards through a result set."),
        0x00000304: ("ERROR_ROWSNOTRELEASED", "The data provider requires that previously fetched data is released before asking for more data."),
        0x00000305: ("ERROR_BAD_ACCESSOR_FLAGS", "The data provider was not able to interpret the flags set for a column binding in an accessor."),
        0x00000306: ("ERROR_ERRORS_ENCOUNTERED", "One or more errors occurred while processing the request."),
        0x00000307: ("ERROR_NOT_CAPABLE", "The implementation is not capable of performing the request."),
        0x00000308: ("ERROR_REQUEST_OUT_OF_SEQUENCE", "The client of a component requested an operation which is not valid given the state of the component instance."),
        0x00000309: ("ERROR_VERSION_PARSE_ERROR", "A version number could not be parsed."),
        0x0000030a: ("ERROR_BADSTARTPOSITION", "The iterator's start position is invalid."),
        0x0000030b: ("ERROR_MEMORY_HARDWARE", "The hardware has reported an uncorrectable memory error."),
        0x0000030c: ("ERROR_DISK_REPAIR_DISABLED", "The attempted operation required self healing to be enabled."),
        0x0000030d: ("ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE", "The Desktop heap encountered an error while allocating session memory. There is more information in the system event log."),
        0x0000030e: ("ERROR_SYSTEM_POWERSTATE_TRANSITION", "The system power state is transitioning from %2 to %3."),
        0x0000030f: ("ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION", "The system power state is transitioning from %2 to %3 but could enter %4."),
        0x00000310: ("ERROR_MCA_EXCEPTION", "A thread is getting dispatched with MCA EXCEPTION because of MCA."),
        0x00000311: ("ERROR_ACCESS_AUDIT_BY_POLICY", "Access to %1 is monitored by policy rule %2."),
        0x00000312: ("ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY", "Access to %1 has been restricted by your Administrator by policy rule %2."),
        0x00000313: ("ERROR_ABANDON_HIBERFILE", "A valid hibernation file has been invalidated and should be abandoned."),
        0x00000314: ("ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED", "{Delayed Write Failed}"),
        0x00000315: ("ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR", "{Delayed Write Failed}"),
        0x00000316: ("ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR", "{Delayed Write Failed}"),
        0x00000317: ("ERROR_BAD_MCFG_TABLE", "The resources required for this device conflict with the MCFG table."),
        0x00000318: ("ERROR_DISK_REPAIR_REDIRECTED", "The volume repair could not be performed while it is online."),
        0x00000319: ("ERROR_DISK_REPAIR_UNSUCCESSFUL", "The volume repair was not successful."),
        0x0000031a: ("ERROR_CORRUPT_LOG_OVERFULL", "One of the volume corruption logs is full. Further corruptions that may be detected won't be logged."),
        0x0000031b: ("ERROR_CORRUPT_LOG_CORRUPTED", "One of the volume corruption logs is internally corrupted and needs to be recreated. The volume may contain undetected corruptions and must be scanned."),
        0x0000031c: ("ERROR_CORRUPT_LOG_UNAVAILABLE", "One of the volume corruption logs is unavailable for being operated on."),
        0x0000031d: ("ERROR_CORRUPT_LOG_DELETED_FULL", "One of the volume corruption logs was deleted while still having corruption records in them. The volume contains detected corruptions and must be scanned."),
        0x0000031e: ("ERROR_CORRUPT_LOG_CLEARED", "One of the volume corruption logs was cleared by chkdsk and no longer contains real corruptions."),
        0x0000031f: ("ERROR_ORPHAN_NAME_EXHAUSTED", "Orphaned files exist on the volume but could not be recovered because no more new names could be created in the recovery directory. Files must be moved from the recovery directory."),
        0x00000320: ("ERROR_OPLOCK_SWITCHED_TO_NEW_HANDLE", "The oplock that was associated with this handle is now associated with a different handle."),
        0x00000321: ("ERROR_CANNOT_GRANT_REQUESTED_OPLOCK", "An oplock of the requested level cannot be granted.  An oplock of a lower level may be available."),
        0x00000322: ("ERROR_CANNOT_BREAK_OPLOCK", "The operation did not complete successfully because it would cause an oplock to be broken. The caller has requested that existing oplocks not be broken."),
        0x00000323: ("ERROR_OPLOCK_HANDLE_CLOSED", "The handle with which this oplock was associated has been closed.  The oplock is now broken."),
        0x00000324: ("ERROR_NO_ACE_CONDITION", "The specified access control entry (ACE) does not contain a condition."),
        0x00000325: ("ERROR_INVALID_ACE_CONDITION", "The specified access control entry (ACE) contains an invalid condition."),
        0x00000326: ("ERROR_FILE_HANDLE_REVOKED", "Access to the specified file handle has been revoked."),
        0x00000327: ("ERROR_IMAGE_AT_DIFFERENT_BASE", "{Image Relocated}"),
        0x000003e2: ("ERROR_EA_ACCESS_DENIED", "Access to the extended attribute was denied."),
        0x000003e3: ("ERROR_OPERATION_ABORTED", "The I/O operation has been aborted because of either a thread exit or an application request."),
        0x000003e4: ("ERROR_IO_INCOMPLETE", "Overlapped I/O event is not in a signaled state."),
        0x000003e5: ("ERROR_IO_PENDING", "Overlapped I/O operation is in progress."),
        0x000003e6: ("ERROR_NOACCESS", "Invalid access to memory location."),
        0x000003e7: ("ERROR_SWAPERROR", "Error performing inpage operation."),
        0x000003e9: ("ERROR_STACK_OVERFLOW", "Recursion too deep; the stack overflowed."),
        0x000003ea: ("ERROR_INVALID_MESSAGE", "The window cannot act on the sent message."),
        0x000003eb: ("ERROR_CAN_NOT_COMPLETE", "Cannot complete this function."),
        0x000003ec: ("ERROR_INVALID_FLAGS", "Invalid flags."),
        0x000003ed: ("ERROR_UNRECOGNIZED_VOLUME", "The volume does not contain a recognized file system."),
        0x000003ee: ("ERROR_FILE_INVALID", "The volume for a file has been externally altered so that the opened file is no longer valid."),
        0x000003ef: ("ERROR_FULLSCREEN_MODE", "The requested operation cannot be performed in full-screen mode."),
        0x000003f0: ("ERROR_NO_TOKEN", "An attempt was made to reference a token that does not exist."),
        0x000003f1: ("ERROR_BADDB", "The configuration registry database is corrupt."),
        0x000003f2: ("ERROR_BADKEY", "The configuration registry key is invalid."),
        0x000003f3: ("ERROR_CANTOPEN", "The configuration registry key could not be opened."),
        0x000003f4: ("ERROR_CANTREAD", "The configuration registry key could not be read."),
        0x000003f5: ("ERROR_CANTWRITE", "The configuration registry key could not be written."),
        0x000003f6: ("ERROR_REGISTRY_RECOVERED", "One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful."),
        0x000003f7: ("ERROR_REGISTRY_CORRUPT", "The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted."),
        0x000003f8: ("ERROR_REGISTRY_IO_FAILED", "An I/O operation initiated by the registry failed unrecoverably. The registry could not read in, or write out, or flush, one of the files that contain the system's image of the registry."),
        0x000003f9: ("ERROR_NOT_REGISTRY_FILE", "The system has attempted to load or restore a file into the registry, but the specified file is not in a registry file format."),
        0x000003fa: ("ERROR_KEY_DELETED", "Illegal operation attempted on a registry key that has been marked for deletion."),
        0x000003fb: ("ERROR_NO_LOG_SPACE", "System could not allocate the required space in a registry log."),
        0x000003fc: ("ERROR_KEY_HAS_CHILDREN", "Cannot create a symbolic link in a registry key that already has subkeys or values."),
        0x000003fd: ("ERROR_CHILD_MUST_BE_VOLATILE", "Cannot create a stable subkey under a volatile parent key."),
        0x000003fe: ("ERROR_NOTIFY_ENUM_DIR", "A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes."),
        0x0000041b: ("ERROR_DEPENDENT_SERVICES_RUNNING", "A stop control has been sent to a service that other running services are dependent on."),
        0x0000041c: ("ERROR_INVALID_SERVICE_CONTROL", "The requested control is not valid for this service."),
        0x0000041d: ("ERROR_SERVICE_REQUEST_TIMEOUT", "The service did not respond to the start or control request in a timely fashion."),
        0x0000041e: ("ERROR_SERVICE_NO_THREAD", "A thread could not be created for the service."),
        0x0000041f: ("ERROR_SERVICE_DATABASE_LOCKED", "The service database is locked."),
        0x00000420: ("ERROR_SERVICE_ALREADY_RUNNING", "An instance of the service is already running."),
        0x00000421: ("ERROR_INVALID_SERVICE_ACCOUNT", "The account name is invalid or does not exist, or the password is invalid for the account name specified."),
        0x00000422: ("ERROR_SERVICE_DISABLED", "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it."),
        0x00000423: ("ERROR_CIRCULAR_DEPENDENCY", "Circular service dependency was specified."),
        0x00000424: ("ERROR_SERVICE_DOES_NOT_EXIST", "The specified service does not exist as an installed service."),
        0x00000425: ("ERROR_SERVICE_CANNOT_ACCEPT_CTRL", "The service cannot accept control messages at this time."),
        0x00000426: ("ERROR_SERVICE_NOT_ACTIVE", "The service has not been started."),
        0x00000427: ("ERROR_FAILED_SERVICE_CONTROLLER_CONNECT", "The service process could not connect to the service controller."),
        0x00000428: ("ERROR_EXCEPTION_IN_SERVICE", "An exception occurred in the service when handling the control request."),
        0x00000429: ("ERROR_DATABASE_DOES_NOT_EXIST", "The database specified does not exist."),
        0x0000042a: ("ERROR_SERVICE_SPECIFIC_ERROR", "The service has returned a service-specific error code."),
        0x0000042b: ("ERROR_PROCESS_ABORTED", "The process terminated unexpectedly."),
        0x0000042c: ("ERROR_SERVICE_DEPENDENCY_FAIL", "The dependency service or group failed to start."),
        0x0000042d: ("ERROR_SERVICE_LOGON_FAILED", "The service did not start due to a logon failure."),
        0x0000042e: ("ERROR_SERVICE_START_HANG", "After starting, the service hung in a start-pending state."),
        0x0000042f: ("ERROR_INVALID_SERVICE_LOCK", "The specified service database lock is invalid."),
        0x00000430: ("ERROR_SERVICE_MARKED_FOR_DELETE", "The specified service has been marked for deletion."),
        0x00000431: ("ERROR_SERVICE_EXISTS", "The specified service already exists."),
        0x00000432: ("ERROR_ALREADY_RUNNING_LKG", "The system is currently running with the last-known-good configuration."),
        0x00000433: ("ERROR_SERVICE_DEPENDENCY_DELETED", "The dependency service does not exist or has been marked for deletion."),
        0x00000434: ("ERROR_BOOT_ALREADY_ACCEPTED", "The current boot has already been accepted for use as the last-known-good control set."),
        0x00000435: ("ERROR_SERVICE_NEVER_STARTED", "No attempts to start the service have been made since the last boot."),
        0x00000436: ("ERROR_DUPLICATE_SERVICE_NAME", "The name is already in use as either a service name or a service display name."),
        0x00000437: ("ERROR_DIFFERENT_SERVICE_ACCOUNT", "The account specified for this service is different from the account specified for other services running in the same process."),
        0x00000438: ("ERROR_CANNOT_DETECT_DRIVER_FAILURE", "Failure actions can only be set for Win32 services, not for drivers."),
        0x00000439: ("ERROR_CANNOT_DETECT_PROCESS_ABORT", "This service runs in the same process as the service control manager."),
        0x0000043a: ("ERROR_NO_RECOVERY_PROGRAM", "No recovery program has been configured for this service."),
        0x0000043b: ("ERROR_SERVICE_NOT_IN_EXE", "The executable program that this service is configured to run in does not implement the service."),
        0x0000043c: ("ERROR_NOT_SAFEBOOT_SERVICE", "This service cannot be started in Safe Mode"),
        0x0000044c: ("ERROR_END_OF_MEDIA", "The physical end of the tape has been reached."),
        0x0000044d: ("ERROR_FILEMARK_DETECTED", "A tape access reached a filemark."),
        0x0000044e: ("ERROR_BEGINNING_OF_MEDIA", "The beginning of the tape or a partition was encountered."),
        0x0000044f: ("ERROR_SETMARK_DETECTED", "A tape access reached the end of a set of files."),
        0x00000450: ("ERROR_NO_DATA_DETECTED", "No more data is on the tape."),
        0x00000451: ("ERROR_PARTITION_FAILURE", "Tape could not be partitioned."),
        0x00000452: ("ERROR_INVALID_BLOCK_LENGTH", "When accessing a new tape of a multivolume partition, the current block size is incorrect."),
        0x00000453: ("ERROR_DEVICE_NOT_PARTITIONED", "Tape partition information could not be found when loading a tape."),
        0x00000454: ("ERROR_UNABLE_TO_LOCK_MEDIA", "Unable to lock the media eject mechanism."),
        0x00000455: ("ERROR_UNABLE_TO_UNLOAD_MEDIA", "Unable to unload the media."),
        0x00000456: ("ERROR_MEDIA_CHANGED", "The media in the drive may have changed."),
        0x00000457: ("ERROR_BUS_RESET", "The I/O bus was reset."),
        0x00000458: ("ERROR_NO_MEDIA_IN_DRIVE", "No media in drive."),
        0x00000459: ("ERROR_NO_UNICODE_TRANSLATION", "No mapping for the Unicode character exists in the target multi-byte code page."),
        0x0000045a: ("ERROR_DLL_INIT_FAILED", "A dynamic link library (DLL) initialization routine failed."),
        0x0000045b: ("ERROR_SHUTDOWN_IN_PROGRESS", "A system shutdown is in progress."),
        0x0000045c: ("ERROR_NO_SHUTDOWN_IN_PROGRESS", "Unable to abort the system shutdown because no shutdown was in progress."),
        0x0000045d: ("ERROR_IO_DEVICE", "The request could not be performed because of an I/O device error."),
        0x0000045e: ("ERROR_SERIAL_NO_DEVICE", "No serial device was successfully initialized. The serial driver will unload."),
        0x0000045f: ("ERROR_IRQ_BUSY", "Unable to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened."),
        0x00000460: ("ERROR_MORE_WRITES", "A serial I/O operation was completed by another write to the serial port."),
        0x00000461: ("ERROR_COUNTER_TIMEOUT", "A serial I/O operation completed because the timeout period expired."),
        0x00000462: ("ERROR_FLOPPY_ID_MARK_NOT_FOUND", "No ID address mark was found on the floppy disk."),
        0x00000463: ("ERROR_FLOPPY_WRONG_CYLINDER", "Mismatch between the floppy disk sector ID field and the floppy disk controller track address."),
        0x00000464: ("ERROR_FLOPPY_UNKNOWN_ERROR", "The floppy disk controller reported an error that is not recognized by the floppy disk driver."),
        0x00000465: ("ERROR_FLOPPY_BAD_REGISTERS", "The floppy disk controller returned inconsistent results in its registers."),
        0x00000466: ("ERROR_DISK_RECALIBRATE_FAILED", "While accessing the hard disk, a recalibrate operation failed, even after retries."),
        0x00000467: ("ERROR_DISK_OPERATION_FAILED", "While accessing the hard disk, a disk operation failed even after retries."),
        0x00000468: ("ERROR_DISK_RESET_FAILED", "While accessing the hard disk, a disk controller reset was needed, but even that failed."),
        0x00000469: ("ERROR_EOM_OVERFLOW", "Physical end of tape encountered."),
        0x0000046a: ("ERROR_NOT_ENOUGH_SERVER_MEMORY", "Not enough server storage is available to process this command."),
        0x0000046b: ("ERROR_POSSIBLE_DEADLOCK", "A potential deadlock condition has been detected."),
        0x0000046c: ("ERROR_MAPPED_ALIGNMENT", "The base address or the file offset specified does not have the proper alignment."),
        0x00000474: ("ERROR_SET_POWER_STATE_VETOED", "An attempt to change the system power state was vetoed by another application or driver."),
        0x00000475: ("ERROR_SET_POWER_STATE_FAILED", "The system BIOS failed an attempt to change the system power state."),
        0x00000476: ("ERROR_TOO_MANY_LINKS", "An attempt was made to create more links on a file than the file system supports."),
        0x0000047e: ("ERROR_OLD_WIN_VERSION", "The specified program requires a newer version of Windows."),
        0x0000047f: ("ERROR_APP_WRONG_OS", "The specified program is not a Windows or MS-DOS program."),
        0x00000480: ("ERROR_SINGLE_INSTANCE_APP", "Cannot start more than one instance of the specified program."),
        0x00000481: ("ERROR_RMODE_APP", "The specified program was written for an earlier version of Windows."),
        0x00000482: ("ERROR_INVALID_DLL", "One of the library files needed to run this application is damaged."),
        0x00000483: ("ERROR_NO_ASSOCIATION", "No application is associated with the specified file for this operation."),
        0x00000484: ("ERROR_DDE_FAIL", "An error occurred in sending the command to the application."),
        0x00000485: ("ERROR_DLL_NOT_FOUND", "One of the library files needed to run this application cannot be found."),
        0x00000486: ("ERROR_NO_MORE_USER_HANDLES", "The current process has used all of its system allowance of handles for Window Manager objects."),
        0x00000487: ("ERROR_MESSAGE_SYNC_ONLY", "The message can be used only with synchronous operations."),
        0x00000488: ("ERROR_SOURCE_ELEMENT_EMPTY", "The indicated source element has no media."),
        0x00000489: ("ERROR_DESTINATION_ELEMENT_FULL", "The indicated destination element already contains media."),
        0x0000048a: ("ERROR_ILLEGAL_ELEMENT_ADDRESS", "The indicated element does not exist."),
        0x0000048b: ("ERROR_MAGAZINE_NOT_PRESENT", "The indicated element is part of a magazine that is not present."),
        0x0000048c: ("ERROR_DEVICE_REINITIALIZATION_NEEDED", "The indicated device requires reinitialization due to hardware errors."),
        0x0000048d: ("ERROR_DEVICE_REQUIRES_CLEANING", "The device has indicated that cleaning is required before further operations are attempted."),
        0x0000048e: ("ERROR_DEVICE_DOOR_OPEN", "The device has indicated that its door is open."),
        0x0000048f: ("ERROR_DEVICE_NOT_CONNECTED", "The device is not connected."),
        0x00000490: ("ERROR_NOT_FOUND", "Element not found."),
        0x00000491: ("ERROR_NO_MATCH", "There was no match for the specified key in the index."),
        0x00000492: ("ERROR_SET_NOT_FOUND", "The property set specified does not exist on the object."),
        0x00000493: ("ERROR_POINT_NOT_FOUND", "The point passed to GetMouseMovePoints is not in the buffer."),
        0x00000494: ("ERROR_NO_TRACKING_SERVICE", "The tracking (workstation) service is not running."),
        0x00000495: ("ERROR_NO_VOLUME_ID", "The Volume ID could not be found."),
        0x00000497: ("ERROR_UNABLE_TO_REMOVE_REPLACED", "Unable to remove the file to be replaced."),
        0x00000498: ("ERROR_UNABLE_TO_MOVE_REPLACEMENT", "Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name."),
        0x00000499: ("ERROR_UNABLE_TO_MOVE_REPLACEMENT_2", "Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name."),
        0x0000049a: ("ERROR_JOURNAL_DELETE_IN_PROGRESS", "The volume change journal is being deleted."),
        0x0000049b: ("ERROR_JOURNAL_NOT_ACTIVE", "The volume change journal is not active."),
        0x0000049c: ("ERROR_POTENTIAL_FILE_FOUND", "A file was found, but it may not be the correct file."),
        0x0000049d: ("ERROR_JOURNAL_ENTRY_DELETED", "The journal entry has been deleted from the journal."),
        0x000004a6: ("ERROR_SHUTDOWN_IS_SCHEDULED", "A system shutdown has already been scheduled."),
        0x000004a7: ("ERROR_SHUTDOWN_USERS_LOGGED_ON", "The system shutdown cannot be initiated because there are other users logged on to the computer."),
        0x000004b0: ("ERROR_BAD_DEVICE", "The specified device name is invalid."),
        0x000004b1: ("ERROR_CONNECTION_UNAVAIL", "The device is not currently connected but it is a remembered connection."),
        0x000004b2: ("ERROR_DEVICE_ALREADY_REMEMBERED", "The local device name has a remembered connection to another network resource."),
        0x000004b3: ("ERROR_NO_NET_OR_BAD_PATH", "The network path was either typed incorrectly, does not exist, or the network provider is not currently available. Please try retyping the path or contact your network administrator."),
        0x000004b4: ("ERROR_BAD_PROVIDER", "The specified network provider name is invalid."),
        0x000004b5: ("ERROR_CANNOT_OPEN_PROFILE", "Unable to open the network connection profile."),
        0x000004b6: ("ERROR_BAD_PROFILE", "The network connection profile is corrupted."),
        0x000004b7: ("ERROR_NOT_CONTAINER", "Cannot enumerate a noncontainer."),
        0x000004b8: ("ERROR_EXTENDED_ERROR", "An extended error has occurred."),
        0x000004b9: ("ERROR_INVALID_GROUPNAME", "The format of the specified group name is invalid."),
        0x000004ba: ("ERROR_INVALID_COMPUTERNAME", "The format of the specified computer name is invalid."),
        0x000004bb: ("ERROR_INVALID_EVENTNAME", "The format of the specified event name is invalid."),
        0x000004bc: ("ERROR_INVALID_DOMAINNAME", "The format of the specified domain name is invalid."),
        0x000004bd: ("ERROR_INVALID_SERVICENAME", "The format of the specified service name is invalid."),
        0x000004be: ("ERROR_INVALID_NETNAME", "The format of the specified network name is invalid."),
        0x000004bf: ("ERROR_INVALID_SHARENAME", "The format of the specified share name is invalid."),
        0x000004c0: ("ERROR_INVALID_PASSWORDNAME", "The format of the specified password is invalid."),
        0x000004c1: ("ERROR_INVALID_MESSAGENAME", "The format of the specified message name is invalid."),
        0x000004c2: ("ERROR_INVALID_MESSAGEDEST", "The format of the specified message destination is invalid."),
        0x000004c3: ("ERROR_SESSION_CREDENTIAL_CONFLICT", "Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again."),
        0x000004c4: ("ERROR_REMOTE_SESSION_LIMIT_EXCEEDED", "An attempt was made to establish a session to a network server, but there are already too many sessions established to that server."),
        0x000004c5: ("ERROR_DUP_DOMAINNAME", "The workgroup or domain name is already in use by another computer on the network."),
        0x000004c6: ("ERROR_NO_NETWORK", "The network is not present or not started."),
        0x000004c7: ("ERROR_CANCELLED", "The operation was canceled by the user."),
        0x000004c8: ("ERROR_USER_MAPPED_FILE", "The requested operation cannot be performed on a file with a user-mapped section open."),
        0x000004c9: ("ERROR_CONNECTION_REFUSED", "The remote computer refused the network connection."),
        0x000004ca: ("ERROR_GRACEFUL_DISCONNECT", "The network connection was gracefully closed."),
        0x000004cb: ("ERROR_ADDRESS_ALREADY_ASSOCIATED", "The network transport endpoint already has an address associated with it."),
        0x000004cc: ("ERROR_ADDRESS_NOT_ASSOCIATED", "An address has not yet been associated with the network endpoint."),
        0x000004cd: ("ERROR_CONNECTION_INVALID", "An operation was attempted on a nonexistent network connection."),
        0x000004ce: ("ERROR_CONNECTION_ACTIVE", "An invalid operation was attempted on an active network connection."),
        0x000004cf: ("ERROR_NETWORK_UNREACHABLE", "The network location cannot be reached. For information about network troubleshooting, see Windows Help."),
        0x000004d0: ("ERROR_HOST_UNREACHABLE", "The network location cannot be reached. For information about network troubleshooting, see Windows Help."),
        0x000004d1: ("ERROR_PROTOCOL_UNREACHABLE", "The network location cannot be reached. For information about network troubleshooting, see Windows Help."),
        0x000004d2: ("ERROR_PORT_UNREACHABLE", "No service is operating at the destination network endpoint on the remote system."),
        0x000004d3: ("ERROR_REQUEST_ABORTED", "The request was aborted."),
        0x000004d4: ("ERROR_CONNECTION_ABORTED", "The network connection was aborted by the local system."),
        0x000004d5: ("ERROR_RETRY", "The operation could not be completed. A retry should be performed."),
        0x000004d6: ("ERROR_CONNECTION_COUNT_LIMIT", "A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached."),
        0x000004d7: ("ERROR_LOGIN_TIME_RESTRICTION", "Attempting to log in during an unauthorized time of day for this account."),
        0x000004d8: ("ERROR_LOGIN_WKSTA_RESTRICTION", "The account is not authorized to log in from this station."),
        0x000004d9: ("ERROR_INCORRECT_ADDRESS", "The network address could not be used for the operation requested."),
        0x000004da: ("ERROR_ALREADY_REGISTERED", "The service is already registered."),
        0x000004db: ("ERROR_SERVICE_NOT_FOUND", "The specified service does not exist."),
        0x000004dc: ("ERROR_NOT_AUTHENTICATED", "The operation being requested was not performed because the user has not been authenticated."),
        0x000004dd: ("ERROR_NOT_LOGGED_ON", "The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist."),
        0x000004de: ("ERROR_CONTINUE", "Continue with work in progress."),
        0x000004df: ("ERROR_ALREADY_INITIALIZED", "An attempt was made to perform an initialization operation when initialization has already been completed."),
        0x000004e0: ("ERROR_NO_MORE_DEVICES", "No more local devices."),
        0x000004e1: ("ERROR_NO_SUCH_SITE", "The specified site does not exist."),
        0x000004e2: ("ERROR_DOMAIN_CONTROLLER_EXISTS", "A domain controller with the specified name already exists."),
        0x000004e3: ("ERROR_ONLY_IF_CONNECTED", "This operation is supported only when you are connected to the server."),
        0x000004e4: ("ERROR_OVERRIDE_NOCHANGES", "The group policy framework should call the extension even if there are no changes."),
        0x000004e5: ("ERROR_BAD_USER_PROFILE", "The specified user does not have a valid profile."),
        0x000004e6: ("ERROR_NOT_SUPPORTED_ON_SBS", "This operation is not supported on a computer running Windows Server 2003 for Small Business Server"),
        0x000004e7: ("ERROR_SERVER_SHUTDOWN_IN_PROGRESS", "The server machine is shutting down."),
        0x000004e8: ("ERROR_HOST_DOWN", "The remote system is not available. For information about network troubleshooting, see Windows Help."),
        0x000004e9: ("ERROR_NON_ACCOUNT_SID", "The security identifier provided is not from an account domain."),
        0x000004ea: ("ERROR_NON_DOMAIN_SID", "The security identifier provided does not have a domain component."),
        0x000004eb: ("ERROR_APPHELP_BLOCK", "AppHelp dialog canceled thus preventing the application from starting."),
        0x000004ec: ("ERROR_ACCESS_DISABLED_BY_POLICY", "This program is blocked by group policy. For more information, contact your system administrator."),
        0x000004ed: ("ERROR_REG_NAT_CONSUMPTION", "A program attempt to use an invalid register value. Normally caused by an uninitialized register. This error is Itanium specific."),
        0x000004ee: ("ERROR_CSCSHARE_OFFLINE", "The share is currently offline or does not exist."),
        0x000004ef: ("ERROR_PKINIT_FAILURE", "The Kerberos protocol encountered an error while validating the KDC certificate during smartcard logon. There is more information in the system event log."),
        0x000004f0: ("ERROR_SMARTCARD_SUBSYSTEM_FAILURE", "The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem."),
        0x000004f1: ("ERROR_DOWNGRADE_DETECTED", "The system cannot contact a domain controller to service the authentication request. Please try again later."),
        0x000004f7: ("ERROR_MACHINE_LOCKED", "The machine is locked and cannot be shut down without the force option."),
        0x000004f9: ("ERROR_CALLBACK_SUPPLIED_INVALID_DATA", "An application-defined callback gave invalid data when called."),
        0x000004fa: ("ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED", "The group policy framework should call the extension in the synchronous foreground policy refresh."),
        0x000004fb: ("ERROR_DRIVER_BLOCKED", "This driver has been blocked from loading"),
        0x000004fc: ("ERROR_INVALID_IMPORT_OF_NON_DLL", "A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image."),
        0x000004fd: ("ERROR_ACCESS_DISABLED_WEBBLADE", "Windows cannot open this program since it has been disabled."),
        0x000004fe: ("ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER", "Windows cannot open this program because the license enforcement system has been tampered with or become corrupted."),
        0x000004ff: ("ERROR_RECOVERY_FAILURE", "A transaction recover failed."),
        0x00000500: ("ERROR_ALREADY_FIBER", "The current thread has already been converted to a fiber."),
        0x00000501: ("ERROR_ALREADY_THREAD", "The current thread has already been converted from a fiber."),
        0x00000502: ("ERROR_STACK_BUFFER_OVERRUN", "The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application."),
        0x00000503: ("ERROR_PARAMETER_QUOTA_EXCEEDED", "Data present in one of the parameters is more than the function can operate on."),
        0x00000504: ("ERROR_DEBUGGER_INACTIVE", "An attempt to do an operation on a debug object failed because the object is in the process of being deleted."),
        0x00000505: ("ERROR_DELAY_LOAD_FAILED", "An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed."),
        0x00000506: ("ERROR_VDM_DISALLOWED", "%1 is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator."),
        0x00000507: ("ERROR_UNIDENTIFIED_ERROR", "Insufficient information exists to identify the cause of failure."),
        0x00000508: ("ERROR_INVALID_CRUNTIME_PARAMETER", "The parameter passed to a C runtime function is incorrect."),
        0x00000509: ("ERROR_BEYOND_VDL", "The operation occurred beyond the valid data length of the file."),
        0x0000050a: ("ERROR_INCOMPATIBLE_SERVICE_SID_TYPE", "The service start failed since one or more services in the same process have an incompatible service SID type setting. A service with restricted service SID type can only coexist in the same process with other services with a restricted SID type. If the service SID type for this service was just configured, the hosting process must be restarted in order to start this service."),
        0x0000050b: ("ERROR_DRIVER_PROCESS_TERMINATED", "The process hosting the driver for this device has been terminated."),
        0x0000050c: ("ERROR_IMPLEMENTATION_LIMIT", "An operation attempted to exceed an implementation-defined limit."),
        0x0000050d: ("ERROR_PROCESS_IS_PROTECTED", "Either the target process, or the target thread's containing process, is a protected process."),
        0x0000050e: ("ERROR_SERVICE_NOTIFY_CLIENT_LAGGING", "The service notification client is lagging too far behind the current state of services in the machine."),
        0x0000050f: ("ERROR_DISK_QUOTA_EXCEEDED", "The requested file operation failed because the storage quota was exceeded."),
        0x00000510: ("ERROR_CONTENT_BLOCKED", "The requested file operation failed because the storage policy blocks that type of file. For more information, contact your system administrator."),
        0x00000511: ("ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE", "A privilege that the service requires to function properly does not exist in the service account configuration."),
        0x00000512: ("ERROR_APP_HANG", "A thread involved in this operation appears to be unresponsive."),
        0x00000513: ("ERROR_INVALID_LABEL", "Indicates a particular Security ID may not be assigned as the label of an object."),
        0x00000514: ("ERROR_NOT_ALL_ASSIGNED", "Not all privileges or groups referenced are assigned to the caller."),
        0x00000515: ("ERROR_SOME_NOT_MAPPED", "Some mapping between account names and security IDs was not done."),
        0x00000516: ("ERROR_NO_QUOTAS_FOR_ACCOUNT", "No system quota limits are specifically set for this account."),
        0x00000517: ("ERROR_LOCAL_USER_SESSION_KEY", "No encryption key is available. A well-known encryption key was returned."),
        0x00000518: ("ERROR_NULL_LM_PASSWORD", "The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a NULL string."),
        0x00000519: ("ERROR_UNKNOWN_REVISION", "The revision level is unknown."),
        0x0000051a: ("ERROR_REVISION_MISMATCH", "Indicates two revision levels are incompatible."),
        0x0000051b: ("ERROR_INVALID_OWNER", "This security ID may not be assigned as the owner of this object."),
        0x0000051c: ("ERROR_INVALID_PRIMARY_GROUP", "This security ID may not be assigned as the primary group of an object."),
        0x0000051d: ("ERROR_NO_IMPERSONATION_TOKEN", "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client."),
        0x0000051e: ("ERROR_CANT_DISABLE_MANDATORY", "The group may not be disabled."),
        0x0000051f: ("ERROR_NO_LOGON_SERVERS", "There are currently no logon servers available to service the logon request."),
        0x00000520: ("ERROR_NO_SUCH_LOGON_SESSION", "A specified logon session does not exist. It may already have been terminated."),
        0x00000521: ("ERROR_NO_SUCH_PRIVILEGE", "A specified privilege does not exist."),
        0x00000522: ("ERROR_PRIVILEGE_NOT_HELD", "A required privilege is not held by the client."),
        0x00000523: ("ERROR_INVALID_ACCOUNT_NAME", "The name provided is not a properly formed account name."),
        0x00000524: ("ERROR_USER_EXISTS", "The specified account already exists."),
        0x00000525: ("ERROR_NO_SUCH_USER", "The specified account does not exist."),
        0x00000526: ("ERROR_GROUP_EXISTS", "The specified group already exists."),
        0x00000527: ("ERROR_NO_SUCH_GROUP", "The specified group does not exist."),
        0x00000528: ("ERROR_MEMBER_IN_GROUP", "Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member."),
        0x00000529: ("ERROR_MEMBER_NOT_IN_GROUP", "The specified user account is not a member of the specified group account."),
        0x0000052a: ("ERROR_LAST_ADMIN", "This operation is disallowed as it could result in an administration account being disabled, deleted or unable to logon."),
        0x0000052b: ("ERROR_WRONG_PASSWORD", "Unable to update the password. The value provided as the current password is incorrect."),
        0x0000052c: ("ERROR_ILL_FORMED_PASSWORD", "Unable to update the password. The value provided for the new password contains values that are not allowed in passwords."),
        0x0000052d: ("ERROR_PASSWORD_RESTRICTION", "Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain."),
        0x0000052e: ("ERROR_LOGON_FAILURE", "The user name or password is incorrect."),
        0x0000052f: ("ERROR_ACCOUNT_RESTRICTION", "Account restrictions are preventing this user from signing in. For example: blank passwords aren't allowed, sign-in times are limited, or a policy restriction has been enforced."),
        0x00000530: ("ERROR_INVALID_LOGON_HOURS", "Your account has time restrictions that keep you from signing in right now."),
        0x00000531: ("ERROR_INVALID_WORKSTATION", "This user isn't allowed to sign in to this computer."),
        0x00000532: ("ERROR_PASSWORD_EXPIRED", "The password for this account has expired."),
        0x00000533: ("ERROR_ACCOUNT_DISABLED", "This user can't sign in because this account is currently disabled."),
        0x00000534: ("ERROR_NONE_MAPPED", "No mapping between account names and security IDs was done."),
        0x00000535: ("ERROR_TOO_MANY_LUIDS_REQUESTED", "Too many local user identifiers (LUIDs) were requested at one time."),
        0x00000536: ("ERROR_LUIDS_EXHAUSTED", "No more local user identifiers (LUIDs) are available."),
        0x00000537: ("ERROR_INVALID_SUB_AUTHORITY", "The subauthority part of a security ID is invalid for this particular use."),
        0x00000538: ("ERROR_INVALID_ACL", "The access control list (ACL) structure is invalid."),
        0x00000539: ("ERROR_INVALID_SID", "The security ID structure is invalid."),
        0x0000053a: ("ERROR_INVALID_SECURITY_DESCR", "The security descriptor structure is invalid."),
        0x0000053c: ("ERROR_BAD_INHERITANCE_ACL", "The inherited access control list (ACL) or access control entry (ACE) could not be built."),
        0x0000053d: ("ERROR_SERVER_DISABLED", "The server is currently disabled."),
        0x0000053e: ("ERROR_SERVER_NOT_DISABLED", "The server is currently enabled."),
        0x0000053f: ("ERROR_INVALID_ID_AUTHORITY", "The value provided was an invalid value for an identifier authority."),
        0x00000540: ("ERROR_ALLOTTED_SPACE_EXCEEDED", "No more memory is available for security information updates."),
        0x00000541: ("ERROR_INVALID_GROUP_ATTRIBUTES", "The specified attributes are invalid, or incompatible with the attributes for the group as a whole."),
        0x00000542: ("ERROR_BAD_IMPERSONATION_LEVEL", "Either a required impersonation level was not provided, or the provided impersonation level is invalid."),
        0x00000543: ("ERROR_CANT_OPEN_ANONYMOUS", "Cannot open an anonymous level security token."),
        0x00000544: ("ERROR_BAD_VALIDATION_CLASS", "The validation information class requested was invalid."),
        0x00000545: ("ERROR_BAD_TOKEN_TYPE", "The type of the token is inappropriate for its attempted use."),
        0x00000546: ("ERROR_NO_SECURITY_ON_OBJECT", "Unable to perform a security operation on an object that has no associated security."),
        0x00000547: ("ERROR_CANT_ACCESS_DOMAIN_INFO", "Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied."),
        0x00000548: ("ERROR_INVALID_SERVER_STATE", "The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation."),
        0x00000549: ("ERROR_INVALID_DOMAIN_STATE", "The domain was in the wrong state to perform the security operation."),
        0x0000054a: ("ERROR_INVALID_DOMAIN_ROLE", "This operation is only allowed for the Primary Domain Controller of the domain."),
        0x0000054b: ("ERROR_NO_SUCH_DOMAIN", "The specified domain either does not exist or could not be contacted."),
        0x0000054c: ("ERROR_DOMAIN_EXISTS", "The specified domain already exists."),
        0x0000054d: ("ERROR_DOMAIN_LIMIT_EXCEEDED", "An attempt was made to exceed the limit on the number of domains per server."),
        0x0000054e: ("ERROR_INTERNAL_DB_CORRUPTION", "Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk."),
        0x0000054f: ("ERROR_INTERNAL_ERROR", "An internal error occurred."),
        0x00000550: ("ERROR_GENERIC_NOT_MAPPED", "Generic access types were contained in an access mask which should already be mapped to nongeneric types."),
        0x00000551: ("ERROR_BAD_DESCRIPTOR_FORMAT", "A security descriptor is not in the right format (absolute or self-relative)."),
        0x00000552: ("ERROR_NOT_LOGON_PROCESS", "The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process."),
        0x00000553: ("ERROR_LOGON_SESSION_EXISTS", "Cannot start a new logon session with an ID that is already in use."),
        0x00000554: ("ERROR_NO_SUCH_PACKAGE", "A specified authentication package is unknown."),
        0x00000555: ("ERROR_BAD_LOGON_SESSION_STATE", "The logon session is not in a state that is consistent with the requested operation."),
        0x00000556: ("ERROR_LOGON_SESSION_COLLISION", "The logon session ID is already in use."),
        0x00000557: ("ERROR_INVALID_LOGON_TYPE", "A logon request contained an invalid logon type value."),
        0x00000558: ("ERROR_CANNOT_IMPERSONATE", "Unable to impersonate using a named pipe until data has been read from that pipe."),
        0x00000559: ("ERROR_RXACT_INVALID_STATE", "The transaction state of a registry subtree is incompatible with the requested operation."),
        0x0000055a: ("ERROR_RXACT_COMMIT_FAILURE", "An internal security database corruption has been encountered."),
        0x0000055b: ("ERROR_SPECIAL_ACCOUNT", "Cannot perform this operation on built-in accounts."),
        0x0000055c: ("ERROR_SPECIAL_GROUP", "Cannot perform this operation on this built-in special group."),
        0x0000055d: ("ERROR_SPECIAL_USER", "Cannot perform this operation on this built-in special user."),
        0x0000055e: ("ERROR_MEMBERS_PRIMARY_GROUP", "The user cannot be removed from a group because the group is currently the user's primary group."),
        0x0000055f: ("ERROR_TOKEN_ALREADY_IN_USE", "The token is already in use as a primary token."),
        0x00000560: ("ERROR_NO_SUCH_ALIAS", "The specified local group does not exist."),
        0x00000561: ("ERROR_MEMBER_NOT_IN_ALIAS", "The specified account name is not a member of the group."),
        0x00000562: ("ERROR_MEMBER_IN_ALIAS", "The specified account name is already a member of the group."),
        0x00000563: ("ERROR_ALIAS_EXISTS", "The specified local group already exists."),
        0x00000564: ("ERROR_LOGON_NOT_GRANTED", "Logon failure: the user has not been granted the requested logon type at this computer."),
        0x00000565: ("ERROR_TOO_MANY_SECRETS", "The maximum number of secrets that may be stored in a single system has been exceeded."),
        0x00000566: ("ERROR_SECRET_TOO_LONG", "The length of a secret exceeds the maximum length allowed."),
        0x00000567: ("ERROR_INTERNAL_DB_ERROR", "The local security authority database contains an internal inconsistency."),
        0x00000568: ("ERROR_TOO_MANY_CONTEXT_IDS", "During a logon attempt, the user's security context accumulated too many security IDs."),
        0x00000569: ("ERROR_LOGON_TYPE_NOT_GRANTED", "Logon failure: the user has not been granted the requested logon type at this computer."),
        0x0000056a: ("ERROR_NT_CROSS_ENCRYPTION_REQUIRED", "A cross-encrypted password is necessary to change a user password."),
        0x0000056b: ("ERROR_NO_SUCH_MEMBER", "A member could not be added to or removed from the local group because the member does not exist."),
        0x0000056c: ("ERROR_INVALID_MEMBER", "A new member could not be added to a local group because the member has the wrong account type."),
        0x0000056d: ("ERROR_TOO_MANY_SIDS", "Too many security IDs have been specified."),
        0x0000056e: ("ERROR_LM_CROSS_ENCRYPTION_REQUIRED", "A cross-encrypted password is necessary to change this user password."),
        0x0000056f: ("ERROR_NO_INHERITANCE", "Indicates an ACL contains no inheritable components."),
        0x00000570: ("ERROR_FILE_CORRUPT", "The file or directory is corrupted and unreadable."),
        0x00000571: ("ERROR_DISK_CORRUPT", "The disk structure is corrupted and unreadable."),
        0x00000572: ("ERROR_NO_USER_SESSION_KEY", "There is no user session key for the specified logon session."),
        0x00000573: ("ERROR_LICENSE_QUOTA_EXCEEDED", "The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because there are already as many connections as the service can accept."),
        0x00000574: ("ERROR_WRONG_TARGET_NAME", "The target account name is incorrect."),
        0x00000575: ("ERROR_MUTUAL_AUTH_FAILED", "Mutual Authentication failed. The server's password is out of date at the domain controller."),
        0x00000576: ("ERROR_TIME_SKEW", "There is a time and/or date difference between the client and server."),
        0x00000577: ("ERROR_CURRENT_DOMAIN_NOT_ALLOWED", "This operation cannot be performed on the current domain."),
        0x00000578: ("ERROR_INVALID_WINDOW_HANDLE", "Invalid window handle."),
        0x00000579: ("ERROR_INVALID_MENU_HANDLE", "Invalid menu handle."),
        0x0000057a: ("ERROR_INVALID_CURSOR_HANDLE", "Invalid cursor handle."),
        0x0000057b: ("ERROR_INVALID_ACCEL_HANDLE", "Invalid accelerator table handle."),
        0x0000057c: ("ERROR_INVALID_HOOK_HANDLE", "Invalid hook handle."),
        0x0000057d: ("ERROR_INVALID_DWP_HANDLE", "Invalid handle to a multiple-window position structure."),
        0x0000057e: ("ERROR_TLW_WITH_WSCHILD", "Cannot create a top-level child window."),
        0x0000057f: ("ERROR_CANNOT_FIND_WND_CLASS", "Cannot find window class."),
        0x00000580: ("ERROR_WINDOW_OF_OTHER_THREAD", "Invalid window; it belongs to other thread."),
        0x00000581: ("ERROR_HOTKEY_ALREADY_REGISTERED", "Hot key is already registered."),
        0x00000582: ("ERROR_CLASS_ALREADY_EXISTS", "Class already exists."),
        0x00000583: ("ERROR_CLASS_DOES_NOT_EXIST", "Class does not exist."),
        0x00000584: ("ERROR_CLASS_HAS_WINDOWS", "Class still has open windows."),
        0x00000585: ("ERROR_INVALID_INDEX", "Invalid index."),
        0x00000586: ("ERROR_INVALID_ICON_HANDLE", "Invalid icon handle."),
        0x00000587: ("ERROR_PRIVATE_DIALOG_INDEX", "Using private DIALOG window words."),
        0x00000588: ("ERROR_LISTBOX_ID_NOT_FOUND", "The list box identifier was not found."),
        0x00000589: ("ERROR_NO_WILDCARD_CHARACTERS", "No wildcards were found."),
        0x0000058a: ("ERROR_CLIPBOARD_NOT_OPEN", "Thread does not have a clipboard open."),
        0x0000058b: ("ERROR_HOTKEY_NOT_REGISTERED", "Hot key is not registered."),
        0x0000058c: ("ERROR_WINDOW_NOT_DIALOG", "The window is not a valid dialog window."),
        0x0000058d: ("ERROR_CONTROL_ID_NOT_FOUND", "Control ID not found."),
        0x0000058e: ("ERROR_INVALID_COMBOBOX_MESSAGE", "Invalid message for a combo box because it does not have an edit control."),
        0x0000058f: ("ERROR_WINDOW_NOT_COMBOBOX", "The window is not a combo box."),
        0x00000590: ("ERROR_INVALID_EDIT_HEIGHT", "Height must be less than 256."),
        0x00000591: ("ERROR_DC_NOT_FOUND", "Invalid device context (DC) handle."),
        0x00000592: ("ERROR_INVALID_HOOK_FILTER", "Invalid hook procedure type."),
        0x00000593: ("ERROR_INVALID_FILTER_PROC", "Invalid hook procedure."),
        0x00000594: ("ERROR_HOOK_NEEDS_HMOD", "Cannot set nonlocal hook without a module handle."),
        0x00000595: ("ERROR_GLOBAL_ONLY_HOOK", "This hook procedure can only be set globally."),
        0x00000596: ("ERROR_JOURNAL_HOOK_SET", "The journal hook procedure is already installed."),
        0x00000597: ("ERROR_HOOK_NOT_INSTALLED", "The hook procedure is not installed."),
        0x00000598: ("ERROR_INVALID_LB_MESSAGE", "Invalid message for single-selection list box."),
        0x00000599: ("ERROR_SETCOUNT_ON_BAD_LB", "LB_SETCOUNT sent to non-lazy list box."),
        0x0000059a: ("ERROR_LB_WITHOUT_TABSTOPS", "This list box does not support tab stops."),
        0x0000059b: ("ERROR_DESTROY_OBJECT_OF_OTHER_THREAD", "Cannot destroy object created by another thread."),
        0x0000059c: ("ERROR_CHILD_WINDOW_MENU", "Child windows cannot have menus."),
        0x0000059d: ("ERROR_NO_SYSTEM_MENU", "The window does not have a system menu."),
        0x0000059e: ("ERROR_INVALID_MSGBOX_STYLE", "Invalid message box style."),
        0x0000059f: ("ERROR_INVALID_SPI_VALUE", "Invalid system-wide (SPI_*) parameter."),
        0x000005a0: ("ERROR_SCREEN_ALREADY_LOCKED", "Screen already locked."),
        0x000005a1: ("ERROR_HWNDS_HAVE_DIFF_PARENT", "All handles to windows in a multiple-window position structure must have the same parent."),
        0x000005a2: ("ERROR_NOT_CHILD_WINDOW", "The window is not a child window."),
        0x000005a3: ("ERROR_INVALID_GW_COMMAND", "Invalid GW_* command."),
        0x000005a4: ("ERROR_INVALID_THREAD_ID", "Invalid thread identifier."),
        0x000005a5: ("ERROR_NON_MDICHILD_WINDOW", "Cannot process a message from a window that is not a multiple document interface (MDI) window."),
        0x000005a6: ("ERROR_POPUP_ALREADY_ACTIVE", "Popup menu already active."),
        0x000005a7: ("ERROR_NO_SCROLLBARS", "The window does not have scroll bars."),
        0x000005a8: ("ERROR_INVALID_SCROLLBAR_RANGE", "Scroll bar range cannot be greater than MAXLONG."),
        0x000005a9: ("ERROR_INVALID_SHOWWIN_COMMAND", "Cannot show or remove the window in the way specified."),
        0x000005aa: ("ERROR_NO_SYSTEM_RESOURCES", "Insufficient system resources exist to complete the requested service."),
        0x000005ab: ("ERROR_NONPAGED_SYSTEM_RESOURCES", "Insufficient system resources exist to complete the requested service."),
        0x000005ac: ("ERROR_PAGED_SYSTEM_RESOURCES", "Insufficient system resources exist to complete the requested service."),
        0x000005ad: ("ERROR_WORKING_SET_QUOTA", "Insufficient quota to complete the requested service."),
        0x000005ae: ("ERROR_PAGEFILE_QUOTA", "Insufficient quota to complete the requested service."),
        0x000005af: ("ERROR_COMMITMENT_LIMIT", "The paging file is too small for this operation to complete."),
        0x000005b0: ("ERROR_MENU_ITEM_NOT_FOUND", "A menu item was not found."),
        0x000005b1: ("ERROR_INVALID_KEYBOARD_HANDLE", "Invalid keyboard layout handle."),
        0x000005b2: ("ERROR_HOOK_TYPE_NOT_ALLOWED", "Hook type not allowed."),
        0x000005b3: ("ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION", "This operation requires an interactive window station."),
        0x000005b4: ("ERROR_TIMEOUT", "This operation returned because the timeout period expired."),
        0x000005b5: ("ERROR_INVALID_MONITOR_HANDLE", "Invalid monitor handle."),
        0x000005b6: ("ERROR_INCORRECT_SIZE", "Incorrect size argument."),
        0x000005b7: ("ERROR_SYMLINK_CLASS_DISABLED", "The symbolic link cannot be followed because its type is disabled."),
        0x000005b8: ("ERROR_SYMLINK_NOT_SUPPORTED", "This application does not support the current operation on symbolic links."),
        0x000005b9: ("ERROR_XML_PARSE_ERROR", "Windows was unable to parse the requested XML data."),
        0x000005ba: ("ERROR_XMLDSIG_ERROR", "An error was encountered while processing an XML digital signature."),
        0x000005bb: ("ERROR_RESTART_APPLICATION", "This application must be restarted."),
        0x000005bc: ("ERROR_WRONG_COMPARTMENT", "The caller made the connection request in the wrong routing compartment."),
        0x000005bd: ("ERROR_AUTHIP_FAILURE", "There was an AuthIP failure when attempting to connect to the remote host."),
        0x000005be: ("ERROR_NO_NVRAM_RESOURCES", "Insufficient NVRAM resources exist to complete the requested service. A reboot might be required."),
        0x000005bf: ("ERROR_NOT_GUI_PROCESS", "Unable to finish the requested operation because the specified process is not a GUI process."),
        0x000005dc: ("ERROR_EVENTLOG_FILE_CORRUPT", "The event log file is corrupted."),
        0x000005dd: ("ERROR_EVENTLOG_CANT_START", "No event log file could be opened, so the event logging service did not start."),
        0x000005de: ("ERROR_LOG_FILE_FULL", "The event log file is full."),
        0x000005df: ("ERROR_EVENTLOG_FILE_CHANGED", "The event log file has changed between read operations."),
        0x0000060e: ("ERROR_INVALID_TASK_NAME", "The specified task name is invalid."),
        0x0000060f: ("ERROR_INVALID_TASK_INDEX", "The specified task index is invalid."),
        0x00000610: ("ERROR_THREAD_ALREADY_IN_TASK", "The specified thread is already joining a task."),
        0x00000641: ("ERROR_INSTALL_SERVICE_FAILURE", "The Windows Installer Service could not be accessed. This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance."),
        0x00000642: ("ERROR_INSTALL_USEREXIT", "User cancelled installation."),
        0x00000643: ("ERROR_INSTALL_FAILURE", "Fatal error during installation."),
        0x00000644: ("ERROR_INSTALL_SUSPEND", "Installation suspended, incomplete."),
        0x00000645: ("ERROR_UNKNOWN_PRODUCT", "This action is only valid for products that are currently installed."),
        0x00000646: ("ERROR_UNKNOWN_FEATURE", "Feature ID not registered."),
        0x00000647: ("ERROR_UNKNOWN_COMPONENT", "Component ID not registered."),
        0x00000648: ("ERROR_UNKNOWN_PROPERTY", "Unknown property."),
        0x00000649: ("ERROR_INVALID_HANDLE_STATE", "Handle is in an invalid state."),
        0x0000064a: ("ERROR_BAD_CONFIGURATION", "The configuration data for this product is corrupt. Contact your support personnel."),
        0x0000064b: ("ERROR_INDEX_ABSENT", "Component qualifier not present."),
        0x0000064c: ("ERROR_INSTALL_SOURCE_ABSENT", "The installation source for this product is not available. Verify that the source exists and that you can access it."),
        0x0000064d: ("ERROR_INSTALL_PACKAGE_VERSION", "This installation package cannot be installed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."),
        0x0000064e: ("ERROR_PRODUCT_UNINSTALLED", "Product is uninstalled."),
        0x0000064f: ("ERROR_BAD_QUERY_SYNTAX", "SQL query syntax invalid or unsupported."),
        0x00000650: ("ERROR_INVALID_FIELD", "Record field does not exist."),
        0x00000651: ("ERROR_DEVICE_REMOVED", "The device has been removed."),
        0x00000652: ("ERROR_INSTALL_ALREADY_RUNNING", "Another installation is already in progress. Complete that installation before proceeding with this install."),
        0x00000653: ("ERROR_INSTALL_PACKAGE_OPEN_FAILED", "This installation package could not be opened. Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package."),
        0x00000654: ("ERROR_INSTALL_PACKAGE_INVALID", "This installation package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer package."),
        0x00000655: ("ERROR_INSTALL_UI_FAILURE", "There was an error starting the Windows Installer service user interface. Contact your support personnel."),
        0x00000656: ("ERROR_INSTALL_LOG_FAILURE", "Error opening installation log file. Verify that the specified log file location exists and that you can write to it."),
        0x00000657: ("ERROR_INSTALL_LANGUAGE_UNSUPPORTED", "The language of this installation package is not supported by your system."),
        0x00000658: ("ERROR_INSTALL_TRANSFORM_FAILURE", "Error applying transforms. Verify that the specified transform paths are valid."),
        0x00000659: ("ERROR_INSTALL_PACKAGE_REJECTED", "This installation is forbidden by system policy. Contact your system administrator."),
        0x0000065a: ("ERROR_FUNCTION_NOT_CALLED", "Function could not be executed."),
        0x0000065b: ("ERROR_FUNCTION_FAILED", "Function failed during execution."),
        0x0000065c: ("ERROR_INVALID_TABLE", "Invalid or unknown table specified."),
        0x0000065d: ("ERROR_DATATYPE_MISMATCH", "Data supplied is of wrong type."),
        0x0000065e: ("ERROR_UNSUPPORTED_TYPE", "Data of this type is not supported."),
        0x0000065f: ("ERROR_CREATE_FAILED", "The Windows Installer service failed to start. Contact your support personnel."),
        0x00000660: ("ERROR_INSTALL_TEMP_UNWRITABLE", "The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder."),
        0x00000661: ("ERROR_INSTALL_PLATFORM_UNSUPPORTED", "This installation package is not supported by this processor type. Contact your product vendor."),
        0x00000662: ("ERROR_INSTALL_NOTUSED", "Component not used on this computer."),
        0x00000663: ("ERROR_PATCH_PACKAGE_OPEN_FAILED", "This update package could not be opened. Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package."),
        0x00000664: ("ERROR_PATCH_PACKAGE_INVALID", "This update package could not be opened. Contact the application vendor to verify that this is a valid Windows Installer update package."),
        0x00000665: ("ERROR_PATCH_PACKAGE_UNSUPPORTED", "This update package cannot be processed by the Windows Installer service. You must install a Windows service pack that contains a newer version of the Windows Installer service."),
        0x00000666: ("ERROR_PRODUCT_VERSION", "Another version of this product is already installed. Installation of this version cannot continue. To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel."),
        0x00000667: ("ERROR_INVALID_COMMAND_LINE", "Invalid command line argument. Consult the Windows Installer SDK for detailed command line help."),
        0x00000668: ("ERROR_INSTALL_REMOTE_DISALLOWED", "Only administrators have permission to add, remove, or configure server software during a Terminal services remote session. If you want to install or configure software on the server, contact your network administrator."),
        0x00000669: ("ERROR_SUCCESS_REBOOT_INITIATED", "The requested operation completed successfully. The system will be restarted so the changes can take effect."),
        0x0000066a: ("ERROR_PATCH_TARGET_NOT_FOUND", "The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program. Verify that the program to be upgraded exists on your computer and that you have the correct upgrade."),
        0x0000066b: ("ERROR_PATCH_PACKAGE_REJECTED", "The update package is not permitted by software restriction policy."),
        0x0000066c: ("ERROR_INSTALL_TRANSFORM_REJECTED", "One or more customizations are not permitted by software restriction policy."),
        0x0000066d: ("ERROR_INSTALL_REMOTE_PROHIBITED", "The Windows Installer does not permit installation from a Remote Desktop Connection."),
        0x0000066e: ("ERROR_PATCH_REMOVAL_UNSUPPORTED", "Uninstallation of the update package is not supported."),
        0x0000066f: ("ERROR_UNKNOWN_PATCH", "The update is not applied to this product."),
        0x00000670: ("ERROR_PATCH_NO_SEQUENCE", "No valid sequence could be found for the set of updates."),
        0x00000671: ("ERROR_PATCH_REMOVAL_DISALLOWED", "Update removal was disallowed by policy."),
        0x00000672: ("ERROR_INVALID_PATCH_XML", "The XML update data is invalid."),
        0x00000673: ("ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT", "Windows Installer does not permit updating of managed advertised products. At least one feature of the product must be installed before applying the update."),
        0x00000674: ("ERROR_INSTALL_SERVICE_SAFEBOOT", "The Windows Installer service is not accessible in Safe Mode. Please try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state."),
        0x00000675: ("ERROR_FAIL_FAST_EXCEPTION", "A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately."),
        0x00000676: ("ERROR_INSTALL_REJECTED", "The app that you are trying to run is not supported on this version of Windows."),
        0x000006a4: ("RPC_S_INVALID_STRING_BINDING", "The string binding is invalid."),
        0x000006a5: ("RPC_S_WRONG_KIND_OF_BINDING", "The binding handle is not the correct type."),
        0x000006a6: ("RPC_S_INVALID_BINDING", "The binding handle is invalid."),
        0x000006a7: ("RPC_S_PROTSEQ_NOT_SUPPORTED", "The RPC protocol sequence is not supported."),
        0x000006a8: ("RPC_S_INVALID_RPC_PROTSEQ", "The RPC protocol sequence is invalid."),
        0x000006a9: ("RPC_S_INVALID_STRING_UUID", "The string universal unique identifier (UUID) is invalid."),
        0x000006aa: ("RPC_S_INVALID_ENDPOINT_FORMAT", "The endpoint format is invalid."),
        0x000006ab: ("RPC_S_INVALID_NET_ADDR", "The network address is invalid."),
        0x000006ac: ("RPC_S_NO_ENDPOINT_FOUND", "No endpoint was found."),
        0x000006ad: ("RPC_S_INVALID_TIMEOUT", "The timeout value is invalid."),
        0x000006ae: ("RPC_S_OBJECT_NOT_FOUND", "The object universal unique identifier (UUID) was not found."),
        0x000006af: ("RPC_S_ALREADY_REGISTERED", "The object universal unique identifier (UUID) has already been registered."),
        0x000006b0: ("RPC_S_TYPE_ALREADY_REGISTERED", "The type universal unique identifier (UUID) has already been registered."),
        0x000006b1: ("RPC_S_ALREADY_LISTENING", "The RPC server is already listening."),
        0x000006b2: ("RPC_S_NO_PROTSEQS_REGISTERED", "No protocol sequences have been registered."),
        0x000006b3: ("RPC_S_NOT_LISTENING", "The RPC server is not listening."),
        0x000006b4: ("RPC_S_UNKNOWN_MGR_TYPE", "The manager type is unknown."),
        0x000006b5: ("RPC_S_UNKNOWN_IF", "The interface is unknown."),
        0x000006b6: ("RPC_S_NO_BINDINGS", "There are no bindings."),
        0x000006b7: ("RPC_S_NO_PROTSEQS", "There are no protocol sequences."),
        0x000006b8: ("RPC_S_CANT_CREATE_ENDPOINT", "The endpoint cannot be created."),
        0x000006b9: ("RPC_S_OUT_OF_RESOURCES", "Not enough resources are available to complete this operation."),
        0x000006ba: ("RPC_S_SERVER_UNAVAILABLE", "The RPC server is unavailable."),
        0x000006bb: ("RPC_S_SERVER_TOO_BUSY", "The RPC server is too busy to complete this operation."),
        0x000006bc: ("RPC_S_INVALID_NETWORK_OPTIONS", "The network options are invalid."),
        0x000006bd: ("RPC_S_NO_CALL_ACTIVE", "There are no remote procedure calls active on this thread."),
        0x000006be: ("RPC_S_CALL_FAILED", "The remote procedure call failed."),
        0x000006bf: ("RPC_S_CALL_FAILED_DNE", "The remote procedure call failed and did not execute."),
        0x000006c0: ("RPC_S_PROTOCOL_ERROR", "A remote procedure call (RPC) protocol error occurred."),
        0x000006c1: ("RPC_S_PROXY_ACCESS_DENIED", "Access to the HTTP proxy is denied."),
        0x000006c2: ("RPC_S_UNSUPPORTED_TRANS_SYN", "The transfer syntax is not supported by the RPC server."),
        0x000006c4: ("RPC_S_UNSUPPORTED_TYPE", "The universal unique identifier (UUID) type is not supported."),
        0x000006c5: ("RPC_S_INVALID_TAG", "The tag is invalid."),
        0x000006c6: ("RPC_S_INVALID_BOUND", "The array bounds are invalid."),
        0x000006c7: ("RPC_S_NO_ENTRY_NAME", "The binding does not contain an entry name."),
        0x000006c8: ("RPC_S_INVALID_NAME_SYNTAX", "The name syntax is invalid."),
        0x000006c9: ("RPC_S_UNSUPPORTED_NAME_SYNTAX", "The name syntax is not supported."),
        0x000006cb: ("RPC_S_UUID_NO_ADDRESS", "No network address is available to use to construct a universal unique identifier (UUID)."),
        0x000006cc: ("RPC_S_DUPLICATE_ENDPOINT", "The endpoint is a duplicate."),
        0x000006cd: ("RPC_S_UNKNOWN_AUTHN_TYPE", "The authentication type is unknown."),
        0x000006ce: ("RPC_S_MAX_CALLS_TOO_SMALL", "The maximum number of calls is too small."),
        0x000006cf: ("RPC_S_STRING_TOO_LONG", "The string is too long."),
        0x000006d0: ("RPC_S_PROTSEQ_NOT_FOUND", "The RPC protocol sequence was not found."),
        0x000006d1: ("RPC_S_PROCNUM_OUT_OF_RANGE", "The procedure number is out of range."),
        0x000006d2: ("RPC_S_BINDING_HAS_NO_AUTH", "The binding does not contain any authentication information."),
        0x000006d3: ("RPC_S_UNKNOWN_AUTHN_SERVICE", "The authentication service is unknown."),
        0x000006d4: ("RPC_S_UNKNOWN_AUTHN_LEVEL", "The authentication level is unknown."),
        0x000006d5: ("RPC_S_INVALID_AUTH_IDENTITY", "The security context is invalid."),
        0x000006d6: ("RPC_S_UNKNOWN_AUTHZ_SERVICE", "The authorization service is unknown."),
        0x000006d7: ("EPT_S_INVALID_ENTRY", "The entry is invalid."),
        0x000006d8: ("EPT_S_CANT_PERFORM_OP", "The server endpoint cannot perform the operation."),
        0x000006d9: ("EPT_S_NOT_REGISTERED", "There are no more endpoints available from the endpoint mapper."),
        0x000006da: ("RPC_S_NOTHING_TO_EXPORT", "No interfaces have been exported."),
        0x000006db: ("RPC_S_INCOMPLETE_NAME", "The entry name is incomplete."),
        0x000006dc: ("RPC_S_INVALID_VERS_OPTION", "The version option is invalid."),
        0x000006dd: ("RPC_S_NO_MORE_MEMBERS", "There are no more members."),
        0x000006de: ("RPC_S_NOT_ALL_OBJS_UNEXPORTED", "There is nothing to unexport."),
        0x000006df: ("RPC_S_INTERFACE_NOT_FOUND", "The interface was not found."),
        0x000006e0: ("RPC_S_ENTRY_ALREADY_EXISTS", "The entry already exists."),
        0x000006e1: ("RPC_S_ENTRY_NOT_FOUND", "The entry is not found."),
        0x000006e2: ("RPC_S_NAME_SERVICE_UNAVAILABLE", "The name service is unavailable."),
        0x000006e3: ("RPC_S_INVALID_NAF_ID", "The network address family is invalid."),
        0x000006e4: ("RPC_S_CANNOT_SUPPORT", "The requested operation is not supported."),
        0x000006e5: ("RPC_S_NO_CONTEXT_AVAILABLE", "No security context is available to allow impersonation."),
        0x000006e6: ("RPC_S_INTERNAL_ERROR", "An internal error occurred in a remote procedure call (RPC)."),
        0x000006e7: ("RPC_S_ZERO_DIVIDE", "The RPC server attempted an integer division by zero."),
        0x000006e8: ("RPC_S_ADDRESS_ERROR", "An addressing error occurred in the RPC server."),
        0x000006e9: ("RPC_S_FP_DIV_ZERO", "A floating-point operation at the RPC server caused a division by zero."),
        0x000006ea: ("RPC_S_FP_UNDERFLOW", "A floating-point underflow occurred at the RPC server."),
        0x000006eb: ("RPC_S_FP_OVERFLOW", "A floating-point overflow occurred at the RPC server."),
        0x000006ec: ("RPC_X_NO_MORE_ENTRIES", "The list of RPC servers available for the binding of auto handles has been exhausted."),
        0x000006ed: ("RPC_X_SS_CHAR_TRANS_OPEN_FAIL", "Unable to open the character translation table file."),
        0x000006ee: ("RPC_X_SS_CHAR_TRANS_SHORT_FILE", "The file containing the character translation table has fewer than 512 bytes."),
        0x000006ef: ("RPC_X_SS_IN_NULL_CONTEXT", "A null context handle was passed from the client to the host during a remote procedure call."),
        0x000006f1: ("RPC_X_SS_CONTEXT_DAMAGED", "The context handle changed during a remote procedure call."),
        0x000006f2: ("RPC_X_SS_HANDLES_MISMATCH", "The binding handles passed to a remote procedure call do not match."),
        0x000006f3: ("RPC_X_SS_CANNOT_GET_CALL_HANDLE", "The stub is unable to get the remote procedure call handle."),
        0x000006f4: ("RPC_X_NULL_REF_POINTER", "A null reference pointer was passed to the stub."),
        0x000006f5: ("RPC_X_ENUM_VALUE_OUT_OF_RANGE", "The enumeration value is out of range."),
        0x000006f6: ("RPC_X_BYTE_COUNT_TOO_SMALL", "The byte count is too small."),
        0x000006f7: ("RPC_X_BAD_STUB_DATA", "The stub received bad data."),
        0x000006f8: ("ERROR_INVALID_USER_BUFFER", "The supplied user buffer is not valid for the requested operation."),
        0x000006f9: ("ERROR_UNRECOGNIZED_MEDIA", "The disk media is not recognized. It may not be formatted."),
        0x000006fa: ("ERROR_NO_TRUST_LSA_SECRET", "The workstation does not have a trust secret."),
        0x000006fb: ("ERROR_NO_TRUST_SAM_ACCOUNT", "The security database on the server does not have a computer account for this workstation trust relationship."),
        0x000006fc: ("ERROR_TRUSTED_DOMAIN_FAILURE", "The trust relationship between the primary domain and the trusted domain failed."),
        0x000006fd: ("ERROR_TRUSTED_RELATIONSHIP_FAILURE", "The trust relationship between this workstation and the primary domain failed."),
        0x000006fe: ("ERROR_TRUST_FAILURE", "The network logon failed."),
        0x000006ff: ("RPC_S_CALL_IN_PROGRESS", "A remote procedure call is already in progress for this thread."),
        0x00000700: ("ERROR_NETLOGON_NOT_STARTED", "An attempt was made to logon, but the network logon service was not started."),
        0x00000701: ("ERROR_ACCOUNT_EXPIRED", "The user's account has expired."),
        0x00000702: ("ERROR_REDIRECTOR_HAS_OPEN_HANDLES", "The redirector is in use and cannot be unloaded."),
        0x00000703: ("ERROR_PRINTER_DRIVER_ALREADY_INSTALLED", "The specified printer driver is already installed."),
        0x00000704: ("ERROR_UNKNOWN_PORT", "The specified port is unknown."),
        0x00000705: ("ERROR_UNKNOWN_PRINTER_DRIVER", "The printer driver is unknown."),
        0x00000706: ("ERROR_UNKNOWN_PRINTPROCESSOR", "The print processor is unknown."),
        0x00000707: ("ERROR_INVALID_SEPARATOR_FILE", "The specified separator file is invalid."),
        0x00000708: ("ERROR_INVALID_PRIORITY", "The specified priority is invalid."),
        0x00000709: ("ERROR_INVALID_PRINTER_NAME", "The printer name is invalid."),
        0x0000070a: ("ERROR_PRINTER_ALREADY_EXISTS", "The printer already exists."),
        0x0000070b: ("ERROR_INVALID_PRINTER_COMMAND", "The printer command is invalid."),
        0x0000070c: ("ERROR_INVALID_DATATYPE", "The specified datatype is invalid."),
        0x0000070d: ("ERROR_INVALID_ENVIRONMENT", "The environment specified is invalid."),
        0x0000070e: ("RPC_S_NO_MORE_BINDINGS", "There are no more bindings."),
        0x0000070f: ("ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT", "The account used is an interdomain trust account. Use your global user account or local user account to access this server."),
        0x00000710: ("ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT", "The account used is a computer account. Use your global user account or local user account to access this server."),
        0x00000711: ("ERROR_NOLOGON_SERVER_TRUST_ACCOUNT", "The account used is a server trust account. Use your global user account or local user account to access this server."),
        0x00000712: ("ERROR_DOMAIN_TRUST_INCONSISTENT", "The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain."),
        0x00000713: ("ERROR_SERVER_HAS_OPEN_HANDLES", "The server is in use and cannot be unloaded."),
        0x00000714: ("ERROR_RESOURCE_DATA_NOT_FOUND", "The specified image file did not contain a resource section."),
        0x00000715: ("ERROR_RESOURCE_TYPE_NOT_FOUND", "The specified resource type cannot be found in the image file."),
        0x00000716: ("ERROR_RESOURCE_NAME_NOT_FOUND", "The specified resource name cannot be found in the image file."),
        0x00000717: ("ERROR_RESOURCE_LANG_NOT_FOUND", "The specified resource language ID cannot be found in the image file."),
        0x00000718: ("ERROR_NOT_ENOUGH_QUOTA", "Not enough quota is available to process this command."),
        0x00000719: ("RPC_S_NO_INTERFACES", "No interfaces have been registered."),
        0x0000071a: ("RPC_S_CALL_CANCELLED", "The remote procedure call was cancelled."),
        0x0000071b: ("RPC_S_BINDING_INCOMPLETE", "The binding handle does not contain all required information."),
        0x0000071c: ("RPC_S_COMM_FAILURE", "A communications failure occurred during a remote procedure call."),
        0x0000071d: ("RPC_S_UNSUPPORTED_AUTHN_LEVEL", "The requested authentication level is not supported."),
        0x0000071e: ("RPC_S_NO_PRINC_NAME", "No principal name registered."),
        0x0000071f: ("RPC_S_NOT_RPC_ERROR", "The error specified is not a valid Windows RPC error code."),
        0x00000720: ("RPC_S_UUID_LOCAL_ONLY", "A UUID that is valid only on this computer has been allocated."),
        0x00000721: ("RPC_S_SEC_PKG_ERROR", "A security package specific error occurred."),
        0x00000722: ("RPC_S_NOT_CANCELLED", "Thread is not canceled."),
        0x00000723: ("RPC_X_INVALID_ES_ACTION", "Invalid operation on the encoding/decoding handle."),
        0x00000724: ("RPC_X_WRONG_ES_VERSION", "Incompatible version of the serializing package."),
        0x00000725: ("RPC_X_WRONG_STUB_VERSION", "Incompatible version of the RPC stub."),
        0x00000726: ("RPC_X_INVALID_PIPE_OBJECT", "The RPC pipe object is invalid or corrupted."),
        0x00000727: ("RPC_X_WRONG_PIPE_ORDER", "An invalid operation was attempted on an RPC pipe object."),
        0x00000728: ("RPC_X_WRONG_PIPE_VERSION", "Unsupported RPC pipe version."),
        0x00000729: ("RPC_S_COOKIE_AUTH_FAILED", "HTTP proxy server rejected the connection because the cookie authentication failed."),
        0x0000076a: ("RPC_S_GROUP_MEMBER_NOT_FOUND", "The group member was not found."),
        0x0000076b: ("EPT_S_CANT_CREATE", "The endpoint mapper database entry could not be created."),
        0x0000076c: ("RPC_S_INVALID_OBJECT", "The object universal unique identifier (UUID) is the nil UUID."),
        0x0000076d: ("ERROR_INVALID_TIME", "The specified time is invalid."),
        0x0000076e: ("ERROR_INVALID_FORM_NAME", "The specified form name is invalid."),
        0x0000076f: ("ERROR_INVALID_FORM_SIZE", "The specified form size is invalid."),
        0x00000770: ("ERROR_ALREADY_WAITING", "The specified printer handle is already being waited on"),
        0x00000771: ("ERROR_PRINTER_DELETED", "The specified printer has been deleted."),
        0x00000772: ("ERROR_INVALID_PRINTER_STATE", "The state of the printer is invalid."),
        0x00000773: ("ERROR_PASSWORD_MUST_CHANGE", "The user's password must be changed before signing in."),
        0x00000774: ("ERROR_DOMAIN_CONTROLLER_NOT_FOUND", "Could not find the domain controller for this domain."),
        0x00000775: ("ERROR_ACCOUNT_LOCKED_OUT", "The referenced account is currently locked out and may not be logged on to."),
        0x00000776: ("OR_INVALID_OXID", "The object exporter specified was not found."),
        0x00000777: ("OR_INVALID_OID", "The object specified was not found."),
        0x00000778: ("OR_INVALID_SET", "The object resolver set specified was not found."),
        0x00000779: ("RPC_S_SEND_INCOMPLETE", "Some data remains to be sent in the request buffer."),
        0x0000077a: ("RPC_S_INVALID_ASYNC_HANDLE", "Invalid asynchronous remote procedure call handle."),
        0x0000077b: ("RPC_S_INVALID_ASYNC_CALL", "Invalid asynchronous RPC call handle for this operation."),
        0x0000077c: ("RPC_X_PIPE_CLOSED", "The RPC pipe object has already been closed."),
        0x0000077d: ("RPC_X_PIPE_DISCIPLINE_ERROR", "The RPC call completed before all pipes were processed."),
        0x0000077e: ("RPC_X_PIPE_EMPTY", "No more data is available from the RPC pipe."),
        0x0000077f: ("ERROR_NO_SITENAME", "No site name is available for this machine."),
        0x00000780: ("ERROR_CANT_ACCESS_FILE", "The file cannot be accessed by the system."),
        0x00000781: ("ERROR_CANT_RESOLVE_FILENAME", "The name of the file cannot be resolved by the system."),
        0x00000782: ("RPC_S_ENTRY_TYPE_MISMATCH", "The entry is not of the expected type."),
        0x00000783: ("RPC_S_NOT_ALL_OBJS_EXPORTED", "Not all object UUIDs could be exported to the specified entry."),
        0x00000784: ("RPC_S_INTERFACE_NOT_EXPORTED", "Interface could not be exported to the specified entry."),
        0x00000785: ("RPC_S_PROFILE_NOT_ADDED", "The specified profile entry could not be added."),
        0x00000786: ("RPC_S_PRF_ELT_NOT_ADDED", "The specified profile element could not be added."),
        0x00000787: ("RPC_S_PRF_ELT_NOT_REMOVED", "The specified profile element could not be removed."),
        0x00000788: ("RPC_S_GRP_ELT_NOT_ADDED", "The group element could not be added."),
        0x00000789: ("RPC_S_GRP_ELT_NOT_REMOVED", "The group element could not be removed."),
        0x0000078a: ("ERROR_KM_DRIVER_BLOCKED", "The printer driver is not compatible with a policy enabled on your computer that blocks NT 4.0 drivers."),
        0x0000078b: ("ERROR_CONTEXT_EXPIRED", "The context has expired and can no longer be used."),
        0x0000078c: ("ERROR_PER_USER_TRUST_QUOTA_EXCEEDED", "The current user's delegated trust creation quota has been exceeded."),
        0x0000078d: ("ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED", "The total delegated trust creation quota has been exceeded."),
        0x0000078e: ("ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED", "The current user's delegated trust deletion quota has been exceeded."),
        0x0000078f: ("ERROR_AUTHENTICATION_FIREWALL_FAILED", "The computer you are signing into is protected by an authentication firewall. The specified account is not allowed to authenticate to the computer."),
        0x00000790: ("ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED", "Remote connections to the Print Spooler are blocked by a policy set on your machine."),
        0x00000791: ("ERROR_NTLM_BLOCKED", "Authentication failed because NTLM authentication has been disabled."),
        0x00000792: ("ERROR_PASSWORD_CHANGE_REQUIRED", "Logon Failure: EAS policy requires that the user change their password before this operation can be performed."),
        0x000007d0: ("ERROR_INVALID_PIXEL_FORMAT", "The pixel format is invalid."),
        0x000007d1: ("ERROR_BAD_DRIVER", "The specified driver is invalid."),
        0x000007d2: ("ERROR_INVALID_WINDOW_STYLE", "The window style or class attribute is invalid for this operation."),
        0x000007d3: ("ERROR_METAFILE_NOT_SUPPORTED", "The requested metafile operation is not supported."),
        0x000007d4: ("ERROR_TRANSFORM_NOT_SUPPORTED", "The requested transformation operation is not supported."),
        0x000007d5: ("ERROR_CLIPPING_NOT_SUPPORTED", "The requested clipping operation is not supported."),
        0x000007da: ("ERROR_INVALID_CMM", "The specified color management module is invalid."),
        0x000007db: ("ERROR_INVALID_PROFILE", "The specified color profile is invalid."),
        0x000007dc: ("ERROR_TAG_NOT_FOUND", "The specified tag was not found."),
        0x000007dd: ("ERROR_TAG_NOT_PRESENT", "A required tag is not present."),
        0x000007de: ("ERROR_DUPLICATE_TAG", "The specified tag is already present."),
        0x000007df: ("ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE", "The specified color profile is not associated with the specified device."),
        0x000007e0: ("ERROR_PROFILE_NOT_FOUND", "The specified color profile was not found."),
        0x000007e1: ("ERROR_INVALID_COLORSPACE", "The specified color space is invalid."),
        0x000007e2: ("ERROR_ICM_NOT_ENABLED", "Image Color Management is not enabled."),
        0x000007e3: ("ERROR_DELETING_ICM_XFORM", "There was an error while deleting the color transform."),
        0x000007e4: ("ERROR_INVALID_TRANSFORM", "The specified color transform is invalid."),
        0x000007e5: ("ERROR_COLORSPACE_MISMATCH", "The specified transform does not match the bitmap's color space."),
        0x000007e6: ("ERROR_INVALID_COLORINDEX", "The specified named color index is not present in the profile."),
        0x000007e7: ("ERROR_PROFILE_DOES_NOT_MATCH_DEVICE", "The specified profile is intended for a device of a different type than the specified device."),
        0x0000083c: ("ERROR_CONNECTED_OTHER_PASSWORD", "The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified."),
        0x0000083d: ("ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT", "The network connection was made successfully using default credentials."),
        0x0000089a: ("ERROR_BAD_USERNAME", "The specified username is invalid."),
        0x000008ca: ("ERROR_NOT_CONNECTED", "This network connection does not exist."),
        0x00000961: ("ERROR_OPEN_FILES", "This network connection has files open or requests pending."),
        0x00000962: ("ERROR_ACTIVE_CONNECTIONS", "Active connections still exist."),
        0x00000964: ("ERROR_DEVICE_IN_USE", "The device is in use by an active process and cannot be disconnected."),
        0x00000bb8: ("ERROR_UNKNOWN_PRINT_MONITOR", "The specified print monitor is unknown."),
        0x00000bb9: ("ERROR_PRINTER_DRIVER_IN_USE", "The specified printer driver is currently in use."),
        0x00000bba: ("ERROR_SPOOL_FILE_NOT_FOUND", "The spool file was not found."),
        0x00000bbb: ("ERROR_SPL_NO_STARTDOC", "A StartDocPrinter call was not issued."),
        0x00000bbc: ("ERROR_SPL_NO_ADDJOB", "An AddJob call was not issued."),
        0x00000bbd: ("ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED", "The specified print processor has already been installed."),
        0x00000bbe: ("ERROR_PRINT_MONITOR_ALREADY_INSTALLED", "The specified print monitor has already been installed."),
        0x00000bbf: ("ERROR_INVALID_PRINT_MONITOR", "The specified print monitor does not have the required functions."),
        0x00000bc0: ("ERROR_PRINT_MONITOR_IN_USE", "The specified print monitor is currently in use."),
        0x00000bc1: ("ERROR_PRINTER_HAS_JOBS_QUEUED", "The requested operation is not allowed when there are jobs queued to the printer."),
        0x00000bc2: ("ERROR_SUCCESS_REBOOT_REQUIRED", "The requested operation is successful. Changes will not be effective until the system is rebooted."),
        0x00000bc3: ("ERROR_SUCCESS_RESTART_REQUIRED", "The requested operation is successful. Changes will not be effective until the service is restarted."),
        0x00000bc4: ("ERROR_PRINTER_NOT_FOUND", "No printers were found."),
        0x00000bc5: ("ERROR_PRINTER_DRIVER_WARNED", "The printer driver is known to be unreliable."),
        0x00000bc6: ("ERROR_PRINTER_DRIVER_BLOCKED", "The printer driver is known to harm the system."),
        0x00000bc7: ("ERROR_PRINTER_DRIVER_PACKAGE_IN_USE", "The specified printer driver package is currently in use."),
        0x00000bc8: ("ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND", "Unable to find a core driver package that is required by the printer driver package."),
        0x00000bc9: ("ERROR_FAIL_REBOOT_REQUIRED", "The requested operation failed. A system reboot is required to roll back changes made."),
        0x00000bca: ("ERROR_FAIL_REBOOT_INITIATED", "The requested operation failed. A system reboot has been initiated to roll back changes made."),
        0x00000bcb: ("ERROR_PRINTER_DRIVER_DOWNLOAD_NEEDED", "The specified printer driver was not found on the system and needs to be downloaded."),
        0x00000bcc: ("ERROR_PRINT_JOB_RESTART_REQUIRED", "The requested print job has failed to print. A print system update requires the job to be resubmitted."),
        0x00000bcd: ("ERROR_INVALID_PRINTER_DRIVER_MANIFEST", "The printer driver does not contain a valid manifest, or contains too many manifests."),
        0x00000bce: ("ERROR_PRINTER_NOT_SHAREABLE", "The specified printer cannot be shared."),
        0x00000bea: ("ERROR_REQUEST_PAUSED", "The operation was paused."),
        0x00000f6e: ("ERROR_IO_REISSUE_AS_CACHED", "Reissue the given operation as a cached IO operation"),
        0x00000fa0: ("ERROR_WINS_INTERNAL", "WINS encountered an error while processing the command."),
        0x00000fa1: ("ERROR_CAN_NOT_DEL_LOCAL_WINS", "The local WINS cannot be deleted."),
        0x00000fa2: ("ERROR_STATIC_INIT", "The importation from the file failed."),
        0x00000fa3: ("ERROR_INC_BACKUP", "The backup failed. Was a full backup done before?"),
        0x00000fa4: ("ERROR_FULL_BACKUP", "The backup failed. Check the directory to which you are backing the database."),
        0x00000fa5: ("ERROR_REC_NON_EXISTENT", "The name does not exist in the WINS database."),
        0x00000fa6: ("ERROR_RPL_NOT_ALLOWED", "Replication with a nonconfigured partner is not allowed."),
        0x00000fd2: ("PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED", "The version of the supplied content information is not supported."),
        0x00000fd3: ("PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO", "The supplied content information is malformed."),
        0x00000fd4: ("PEERDIST_ERROR_MISSING_DATA", "The requested data cannot be found in local or peer caches."),
        0x00000fd5: ("PEERDIST_ERROR_NO_MORE", "No more data is available or required."),
        0x00000fd6: ("PEERDIST_ERROR_NOT_INITIALIZED", "The supplied object has not been initialized."),
        0x00000fd7: ("PEERDIST_ERROR_ALREADY_INITIALIZED", "The supplied object has already been initialized."),
        0x00000fd8: ("PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS", "A shutdown operation is already in progress."),
        0x00000fd9: ("PEERDIST_ERROR_INVALIDATED", "The supplied object has already been invalidated."),
        0x00000fda: ("PEERDIST_ERROR_ALREADY_EXISTS", "An element already exists and was not replaced."),
        0x00000fdb: ("PEERDIST_ERROR_OPERATION_NOTFOUND", "Can not cancel the requested operation as it has already been completed."),
        0x00000fdc: ("PEERDIST_ERROR_ALREADY_COMPLETED", "Can not perform the reqested operation because it has already been carried out."),
        0x00000fdd: ("PEERDIST_ERROR_OUT_OF_BOUNDS", "An operation accessed data beyond the bounds of valid data."),
        0x00000fde: ("PEERDIST_ERROR_VERSION_UNSUPPORTED", "The requested version is not supported."),
        0x00000fdf: ("PEERDIST_ERROR_INVALID_CONFIGURATION", "A configuration value is invalid."),
        0x00000fe0: ("PEERDIST_ERROR_NOT_LICENSED", "The SKU is not licensed."),
        0x00000fe1: ("PEERDIST_ERROR_SERVICE_UNAVAILABLE", "PeerDist Service is still initializing and will be available shortly."),
        0x00000fe2: ("PEERDIST_ERROR_TRUST_FAILURE", "Communication with one or more computers will be temporarily blocked due to recent errors."),
        0x00001004: ("ERROR_DHCP_ADDRESS_CONFLICT", "The DHCP client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address."),
        0x00001068: ("ERROR_WMI_GUID_NOT_FOUND", "The GUID passed was not recognized as valid by a WMI data provider."),
        0x00001069: ("ERROR_WMI_INSTANCE_NOT_FOUND", "The instance name passed was not recognized as valid by a WMI data provider."),
        0x0000106a: ("ERROR_WMI_ITEMID_NOT_FOUND", "The data item ID passed was not recognized as valid by a WMI data provider."),
        0x0000106b: ("ERROR_WMI_TRY_AGAIN", "The WMI request could not be completed and should be retried."),
        0x0000106c: ("ERROR_WMI_DP_NOT_FOUND", "The WMI data provider could not be located."),
        0x0000106d: ("ERROR_WMI_UNRESOLVED_INSTANCE_REF", "The WMI data provider references an instance set that has not been registered."),
        0x0000106e: ("ERROR_WMI_ALREADY_ENABLED", "The WMI data block or event notification has already been enabled."),
        0x0000106f: ("ERROR_WMI_GUID_DISCONNECTED", "The WMI data block is no longer available."),
        0x00001070: ("ERROR_WMI_SERVER_UNAVAILABLE", "The WMI data service is not available."),
        0x00001071: ("ERROR_WMI_DP_FAILED", "The WMI data provider failed to carry out the request."),
        0x00001072: ("ERROR_WMI_INVALID_MOF", "The WMI MOF information is not valid."),
        0x00001073: ("ERROR_WMI_INVALID_REGINFO", "The WMI registration information is not valid."),
        0x00001074: ("ERROR_WMI_ALREADY_DISABLED", "The WMI data block or event notification has already been disabled."),
        0x00001075: ("ERROR_WMI_READ_ONLY", "The WMI data item or data block is read only."),
        0x00001076: ("ERROR_WMI_SET_FAILURE", "The WMI data item or data block could not be changed."),
        0x0000109a: ("ERROR_NOT_APPCONTAINER", "This operation is only valid in the context of an app container."),
        0x0000109b: ("ERROR_APPCONTAINER_REQUIRED", "This application can only run in the context of an app container."),
        0x0000109c: ("ERROR_NOT_SUPPORTED_IN_APPCONTAINER", "This functionality is not supported in the context of an app container."),
        0x0000109d: ("ERROR_INVALID_PACKAGE_SID_LENGTH", "The length of the SID supplied is not a valid length for app container SIDs."),
        0x000010cc: ("ERROR_INVALID_MEDIA", "The media identifier does not represent a valid medium."),
        0x000010cd: ("ERROR_INVALID_LIBRARY", "The library identifier does not represent a valid library."),
        0x000010ce: ("ERROR_INVALID_MEDIA_POOL", "The media pool identifier does not represent a valid media pool."),
        0x000010cf: ("ERROR_DRIVE_MEDIA_MISMATCH", "The drive and medium are not compatible or exist in different libraries."),
        0x000010d0: ("ERROR_MEDIA_OFFLINE", "The medium currently exists in an offline library and must be online to perform this operation."),
        0x000010d1: ("ERROR_LIBRARY_OFFLINE", "The operation cannot be performed on an offline library."),
        0x000010d2: ("ERROR_EMPTY", "The library, drive, or media pool is empty."),
        0x000010d3: ("ERROR_NOT_EMPTY", "The library, drive, or media pool must be empty to perform this operation."),
        0x000010d4: ("ERROR_MEDIA_UNAVAILABLE", "No media is currently available in this media pool or library."),
        0x000010d5: ("ERROR_RESOURCE_DISABLED", "A resource required for this operation is disabled."),
        0x000010d6: ("ERROR_INVALID_CLEANER", "The media identifier does not represent a valid cleaner."),
        0x000010d7: ("ERROR_UNABLE_TO_CLEAN", "The drive cannot be cleaned or does not support cleaning."),
        0x000010d8: ("ERROR_OBJECT_NOT_FOUND", "The object identifier does not represent a valid object."),
        0x000010d9: ("ERROR_DATABASE_FAILURE", "Unable to read from or write to the database."),
        0x000010da: ("ERROR_DATABASE_FULL", "The database is full."),
        0x000010db: ("ERROR_MEDIA_INCOMPATIBLE", "The medium is not compatible with the device or media pool."),
        0x000010dc: ("ERROR_RESOURCE_NOT_PRESENT", "The resource required for this operation does not exist."),
        0x000010dd: ("ERROR_INVALID_OPERATION", "The operation identifier is not valid."),
        0x000010de: ("ERROR_MEDIA_NOT_AVAILABLE", "The media is not mounted or ready for use."),
        0x000010df: ("ERROR_DEVICE_NOT_AVAILABLE", "The device is not ready for use."),
        0x000010e0: ("ERROR_REQUEST_REFUSED", "The operator or administrator has refused the request."),
        0x000010e1: ("ERROR_INVALID_DRIVE_OBJECT", "The drive identifier does not represent a valid drive."),
        0x000010e2: ("ERROR_LIBRARY_FULL", "Library is full. No slot is available for use."),
        0x000010e3: ("ERROR_MEDIUM_NOT_ACCESSIBLE", "The transport cannot access the medium."),
        0x000010e4: ("ERROR_UNABLE_TO_LOAD_MEDIUM", "Unable to load the medium into the drive."),
        0x000010e5: ("ERROR_UNABLE_TO_INVENTORY_DRIVE", "Unable to retrieve the drive status."),
        0x000010e6: ("ERROR_UNABLE_TO_INVENTORY_SLOT", "Unable to retrieve the slot status."),
        0x000010e7: ("ERROR_UNABLE_TO_INVENTORY_TRANSPORT", "Unable to retrieve status about the transport."),
        0x000010e8: ("ERROR_TRANSPORT_FULL", "Cannot use the transport because it is already in use."),
        0x000010e9: ("ERROR_CONTROLLING_IEPORT", "Unable to open or close the inject/eject port."),
        0x000010ea: ("ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA", "Unable to eject the medium because it is in a drive."),
        0x000010eb: ("ERROR_CLEANER_SLOT_SET", "A cleaner slot is already reserved."),
        0x000010ec: ("ERROR_CLEANER_SLOT_NOT_SET", "A cleaner slot is not reserved."),
        0x000010ed: ("ERROR_CLEANER_CARTRIDGE_SPENT", "The cleaner cartridge has performed the maximum number of drive cleanings."),
        0x000010ee: ("ERROR_UNEXPECTED_OMID", "Unexpected on-medium identifier."),
        0x000010ef: ("ERROR_CANT_DELETE_LAST_ITEM", "The last remaining item in this group or resource cannot be deleted."),
        0x000010f0: ("ERROR_MESSAGE_EXCEEDS_MAX_SIZE", "The message provided exceeds the maximum size allowed for this parameter."),
        0x000010f1: ("ERROR_VOLUME_CONTAINS_SYS_FILES", "The volume contains system or paging files."),
        0x000010f2: ("ERROR_INDIGENOUS_TYPE", "The media type cannot be removed from this library since at least one drive in the library reports it can support this media type."),
        0x000010f3: ("ERROR_NO_SUPPORTING_DRIVES", "This offline media cannot be mounted on this system since no enabled drives are present which can be used."),
        0x000010f4: ("ERROR_CLEANER_CARTRIDGE_INSTALLED", "A cleaner cartridge is present in the tape library."),
        0x000010f5: ("ERROR_IEPORT_FULL", "Cannot use the inject/eject port because it is not empty."),
        0x000010fe: ("ERROR_FILE_OFFLINE", "This file is currently not available for use on this computer."),
        0x000010ff: ("ERROR_REMOTE_STORAGE_NOT_ACTIVE", "The remote storage service is not operational at this time."),
        0x00001100: ("ERROR_REMOTE_STORAGE_MEDIA_ERROR", "The remote storage service encountered a media error."),
        0x00001126: ("ERROR_NOT_A_REPARSE_POINT", "The file or directory is not a reparse point."),
        0x00001127: ("ERROR_REPARSE_ATTRIBUTE_CONFLICT", "The reparse point attribute cannot be set because it conflicts with an existing attribute."),
        0x00001128: ("ERROR_INVALID_REPARSE_DATA", "The data present in the reparse point buffer is invalid."),
        0x00001129: ("ERROR_REPARSE_TAG_INVALID", "The tag present in the reparse point buffer is invalid."),
        0x0000112a: ("ERROR_REPARSE_TAG_MISMATCH", "There is a mismatch between the tag specified in the request and the tag present in the reparse point."),
        0x00001130: ("ERROR_APP_DATA_NOT_FOUND", "Fast Cache data not found."),
        0x00001131: ("ERROR_APP_DATA_EXPIRED", "Fast Cache data expired."),
        0x00001132: ("ERROR_APP_DATA_CORRUPT", "Fast Cache data corrupt."),
        0x00001133: ("ERROR_APP_DATA_LIMIT_EXCEEDED", "Fast Cache data has exceeded its max size and cannot be updated."),
        0x00001134: ("ERROR_APP_DATA_REBOOT_REQUIRED", "Fast Cache has been ReArmed and requires a reboot until it can be updated."),
        0x00001144: ("ERROR_SECUREBOOT_ROLLBACK_DETECTED", "Secure Boot detected that rollback of protected data has been attempted."),
        0x00001145: ("ERROR_SECUREBOOT_POLICY_VIOLATION", "The value is protected by Secure Boot policy and cannot be modified or deleted."),
        0x00001146: ("ERROR_SECUREBOOT_INVALID_POLICY", "The Secure Boot policy is invalid."),
        0x00001147: ("ERROR_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND", "A new Secure Boot policy did not contain the current publisher on its update list."),
        0x00001148: ("ERROR_SECUREBOOT_POLICY_NOT_SIGNED", "The Secure Boot policy is either not signed or is signed by a non-trusted signer."),
        0x00001149: ("ERROR_SECUREBOOT_NOT_ENABLED", "Secure Boot is not enabled on this machine."),
        0x0000114a: ("ERROR_SECUREBOOT_FILE_REPLACED", "Secure Boot requires that certain files and drivers are not replaced by other files or drivers."),
        0x00001158: ("ERROR_OFFLOAD_READ_FLT_NOT_SUPPORTED", "The copy offload read operation is not supported by a filter."),
        0x00001159: ("ERROR_OFFLOAD_WRITE_FLT_NOT_SUPPORTED", "The copy offload write operation is not supported by a filter."),
        0x0000115a: ("ERROR_OFFLOAD_READ_FILE_NOT_SUPPORTED", "The copy offload read operation is not supported for the file."),
        0x0000115b: ("ERROR_OFFLOAD_WRITE_FILE_NOT_SUPPORTED", "The copy offload write operation is not supported for the file."),
        0x00001194: ("ERROR_VOLUME_NOT_SIS_ENABLED", "Single Instance Storage is not available on this volume."),
        0x00001389: ("ERROR_DEPENDENT_RESOURCE_EXISTS", "The operation cannot be completed because other resources are dependent on this resource."),
        0x0000138a: ("ERROR_DEPENDENCY_NOT_FOUND", "The cluster resource dependency cannot be found."),
        0x0000138b: ("ERROR_DEPENDENCY_ALREADY_EXISTS", "The cluster resource cannot be made dependent on the specified resource because it is already dependent."),
        0x0000138c: ("ERROR_RESOURCE_NOT_ONLINE", "The cluster resource is not online."),
        0x0000138d: ("ERROR_HOST_NODE_NOT_AVAILABLE", "A cluster node is not available for this operation."),
        0x0000138e: ("ERROR_RESOURCE_NOT_AVAILABLE", "The cluster resource is not available."),
        0x0000138f: ("ERROR_RESOURCE_NOT_FOUND", "The cluster resource could not be found."),
        0x00001390: ("ERROR_SHUTDOWN_CLUSTER", "The cluster is being shut down."),
        0x00001391: ("ERROR_CANT_EVICT_ACTIVE_NODE", "A cluster node cannot be evicted from the cluster unless the node is down or it is the last node."),
        0x00001392: ("ERROR_OBJECT_ALREADY_EXISTS", "The object already exists."),
        0x00001393: ("ERROR_OBJECT_IN_LIST", "The object is already in the list."),
        0x00001394: ("ERROR_GROUP_NOT_AVAILABLE", "The cluster group is not available for any new requests."),
        0x00001395: ("ERROR_GROUP_NOT_FOUND", "The cluster group could not be found."),
        0x00001396: ("ERROR_GROUP_NOT_ONLINE", "The operation could not be completed because the cluster group is not online."),
        0x00001397: ("ERROR_HOST_NODE_NOT_RESOURCE_OWNER", "The operation failed because either the specified cluster node is not the owner of the resource, or the node is not a possible owner of the resource."),
        0x00001398: ("ERROR_HOST_NODE_NOT_GROUP_OWNER", "The operation failed because either the specified cluster node is not the owner of the group, or the node is not a possible owner of the group."),
        0x00001399: ("ERROR_RESMON_CREATE_FAILED", "The cluster resource could not be created in the specified resource monitor."),
        0x0000139a: ("ERROR_RESMON_ONLINE_FAILED", "The cluster resource could not be brought online by the resource monitor."),
        0x0000139b: ("ERROR_RESOURCE_ONLINE", "The operation could not be completed because the cluster resource is online."),
        0x0000139c: ("ERROR_QUORUM_RESOURCE", "The cluster resource could not be deleted or brought offline because it is the quorum resource."),
        0x0000139d: ("ERROR_NOT_QUORUM_CAPABLE", "The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource."),
        0x0000139e: ("ERROR_CLUSTER_SHUTTING_DOWN", "The cluster software is shutting down."),
        0x0000139f: ("ERROR_INVALID_STATE", "The group or resource is not in the correct state to perform the requested operation."),
        0x000013a0: ("ERROR_RESOURCE_PROPERTIES_STORED", "The properties were stored but not all changes will take effect until the next time the resource is brought online."),
        0x000013a1: ("ERROR_NOT_QUORUM_CLASS", "The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class."),
        0x000013a2: ("ERROR_CORE_RESOURCE", "The cluster resource could not be deleted since it is a core resource."),
        0x000013a3: ("ERROR_QUORUM_RESOURCE_ONLINE_FAILED", "The quorum resource failed to come online."),
        0x000013a4: ("ERROR_QUORUMLOG_OPEN_FAILED", "The quorum log could not be created or mounted successfully."),
        0x000013a5: ("ERROR_CLUSTERLOG_CORRUPT", "The cluster log is corrupt."),
        0x000013a6: ("ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE", "The record could not be written to the cluster log since it exceeds the maximum size."),
        0x000013a7: ("ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE", "The cluster log exceeds its maximum size."),
        0x000013a8: ("ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND", "No checkpoint record was found in the cluster log."),
        0x000013a9: ("ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE", "The minimum required disk space needed for logging is not available."),
        0x000013aa: ("ERROR_QUORUM_OWNER_ALIVE", "The cluster node failed to take control of the quorum resource because the resource is owned by another active node."),
        0x000013ab: ("ERROR_NETWORK_NOT_AVAILABLE", "A cluster network is not available for this operation."),
        0x000013ac: ("ERROR_NODE_NOT_AVAILABLE", "A cluster node is not available for this operation."),
        0x000013ad: ("ERROR_ALL_NODES_NOT_AVAILABLE", "All cluster nodes must be running to perform this operation."),
        0x000013ae: ("ERROR_RESOURCE_FAILED", "A cluster resource failed."),
        0x000013af: ("ERROR_CLUSTER_INVALID_NODE", "The cluster node is not valid."),
        0x000013b0: ("ERROR_CLUSTER_NODE_EXISTS", "The cluster node already exists."),
        0x000013b1: ("ERROR_CLUSTER_JOIN_IN_PROGRESS", "A node is in the process of joining the cluster."),
        0x000013b2: ("ERROR_CLUSTER_NODE_NOT_FOUND", "The cluster node was not found."),
        0x000013b3: ("ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND", "The cluster local node information was not found."),
        0x000013b4: ("ERROR_CLUSTER_NETWORK_EXISTS", "The cluster network already exists."),
        0x000013b5: ("ERROR_CLUSTER_NETWORK_NOT_FOUND", "The cluster network was not found."),
        0x000013b6: ("ERROR_CLUSTER_NETINTERFACE_EXISTS", "The cluster network interface already exists."),
        0x000013b7: ("ERROR_CLUSTER_NETINTERFACE_NOT_FOUND", "The cluster network interface was not found."),
        0x000013b8: ("ERROR_CLUSTER_INVALID_REQUEST", "The cluster request is not valid for this object."),
        0x000013b9: ("ERROR_CLUSTER_INVALID_NETWORK_PROVIDER", "The cluster network provider is not valid."),
        0x000013ba: ("ERROR_CLUSTER_NODE_DOWN", "The cluster node is down."),
        0x000013bb: ("ERROR_CLUSTER_NODE_UNREACHABLE", "The cluster node is not reachable."),
        0x000013bc: ("ERROR_CLUSTER_NODE_NOT_MEMBER", "The cluster node is not a member of the cluster."),
        0x000013bd: ("ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS", "A cluster join operation is not in progress."),
        0x000013be: ("ERROR_CLUSTER_INVALID_NETWORK", "The cluster network is not valid."),
        0x000013c0: ("ERROR_CLUSTER_NODE_UP", "The cluster node is up."),
        0x000013c1: ("ERROR_CLUSTER_IPADDR_IN_USE", "The cluster IP address is already in use."),
        0x000013c2: ("ERROR_CLUSTER_NODE_NOT_PAUSED", "The cluster node is not paused."),
        0x000013c3: ("ERROR_CLUSTER_NO_SECURITY_CONTEXT", "No cluster security context is available."),
        0x000013c4: ("ERROR_CLUSTER_NETWORK_NOT_INTERNAL", "The cluster network is not configured for internal cluster communication."),
        0x000013c5: ("ERROR_CLUSTER_NODE_ALREADY_UP", "The cluster node is already up."),
        0x000013c6: ("ERROR_CLUSTER_NODE_ALREADY_DOWN", "The cluster node is already down."),
        0x000013c7: ("ERROR_CLUSTER_NETWORK_ALREADY_ONLINE", "The cluster network is already online."),
        0x000013c8: ("ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE", "The cluster network is already offline."),
        0x000013c9: ("ERROR_CLUSTER_NODE_ALREADY_MEMBER", "The cluster node is already a member of the cluster."),
        0x000013ca: ("ERROR_CLUSTER_LAST_INTERNAL_NETWORK", "The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network."),
        0x000013cb: ("ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS", "One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network."),
        0x000013cc: ("ERROR_INVALID_OPERATION_ON_QUORUM", "This operation cannot be performed on the cluster resource as it the quorum resource. You may not bring the quorum resource offline or modify its possible owners list."),
        0x000013cd: ("ERROR_DEPENDENCY_NOT_ALLOWED", "The cluster quorum resource is not allowed to have any dependencies."),
        0x000013ce: ("ERROR_CLUSTER_NODE_PAUSED", "The cluster node is paused."),
        0x000013cf: ("ERROR_NODE_CANT_HOST_RESOURCE", "The cluster resource cannot be brought online. The owner node cannot run this resource."),
        0x000013d0: ("ERROR_CLUSTER_NODE_NOT_READY", "The cluster node is not ready to perform the requested operation."),
        0x000013d1: ("ERROR_CLUSTER_NODE_SHUTTING_DOWN", "The cluster node is shutting down."),
        0x000013d2: ("ERROR_CLUSTER_JOIN_ABORTED", "The cluster join operation was aborted."),
        0x000013d3: ("ERROR_CLUSTER_INCOMPATIBLE_VERSIONS", "The cluster join operation failed due to incompatible software versions between the joining node and its sponsor."),
        0x000013d4: ("ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED", "This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor."),
        0x000013d5: ("ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED", "The system configuration changed during the cluster join or form operation. The join or form operation was aborted."),
        0x000013d6: ("ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND", "The specified resource type was not found."),
        0x000013d7: ("ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED", "The specified node does not support a resource of this type. This may be due to version inconsistencies or due to the absence of the resource DLL on this node."),
        0x000013d8: ("ERROR_CLUSTER_RESNAME_NOT_FOUND", "The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL."),
        0x000013d9: ("ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED", "No authentication package could be registered with the RPC server."),
        0x000013da: ("ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST", "You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group."),
        0x000013db: ("ERROR_CLUSTER_DATABASE_SEQMISMATCH", "The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join."),
        0x000013dc: ("ERROR_RESMON_INVALID_STATE", "The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state."),
        0x000013dd: ("ERROR_CLUSTER_GUM_NOT_LOCKER", "A non locker code got a request to reserve the lock for making global updates."),
        0x000013de: ("ERROR_QUORUM_DISK_NOT_FOUND", "The quorum disk could not be located by the cluster service."),
        0x000013df: ("ERROR_DATABASE_BACKUP_CORRUPT", "The backed up cluster database is possibly corrupt."),
        0x000013e0: ("ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT", "A DFS root already exists in this cluster node."),
        0x000013e1: ("ERROR_RESOURCE_PROPERTY_UNCHANGEABLE", "An attempt to modify a resource property failed because it conflicts with another existing property."),
        0x00001702: ("ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE", "An operation was attempted that is incompatible with the current membership state of the node."),
        0x00001703: ("ERROR_CLUSTER_QUORUMLOG_NOT_FOUND", "The quorum resource does not contain the quorum log."),
        0x00001704: ("ERROR_CLUSTER_MEMBERSHIP_HALT", "The membership engine requested shutdown of the cluster service on this node."),
        0x00001705: ("ERROR_CLUSTER_INSTANCE_ID_MISMATCH", "The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node."),
        0x00001706: ("ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP", "A matching cluster network for the specified IP address could not be found."),
        0x00001707: ("ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH", "The actual data type of the property did not match the expected data type of the property."),
        0x00001708: ("ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP", "The cluster node was evicted from the cluster successfully, but the node was not cleaned up. To determine what cleanup steps failed and how to recover, see the Failover Clustering application event log using Event Viewer."),
        0x00001709: ("ERROR_CLUSTER_PARAMETER_MISMATCH", "Two or more parameter values specified for a resource's properties are in conflict."),
        0x0000170a: ("ERROR_NODE_CANNOT_BE_CLUSTERED", "This computer cannot be made a member of a cluster."),
        0x0000170b: ("ERROR_CLUSTER_WRONG_OS_VERSION", "This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed."),
        0x0000170c: ("ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME", "A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster."),
        0x0000170d: ("ERROR_CLUSCFG_ALREADY_COMMITTED", "The cluster configuration action has already been committed."),
        0x0000170e: ("ERROR_CLUSCFG_ROLLBACK_FAILED", "The cluster configuration action could not be rolled back."),
        0x0000170f: ("ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT", "The drive letter assigned to a system disk on one node conflicted with the drive letter assigned to a disk on another node."),
        0x00001710: ("ERROR_CLUSTER_OLD_VERSION", "One or more nodes in the cluster are running a version of Windows that does not support this operation."),
        0x00001711: ("ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME", "The name of the corresponding computer account doesn't match the Network Name for this resource."),
        0x00001712: ("ERROR_CLUSTER_NO_NET_ADAPTERS", "No network adapters are available."),
        0x00001713: ("ERROR_CLUSTER_POISONED", "The cluster node has been poisoned."),
        0x00001714: ("ERROR_CLUSTER_GROUP_MOVING", "The group is unable to accept the request since it is moving to another node."),
        0x00001715: ("ERROR_CLUSTER_RESOURCE_TYPE_BUSY", "The resource type cannot accept the request since is too busy performing another operation."),
        0x00001716: ("ERROR_RESOURCE_CALL_TIMED_OUT", "The call to the cluster resource DLL timed out."),
        0x00001717: ("ERROR_INVALID_CLUSTER_IPV6_ADDRESS", "The address is not valid for an IPv6 Address resource. A global IPv6 address is required, and it must match a cluster network. Compatibility addresses are not permitted."),
        0x00001718: ("ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION", "An internal cluster error occurred. A call to an invalid function was attempted."),
        0x00001719: ("ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS", "A parameter value is out of acceptable range."),
        0x0000171a: ("ERROR_CLUSTER_PARTIAL_SEND", "A network error occurred while sending data to another node in the cluster. The number of bytes transmitted was less than required."),
        0x0000171b: ("ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION", "An invalid cluster registry operation was attempted."),
        0x0000171c: ("ERROR_CLUSTER_INVALID_STRING_TERMINATION", "An input string of characters is not properly terminated."),
        0x0000171d: ("ERROR_CLUSTER_INVALID_STRING_FORMAT", "An input string of characters is not in a valid format for the data it represents."),
        0x0000171e: ("ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS", "An internal cluster error occurred. A cluster database transaction was attempted while a transaction was already in progress."),
        0x0000171f: ("ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS", "An internal cluster error occurred. There was an attempt to commit a cluster database transaction while no transaction was in progress."),
        0x00001720: ("ERROR_CLUSTER_NULL_DATA", "An internal cluster error occurred. Data was not properly initialized."),
        0x00001721: ("ERROR_CLUSTER_PARTIAL_READ", "An error occurred while reading from a stream of data. An unexpected number of bytes was returned."),
        0x00001722: ("ERROR_CLUSTER_PARTIAL_WRITE", "An error occurred while writing to a stream of data. The required number of bytes could not be written."),
        0x00001723: ("ERROR_CLUSTER_CANT_DESERIALIZE_DATA", "An error occurred while deserializing a stream of cluster data."),
        0x00001724: ("ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT", "One or more property values for this resource are in conflict with one or more property values associated with its dependent resource(s)."),
        0x00001725: ("ERROR_CLUSTER_NO_QUORUM", "A quorum of cluster nodes was not present to form a cluster."),
        0x00001726: ("ERROR_CLUSTER_INVALID_IPV6_NETWORK", "The cluster network is not valid for an IPv6 Address resource, or it does not match the configured address."),
        0x00001727: ("ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK", "The cluster network is not valid for an IPv6 Tunnel resource. Check the configuration of the IP Address resource on which the IPv6 Tunnel resource depends."),
        0x00001728: ("ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP", "Quorum resource cannot reside in the Available Storage group."),
        0x00001729: ("ERROR_DEPENDENCY_TREE_TOO_COMPLEX", "The dependencies for this resource are nested too deeply."),
        0x0000172a: ("ERROR_EXCEPTION_IN_RESOURCE_CALL", "The call into the resource DLL raised an unhandled exception."),
        0x0000172b: ("ERROR_CLUSTER_RHS_FAILED_INITIALIZATION", "The RHS process failed to initialize."),
        0x0000172c: ("ERROR_CLUSTER_NOT_INSTALLED", "The Failover Clustering feature is not installed on this node."),
        0x0000172d: ("ERROR_CLUSTER_RESOURCES_MUST_BE_ONLINE_ON_THE_SAME_NODE", "The resources must be online on the same node for this operation"),
        0x0000172e: ("ERROR_CLUSTER_MAX_NODES_IN_CLUSTER", "A new node can not be added since this cluster is already at its maximum number of nodes."),
        0x0000172f: ("ERROR_CLUSTER_TOO_MANY_NODES", "This cluster can not be created since the specified number of nodes exceeds the maximum allowed limit."),
        0x00001730: ("ERROR_CLUSTER_OBJECT_ALREADY_USED", "An attempt to use the specified cluster name failed because an enabled computer object with the given name already exists in the domain."),
        0x00001731: ("ERROR_NONCORE_GROUPS_FOUND", "This cluster cannot be destroyed. It has non-core application groups which must be deleted before the cluster can be destroyed."),
        0x00001732: ("ERROR_FILE_SHARE_RESOURCE_CONFLICT", "File share associated with file share witness resource cannot be hosted by this cluster or any of its nodes."),
        0x00001733: ("ERROR_CLUSTER_EVICT_INVALID_REQUEST", "Eviction of this node is invalid at this time. Due to quorum requirements node eviction will result in cluster shutdown."),
        0x00001734: ("ERROR_CLUSTER_SINGLETON_RESOURCE", "Only one instance of this resource type is allowed in the cluster."),
        0x00001735: ("ERROR_CLUSTER_GROUP_SINGLETON_RESOURCE", "Only one instance of this resource type is allowed per resource group."),
        0x00001736: ("ERROR_CLUSTER_RESOURCE_PROVIDER_FAILED", "The resource failed to come online due to the failure of one or more provider resources."),
        0x00001737: ("ERROR_CLUSTER_RESOURCE_CONFIGURATION_ERROR", "The resource has indicated that it cannot come online on any node."),
        0x00001738: ("ERROR_CLUSTER_GROUP_BUSY", "The current operation cannot be performed on this group at this time."),
        0x00001739: ("ERROR_CLUSTER_NOT_SHARED_VOLUME", "The directory or file is not located on a cluster shared volume."),
        0x0000173a: ("ERROR_CLUSTER_INVALID_SECURITY_DESCRIPTOR", "The Security Descriptor does not meet the requirements for a cluster."),
        0x0000173b: ("ERROR_CLUSTER_SHARED_VOLUMES_IN_USE", "There is one or more shared volumes resources configured in the cluster."),
        0x0000173c: ("ERROR_CLUSTER_USE_SHARED_VOLUMES_API", "This group or resource cannot be directly manipulated."),
        0x0000173d: ("ERROR_CLUSTER_BACKUP_IN_PROGRESS", "Back up is in progress. Please wait for backup completion before trying this operation again."),
        0x0000173e: ("ERROR_NON_CSV_PATH", "The path does not belong to a cluster shared volume."),
        0x0000173f: ("ERROR_CSV_VOLUME_NOT_LOCAL", "The cluster shared volume is not locally mounted on this node."),
        0x00001740: ("ERROR_CLUSTER_WATCHDOG_TERMINATING", "The cluster watchdog is terminating."),
        0x00001741: ("ERROR_CLUSTER_RESOURCE_VETOED_MOVE_INCOMPATIBLE_NODES", "A resource vetoed a move between two nodes because they are incompatible."),
        0x00001742: ("ERROR_CLUSTER_INVALID_NODE_WEIGHT", "The request is invalid either because node weight cannot be changed while the cluster is in disk-only quorum mode, or because changing the node weight would violate the minimum cluster quorum requirements."),
        0x00001743: ("ERROR_CLUSTER_RESOURCE_VETOED_CALL", "The resource vetoed the call."),
        0x00001744: ("ERROR_RESMON_SYSTEM_RESOURCES_LACKING", "Resource could not start or run because it could not reserve sufficient system resources."),
        0x00001745: ("ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_DESTINATION", "A resource vetoed a move between two nodes because the destination currently does not have enough resources to complete the operation."),
        0x00001746: ("ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_SOURCE", ""),
        0x00001747: ("ERROR_CLUSTER_GROUP_QUEUED", ""),
        0x00001748: ("ERROR_CLUSTER_RESOURCE_LOCKED_STATUS", ""),
        0x00001749: ("ERROR_CLUSTER_SHARED_VOLUME_FAILOVER_NOT_ALLOWED", ""),
        0x0000174a: ("ERROR_CLUSTER_NODE_DRAIN_IN_PROGRESS", ""),
        0x0000174b: ("ERROR_CLUSTER_DISK_NOT_CONNECTED", ""),
        0x0000174c: ("ERROR_DISK_NOT_CSV_CAPABLE", ""),
        0x0000174d: ("ERROR_RESOURCE_NOT_IN_AVAILABLE_STORAGE", ""),
        0x0000174e: ("ERROR_CLUSTER_SHARED_VOLUME_REDIRECTED", ""),
        0x0000174f: ("ERROR_CLUSTER_SHARED_VOLUME_NOT_REDIRECTED", ""),
        0x00001750: ("ERROR_CLUSTER_CANNOT_RETURN_PROPERTIES", ""),
        0x00001751: ("ERROR_CLUSTER_RESOURCE_CONTAINS_UNSUPPORTED_DIFF_AREA_FOR_SHARED_VOLUMES", ""),
        0x00001752: ("ERROR_CLUSTER_RESOURCE_IS_IN_MAINTENANCE_MODE", ""),
        0x00001753: ("ERROR_CLUSTER_AFFINITY_CONFLICT", ""),
        0x00001754: ("ERROR_CLUSTER_RESOURCE_IS_REPLICA_VIRTUAL_MACHINE", ""),
        0x00001770: ("ERROR_ENCRYPTION_FAILED", "The specified file could not be encrypted."),
        0x00001771: ("ERROR_DECRYPTION_FAILED", "The specified file could not be decrypted."),
        0x00001772: ("ERROR_FILE_ENCRYPTED", "The specified file is encrypted and the user does not have the ability to decrypt it."),
        0x00001773: ("ERROR_NO_RECOVERY_POLICY", "There is no valid encryption recovery policy configured for this system."),
        0x00001774: ("ERROR_NO_EFS", "The required encryption driver is not loaded for this system."),
        0x00001775: ("ERROR_WRONG_EFS", "The file was encrypted with a different encryption driver than is currently loaded."),
        0x00001776: ("ERROR_NO_USER_KEYS", "There are no EFS keys defined for the user."),
        0x00001777: ("ERROR_FILE_NOT_ENCRYPTED", "The specified file is not encrypted."),
        0x00001778: ("ERROR_NOT_EXPORT_FORMAT", "The specified file is not in the defined EFS export format."),
        0x00001779: ("ERROR_FILE_READ_ONLY", "The specified file is read only."),
        0x0000177a: ("ERROR_DIR_EFS_DISALLOWED", "The directory has been disabled for encryption."),
        0x0000177b: ("ERROR_EFS_SERVER_NOT_TRUSTED", "The server is not trusted for remote encryption operation."),
        0x0000177c: ("ERROR_BAD_RECOVERY_POLICY", "Recovery policy configured for this system contains invalid recovery certificate."),
        0x0000177d: ("ERROR_EFS_ALG_BLOB_TOO_BIG", "The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file."),
        0x0000177e: ("ERROR_VOLUME_NOT_SUPPORT_EFS", "The disk partition does not support file encryption."),
        0x0000177f: ("ERROR_EFS_DISABLED", "This machine is disabled for file encryption."),
        0x00001780: ("ERROR_EFS_VERSION_NOT_SUPPORT", "A newer system is required to decrypt this encrypted file."),
        0x00001781: ("ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE", "The remote server sent an invalid response for a file being opened with Client Side Encryption."),
        0x00001782: ("ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER", "Client Side Encryption is not supported by the remote server even though it claims to support it."),
        0x00001783: ("ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE", "File is encrypted and should be opened in Client Side Encryption mode."),
        0x00001784: ("ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE", "A new encrypted file is being created and a $EFS needs to be provided."),
        0x00001785: ("ERROR_CS_ENCRYPTION_FILE_NOT_CSE", "The SMB client requested a CSE FSCTL on a non-CSE file."),
        0x00001786: ("ERROR_ENCRYPTION_POLICY_DENIES_OPERATION", "The requested operation was blocked by policy. For more information, contact your system administrator."),
        0x000017e6: ("ERROR_NO_BROWSER_SERVERS_FOUND", "The list of servers for this workgroup is not currently available"),
        0x00001838: ("SCHED_E_SERVICE_NOT_LOCALSYSTEM", "The Task Scheduler service must be configured to run in the System account to function properly. Individual tasks may be configured to run in other accounts."),
        0x000019c8: ("ERROR_LOG_SECTOR_INVALID", "Log service encountered an invalid log sector."),
        0x000019c9: ("ERROR_LOG_SECTOR_PARITY_INVALID", "Log service encountered a log sector with invalid block parity."),
        0x000019ca: ("ERROR_LOG_SECTOR_REMAPPED", "Log service encountered a remapped log sector."),
        0x000019cb: ("ERROR_LOG_BLOCK_INCOMPLETE", "Log service encountered a partial or incomplete log block."),
        0x000019cc: ("ERROR_LOG_INVALID_RANGE", "Log service encountered an attempt access data outside the active log range."),
        0x000019cd: ("ERROR_LOG_BLOCKS_EXHAUSTED", "Log service user marshalling buffers are exhausted."),
        0x000019ce: ("ERROR_LOG_READ_CONTEXT_INVALID", "Log service encountered an attempt read from a marshalling area with an invalid read context."),
        0x000019cf: ("ERROR_LOG_RESTART_INVALID", "Log service encountered an invalid log restart area."),
        0x000019d0: ("ERROR_LOG_BLOCK_VERSION", "Log service encountered an invalid log block version."),
        0x000019d1: ("ERROR_LOG_BLOCK_INVALID", "Log service encountered an invalid log block."),
        0x000019d2: ("ERROR_LOG_READ_MODE_INVALID", "Log service encountered an attempt to read the log with an invalid read mode."),
        0x000019d3: ("ERROR_LOG_NO_RESTART", "Log service encountered a log stream with no restart area."),
        0x000019d4: ("ERROR_LOG_METADATA_CORRUPT", "Log service encountered a corrupted metadata file."),
        0x000019d5: ("ERROR_LOG_METADATA_INVALID", "Log service encountered a metadata file that could not be created by the log file system."),
        0x000019d6: ("ERROR_LOG_METADATA_INCONSISTENT", "Log service encountered a metadata file with inconsistent data."),
        0x000019d7: ("ERROR_LOG_RESERVATION_INVALID", "Log service encountered an attempt to erroneous allocate or dispose reservation space."),
        0x000019d8: ("ERROR_LOG_CANT_DELETE", "Log service cannot delete log file or file system container."),
        0x000019d9: ("ERROR_LOG_CONTAINER_LIMIT_EXCEEDED", "Log service has reached the maximum allowable containers allocated to a log file."),
        0x000019da: ("ERROR_LOG_START_OF_LOG", "Log service has attempted to read or write backward past the start of the log."),
        0x000019db: ("ERROR_LOG_POLICY_ALREADY_INSTALLED", "Log policy could not be installed because a policy of the same type is already present."),
        0x000019dc: ("ERROR_LOG_POLICY_NOT_INSTALLED", "Log policy in question was not installed at the time of the request."),
        0x000019dd: ("ERROR_LOG_POLICY_INVALID", "The installed set of policies on the log is invalid."),
        0x000019de: ("ERROR_LOG_POLICY_CONFLICT", "A policy on the log in question prevented the operation from completing."),
        0x000019df: ("ERROR_LOG_PINNED_ARCHIVE_TAIL", "Log space cannot be reclaimed because the log is pinned by the archive tail."),
        0x000019e0: ("ERROR_LOG_RECORD_NONEXISTENT", "Log record is not a record in the log file."),
        0x000019e1: ("ERROR_LOG_RECORDS_RESERVED_INVALID", "Number of reserved log records or the adjustment of the number of reserved log records is invalid."),
        0x000019e2: ("ERROR_LOG_SPACE_RESERVED_INVALID", "Reserved log space or the adjustment of the log space is invalid."),
        0x000019e3: ("ERROR_LOG_TAIL_INVALID", "An new or existing archive tail or base of the active log is invalid."),
        0x000019e4: ("ERROR_LOG_FULL", "Log space is exhausted."),
        0x000019e5: ("ERROR_COULD_NOT_RESIZE_LOG", "The log could not be set to the requested size."),
        0x000019e6: ("ERROR_LOG_MULTIPLEXED", "Log is multiplexed, no direct writes to the physical log is allowed."),
        0x000019e7: ("ERROR_LOG_DEDICATED", "The operation failed because the log is a dedicated log."),
        0x000019e8: ("ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS", "The operation requires an archive context."),
        0x000019e9: ("ERROR_LOG_ARCHIVE_IN_PROGRESS", "Log archival is in progress."),
        0x000019ea: ("ERROR_LOG_EPHEMERAL", "The operation requires a non-ephemeral log, but the log is ephemeral."),
        0x000019eb: ("ERROR_LOG_NOT_ENOUGH_CONTAINERS", "The log must have at least two containers before it can be read from or written to."),
        0x000019ec: ("ERROR_LOG_CLIENT_ALREADY_REGISTERED", "A log client has already registered on the stream."),
        0x000019ed: ("ERROR_LOG_CLIENT_NOT_REGISTERED", "A log client has not been registered on the stream."),
        0x000019ee: ("ERROR_LOG_FULL_HANDLER_IN_PROGRESS", "A request has already been made to handle the log full condition."),
        0x000019ef: ("ERROR_LOG_CONTAINER_READ_FAILED", "Log service encountered an error when attempting to read from a log container."),
        0x000019f0: ("ERROR_LOG_CONTAINER_WRITE_FAILED", "Log service encountered an error when attempting to write to a log container."),
        0x000019f1: ("ERROR_LOG_CONTAINER_OPEN_FAILED", "Log service encountered an error when attempting open a log container."),
        0x000019f2: ("ERROR_LOG_CONTAINER_STATE_INVALID", "Log service encountered an invalid container state when attempting a requested action."),
        0x000019f3: ("ERROR_LOG_STATE_INVALID", "Log service is not in the correct state to perform a requested action."),
        0x000019f4: ("ERROR_LOG_PINNED", "Log space cannot be reclaimed because the log is pinned."),
        0x000019f5: ("ERROR_LOG_METADATA_FLUSH_FAILED", "Log metadata flush failed."),
        0x000019f6: ("ERROR_LOG_INCONSISTENT_SECURITY", "Security on the log and its containers is inconsistent."),
        0x000019f7: ("ERROR_LOG_APPENDED_FLUSH_FAILED", "Records were appended to the log or reservation changes were made, but the log could not be flushed."),
        0x000019f8: ("ERROR_LOG_PINNED_RESERVATION", "The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available."),
        0x00001a2c: ("ERROR_INVALID_TRANSACTION", "The transaction handle associated with this operation is not valid."),
        0x00001a2d: ("ERROR_TRANSACTION_NOT_ACTIVE", "The requested operation was made in the context of a transaction that is no longer active."),
        0x00001a2e: ("ERROR_TRANSACTION_REQUEST_NOT_VALID", "The requested operation is not valid on the Transaction object in its current state."),
        0x00001a2f: ("ERROR_TRANSACTION_NOT_REQUESTED", "The caller has called a response API, but the response is not expected because the TM did not issue the corresponding request to the caller."),
        0x00001a30: ("ERROR_TRANSACTION_ALREADY_ABORTED", "It is too late to perform the requested operation, since the Transaction has already been aborted."),
        0x00001a31: ("ERROR_TRANSACTION_ALREADY_COMMITTED", "It is too late to perform the requested operation, since the Transaction has already been committed."),
        0x00001a32: ("ERROR_TM_INITIALIZATION_FAILED", "The Transaction Manager was unable to be successfully initialized. Transacted operations are not supported."),
        0x00001a33: ("ERROR_RESOURCEMANAGER_READ_ONLY", "The specified ResourceManager made no changes or updates to the resource under this transaction."),
        0x00001a34: ("ERROR_TRANSACTION_NOT_JOINED", "The resource manager has attempted to prepare a transaction that it has not successfully joined."),
        0x00001a35: ("ERROR_TRANSACTION_SUPERIOR_EXISTS", "The Transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allow."),
        0x00001a36: ("ERROR_CRM_PROTOCOL_ALREADY_EXISTS", "The RM tried to register a protocol that already exists."),
        0x00001a37: ("ERROR_TRANSACTION_PROPAGATION_FAILED", "The attempt to propagate the Transaction failed."),
        0x00001a38: ("ERROR_CRM_PROTOCOL_NOT_FOUND", "The requested propagation protocol was not registered as a CRM."),
        0x00001a39: ("ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER", "The buffer passed in to PushTransaction or PullTransaction is not in a valid format."),
        0x00001a3a: ("ERROR_CURRENT_TRANSACTION_NOT_VALID", "The current transaction context associated with the thread is not a valid handle to a transaction object."),
        0x00001a3b: ("ERROR_TRANSACTION_NOT_FOUND", "The specified Transaction object could not be opened, because it was not found."),
        0x00001a3c: ("ERROR_RESOURCEMANAGER_NOT_FOUND", "The specified ResourceManager object could not be opened, because it was not found."),
        0x00001a3d: ("ERROR_ENLISTMENT_NOT_FOUND", "The specified Enlistment object could not be opened, because it was not found."),
        0x00001a3e: ("ERROR_TRANSACTIONMANAGER_NOT_FOUND", "The specified TransactionManager object could not be opened, because it was not found."),
        0x00001a3f: ("ERROR_TRANSACTIONMANAGER_NOT_ONLINE", "The object specified could not be created or opened, because its associated TransactionManager is not online.  The TransactionManager must be brought fully Online by calling RecoverTransactionManager to recover to the end of its LogFile before objects in its Transaction or ResourceManager namespaces can be opened.  In addition, errors in writing records to its LogFile can cause a TransactionManager to go offline."),
        0x00001a40: ("ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION", "The specified TransactionManager was unable to create the objects contained in its logfile in the Ob namespace. Therefore, the TransactionManager was unable to recover."),
        0x00001a41: ("ERROR_TRANSACTION_NOT_ROOT", "The call to create a superior Enlistment on this Transaction object could not be completed, because the Transaction object specified for the enlistment is a subordinate branch of the Transaction. Only the root of the Transaction can be enlisted on as a superior."),
        0x00001a42: ("ERROR_TRANSACTION_OBJECT_EXPIRED", "Because the associated transaction manager or resource manager has been closed, the handle is no longer valid."),
        0x00001a43: ("ERROR_TRANSACTION_RESPONSE_NOT_ENLISTED", "The specified operation could not be performed on this Superior enlistment, because the enlistment was not created with the corresponding completion response in the NotificationMask."),
        0x00001a44: ("ERROR_TRANSACTION_RECORD_TOO_LONG", "The specified operation could not be performed, because the record that would be logged was too long. This can occur because of two conditions: either there are too many Enlistments on this Transaction, or the combined RecoveryInformation being logged on behalf of those Enlistments is too long."),
        0x00001a45: ("ERROR_IMPLICIT_TRANSACTION_NOT_SUPPORTED", "Implicit transaction are not supported."),
        0x00001a46: ("ERROR_TRANSACTION_INTEGRITY_VIOLATED", "The kernel transaction manager had to abort or forget the transaction because it blocked forward progress."),
        0x00001a47: ("ERROR_TRANSACTIONMANAGER_IDENTITY_MISMATCH", "The TransactionManager identity that was supplied did not match the one recorded in the TransactionManager's log file."),
        0x00001a48: ("ERROR_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT", "This snapshot operation cannot continue because a transactional resource manager cannot be frozen in its current state.  Please try again."),
        0x00001a49: ("ERROR_TRANSACTION_MUST_WRITETHROUGH", "The transaction cannot be enlisted on with the specified EnlistmentMask, because the transaction has already completed the PrePrepare phase.  In order to ensure correctness, the ResourceManager must switch to a write-through mode and cease caching data within this transaction.  Enlisting for only subsequent transaction phases may still succeed."),
        0x00001a4a: ("ERROR_TRANSACTION_NO_SUPERIOR", "The transaction does not have a superior enlistment."),
        0x00001a4b: ("ERROR_HEURISTIC_DAMAGE_POSSIBLE", "The attempt to commit the Transaction completed, but it is possible that some portion of the transaction tree did not commit successfully due to heuristics.  Therefore it is possible that some data modified in the transaction may not have committed, resulting in transactional inconsistency.  If possible, check the consistency of the associated data."),
        0x00001a90: ("ERROR_TRANSACTIONAL_CONFLICT", "The function attempted to use a name that is reserved for use by another transaction."),
        0x00001a91: ("ERROR_RM_NOT_ACTIVE", "Transaction support within the specified resource manager is not started or was shut down due to an error."),
        0x00001a92: ("ERROR_RM_METADATA_CORRUPT", "The metadata of the RM has been corrupted. The RM will not function."),
        0x00001a93: ("ERROR_DIRECTORY_NOT_RM", "The specified directory does not contain a resource manager."),
        0x00001a95: ("ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE", "The remote server or share does not support transacted file operations."),
        0x00001a96: ("ERROR_LOG_RESIZE_INVALID_SIZE", "The requested log size is invalid."),
        0x00001a97: ("ERROR_OBJECT_NO_LONGER_EXISTS", "The object (file, stream, link) corresponding to the handle has been deleted by a Transaction Savepoint Rollback."),
        0x00001a98: ("ERROR_STREAM_MINIVERSION_NOT_FOUND", "The specified file miniversion was not found for this transacted file open."),
        0x00001a99: ("ERROR_STREAM_MINIVERSION_NOT_VALID", "The specified file miniversion was found but has been invalidated. Most likely cause is a transaction savepoint rollback."),
        0x00001a9a: ("ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION", "A miniversion may only be opened in the context of the transaction that created it."),
        0x00001a9b: ("ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT", "It is not possible to open a miniversion with modify access."),
        0x00001a9c: ("ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS", "It is not possible to create any more miniversions for this stream."),
        0x00001a9e: ("ERROR_REMOTE_FILE_VERSION_MISMATCH", "The remote server sent mismatching version number or Fid for a file opened with transactions."),
        0x00001a9f: ("ERROR_HANDLE_NO_LONGER_VALID", "The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint."),
        0x00001aa0: ("ERROR_NO_TXF_METADATA", "There is no transaction metadata on the file."),
        0x00001aa1: ("ERROR_LOG_CORRUPTION_DETECTED", "The log data is corrupt."),
        0x00001aa2: ("ERROR_CANT_RECOVER_WITH_HANDLE_OPEN", "The file can't be recovered because there is a handle still open on it."),
        0x00001aa3: ("ERROR_RM_DISCONNECTED", "The transaction outcome is unavailable because the resource manager responsible for it has disconnected."),
        0x00001aa4: ("ERROR_ENLISTMENT_NOT_SUPERIOR", "The request was rejected because the enlistment in question is not a superior enlistment."),
        0x00001aa5: ("ERROR_RECOVERY_NOT_NEEDED", "The transactional resource manager is already consistent. Recovery is not needed."),
        0x00001aa6: ("ERROR_RM_ALREADY_STARTED", "The transactional resource manager has already been started."),
        0x00001aa7: ("ERROR_FILE_IDENTITY_NOT_PERSISTENT", "The file cannot be opened transactionally, because its identity depends on the outcome of an unresolved transaction."),
        0x00001aa8: ("ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY", "The operation cannot be performed because another transaction is depending on the fact that this property will not change."),
        0x00001aa9: ("ERROR_CANT_CROSS_RM_BOUNDARY", "The operation would involve a single file with two transactional resource managers and is therefore not allowed."),
        0x00001aaa: ("ERROR_TXF_DIR_NOT_EMPTY", "The $Txf directory must be empty for this operation to succeed."),
        0x00001aab: ("ERROR_INDOUBT_TRANSACTIONS_EXIST", "The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed."),
        0x00001aac: ("ERROR_TM_VOLATILE", "The operation could not be completed because the transaction manager does not have a log."),
        0x00001aad: ("ERROR_ROLLBACK_TIMER_EXPIRED", "A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution."),
        0x00001aae: ("ERROR_TXF_ATTRIBUTE_CORRUPT", "The transactional metadata attribute on the file or directory is corrupt and unreadable."),
        0x00001aaf: ("ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION", "The encryption operation could not be completed because a transaction is active."),
        0x00001ab0: ("ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED", "This object is not allowed to be opened in a transaction."),
        0x00001ab1: ("ERROR_LOG_GROWTH_FAILED", "An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log."),
        0x00001ab2: ("ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE", "Memory mapping (creating a mapped section) a remote file under a transaction is not supported."),
        0x00001ab3: ("ERROR_TXF_METADATA_ALREADY_PRESENT", "Transaction metadata is already present on this file and cannot be superseded."),
        0x00001ab4: ("ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET", "A transaction scope could not be entered because the scope handler has not been initialized."),
        0x00001ab5: ("ERROR_TRANSACTION_REQUIRED_PROMOTION", "Promotion was required in order to allow the resource manager to enlist, but the transaction was set to disallow it."),
        0x00001ab6: ("ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION", "This file is open for modification in an unresolved transaction and may be opened for execute only by a transacted reader."),
        0x00001ab7: ("ERROR_TRANSACTIONS_NOT_FROZEN", "The request to thaw frozen transactions was ignored because transactions had not previously been frozen."),
        0x00001ab8: ("ERROR_TRANSACTION_FREEZE_IN_PROGRESS", "Transactions cannot be frozen because a freeze is already in progress."),
        0x00001ab9: ("ERROR_NOT_SNAPSHOT_VOLUME", "The target volume is not a snapshot volume. This operation is only valid on a volume mounted as a snapshot."),
        0x00001aba: ("ERROR_NO_SAVEPOINT_WITH_OPEN_FILES", "The savepoint operation failed because files are open on the transaction. This is not permitted."),
        0x00001abb: ("ERROR_DATA_LOST_REPAIR", "Windows has discovered corruption in a file, and that file has since been repaired. Data loss may have occurred."),
        0x00001abc: ("ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION", "The sparse operation could not be completed because a transaction is active on the file."),
        0x00001abd: ("ERROR_TM_IDENTITY_MISMATCH", "The call to create a TransactionManager object failed because the Tm Identity stored in the logfile does not match the Tm Identity that was passed in as an argument."),
        0x00001abe: ("ERROR_FLOATED_SECTION", "I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data."),
        0x00001abf: ("ERROR_CANNOT_ACCEPT_TRANSACTED_WORK", "The transactional resource manager cannot currently accept transacted work due to a transient condition such as low resources."),
        0x00001ac0: ("ERROR_CANNOT_ABORT_TRANSACTIONS", "The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down."),
        0x00001ac1: ("ERROR_BAD_CLUSTERS", "The operation could not be completed due to bad clusters on disk."),
        0x00001ac2: ("ERROR_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION", "The compression operation could not be completed because a transaction is active on the file."),
        0x00001ac3: ("ERROR_VOLUME_DIRTY", "The operation could not be completed because the volume is dirty. Please run chkdsk and try again."),
        0x00001ac4: ("ERROR_NO_LINK_TRACKING_IN_TRANSACTION", "The link tracking operation could not be completed because a transaction is active."),
        0x00001ac5: ("ERROR_OPERATION_NOT_SUPPORTED_IN_TRANSACTION", "This operation cannot be performed in a transaction."),
        0x00001ac6: ("ERROR_EXPIRED_HANDLE", "The handle is no longer properly associated with its transaction.  It may have been opened in a transactional resource manager that was subsequently forced to restart.  Please close the handle and open a new one."),
        0x00001ac7: ("ERROR_TRANSACTION_NOT_ENLISTED", "The specified operation could not be performed because the resource manager is not enlisted in the transaction."),
        0x00001b59: ("ERROR_CTX_WINSTATION_NAME_INVALID", "The specified session name is invalid."),
        0x00001b5a: ("ERROR_CTX_INVALID_PD", "The specified protocol driver is invalid."),
        0x00001b5b: ("ERROR_CTX_PD_NOT_FOUND", "The specified protocol driver was not found in the system path."),
        0x00001b5c: ("ERROR_CTX_WD_NOT_FOUND", "The specified terminal connection driver was not found in the system path."),
        0x00001b5d: ("ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY", "A registry key for event logging could not be created for this session."),
        0x00001b5e: ("ERROR_CTX_SERVICE_NAME_COLLISION", "A service with the same name already exists on the system."),
        0x00001b5f: ("ERROR_CTX_CLOSE_PENDING", "A close operation is pending on the session."),
        0x00001b60: ("ERROR_CTX_NO_OUTBUF", "There are no free output buffers available."),
        0x00001b61: ("ERROR_CTX_MODEM_INF_NOT_FOUND", "The MODEM.INF file was not found."),
        0x00001b62: ("ERROR_CTX_INVALID_MODEMNAME", "The modem name was not found in MODEM.INF."),
        0x00001b63: ("ERROR_CTX_MODEM_RESPONSE_ERROR", "The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem."),
        0x00001b64: ("ERROR_CTX_MODEM_RESPONSE_TIMEOUT", "The modem did not respond to the command sent to it. Verify that the modem is properly cabled and powered on."),
        0x00001b65: ("ERROR_CTX_MODEM_RESPONSE_NO_CARRIER", "Carrier detect has failed or carrier has been dropped due to disconnect."),
        0x00001b66: ("ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE", "Dial tone not detected within the required time. Verify that the phone cable is properly attached and functional."),
        0x00001b67: ("ERROR_CTX_MODEM_RESPONSE_BUSY", "Busy signal detected at remote site on callback."),
        0x00001b68: ("ERROR_CTX_MODEM_RESPONSE_VOICE", "Voice detected at remote site on callback."),
        0x00001b69: ("ERROR_CTX_TD_ERROR", "Transport driver error"),
        0x00001b6e: ("ERROR_CTX_WINSTATION_NOT_FOUND", "The specified session cannot be found."),
        0x00001b6f: ("ERROR_CTX_WINSTATION_ALREADY_EXISTS", "The specified session name is already in use."),
        0x00001b70: ("ERROR_CTX_WINSTATION_BUSY", "The task you are trying to do can't be completed because Remote Desktop Services is currently busy. Please try again in a few minutes. Other users should still be able to log on."),
        0x00001b71: ("ERROR_CTX_BAD_VIDEO_MODE", "An attempt has been made to connect to a session whose video mode is not supported by the current client."),
        0x00001b7b: ("ERROR_CTX_GRAPHICS_INVALID", "The application attempted to enable DOS graphics mode. DOS graphics mode is not supported."),
        0x00001b7d: ("ERROR_CTX_LOGON_DISABLED", "Your interactive logon privilege has been disabled. Please contact your administrator."),
        0x00001b7e: ("ERROR_CTX_NOT_CONSOLE", "The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access."),
        0x00001b80: ("ERROR_CTX_CLIENT_QUERY_TIMEOUT", "The client failed to respond to the server connect message."),
        0x00001b81: ("ERROR_CTX_CONSOLE_DISCONNECT", "Disconnecting the console session is not supported."),
        0x00001b82: ("ERROR_CTX_CONSOLE_CONNECT", "Reconnecting a disconnected session to the console is not supported."),
        0x00001b84: ("ERROR_CTX_SHADOW_DENIED", "The request to control another session remotely was denied."),
        0x00001b85: ("ERROR_CTX_WINSTATION_ACCESS_DENIED", "The requested session access is denied."),
        0x00001b89: ("ERROR_CTX_INVALID_WD", "The specified terminal connection driver is invalid."),
        0x00001b8a: ("ERROR_CTX_SHADOW_INVALID", "The requested session cannot be controlled remotely."),
        0x00001b8b: ("ERROR_CTX_SHADOW_DISABLED", "The requested session is not configured to allow remote control."),
        0x00001b8c: ("ERROR_CTX_CLIENT_LICENSE_IN_USE", "Your request to connect to this Terminal Server has been rejected. Your Terminal Server client license number is currently being used by another user. Please call your system administrator to obtain a unique license number."),
        0x00001b8d: ("ERROR_CTX_CLIENT_LICENSE_NOT_SET", "Your request to connect to this Terminal Server has been rejected. Your Terminal Server client license number has not been entered for this copy of the Terminal Server client. Please contact your system administrator."),
        0x00001b8e: ("ERROR_CTX_LICENSE_NOT_AVAILABLE", "The number of connections to this computer is limited and all connections are in use right now. Try connecting later or contact your system administrator."),
        0x00001b8f: ("ERROR_CTX_LICENSE_CLIENT_INVALID", "The client you are using is not licensed to use this system. Your logon request is denied."),
        0x00001b90: ("ERROR_CTX_LICENSE_EXPIRED", "The system license has expired. Your logon request is denied."),
        0x00001b91: ("ERROR_CTX_SHADOW_NOT_RUNNING", "Remote control could not be terminated because the specified session is not currently being remotely controlled."),
        0x00001b92: ("ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE", "The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported."),
        0x00001b93: ("ERROR_ACTIVATION_COUNT_EXCEEDED", "Activation has already been reset the maximum number of times for this installation. Your activation timer will not be cleared."),
        0x00001b94: ("ERROR_CTX_WINSTATIONS_DISABLED", "Remote logins are currently disabled."),
        0x00001b95: ("ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED", "You do not have the proper encryption level to access this Session."),
        0x00001b96: ("ERROR_CTX_SESSION_IN_USE", "The user %s\\%s is currently logged on to this computer. Only the current user or an administrator can log on to this computer."),
        0x00001b97: ("ERROR_CTX_NO_FORCE_LOGOFF", "The user %s\\%s is already logged on to the console of this computer. You do not have permission to log in at this time. To resolve this issue, contact %s\\%s and have them log off."),
        0x00001b98: ("ERROR_CTX_ACCOUNT_RESTRICTION", "Unable to log you on because of an account restriction."),
        0x00001b99: ("ERROR_RDP_PROTOCOL_ERROR", "The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client."),
        0x00001b9a: ("ERROR_CTX_CDM_CONNECT", "The Client Drive Mapping Service Has Connected on Terminal Connection."),
        0x00001b9b: ("ERROR_CTX_CDM_DISCONNECT", "The Client Drive Mapping Service Has Disconnected on Terminal Connection."),
        0x00001b9c: ("ERROR_CTX_SECURITY_LAYER_ERROR", "The Terminal Server security layer detected an error in the protocol stream and has disconnected the client."),
        0x00001b9d: ("ERROR_TS_INCOMPATIBLE_SESSIONS", "The target session is incompatible with the current session."),
        0x00001b9e: ("ERROR_TS_VIDEO_SUBSYSTEM_ERROR", "Windows can't connect to your session because a problem occurred in the Windows video subsystem. Try connecting again later, or contact the server administrator for assistance."),
        0x00001f41: ("FRS_ERR_INVALID_API_SEQUENCE", "The file replication service API was called incorrectly."),
        0x00001f42: ("FRS_ERR_STARTING_SERVICE", "The file replication service cannot be started."),
        0x00001f43: ("FRS_ERR_STOPPING_SERVICE", "The file replication service cannot be stopped."),
        0x00001f44: ("FRS_ERR_INTERNAL_API", "The file replication service API terminated the request. The event log may have more information."),
        0x00001f45: ("FRS_ERR_INTERNAL", "The file replication service terminated the request. The event log may have more information."),
        0x00001f46: ("FRS_ERR_SERVICE_COMM", "The file replication service cannot be contacted. The event log may have more information."),
        0x00001f47: ("FRS_ERR_INSUFFICIENT_PRIV", "The file replication service cannot satisfy the request because the user has insufficient privileges. The event log may have more information."),
        0x00001f48: ("FRS_ERR_AUTHENTICATION", "The file replication service cannot satisfy the request because authenticated RPC is not available. The event log may have more information."),
        0x00001f49: ("FRS_ERR_PARENT_INSUFFICIENT_PRIV", "The file replication service cannot satisfy the request because the user has insufficient privileges on the domain controller. The event log may have more information."),
        0x00001f4a: ("FRS_ERR_PARENT_AUTHENTICATION", "The file replication service cannot satisfy the request because authenticated RPC is not available on the domain controller. The event log may have more information."),
        0x00001f4b: ("FRS_ERR_CHILD_TO_PARENT_COMM", "The file replication service cannot communicate with the file replication service on the domain controller. The event log may have more information."),
        0x00001f4c: ("FRS_ERR_PARENT_TO_CHILD_COMM", "The file replication service on the domain controller cannot communicate with the file replication service on this computer. The event log may have more information."),
        0x00001f4d: ("FRS_ERR_SYSVOL_POPULATE", "The file replication service cannot populate the system volume because of an internal error. The event log may have more information."),
        0x00001f4e: ("FRS_ERR_SYSVOL_POPULATE_TIMEOUT", "The file replication service cannot populate the system volume because of an internal timeout. The event log may have more information."),
        0x00001f4f: ("FRS_ERR_SYSVOL_IS_BUSY", "The file replication service cannot process the request. The system volume is busy with a previous request."),
        0x00001f50: ("FRS_ERR_SYSVOL_DEMOTE", "The file replication service cannot stop replicating the system volume because of an internal error. The event log may have more information."),
        0x00001f51: ("FRS_ERR_INVALID_SERVICE_PARAMETER", "The file replication service detected an invalid parameter."),
        0x00002008: ("ERROR_DS_NOT_INSTALLED", "An error occurred while installing the directory service. For more information, see the event log."),
        0x00002009: ("ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY", "The directory service evaluated group memberships locally."),
        0x0000200a: ("ERROR_DS_NO_ATTRIBUTE_OR_VALUE", "The specified directory service attribute or value does not exist."),
        0x0000200b: ("ERROR_DS_INVALID_ATTRIBUTE_SYNTAX", "The attribute syntax specified to the directory service is invalid."),
        0x0000200c: ("ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED", "The attribute type specified to the directory service is not defined."),
        0x0000200d: ("ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS", "The specified directory service attribute or value already exists."),
        0x0000200e: ("ERROR_DS_BUSY", "The directory service is busy."),
        0x0000200f: ("ERROR_DS_UNAVAILABLE", "The directory service is unavailable."),
        0x00002010: ("ERROR_DS_NO_RIDS_ALLOCATED", "The directory service was unable to allocate a relative identifier."),
        0x00002011: ("ERROR_DS_NO_MORE_RIDS", "The directory service has exhausted the pool of relative identifiers."),
        0x00002012: ("ERROR_DS_INCORRECT_ROLE_OWNER", "The requested operation could not be performed because the directory service is not the master for that type of operation."),
        0x00002013: ("ERROR_DS_RIDMGR_INIT_ERROR", "The directory service was unable to initialize the subsystem that allocates relative identifiers."),
        0x00002014: ("ERROR_DS_OBJ_CLASS_VIOLATION", "The requested operation did not satisfy one or more constraints associated with the class of the object."),
        0x00002015: ("ERROR_DS_CANT_ON_NON_LEAF", "The directory service can perform the requested operation only on a leaf object."),
        0x00002016: ("ERROR_DS_CANT_ON_RDN", "The directory service cannot perform the requested operation on the RDN attribute of an object."),
        0x00002017: ("ERROR_DS_CANT_MOD_OBJ_CLASS", "The directory service detected an attempt to modify the object class of an object."),
        0x00002018: ("ERROR_DS_CROSS_DOM_MOVE_ERROR", "The requested cross-domain move operation could not be performed."),
        0x00002019: ("ERROR_DS_GC_NOT_AVAILABLE", "Unable to contact the global catalog server."),
        0x0000201a: ("ERROR_SHARED_POLICY", "The policy object is shared and can only be modified at the root."),
        0x0000201b: ("ERROR_POLICY_OBJECT_NOT_FOUND", "The policy object does not exist."),
        0x0000201c: ("ERROR_POLICY_ONLY_IN_DS", "The requested policy information is only in the directory service."),
        0x0000201d: ("ERROR_PROMOTION_ACTIVE", "A domain controller promotion is currently active."),
        0x0000201e: ("ERROR_NO_PROMOTION_ACTIVE", "A domain controller promotion is not currently active"),
        0x00002020: ("ERROR_DS_OPERATIONS_ERROR", "An operations error occurred."),
        0x00002021: ("ERROR_DS_PROTOCOL_ERROR", "A protocol error occurred."),
        0x00002022: ("ERROR_DS_TIMELIMIT_EXCEEDED", "The time limit for this request was exceeded."),
        0x00002023: ("ERROR_DS_SIZELIMIT_EXCEEDED", "The size limit for this request was exceeded."),
        0x00002024: ("ERROR_DS_ADMIN_LIMIT_EXCEEDED", "The administrative limit for this request was exceeded."),
        0x00002025: ("ERROR_DS_COMPARE_FALSE", "The compare response was false."),
        0x00002026: ("ERROR_DS_COMPARE_TRUE", "The compare response was true."),
        0x00002027: ("ERROR_DS_AUTH_METHOD_NOT_SUPPORTED", "The requested authentication method is not supported by the server."),
        0x00002028: ("ERROR_DS_STRONG_AUTH_REQUIRED", "A more secure authentication method is required for this server."),
        0x00002029: ("ERROR_DS_INAPPROPRIATE_AUTH", "Inappropriate authentication."),
        0x0000202a: ("ERROR_DS_AUTH_UNKNOWN", "The authentication mechanism is unknown."),
        0x0000202b: ("ERROR_DS_REFERRAL", "A referral was returned from the server."),
        0x0000202c: ("ERROR_DS_UNAVAILABLE_CRIT_EXTENSION", "The server does not support the requested critical extension."),
        0x0000202d: ("ERROR_DS_CONFIDENTIALITY_REQUIRED", "This request requires a secure connection."),
        0x0000202e: ("ERROR_DS_INAPPROPRIATE_MATCHING", "Inappropriate matching."),
        0x0000202f: ("ERROR_DS_CONSTRAINT_VIOLATION", "A constraint violation occurred."),
        0x00002030: ("ERROR_DS_NO_SUCH_OBJECT", "There is no such object on the server."),
        0x00002031: ("ERROR_DS_ALIAS_PROBLEM", "There is an alias problem."),
        0x00002032: ("ERROR_DS_INVALID_DN_SYNTAX", "An invalid dn syntax has been specified."),
        0x00002033: ("ERROR_DS_IS_LEAF", "The object is a leaf object."),
        0x00002034: ("ERROR_DS_ALIAS_DEREF_PROBLEM", "There is an alias dereferencing problem."),
        0x00002035: ("ERROR_DS_UNWILLING_TO_PERFORM", "The server is unwilling to process the request."),
        0x00002036: ("ERROR_DS_LOOP_DETECT", "A loop has been detected."),
        0x00002037: ("ERROR_DS_NAMING_VIOLATION", "There is a naming violation."),
        0x00002038: ("ERROR_DS_OBJECT_RESULTS_TOO_LARGE", "The result set is too large."),
        0x00002039: ("ERROR_DS_AFFECTS_MULTIPLE_DSAS", "The operation affects multiple DSAs"),
        0x0000203a: ("ERROR_DS_SERVER_DOWN", "The server is not operational."),
        0x0000203b: ("ERROR_DS_LOCAL_ERROR", "A local error has occurred."),
        0x0000203c: ("ERROR_DS_ENCODING_ERROR", "An encoding error has occurred."),
        0x0000203d: ("ERROR_DS_DECODING_ERROR", "A decoding error has occurred."),
        0x0000203e: ("ERROR_DS_FILTER_UNKNOWN", "The search filter cannot be recognized."),
        0x0000203f: ("ERROR_DS_PARAM_ERROR", "One or more parameters are illegal."),
        0x00002040: ("ERROR_DS_NOT_SUPPORTED", "The specified method is not supported."),
        0x00002041: ("ERROR_DS_NO_RESULTS_RETURNED", "No results were returned."),
        0x00002042: ("ERROR_DS_CONTROL_NOT_FOUND", "The specified control is not supported by the server."),
        0x00002043: ("ERROR_DS_CLIENT_LOOP", "A referral loop was detected by the client."),
        0x00002044: ("ERROR_DS_REFERRAL_LIMIT_EXCEEDED", "The preset referral limit was exceeded."),
        0x00002045: ("ERROR_DS_SORT_CONTROL_MISSING", "The search requires a SORT control."),
        0x00002046: ("ERROR_DS_OFFSET_RANGE_ERROR", "The search results exceed the offset range specified."),
        0x00002047: ("ERROR_DS_RIDMGR_DISABLED", "The directory service detected the subsystem that allocates relative identifiers is disabled. This can occur as a protective mechanism when the system determines a significant portion of relative identifiers (RIDs) have been exhausted. Please see https://go.microsoft.com/fwlink/?LinkId=228610 for recommended diagnostic steps and the procedure to re-enable account creation."),
        0x0000206d: ("ERROR_DS_ROOT_MUST_BE_NC", "The root object must be the head of a naming context. The root object cannot have an instantiated parent."),
        0x0000206e: ("ERROR_DS_ADD_REPLICA_INHIBITED", "The add replica operation cannot be performed. The naming context must be writeable in order to create the replica."),
        0x0000206f: ("ERROR_DS_ATT_NOT_DEF_IN_SCHEMA", "A reference to an attribute that is not defined in the schema occurred."),
        0x00002070: ("ERROR_DS_MAX_OBJ_SIZE_EXCEEDED", "The maximum size of an object has been exceeded."),
        0x00002071: ("ERROR_DS_OBJ_STRING_NAME_EXISTS", "An attempt was made to add an object to the directory with a name that is already in use."),
        0x00002072: ("ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA", "An attempt was made to add an object of a class that does not have an RDN defined in the schema."),
        0x00002073: ("ERROR_DS_RDN_DOESNT_MATCH_SCHEMA", "An attempt was made to add an object using an RDN that is not the RDN defined in the schema."),
        0x00002074: ("ERROR_DS_NO_REQUESTED_ATTS_FOUND", "None of the requested attributes were found on the objects."),
        0x00002075: ("ERROR_DS_USER_BUFFER_TO_SMALL", "The user buffer is too small."),
        0x00002076: ("ERROR_DS_ATT_IS_NOT_ON_OBJ", "The attribute specified in the operation is not present on the object."),
        0x00002077: ("ERROR_DS_ILLEGAL_MOD_OPERATION", "Illegal modify operation. Some aspect of the modification is not permitted."),
        0x00002078: ("ERROR_DS_OBJ_TOO_LARGE", "The specified object is too large."),
        0x00002079: ("ERROR_DS_BAD_INSTANCE_TYPE", "The specified instance type is not valid."),
        0x0000207a: ("ERROR_DS_MASTERDSA_REQUIRED", "The operation must be performed at a master DSA."),
        0x0000207b: ("ERROR_DS_OBJECT_CLASS_REQUIRED", "The object class attribute must be specified."),
        0x0000207c: ("ERROR_DS_MISSING_REQUIRED_ATT", "A required attribute is missing."),
        0x0000207d: ("ERROR_DS_ATT_NOT_DEF_FOR_CLASS", "An attempt was made to modify an object to include an attribute that is not legal for its class."),
        0x0000207e: ("ERROR_DS_ATT_ALREADY_EXISTS", "The specified attribute is already present on the object."),
        0x00002080: ("ERROR_DS_CANT_ADD_ATT_VALUES", "The specified attribute is not present, or has no values."),
        0x00002081: ("ERROR_DS_SINGLE_VALUE_CONSTRAINT", "Multiple values were specified for an attribute that can have only one value."),
        0x00002082: ("ERROR_DS_RANGE_CONSTRAINT", "A value for the attribute was not in the acceptable range of values."),
        0x00002083: ("ERROR_DS_ATT_VAL_ALREADY_EXISTS", "The specified value already exists."),
        0x00002084: ("ERROR_DS_CANT_REM_MISSING_ATT", "The attribute cannot be removed because it is not present on the object."),
        0x00002085: ("ERROR_DS_CANT_REM_MISSING_ATT_VAL", "The attribute value cannot be removed because it is not present on the object."),
        0x00002086: ("ERROR_DS_ROOT_CANT_BE_SUBREF", "The specified root object cannot be a subref."),
        0x00002087: ("ERROR_DS_NO_CHAINING", "Chaining is not permitted."),
        0x00002088: ("ERROR_DS_NO_CHAINED_EVAL", "Chained evaluation is not permitted."),
        0x00002089: ("ERROR_DS_NO_PARENT_OBJECT", "The operation could not be performed because the object's parent is either uninstantiated or deleted."),
        0x0000208a: ("ERROR_DS_PARENT_IS_AN_ALIAS", "Having a parent that is an alias is not permitted. Aliases are leaf objects."),
        0x0000208b: ("ERROR_DS_CANT_MIX_MASTER_AND_REPS", "The object and parent must be of the same type, either both masters or both replicas."),
        0x0000208c: ("ERROR_DS_CHILDREN_EXIST", "The operation cannot be performed because child objects exist. This operation can only be performed on a leaf object."),
        0x0000208d: ("ERROR_DS_OBJ_NOT_FOUND", "Directory object not found."),
        0x0000208e: ("ERROR_DS_ALIASED_OBJ_MISSING", "The aliased object is missing."),
        0x0000208f: ("ERROR_DS_BAD_NAME_SYNTAX", "The object name has bad syntax."),
        0x00002090: ("ERROR_DS_ALIAS_POINTS_TO_ALIAS", "It is not permitted for an alias to refer to another alias."),
        0x00002091: ("ERROR_DS_CANT_DEREF_ALIAS", "The alias cannot be dereferenced."),
        0x00002092: ("ERROR_DS_OUT_OF_SCOPE", "The operation is out of scope."),
        0x00002093: ("ERROR_DS_OBJECT_BEING_REMOVED", "The operation cannot continue because the object is in the process of being removed."),
        0x00002094: ("ERROR_DS_CANT_DELETE_DSA_OBJ", "The DSA object cannot be deleted."),
        0x00002095: ("ERROR_DS_GENERIC_ERROR", "A directory service error has occurred."),
        0x00002096: ("ERROR_DS_DSA_MUST_BE_INT_MASTER", "The operation can only be performed on an internal master DSA object."),
        0x00002097: ("ERROR_DS_CLASS_NOT_DSA", "The object must be of class DSA."),
        0x00002098: ("ERROR_DS_INSUFF_ACCESS_RIGHTS", "Insufficient access rights to perform the operation."),
        0x00002099: ("ERROR_DS_ILLEGAL_SUPERIOR", "The object cannot be added because the parent is not on the list of possible superiors."),
        0x0000209a: ("ERROR_DS_ATTRIBUTE_OWNED_BY_SAM", "Access to the attribute is not permitted because the attribute is owned by the Security Accounts Manager (SAM)."),
        0x0000209b: ("ERROR_DS_NAME_TOO_MANY_PARTS", "The name has too many parts."),
        0x0000209c: ("ERROR_DS_NAME_TOO_LONG", "The name is too long."),
        0x0000209d: ("ERROR_DS_NAME_VALUE_TOO_LONG", "The name value is too long."),
        0x0000209e: ("ERROR_DS_NAME_UNPARSEABLE", "The directory service encountered an error parsing a name."),
        0x0000209f: ("ERROR_DS_NAME_TYPE_UNKNOWN", "The directory service cannot get the attribute type for a name."),
        0x000020a0: ("ERROR_DS_NOT_AN_OBJECT", "The name does not identify an object; the name identifies a phantom."),
        0x000020a1: ("ERROR_DS_SEC_DESC_TOO_SHORT", "The security descriptor is too short."),
        0x000020a2: ("ERROR_DS_SEC_DESC_INVALID", "The security descriptor is invalid."),
        0x000020a3: ("ERROR_DS_NO_DELETED_NAME", "Failed to create name for deleted object."),
        0x000020a4: ("ERROR_DS_SUBREF_MUST_HAVE_PARENT", "The parent of a new subref must exist."),
        0x000020a5: ("ERROR_DS_NCNAME_MUST_BE_NC", "The object must be a naming context."),
        0x000020a6: ("ERROR_DS_CANT_ADD_SYSTEM_ONLY", "It is not permitted to add an attribute which is owned by the system."),
        0x000020a7: ("ERROR_DS_CLASS_MUST_BE_CONCRETE", "The class of the object must be structural; you cannot instantiate an abstract class."),
        0x000020a8: ("ERROR_DS_INVALID_DMD", "The schema object could not be found."),
        0x000020a9: ("ERROR_DS_OBJ_GUID_EXISTS", "A local object with this GUID (dead or alive) already exists."),
        0x000020aa: ("ERROR_DS_NOT_ON_BACKLINK", "The operation cannot be performed on a back link."),
        0x000020ab: ("ERROR_DS_NO_CROSSREF_FOR_NC", "The cross reference for the specified naming context could not be found."),
        0x000020ac: ("ERROR_DS_SHUTTING_DOWN", "The operation could not be performed because the directory service is shutting down."),
        0x000020ad: ("ERROR_DS_UNKNOWN_OPERATION", "The directory service request is invalid."),
        0x000020ae: ("ERROR_DS_INVALID_ROLE_OWNER", "The role owner attribute could not be read."),
        0x000020af: ("ERROR_DS_COULDNT_CONTACT_FSMO", "The requested FSMO operation failed. The current FSMO holder could not be contacted."),
        0x000020b0: ("ERROR_DS_CROSS_NC_DN_RENAME", "Modification of a DN across a naming context is not permitted."),
        0x000020b1: ("ERROR_DS_CANT_MOD_SYSTEM_ONLY", "The attribute cannot be modified because it is owned by the system."),
        0x000020b2: ("ERROR_DS_REPLICATOR_ONLY", "Only the replicator can perform this function."),
        0x000020b3: ("ERROR_DS_OBJ_CLASS_NOT_DEFINED", "The specified class is not defined."),
        0x000020b4: ("ERROR_DS_OBJ_CLASS_NOT_SUBCLASS", "The specified class is not a subclass."),
        0x000020b5: ("ERROR_DS_NAME_REFERENCE_INVALID", "The name reference is invalid."),
        0x000020b6: ("ERROR_DS_CROSS_REF_EXISTS", "A cross reference already exists."),
        0x000020b7: ("ERROR_DS_CANT_DEL_MASTER_CROSSREF", "It is not permitted to delete a master cross reference."),
        0x000020b8: ("ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD", "Subtree notifications are only supported on NC heads."),
        0x000020b9: ("ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX", "Notification filter is too complex."),
        0x000020ba: ("ERROR_DS_DUP_RDN", "Schema update failed: duplicate RDN."),
        0x000020bb: ("ERROR_DS_DUP_OID", "Schema update failed: duplicate OID."),
        0x000020bc: ("ERROR_DS_DUP_MAPI_ID", "Schema update failed: duplicate MAPI identifier."),
        0x000020bd: ("ERROR_DS_DUP_SCHEMA_ID_GUID", "Schema update failed: duplicate schema-id GUID."),
        0x000020be: ("ERROR_DS_DUP_LDAP_DISPLAY_NAME", "Schema update failed: duplicate LDAP display name."),
        0x000020bf: ("ERROR_DS_SEMANTIC_ATT_TEST", "Schema update failed: range-lower less than range upper."),
        0x000020c0: ("ERROR_DS_SYNTAX_MISMATCH", "Schema update failed: syntax mismatch."),
        0x000020c1: ("ERROR_DS_EXISTS_IN_MUST_HAVE", "Schema deletion failed: attribute is used in must-contain."),
        0x000020c2: ("ERROR_DS_EXISTS_IN_MAY_HAVE", "Schema deletion failed: attribute is used in may-contain."),
        0x000020c3: ("ERROR_DS_NONEXISTENT_MAY_HAVE", "Schema update failed: attribute in may-contain does not exist."),
        0x000020c4: ("ERROR_DS_NONEXISTENT_MUST_HAVE", "Schema update failed: attribute in must-contain does not exist."),
        0x000020c5: ("ERROR_DS_AUX_CLS_TEST_FAIL", "Schema update failed: class in aux-class list does not exist or is not an auxiliary class."),
        0x000020c6: ("ERROR_DS_NONEXISTENT_POSS_SUP", "Schema update failed: class in poss-superiors does not exist."),
        0x000020c7: ("ERROR_DS_SUB_CLS_TEST_FAIL", "Schema update failed: class in subclassof list does not exist or does not satisfy hierarchy rules."),
        0x000020c8: ("ERROR_DS_BAD_RDN_ATT_ID_SYNTAX", "Schema update failed: Rdn-Att-Id has wrong syntax."),
        0x000020c9: ("ERROR_DS_EXISTS_IN_AUX_CLS", "Schema deletion failed: class is used as auxiliary class."),
        0x000020ca: ("ERROR_DS_EXISTS_IN_SUB_CLS", "Schema deletion failed: class is used as sub class."),
        0x000020cb: ("ERROR_DS_EXISTS_IN_POSS_SUP", "Schema deletion failed: class is used as poss superior."),
        0x000020cc: ("ERROR_DS_RECALCSCHEMA_FAILED", "Schema update failed in recalculating validation cache."),
        0x000020cd: ("ERROR_DS_TREE_DELETE_NOT_FINISHED", "The tree deletion is not finished. The request must be made again to continue deleting the tree."),
        0x000020ce: ("ERROR_DS_CANT_DELETE", "The requested delete operation could not be performed."),
        0x000020cf: ("ERROR_DS_ATT_SCHEMA_REQ_ID", "Cannot read the governs class identifier for the schema record."),
        0x000020d0: ("ERROR_DS_BAD_ATT_SCHEMA_SYNTAX", "The attribute schema has bad syntax."),
        0x000020d1: ("ERROR_DS_CANT_CACHE_ATT", "The attribute could not be cached."),
        0x000020d2: ("ERROR_DS_CANT_CACHE_CLASS", "The class could not be cached."),
        0x000020d3: ("ERROR_DS_CANT_REMOVE_ATT_CACHE", "The attribute could not be removed from the cache."),
        0x000020d4: ("ERROR_DS_CANT_REMOVE_CLASS_CACHE", "The class could not be removed from the cache."),
        0x000020d5: ("ERROR_DS_CANT_RETRIEVE_DN", "The distinguished name attribute could not be read."),
        0x000020d6: ("ERROR_DS_MISSING_SUPREF", "No superior reference has been configured for the directory service. The directory service is therefore unable to issue referrals to objects outside this forest."),
        0x000020d7: ("ERROR_DS_CANT_RETRIEVE_INSTANCE", "The instance type attribute could not be retrieved."),
        0x000020d8: ("ERROR_DS_CODE_INCONSISTENCY", "An internal error has occurred."),
        0x000020d9: ("ERROR_DS_DATABASE_ERROR", "A database error has occurred."),
        0x000020da: ("ERROR_DS_GOVERNSID_MISSING", "The attribute GOVERNSID is missing."),
        0x000020db: ("ERROR_DS_MISSING_EXPECTED_ATT", "An expected attribute is missing."),
        0x000020dc: ("ERROR_DS_NCNAME_MISSING_CR_REF", "The specified naming context is missing a cross reference."),
        0x000020dd: ("ERROR_DS_SECURITY_CHECKING_ERROR", "A security checking error has occurred."),
        0x000020de: ("ERROR_DS_SCHEMA_NOT_LOADED", "The schema is not loaded."),
        0x000020df: ("ERROR_DS_SCHEMA_ALLOC_FAILED", "Schema allocation failed. Please check if the machine is running low on memory."),
        0x000020e0: ("ERROR_DS_ATT_SCHEMA_REQ_SYNTAX", "Failed to obtain the required syntax for the attribute schema."),
        0x000020e1: ("ERROR_DS_GCVERIFY_ERROR", "The global catalog verification failed. The global catalog is not available or does not support the operation. Some part of the directory is currently not available."),
        0x000020e2: ("ERROR_DS_DRA_SCHEMA_MISMATCH", "The replication operation failed because of a schema mismatch between the servers involved."),
        0x000020e3: ("ERROR_DS_CANT_FIND_DSA_OBJ", "The DSA object could not be found."),
        0x000020e4: ("ERROR_DS_CANT_FIND_EXPECTED_NC", "The naming context could not be found."),
        0x000020e5: ("ERROR_DS_CANT_FIND_NC_IN_CACHE", "The naming context could not be found in the cache."),
        0x000020e6: ("ERROR_DS_CANT_RETRIEVE_CHILD", "The child object could not be retrieved."),
        0x000020e7: ("ERROR_DS_SECURITY_ILLEGAL_MODIFY", "The modification was not permitted for security reasons."),
        0x000020e8: ("ERROR_DS_CANT_REPLACE_HIDDEN_REC", "The operation cannot replace the hidden record."),
        0x000020e9: ("ERROR_DS_BAD_HIERARCHY_FILE", "The hierarchy file is invalid."),
        0x000020ea: ("ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED", "The attempt to build the hierarchy table failed."),
        0x000020eb: ("ERROR_DS_CONFIG_PARAM_MISSING", "The directory configuration parameter is missing from the registry."),
        0x000020ec: ("ERROR_DS_COUNTING_AB_INDICES_FAILED", "The attempt to count the address book indices failed."),
        0x000020ed: ("ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED", "The allocation of the hierarchy table failed."),
        0x000020ee: ("ERROR_DS_INTERNAL_FAILURE", "The directory service encountered an internal failure."),
        0x000020ef: ("ERROR_DS_UNKNOWN_ERROR", "The directory service encountered an unknown failure."),
        0x000020f0: ("ERROR_DS_ROOT_REQUIRES_CLASS_TOP", "A root object requires a class of 'top'."),
        0x000020f1: ("ERROR_DS_REFUSING_FSMO_ROLES", "This directory server is shutting down, and cannot take ownership of new floating single-master operation roles."),
        0x000020f2: ("ERROR_DS_MISSING_FSMO_SETTINGS", "The directory service is missing mandatory configuration information, and is unable to determine the ownership of floating single-master operation roles."),
        0x000020f3: ("ERROR_DS_UNABLE_TO_SURRENDER_ROLES", "The directory service was unable to transfer ownership of one or more floating single-master operation roles to other servers."),
        0x000020f4: ("ERROR_DS_DRA_GENERIC", "The replication operation failed."),
        0x000020f5: ("ERROR_DS_DRA_INVALID_PARAMETER", "An invalid parameter was specified for this replication operation."),
        0x000020f6: ("ERROR_DS_DRA_BUSY", "The directory service is too busy to complete the replication operation at this time."),
        0x000020f7: ("ERROR_DS_DRA_BAD_DN", "The distinguished name specified for this replication operation is invalid."),
        0x000020f8: ("ERROR_DS_DRA_BAD_NC", "The naming context specified for this replication operation is invalid."),
        0x000020f9: ("ERROR_DS_DRA_DN_EXISTS", "The distinguished name specified for this replication operation already exists."),
        0x000020fa: ("ERROR_DS_DRA_INTERNAL_ERROR", "The replication system encountered an internal error."),
        0x000020fb: ("ERROR_DS_DRA_INCONSISTENT_DIT", "The replication operation encountered a database inconsistency."),
        0x000020fc: ("ERROR_DS_DRA_CONNECTION_FAILED", "The server specified for this replication operation could not be contacted."),
        0x000020fd: ("ERROR_DS_DRA_BAD_INSTANCE_TYPE", "The replication operation encountered an object with an invalid instance type."),
        0x000020fe: ("ERROR_DS_DRA_OUT_OF_MEM", "The replication operation failed to allocate memory."),
        0x000020ff: ("ERROR_DS_DRA_MAIL_PROBLEM", "The replication operation encountered an error with the mail system."),
        0x00002100: ("ERROR_DS_DRA_REF_ALREADY_EXISTS", "The replication reference information for the target server already exists."),
        0x00002101: ("ERROR_DS_DRA_REF_NOT_FOUND", "The replication reference information for the target server does not exist."),
        0x00002102: ("ERROR_DS_DRA_OBJ_IS_REP_SOURCE", "The naming context cannot be removed because it is replicated to another server."),
        0x00002103: ("ERROR_DS_DRA_DB_ERROR", "The replication operation encountered a database error."),
        0x00002104: ("ERROR_DS_DRA_NO_REPLICA", "The naming context is in the process of being removed or is not replicated from the specified server."),
        0x00002105: ("ERROR_DS_DRA_ACCESS_DENIED", "Replication access was denied."),
        0x00002106: ("ERROR_DS_DRA_NOT_SUPPORTED", "The requested operation is not supported by this version of the directory service."),
        0x00002107: ("ERROR_DS_DRA_RPC_CANCELLED", "The replication remote procedure call was cancelled."),
        0x00002108: ("ERROR_DS_DRA_SOURCE_DISABLED", "The source server is currently rejecting replication requests."),
        0x00002109: ("ERROR_DS_DRA_SINK_DISABLED", "The destination server is currently rejecting replication requests."),
        0x0000210a: ("ERROR_DS_DRA_NAME_COLLISION", "The replication operation failed due to a collision of object names."),
        0x0000210b: ("ERROR_DS_DRA_SOURCE_REINSTALLED", "The replication source has been reinstalled."),
        0x0000210c: ("ERROR_DS_DRA_MISSING_PARENT", "The replication operation failed because a required parent object is missing."),
        0x0000210d: ("ERROR_DS_DRA_PREEMPTED", "The replication operation was preempted."),
        0x0000210e: ("ERROR_DS_DRA_ABANDON_SYNC", "The replication synchronization attempt was abandoned because of a lack of updates."),
        0x0000210f: ("ERROR_DS_DRA_SHUTDOWN", "The replication operation was terminated because the system is shutting down."),
        0x00002110: ("ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET", "Synchronization attempt failed because the destination DC is currently waiting to synchronize new partial attributes from source. This condition is normal if a recent schema change modified the partial attribute set. The destination partial attribute set is not a subset of source partial attribute set."),
        0x00002111: ("ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA", "The replication synchronization attempt failed because a master replica attempted to sync from a partial replica."),
        0x00002112: ("ERROR_DS_DRA_EXTN_CONNECTION_FAILED", "The server specified for this replication operation was contacted, but that server was unable to contact an additional server needed to complete the operation."),
        0x00002113: ("ERROR_DS_INSTALL_SCHEMA_MISMATCH", "The version of the directory service schema of the source forest is not compatible with the version of directory service on this computer."),
        0x00002114: ("ERROR_DS_DUP_LINK_ID", "Schema update failed: An attribute with the same link identifier already exists."),
        0x00002115: ("ERROR_DS_NAME_ERROR_RESOLVING", "Name translation: Generic processing error."),
        0x00002116: ("ERROR_DS_NAME_ERROR_NOT_FOUND", "Name translation: Could not find the name or insufficient right to see name."),
        0x00002117: ("ERROR_DS_NAME_ERROR_NOT_UNIQUE", "Name translation: Input name mapped to more than one output name."),
        0x00002118: ("ERROR_DS_NAME_ERROR_NO_MAPPING", "Name translation: Input name found, but not the associated output format."),
        0x00002119: ("ERROR_DS_NAME_ERROR_DOMAIN_ONLY", "Name translation: Unable to resolve completely, only the domain was found."),
        0x0000211a: ("ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING", "Name translation: Unable to perform purely syntactical mapping at the client without going out to the wire."),
        0x0000211b: ("ERROR_DS_CONSTRUCTED_ATT_MOD", "Modification of a constructed attribute is not allowed."),
        0x0000211c: ("ERROR_DS_WRONG_OM_OBJ_CLASS", "The OM-Object-Class specified is incorrect for an attribute with the specified syntax."),
        0x0000211d: ("ERROR_DS_DRA_REPL_PENDING", "The replication request has been posted; waiting for reply."),
        0x0000211e: ("ERROR_DS_DS_REQUIRED", "The requested operation requires a directory service, and none was available."),
        0x0000211f: ("ERROR_DS_INVALID_LDAP_DISPLAY_NAME", "The LDAP display name of the class or attribute contains non-ASCII characters."),
        0x00002120: ("ERROR_DS_NON_BASE_SEARCH", "The requested search operation is only supported for base searches."),
        0x00002121: ("ERROR_DS_CANT_RETRIEVE_ATTS", "The search failed to retrieve attributes from the database."),
        0x00002122: ("ERROR_DS_BACKLINK_WITHOUT_LINK", "The schema update operation tried to add a backward link attribute that has no corresponding forward link."),
        0x00002123: ("ERROR_DS_EPOCH_MISMATCH", "Source and destination of a cross-domain move do not agree on the object's epoch number. Either source or destination does not have the latest version of the object."),
        0x00002124: ("ERROR_DS_SRC_NAME_MISMATCH", "Source and destination of a cross-domain move do not agree on the object's current name. Either source or destination does not have the latest version of the object."),
        0x00002125: ("ERROR_DS_SRC_AND_DST_NC_IDENTICAL", "Source and destination for the cross-domain move operation are identical. Caller should use local move operation instead of cross-domain move operation."),
        0x00002126: ("ERROR_DS_DST_NC_MISMATCH", "Source and destination for a cross-domain move are not in agreement on the naming contexts in the forest. Either source or destination does not have the latest version of the Partitions container."),
        0x00002127: ("ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC", "Destination of a cross-domain move is not authoritative for the destination naming context."),
        0x00002128: ("ERROR_DS_SRC_GUID_MISMATCH", "Source and destination of a cross-domain move do not agree on the identity of the source object. Either source or destination does not have the latest version of the source object."),
        0x00002129: ("ERROR_DS_CANT_MOVE_DELETED_OBJECT", "Object being moved across-domains is already known to be deleted by the destination server. The source server does not have the latest version of the source object."),
        0x0000212a: ("ERROR_DS_PDC_OPERATION_IN_PROGRESS", "Another operation which requires exclusive access to the PDC FSMO is already in progress."),
        0x0000212b: ("ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD", "A cross-domain move operation failed such that two versions of the moved object exist - one each in the source and destination domains. The destination object needs to be removed to restore the system to a consistent state."),
        0x0000212c: ("ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION", "This object may not be moved across domain boundaries either because cross-domain moves for this class are disallowed, or the object has some special characteristics, e.g.: trust account or restricted RID, which prevent its move."),
        0x0000212d: ("ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS", "Can't move objects with memberships across domain boundaries as once moved, this would violate the membership conditions of the account group. Remove the object from any account group memberships and retry."),
        0x0000212e: ("ERROR_DS_NC_MUST_HAVE_NC_PARENT", "A naming context head must be the immediate child of another naming context head, not of an interior node."),
        0x0000212f: ("ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE", "The directory cannot validate the proposed naming context name because it does not hold a replica of the naming context above the proposed naming context. Please ensure that the domain naming master role is held by a server that is configured as a global catalog server, and that the server is up to date with its replication partners. (Applies only to Windows 2000 Domain Naming masters)"),
        0x00002130: ("ERROR_DS_DST_DOMAIN_NOT_NATIVE", "Destination domain must be in native mode."),
        0x00002131: ("ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER", "The operation cannot be performed because the server does not have an infrastructure container in the domain of interest."),
        0x00002132: ("ERROR_DS_CANT_MOVE_ACCOUNT_GROUP", "Cross-domain move of non-empty account groups is not allowed."),
        0x00002133: ("ERROR_DS_CANT_MOVE_RESOURCE_GROUP", "Cross-domain move of non-empty resource groups is not allowed."),
        0x00002134: ("ERROR_DS_INVALID_SEARCH_FLAG", "The search flags for the attribute are invalid. The ANR bit is valid only on attributes of Unicode or Teletex strings."),
        0x00002135: ("ERROR_DS_NO_TREE_DELETE_ABOVE_NC", "Tree deletions starting at an object which has an NC head as a descendant are not allowed."),
        0x00002136: ("ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE", "The directory service failed to lock a tree in preparation for a tree deletion because the tree was in use."),
        0x00002137: ("ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE", "The directory service failed to identify the list of objects to delete while attempting a tree deletion."),
        0x00002138: ("ERROR_DS_SAM_INIT_FAILURE", "Security Accounts Manager initialization failed because of the following error: %1."),
        0x00002139: ("ERROR_DS_SENSITIVE_GROUP_VIOLATION", "Only an administrator can modify the membership list of an administrative group."),
        0x0000213a: ("ERROR_DS_CANT_MOD_PRIMARYGROUPID", "Cannot change the primary group ID of a domain controller account."),
        0x0000213b: ("ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD", "An attempt is made to modify the base schema."),
        0x0000213c: ("ERROR_DS_NONSAFE_SCHEMA_CHANGE", "Adding a new mandatory attribute to an existing class, deleting a mandatory attribute from an existing class, or adding an optional attribute to the special class Top that is not a backlink attribute (directly or through inheritance, for example, by adding or deleting an auxiliary class) is not allowed."),
        0x0000213d: ("ERROR_DS_SCHEMA_UPDATE_DISALLOWED", "Schema update is not allowed on this DC because the DC is not the schema FSMO Role Owner."),
        0x0000213e: ("ERROR_DS_CANT_CREATE_UNDER_SCHEMA", "An object of this class cannot be created under the schema container. You can only create attribute-schema and class-schema objects under the schema container."),
        0x0000213f: ("ERROR_DS_INSTALL_NO_SRC_SCH_VERSION", "The replica/child install failed to get the objectVersion attribute on the schema container on the source DC. Either the attribute is missing on the schema container or the credentials supplied do not have permission to read it."),
        0x00002140: ("ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE", "The replica/child install failed to read the objectVersion attribute in the SCHEMA section of the file schema.ini in the system32 directory."),
        0x00002141: ("ERROR_DS_INVALID_GROUP_TYPE", "The specified group type is invalid."),
        0x00002142: ("ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN", "You cannot nest global groups in a mixed domain if the group is security-enabled."),
        0x00002143: ("ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN", "You cannot nest local groups in a mixed domain if the group is security-enabled."),
        0x00002144: ("ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER", "A global group cannot have a local group as a member."),
        0x00002145: ("ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER", "A global group cannot have a universal group as a member."),
        0x00002146: ("ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER", "A universal group cannot have a local group as a member."),
        0x00002147: ("ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER", "A global group cannot have a cross-domain member."),
        0x00002148: ("ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER", "A local group cannot have another cross domain local group as a member."),
        0x00002149: ("ERROR_DS_HAVE_PRIMARY_MEMBERS", "A group with primary members cannot change to a security-disabled group."),
        0x0000214a: ("ERROR_DS_STRING_SD_CONVERSION_FAILED", "The schema cache load failed to convert the string default SD on a class-schema object."),
        0x0000214b: ("ERROR_DS_NAMING_MASTER_GC", "Only DSAs configured to be Global Catalog servers should be allowed to hold the Domain Naming Master FSMO role. (Applies only to Windows 2000 servers)"),
        0x0000214c: ("ERROR_DS_DNS_LOOKUP_FAILURE", "The DSA operation is unable to proceed because of a DNS lookup failure."),
        0x0000214d: ("ERROR_DS_COULDNT_UPDATE_SPNS", "While processing a change to the DNS Host Name for an object, the Service Principal Name values could not be kept in sync."),
        0x0000214e: ("ERROR_DS_CANT_RETRIEVE_SD", "The Security Descriptor attribute could not be read."),
        0x0000214f: ("ERROR_DS_KEY_NOT_UNIQUE", "The object requested was not found, but an object with that key was found."),
        0x00002150: ("ERROR_DS_WRONG_LINKED_ATT_SYNTAX", "The syntax of the linked attribute being added is incorrect. Forward links can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can only have syntax 2.5.5.1"),
        0x00002151: ("ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD", "Security Account Manager needs to get the boot password."),
        0x00002152: ("ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY", "Security Account Manager needs to get the boot key from floppy disk."),
        0x00002153: ("ERROR_DS_CANT_START", "Directory Service cannot start."),
        0x00002154: ("ERROR_DS_INIT_FAILURE", "Directory Services could not start."),
        0x00002155: ("ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION", "The connection between client and server requires packet privacy or better."),
        0x00002156: ("ERROR_DS_SOURCE_DOMAIN_IN_FOREST", "The source domain may not be in the same forest as destination."),
        0x00002157: ("ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST", "The destination domain must be in the forest."),
        0x00002158: ("ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED", "The operation requires that destination domain auditing be enabled."),
        0x00002159: ("ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN", "The operation couldn't locate a DC for the source domain."),
        0x0000215a: ("ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER", "The source object must be a group or user."),
        0x0000215b: ("ERROR_DS_SRC_SID_EXISTS_IN_FOREST", "The source object's SID already exists in destination forest."),
        0x0000215c: ("ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH", "The source and destination object must be of the same type."),
        0x0000215d: ("ERROR_SAM_INIT_FAILURE", "Security Accounts Manager initialization failed because of the following error: %1."),
        0x0000215e: ("ERROR_DS_DRA_SCHEMA_INFO_SHIP", "Schema information could not be included in the replication request."),
        0x0000215f: ("ERROR_DS_DRA_SCHEMA_CONFLICT", "The replication operation could not be completed due to a schema incompatibility."),
        0x00002160: ("ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT", "The replication operation could not be completed due to a previous schema incompatibility."),
        0x00002161: ("ERROR_DS_DRA_OBJ_NC_MISMATCH", "The replication update could not be applied because either the source or the destination has not yet received information regarding a recent cross-domain move operation."),
        0x00002162: ("ERROR_DS_NC_STILL_HAS_DSAS", "The requested domain could not be deleted because there exist domain controllers that still host this domain."),
        0x00002163: ("ERROR_DS_GC_REQUIRED", "The requested operation can be performed only on a global catalog server."),
        0x00002164: ("ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY", "A local group can only be a member of other local groups in the same domain."),
        0x00002165: ("ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS", "Foreign security principals cannot be members of universal groups."),
        0x00002166: ("ERROR_DS_CANT_ADD_TO_GC", "The attribute is not allowed to be replicated to the GC because of security reasons."),
        0x00002167: ("ERROR_DS_NO_CHECKPOINT_WITH_PDC", "The checkpoint with the PDC could not be taken because there too many modifications being processed currently."),
        0x00002168: ("ERROR_DS_SOURCE_AUDITING_NOT_ENABLED", "The operation requires that source domain auditing be enabled."),
        0x00002169: ("ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC", "Security principal objects can only be created inside domain naming contexts."),
        0x0000216a: ("ERROR_DS_INVALID_NAME_FOR_SPN", "A Service Principal Name (SPN) could not be constructed because the provided hostname is not in the necessary format."),
        0x0000216b: ("ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS", "A Filter was passed that uses constructed attributes."),
        0x0000216c: ("ERROR_DS_UNICODEPWD_NOT_IN_QUOTES", "The unicodePwd attribute value must be enclosed in double quotes."),
        0x0000216d: ("ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED", "Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased."),
        0x0000216e: ("ERROR_DS_MUST_BE_RUN_ON_DST_DC", "For security reasons, the operation must be run on the destination DC."),
        0x0000216f: ("ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER", "For security reasons, the source DC must be NT4SP4 or greater."),
        0x00002170: ("ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ", "Critical Directory Service System objects cannot be deleted during tree delete operations. The tree delete may have been partially performed."),
        0x00002171: ("ERROR_DS_INIT_FAILURE_CONSOLE", "Directory Services could not start because of the following error: %1."),
        0x00002172: ("ERROR_DS_SAM_INIT_FAILURE_CONSOLE", "Security Accounts Manager initialization failed because of the following error: %1."),
        0x00002173: ("ERROR_DS_FOREST_VERSION_TOO_HIGH", "The version of the operating system is incompatible with the current AD DS forest functional level or AD LDS Configuration Set functional level. You must upgrade to a new version of the operating system before this server can become an AD DS Domain Controller or add an AD LDS Instance in this AD DS Forest or AD LDS Configuration Set."),
        0x00002174: ("ERROR_DS_DOMAIN_VERSION_TOO_HIGH", "The version of the operating system installed is incompatible with the current domain functional level. You must upgrade to a new version of the operating system before this server can become a domain controller in this domain."),
        0x00002175: ("ERROR_DS_FOREST_VERSION_TOO_LOW", "The version of the operating system installed on this server no longer supports the current AD DS Forest functional level or AD LDS Configuration Set functional level. You must raise the AD DS Forest functional level or AD LDS Configuration Set functional level before this server can become an AD DS Domain Controller or an AD LDS Instance in this Forest or Configuration Set."),
        0x00002176: ("ERROR_DS_DOMAIN_VERSION_TOO_LOW", "The version of the operating system installed on this server no longer supports the current domain functional level. You must raise the domain functional level before this server can become a domain controller in this domain."),
        0x00002177: ("ERROR_DS_INCOMPATIBLE_VERSION", "The version of the operating system installed on this server is incompatible with the functional level of the domain or forest."),
        0x00002178: ("ERROR_DS_LOW_DSA_VERSION", "The functional level of the domain (or forest) cannot be raised to the requested value, because there exist one or more domain controllers in the domain (or forest) that are at a lower incompatible functional level."),
        0x00002179: ("ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN", "The forest functional level cannot be raised to the requested value since one or more domains are still in mixed domain mode. All domains in the forest must be in native mode, for you to raise the forest functional level."),
        0x0000217a: ("ERROR_DS_NOT_SUPPORTED_SORT_ORDER", "The sort order requested is not supported."),
        0x0000217b: ("ERROR_DS_NAME_NOT_UNIQUE", "The requested name already exists as a unique identifier."),
        0x0000217c: ("ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4", "The machine account was created pre-NT4. The account needs to be recreated."),
        0x0000217d: ("ERROR_DS_OUT_OF_VERSION_STORE", "The database is out of version store."),
        0x0000217e: ("ERROR_DS_INCOMPATIBLE_CONTROLS_USED", "Unable to continue operation because multiple conflicting controls were used."),
        0x0000217f: ("ERROR_DS_NO_REF_DOMAIN", "Unable to find a valid security descriptor reference domain for this partition."),
        0x00002180: ("ERROR_DS_RESERVED_LINK_ID", "Schema update failed: The link identifier is reserved."),
        0x00002181: ("ERROR_DS_LINK_ID_NOT_AVAILABLE", "Schema update failed: There are no link identifiers available."),
        0x00002182: ("ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER", "An account group cannot have a universal group as a member."),
        0x00002183: ("ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE", "Rename or move operations on naming context heads or read-only objects are not allowed."),
        0x00002184: ("ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC", "Move operations on objects in the schema naming context are not allowed."),
        0x00002185: ("ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG", "A system flag has been set on the object and does not allow the object to be moved or renamed."),
        0x00002186: ("ERROR_DS_MODIFYDN_WRONG_GRANDPARENT", "This object is not allowed to change its grandparent container. Moves are not forbidden on this object, but are restricted to sibling containers."),
        0x00002187: ("ERROR_DS_NAME_ERROR_TRUST_REFERRAL", "Unable to resolve completely, a referral to another forest is generated."),
        0x00002188: ("ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER", "The requested action is not supported on standard server."),
        0x00002189: ("ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD", "Could not access a partition of the directory service located on a remote server. Make sure at least one server is running for the partition in question."),
        0x0000218a: ("ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2", "The directory cannot validate the proposed naming context (or partition) name because it does not hold a replica nor can it contact a replica of the naming context above the proposed naming context. Please ensure that the parent naming context is properly registered in DNS, and at least one replica of this naming context is reachable by the Domain Naming master."),
        0x0000218b: ("ERROR_DS_THREAD_LIMIT_EXCEEDED", "The thread limit for this request was exceeded."),
        0x0000218c: ("ERROR_DS_NOT_CLOSEST", "The Global catalog server is not in the closest site."),
        0x0000218d: ("ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF", "The DS cannot derive a service principal name (SPN) with which to mutually authenticate the target server because the corresponding server object in the local DS database has no serverReference attribute."),
        0x0000218e: ("ERROR_DS_SINGLE_USER_MODE_FAILED", "The Directory Service failed to enter single user mode."),
        0x0000218f: ("ERROR_DS_NTDSCRIPT_SYNTAX_ERROR", "The Directory Service cannot parse the script because of a syntax error."),
        0x00002190: ("ERROR_DS_NTDSCRIPT_PROCESS_ERROR", "The Directory Service cannot process the script because of an error."),
        0x00002191: ("ERROR_DS_DIFFERENT_REPL_EPOCHS", "The directory service cannot perform the requested operation because the servers involved are of different replication epochs (which is usually related to a domain rename that is in progress)."),
        0x00002192: ("ERROR_DS_DRS_EXTENSIONS_CHANGED", "The directory service binding must be renegotiated due to a change in the server extensions information."),
        0x00002193: ("ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR", "Operation not allowed on a disabled cross ref."),
        0x00002194: ("ERROR_DS_NO_MSDS_INTID", "Schema update failed: No values for msDS-IntId are available."),
        0x00002195: ("ERROR_DS_DUP_MSDS_INTID", "Schema update failed: Duplicate msDS-INtId. Retry the operation."),
        0x00002196: ("ERROR_DS_EXISTS_IN_RDNATTID", "Schema deletion failed: attribute is used in rDNAttID."),
        0x00002197: ("ERROR_DS_AUTHORIZATION_FAILED", "The directory service failed to authorize the request."),
        0x00002198: ("ERROR_DS_INVALID_SCRIPT", "The Directory Service cannot process the script because it is invalid."),
        0x00002199: ("ERROR_DS_REMOTE_CROSSREF_OP_FAILED", "The remote create cross reference operation failed on the Domain Naming Master FSMO. The operation's error is in the extended data."),
        0x0000219a: ("ERROR_DS_CROSS_REF_BUSY", "A cross reference is in use locally with the same name."),
        0x0000219b: ("ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN", "The DS cannot derive a service principal name (SPN) with which to mutually authenticate the target server because the server's domain has been deleted from the forest."),
        0x0000219c: ("ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC", "Writeable NCs prevent this DC from demoting."),
        0x0000219d: ("ERROR_DS_DUPLICATE_ID_FOUND", "The requested object has a non-unique identifier and cannot be retrieved."),
        0x0000219e: ("ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT", "Insufficient attributes were given to create an object. This object may not exist because it may have been deleted and already garbage collected."),
        0x0000219f: ("ERROR_DS_GROUP_CONVERSION_ERROR", "The group cannot be converted due to attribute restrictions on the requested group type."),
        0x000021a0: ("ERROR_DS_CANT_MOVE_APP_BASIC_GROUP", "Cross-domain move of non-empty basic application groups is not allowed."),
        0x000021a1: ("ERROR_DS_CANT_MOVE_APP_QUERY_GROUP", "Cross-domain move of non-empty query based application groups is not allowed."),
        0x000021a2: ("ERROR_DS_ROLE_NOT_VERIFIED", "The FSMO role ownership could not be verified because its directory partition has not replicated successfully with at least one replication partner."),
        0x000021a3: ("ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL", "The target container for a redirection of a well known object container cannot already be a special container."),
        0x000021a4: ("ERROR_DS_DOMAIN_RENAME_IN_PROGRESS", "The Directory Service cannot perform the requested operation because a domain rename operation is in progress."),
        0x000021a5: ("ERROR_DS_EXISTING_AD_CHILD_NC", "The directory service detected a child partition below the requested partition name. The partition hierarchy must be created in a top down method."),
        0x000021a6: ("ERROR_DS_REPL_LIFETIME_EXCEEDED", "The directory service cannot replicate with this server because the time since the last replication with this server has exceeded the tombstone lifetime."),
        0x000021a7: ("ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER", "The requested operation is not allowed on an object under the system container."),
        0x000021a8: ("ERROR_DS_LDAP_SEND_QUEUE_FULL", "The LDAP servers network send queue has filled up because the client is not processing the results of its requests fast enough. No more requests will be processed until the client catches up. If the client does not catch up then it will be disconnected."),
        0x000021a9: ("ERROR_DS_DRA_OUT_SCHEDULE_WINDOW", "The scheduled replication did not take place because the system was too busy to execute the request within the schedule window. The replication queue is overloaded. Consider reducing the number of partners or decreasing the scheduled replication frequency."),
        0x000021aa: ("ERROR_DS_POLICY_NOT_KNOWN", "At this time, it cannot be determined if the branch replication policy is available on the hub domain controller. Please retry at a later time to account for replication latencies."),
        0x000021ab: ("ERROR_NO_SITE_SETTINGS_OBJECT", "The site settings object for the specified site does not exist."),
        0x000021ac: ("ERROR_NO_SECRETS", "The local account store does not contain secret material for the specified account."),
        0x000021ad: ("ERROR_NO_WRITABLE_DC_FOUND", "Could not find a writable domain controller in the domain."),
        0x000021ae: ("ERROR_DS_NO_SERVER_OBJECT", "The server object for the domain controller does not exist."),
        0x000021af: ("ERROR_DS_NO_NTDSA_OBJECT", "The NTDS Settings object for the domain controller does not exist."),
        0x000021b0: ("ERROR_DS_NON_ASQ_SEARCH", "The requested search operation is not supported for ASQ searches."),
        0x000021b1: ("ERROR_DS_AUDIT_FAILURE", "A required audit event could not be generated for the operation."),
        0x000021b2: ("ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE", "The search flags for the attribute are invalid. The subtree index bit is valid only on single valued attributes."),
        0x000021b3: ("ERROR_DS_INVALID_SEARCH_FLAG_TUPLE", "The search flags for the attribute are invalid. The tuple index bit is valid only on attributes of Unicode strings."),
        0x000021b4: ("ERROR_DS_HIERARCHY_TABLE_TOO_DEEP", "The address books are nested too deeply. Failed to build the hierarchy table."),
        0x000021b5: ("ERROR_DS_DRA_CORRUPT_UTD_VECTOR", "The specified up-to-date-ness vector is corrupt."),
        0x000021b6: ("ERROR_DS_DRA_SECRETS_DENIED", "The request to replicate secrets is denied."),
        0x000021b7: ("ERROR_DS_RESERVED_MAPI_ID", "Schema update failed: The MAPI identifier is reserved."),
        0x000021b8: ("ERROR_DS_MAPI_ID_NOT_AVAILABLE", "Schema update failed: There are no MAPI identifiers available."),
        0x000021b9: ("ERROR_DS_DRA_MISSING_KRBTGT_SECRET", "The replication operation failed because the required attributes of the local krbtgt object are missing."),
        0x000021ba: ("ERROR_DS_DOMAIN_NAME_EXISTS_IN_FOREST", "The domain name of the trusted domain already exists in the forest."),
        0x000021bb: ("ERROR_DS_FLAT_NAME_EXISTS_IN_FOREST", "The flat name of the trusted domain already exists in the forest."),
        0x000021bc: ("ERROR_INVALID_USER_PRINCIPAL_NAME", "The User Principal Name (UPN) is invalid."),
        0x000021bd: ("ERROR_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS", "OID mapped groups cannot have members."),
        0x000021be: ("ERROR_DS_OID_NOT_FOUND", "The specified OID cannot be found."),
        0x000021bf: ("ERROR_DS_DRA_RECYCLED_TARGET", "The replication operation failed because the target object referred by a link value is recycled."),
        0x000021c0: ("ERROR_DS_DISALLOWED_NC_REDIRECT", "The redirect operation failed because the target object is in a NC different from the domain NC of the current domain controller."),
        0x000021c1: ("ERROR_DS_HIGH_ADLDS_FFL", "The functional level of the AD LDS configuration set cannot be lowered to the requested value."),
        0x000021c2: ("ERROR_DS_HIGH_DSA_VERSION", "The functional level of the domain (or forest) cannot be lowered to the requested value."),
        0x000021c3: ("ERROR_DS_LOW_ADLDS_FFL", "The functional level of the AD LDS configuration set cannot be raised to the requested value, because there exist one or more ADLDS instances that are at a lower incompatible functional level."),
        0x000021c4: ("ERROR_DOMAIN_SID_SAME_AS_LOCAL_WORKSTATION", "The domain join cannot be completed because the SID of the domain you attempted to join was identical to the SID of this machine. This is a symptom of an improperly cloned operating system install.  You should run sysprep on this machine in order to generate a new machine SID. Please see https://go.microsoft.com/fwlink/?LinkId=168895 for more information."),
        0x000021c5: ("ERROR_DS_UNDELETE_SAM_VALIDATION_FAILED", "The undelete operation failed because the Sam Account Name or Additional Sam Account Name of the object being undeleted conflicts with an existing live object."),
        0x000021c6: ("ERROR_INCORRECT_ACCOUNT_TYPE", "The system is not authoritative for the specified account and therefore cannot complete the operation. Please retry the operation using the provider associated with this account. If this is an online provider please use the provider's online site."),
        0x00002329: ("DNS_ERROR_RCODE_FORMAT_ERROR", "DNS server unable to interpret format."),
        0x0000232a: ("DNS_ERROR_RCODE_SERVER_FAILURE", "DNS server failure."),
        0x0000232b: ("DNS_ERROR_RCODE_NAME_ERROR", "DNS name does not exist."),
        0x0000232c: ("DNS_ERROR_RCODE_NOT_IMPLEMENTED", "DNS request not supported by name server."),
        0x0000232d: ("DNS_ERROR_RCODE_REFUSED", "DNS operation refused."),
        0x0000232e: ("DNS_ERROR_RCODE_YXDOMAIN", "DNS name that ought not exist, does exist."),
        0x0000232f: ("DNS_ERROR_RCODE_YXRRSET", "DNS RR set that ought not exist, does exist."),
        0x00002330: ("DNS_ERROR_RCODE_NXRRSET", "DNS RR set that ought to exist, does not exist."),
        0x00002331: ("DNS_ERROR_RCODE_NOTAUTH", "DNS server not authoritative for zone."),
        0x00002332: ("DNS_ERROR_RCODE_NOTZONE", "DNS name in update or prereq is not in zone."),
        0x00002338: ("DNS_ERROR_RCODE_BADSIG", "DNS signature failed to verify."),
        0x00002339: ("DNS_ERROR_RCODE_BADKEY", "DNS bad key."),
        0x0000233a: ("DNS_ERROR_RCODE_BADTIME", "DNS signature validity expired."),
        0x0000238d: ("DNS_ERROR_KEYMASTER_REQUIRED", "Only the DNS server acting as the key master for the zone may perform this operation."),
        0x0000238e: ("DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE", "This operation is not allowed on a zone that is signed or has signing keys."),
        0x0000238f: ("DNS_ERROR_NSEC3_INCOMPATIBLE_WITH_RSA_SHA1", "NSEC3 is not compatible with the RSA-SHA-1 algorithm. Choose a different algorithm or use NSEC."),
        0x00002390: ("DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS", "The zone does not have enough signing keys. There must be at least one key signing key (KSK) and at least one zone signing key (ZSK)."),
        0x00002391: ("DNS_ERROR_UNSUPPORTED_ALGORITHM", "The specified algorithm is not supported."),
        0x00002392: ("DNS_ERROR_INVALID_KEY_SIZE", "The specified key size is not supported."),
        0x00002393: ("DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE", "One or more of the signing keys for a zone are not accessible to the DNS server. Zone signing will not be operational until this error is resolved."),
        0x00002394: ("DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION", "The specified key storage provider does not support DPAPI++ data protection. Zone signing will not be operational until this error is resolved."),
        0x00002395: ("DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR", "An unexpected DPAPI++ error was encountered. Zone signing will not be operational until this error is resolved."),
        0x00002396: ("DNS_ERROR_UNEXPECTED_CNG_ERROR", "An unexpected crypto error was encountered. Zone signing may not be operational until this error is resolved."),
        0x00002397: ("DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION", "The DNS server encountered a signing key with an unknown version. Zone signing will not be operational until this error is resolved."),
        0x00002398: ("DNS_ERROR_KSP_NOT_ACCESSIBLE", "The specified key service provider cannot be opened by the DNS server."),
        0x00002399: ("DNS_ERROR_TOO_MANY_SKDS", "The DNS server cannot accept any more signing keys with the specified algorithm and KSK flag value for this zone."),
        0x0000239a: ("DNS_ERROR_INVALID_ROLLOVER_PERIOD", "The specified rollover period is invalid."),
        0x0000239b: ("DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET", "The specified initial rollover offset is invalid."),
        0x0000239c: ("DNS_ERROR_ROLLOVER_IN_PROGRESS", "The specified signing key is already in process of rolling over keys."),
        0x0000239d: ("DNS_ERROR_STANDBY_KEY_NOT_PRESENT", "The specified signing key does not have a standby key to revoke."),
        0x0000239e: ("DNS_ERROR_NOT_ALLOWED_ON_ZSK", "This operation is not allowed on a zone signing key (ZSK)."),
        0x0000239f: ("DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD", "This operation is not allowed on an active signing key."),
        0x000023a0: ("DNS_ERROR_ROLLOVER_ALREADY_QUEUED", "The specified signing key is already queued for rollover."),
        0x000023a1: ("DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE", "This operation is not allowed on an unsigned zone."),
        0x000023a2: ("DNS_ERROR_BAD_KEYMASTER", "This operation could not be completed because the DNS server listed as the current key master for this zone is down or misconfigured. Resolve the problem on the current key master for this zone or use another DNS server to seize the key master role."),
        0x000023a3: ("DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD", "The specified signature validity period is invalid."),
        0x000023a4: ("DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT", "The specified NSEC3 iteration count is higher than allowed by the minimum key length used in the zone."),
        0x000023a5: ("DNS_ERROR_DNSSEC_IS_DISABLED", "This operation could not be completed because the DNS server has been configured with DNSSEC features disabled. Enable DNSSEC on the DNS server."),
        0x000023a6: ("DNS_ERROR_INVALID_XML", "This operation could not be completed because the XML stream received is empty or syntactically invalid."),
        0x000023a7: ("DNS_ERROR_NO_VALID_TRUST_ANCHORS", "This operation completed, but no trust anchors were added because all of the trust anchors received were either invalid, unsupported, expired, or would not become valid in less than 30 days."),
        0x000023a8: ("DNS_ERROR_ROLLOVER_NOT_POKEABLE", "The specified signing key is not waiting for parental DS update."),
        0x000023a9: ("DNS_ERROR_NSEC3_NAME_COLLISION", "Hash collision detected during NSEC3 signing. Specify a different user-provided salt, or use a randomly generated salt, and attempt to sign the zone again."),
        0x000023aa: ("DNS_ERROR_NSEC_INCOMPATIBLE_WITH_NSEC3_RSA_SHA1", "NSEC is not compatible with the NSEC3-RSA-SHA-1 algorithm. Choose a different algorithm or use NSEC3."),
        0x0000251d: ("DNS_INFO_NO_RECORDS", "No records found for given DNS query."),
        0x0000251e: ("DNS_ERROR_BAD_PACKET", "Bad DNS packet."),
        0x0000251f: ("DNS_ERROR_NO_PACKET", "No DNS packet."),
        0x00002520: ("DNS_ERROR_RCODE", "DNS error, check rcode."),
        0x00002521: ("DNS_ERROR_UNSECURE_PACKET", "Unsecured DNS packet."),
        0x00002522: ("DNS_REQUEST_PENDING", "DNS query request is pending."),
        0x0000254f: ("DNS_ERROR_INVALID_TYPE", "Invalid DNS type."),
        0x00002550: ("DNS_ERROR_INVALID_IP_ADDRESS", "Invalid IP address."),
        0x00002551: ("DNS_ERROR_INVALID_PROPERTY", "Invalid property."),
        0x00002552: ("DNS_ERROR_TRY_AGAIN_LATER", "Try DNS operation again later."),
        0x00002553: ("DNS_ERROR_NOT_UNIQUE", "Record for given name and type is not unique."),
        0x00002554: ("DNS_ERROR_NON_RFC_NAME", "DNS name does not comply with RFC specifications."),
        0x00002555: ("DNS_STATUS_FQDN", "DNS name is a fully-qualified DNS name."),
        0x00002556: ("DNS_STATUS_DOTTED_NAME", "DNS name is dotted (multi-label)."),
        0x00002557: ("DNS_STATUS_SINGLE_PART_NAME", "DNS name is a single-part name."),
        0x00002558: ("DNS_ERROR_INVALID_NAME_CHAR", "DNS name contains an invalid character."),
        0x00002559: ("DNS_ERROR_NUMERIC_NAME", "DNS name is entirely numeric."),
        0x0000255a: ("DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER", "The operation requested is not permitted on a DNS root server."),
        0x0000255b: ("DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION", "The record could not be created because this part of the DNS namespace has been delegated to another server."),
        0x0000255c: ("DNS_ERROR_CANNOT_FIND_ROOT_HINTS", "The DNS server could not find a set of root hints."),
        0x0000255d: ("DNS_ERROR_INCONSISTENT_ROOT_HINTS", "The DNS server found root hints but they were not consistent across all adapters."),
        0x0000255e: ("DNS_ERROR_DWORD_VALUE_TOO_SMALL", "The specified value is too small for this parameter."),
        0x0000255f: ("DNS_ERROR_DWORD_VALUE_TOO_LARGE", "The specified value is too large for this parameter."),
        0x00002560: ("DNS_ERROR_BACKGROUND_LOADING", "This operation is not allowed while the DNS server is loading zones in the background. Please try again later."),
        0x00002561: ("DNS_ERROR_NOT_ALLOWED_ON_RODC", "The operation requested is not permitted on against a DNS server running on a read-only DC."),
        0x00002562: ("DNS_ERROR_NOT_ALLOWED_UNDER_DNAME", "No data is allowed to exist underneath a DNAME record."),
        0x00002563: ("DNS_ERROR_DELEGATION_REQUIRED", "This operation requires credentials delegation."),
        0x00002564: ("DNS_ERROR_INVALID_POLICY_TABLE", "Name resolution policy table has been corrupted. DNS resolution will fail until it is fixed. Contact your network administrator."),
        0x00002581: ("DNS_ERROR_ZONE_DOES_NOT_EXIST", "DNS zone does not exist."),
        0x00002582: ("DNS_ERROR_NO_ZONE_INFO", "DNS zone information not available."),
        0x00002583: ("DNS_ERROR_INVALID_ZONE_OPERATION", "Invalid operation for DNS zone."),
        0x00002584: ("DNS_ERROR_ZONE_CONFIGURATION_ERROR", "Invalid DNS zone configuration."),
        0x00002585: ("DNS_ERROR_ZONE_HAS_NO_SOA_RECORD", "DNS zone has no start of authority (SOA) record."),
        0x00002586: ("DNS_ERROR_ZONE_HAS_NO_NS_RECORDS", "DNS zone has no Name Server (NS) record."),
        0x00002587: ("DNS_ERROR_ZONE_LOCKED", "DNS zone is locked."),
        0x00002588: ("DNS_ERROR_ZONE_CREATION_FAILED", "DNS zone creation failed."),
        0x00002589: ("DNS_ERROR_ZONE_ALREADY_EXISTS", "DNS zone already exists."),
        0x0000258a: ("DNS_ERROR_AUTOZONE_ALREADY_EXISTS", "DNS automatic zone already exists."),
        0x0000258b: ("DNS_ERROR_INVALID_ZONE_TYPE", "Invalid DNS zone type."),
        0x0000258c: ("DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP", "Secondary DNS zone requires master IP address."),
        0x0000258d: ("DNS_ERROR_ZONE_NOT_SECONDARY", "DNS zone not secondary."),
        0x0000258e: ("DNS_ERROR_NEED_SECONDARY_ADDRESSES", "Need secondary IP address."),
        0x0000258f: ("DNS_ERROR_WINS_INIT_FAILED", "WINS initialization failed."),
        0x00002590: ("DNS_ERROR_NEED_WINS_SERVERS", "Need WINS servers."),
        0x00002591: ("DNS_ERROR_NBSTAT_INIT_FAILED", "NBTSTAT initialization call failed."),
        0x00002592: ("DNS_ERROR_SOA_DELETE_INVALID", "Invalid delete of start of authority (SOA)"),
        0x00002593: ("DNS_ERROR_FORWARDER_ALREADY_EXISTS", "A conditional forwarding zone already exists for that name."),
        0x00002594: ("DNS_ERROR_ZONE_REQUIRES_MASTER_IP", "This zone must be configured with one or more master DNS server IP addresses."),
        0x00002595: ("DNS_ERROR_ZONE_IS_SHUTDOWN", "The operation cannot be performed because this zone is shut down."),
        0x00002596: ("DNS_ERROR_ZONE_LOCKED_FOR_SIGNING", "This operation cannot be performed because the zone is currently being signed. Please try again later."),
        0x000025b3: ("DNS_ERROR_PRIMARY_REQUIRES_DATAFILE", "Primary DNS zone requires datafile."),
        0x000025b4: ("DNS_ERROR_INVALID_DATAFILE_NAME", "Invalid datafile name for DNS zone."),
        0x000025b5: ("DNS_ERROR_DATAFILE_OPEN_FAILURE", "Failed to open datafile for DNS zone."),
        0x000025b6: ("DNS_ERROR_FILE_WRITEBACK_FAILED", "Failed to write datafile for DNS zone."),
        0x000025b7: ("DNS_ERROR_DATAFILE_PARSING", "Failure while reading datafile for DNS zone."),
        0x000025e5: ("DNS_ERROR_RECORD_DOES_NOT_EXIST", "DNS record does not exist."),
        0x000025e6: ("DNS_ERROR_RECORD_FORMAT", "DNS record format error."),
        0x000025e7: ("DNS_ERROR_NODE_CREATION_FAILED", "Node creation failure in DNS."),
        0x000025e8: ("DNS_ERROR_UNKNOWN_RECORD_TYPE", "Unknown DNS record type."),
        0x000025e9: ("DNS_ERROR_RECORD_TIMED_OUT", "DNS record timed out."),
        0x000025ea: ("DNS_ERROR_NAME_NOT_IN_ZONE", "Name not in DNS zone."),
        0x000025eb: ("DNS_ERROR_CNAME_LOOP", "CNAME loop detected."),
        0x000025ec: ("DNS_ERROR_NODE_IS_CNAME", "Node is a CNAME DNS record."),
        0x000025ed: ("DNS_ERROR_CNAME_COLLISION", "A CNAME record already exists for given name."),
        0x000025ee: ("DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT", "Record only at DNS zone root."),
        0x000025ef: ("DNS_ERROR_RECORD_ALREADY_EXISTS", "DNS record already exists."),
        0x000025f0: ("DNS_ERROR_SECONDARY_DATA", "Secondary DNS zone data error."),
        0x000025f1: ("DNS_ERROR_NO_CREATE_CACHE_DATA", "Could not create DNS cache data."),
        0x000025f2: ("DNS_ERROR_NAME_DOES_NOT_EXIST", "DNS name does not exist."),
        0x000025f3: ("DNS_WARNING_PTR_CREATE_FAILED", "Could not create pointer (PTR) record."),
        0x000025f4: ("DNS_WARNING_DOMAIN_UNDELETED", "DNS domain was undeleted."),
        0x000025f5: ("DNS_ERROR_DS_UNAVAILABLE", "The directory service is unavailable."),
        0x000025f6: ("DNS_ERROR_DS_ZONE_ALREADY_EXISTS", "DNS zone already exists in the directory service."),
        0x000025f7: ("DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE", "DNS server not creating or reading the boot file for the directory service integrated DNS zone."),
        0x000025f8: ("DNS_ERROR_NODE_IS_DNAME", "Node is a DNAME DNS record."),
        0x000025f9: ("DNS_ERROR_DNAME_COLLISION", "A DNAME record already exists for given name."),
        0x000025fa: ("DNS_ERROR_ALIAS_LOOP", "An alias loop has been detected with either CNAME or DNAME records."),
        0x00002617: ("DNS_INFO_AXFR_COMPLETE", "DNS AXFR (zone transfer) complete."),
        0x00002618: ("DNS_ERROR_AXFR", "DNS zone transfer failed."),
        0x00002619: ("DNS_INFO_ADDED_LOCAL_WINS", "Added local WINS server."),
        0x00002649: ("DNS_STATUS_CONTINUE_NEEDED", "Secure update call needs to continue update request."),
        0x0000267b: ("DNS_ERROR_NO_TCPIP", "TCP/IP network protocol not installed."),
        0x0000267c: ("DNS_ERROR_NO_DNS_SERVERS", "No DNS servers configured for local system."),
        0x000026ad: ("DNS_ERROR_DP_DOES_NOT_EXIST", "The specified directory partition does not exist."),
        0x000026ae: ("DNS_ERROR_DP_ALREADY_EXISTS", "The specified directory partition already exists."),
        0x000026af: ("DNS_ERROR_DP_NOT_ENLISTED", "This DNS server is not enlisted in the specified directory partition."),
        0x000026b0: ("DNS_ERROR_DP_ALREADY_ENLISTED", "This DNS server is already enlisted in the specified directory partition."),
        0x000026b1: ("DNS_ERROR_DP_NOT_AVAILABLE", "The directory partition is not available at this time. Please wait a few minutes and try again."),
        0x000026b2: ("DNS_ERROR_DP_FSMO_ERROR", "The operation failed because the domain naming master FSMO role could not be reached. The domain controller holding the domain naming master FSMO role is down or unable to service the request or is not running Windows Server 2003 or later."),
        0x00002714: ("WSAEINTR", "A blocking operation was interrupted by a call to WSACancelBlockingCall."),
        0x00002719: ("WSAEBADF", "The file handle supplied is not valid."),
        0x0000271d: ("WSAEACCES", "An attempt was made to access a socket in a way forbidden by its access permissions."),
        0x0000271e: ("WSAEFAULT", "The system detected an invalid pointer address in attempting to use a pointer argument in a call."),
        0x00002726: ("WSAEINVAL", "An invalid argument was supplied."),
        0x00002728: ("WSAEMFILE", "Too many open sockets."),
        0x00002733: ("WSAEWOULDBLOCK", "A non-blocking socket operation could not be completed immediately."),
        0x00002734: ("WSAEINPROGRESS", "A blocking operation is currently executing."),
        0x00002735: ("WSAEALREADY", "An operation was attempted on a non-blocking socket that already had an operation in progress."),
        0x00002736: ("WSAENOTSOCK", "An operation was attempted on something that is not a socket."),
        0x00002737: ("WSAEDESTADDRREQ", "A required address was omitted from an operation on a socket."),
        0x00002738: ("WSAEMSGSIZE", "A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself."),
        0x00002739: ("WSAEPROTOTYPE", "A protocol was specified in the socket function call that does not support the semantics of the socket type requested."),
        0x0000273a: ("WSAENOPROTOOPT", "An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call."),
        0x0000273b: ("WSAEPROTONOSUPPORT", "The requested protocol has not been configured into the system, or no implementation for it exists."),
        0x0000273c: ("WSAESOCKTNOSUPPORT", "The support for the specified socket type does not exist in this address family."),
        0x0000273d: ("WSAEOPNOTSUPP", "The attempted operation is not supported for the type of object referenced."),
        0x0000273e: ("WSAEPFNOSUPPORT", "The protocol family has not been configured into the system or no implementation for it exists."),
        0x0000273f: ("WSAEAFNOSUPPORT", "An address incompatible with the requested protocol was used."),
        0x00002740: ("WSAEADDRINUSE", "Only one usage of each socket address (protocol/network address/port) is normally permitted."),
        0x00002741: ("WSAEADDRNOTAVAIL", "The requested address is not valid in its context."),
        0x00002742: ("WSAENETDOWN", "A socket operation encountered a dead network."),
        0x00002743: ("WSAENETUNREACH", "A socket operation was attempted to an unreachable network."),
        0x00002744: ("WSAENETRESET", "The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress."),
        0x00002745: ("WSAECONNABORTED", "An established connection was aborted by the software in your host machine."),
        0x00002746: ("WSAECONNRESET", "An existing connection was forcibly closed by the remote host."),
        0x00002747: ("WSAENOBUFS", "An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full."),
        0x00002748: ("WSAEISCONN", "A connect request was made on an already connected socket."),
        0x00002749: ("WSAENOTCONN", "A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied."),
        0x0000274a: ("WSAESHUTDOWN", "A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call."),
        0x0000274b: ("WSAETOOMANYREFS", "Too many references to some kernel object."),
        0x0000274c: ("WSAETIMEDOUT", "A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond."),
        0x0000274d: ("WSAECONNREFUSED", "No connection could be made because the target machine actively refused it."),
        0x0000274e: ("WSAELOOP", "Cannot translate name."),
        0x0000274f: ("WSAENAMETOOLONG", "Name component or name was too long."),
        0x00002750: ("WSAEHOSTDOWN", "A socket operation failed because the destination host was down."),
        0x00002751: ("WSAEHOSTUNREACH", "A socket operation was attempted to an unreachable host."),
        0x00002752: ("WSAENOTEMPTY", "Cannot remove a directory that is not empty."),
        0x00002753: ("WSAEPROCLIM", "A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously."),
        0x00002754: ("WSAEUSERS", "Ran out of quota."),
        0x00002755: ("WSAEDQUOT", "Ran out of disk quota."),
        0x00002756: ("WSAESTALE", "File handle reference is no longer available."),
        0x00002757: ("WSAEREMOTE", "Item is not available locally."),
        0x0000276b: ("WSASYSNOTREADY", "WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable."),
        0x0000276c: ("WSAVERNOTSUPPORTED", "The Windows Sockets version requested is not supported."),
        0x0000276d: ("WSANOTINITIALISED", "Either the application has not called WSAStartup, or WSAStartup failed."),
        0x00002775: ("WSAEDISCON", "Returned by WSARecv or WSARecvFrom to indicate the remote party has initiated a graceful shutdown sequence."),
        0x00002776: ("WSAENOMORE", "No more results can be returned by WSALookupServiceNext."),
        0x00002777: ("WSAECANCELLED", "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled."),
        0x00002778: ("WSAEINVALIDPROCTABLE", "The procedure call table is invalid."),
        0x00002779: ("WSAEINVALIDPROVIDER", "The requested service provider is invalid."),
        0x0000277a: ("WSAEPROVIDERFAILEDINIT", "The requested service provider could not be loaded or initialized."),
        0x0000277b: ("WSASYSCALLFAILURE", "A system call has failed."),
        0x0000277c: ("WSASERVICE_NOT_FOUND", "No such service is known. The service cannot be found in the specified name space."),
        0x0000277d: ("WSATYPE_NOT_FOUND", "The specified class was not found."),
        0x0000277e: ("WSA_E_NO_MORE", "No more results can be returned by WSALookupServiceNext."),
        0x0000277f: ("WSA_E_CANCELLED", "A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled."),
        0x00002780: ("WSAEREFUSED", "A database query failed because it was actively refused."),
        0x00002af9: ("WSAHOST_NOT_FOUND", "No such host is known."),
        0x00002afa: ("WSATRY_AGAIN", "This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server."),
        0x00002afb: ("WSANO_RECOVERY", "A non-recoverable error occurred during a database lookup."),
        0x00002afc: ("WSANO_DATA", "The requested name is valid, but no data of the requested type was found."),
        0x00002afd: ("WSA_QOS_RECEIVERS", "At least one reserve has arrived."),
        0x00002afe: ("WSA_QOS_SENDERS", "At least one path has arrived."),
        0x00002aff: ("WSA_QOS_NO_SENDERS", "There are no senders."),
        0x00002b00: ("WSA_QOS_NO_RECEIVERS", "There are no receivers."),
        0x00002b01: ("WSA_QOS_REQUEST_CONFIRMED", "Reserve has been confirmed."),
        0x00002b02: ("WSA_QOS_ADMISSION_FAILURE", "Error due to lack of resources."),
        0x00002b03: ("WSA_QOS_POLICY_FAILURE", "Rejected for administrative reasons - bad credentials."),
        0x00002b04: ("WSA_QOS_BAD_STYLE", "Unknown or conflicting style."),
        0x00002b05: ("WSA_QOS_BAD_OBJECT", "Problem with some part of the filterspec or providerspecific buffer in general."),
        0x00002b06: ("WSA_QOS_TRAFFIC_CTRL_ERROR", "Problem with some part of the flowspec."),
        0x00002b07: ("WSA_QOS_GENERIC_ERROR", "General QOS error."),
        0x00002b08: ("WSA_QOS_ESERVICETYPE", "An invalid or unrecognized service type was found in the flowspec."),
        0x00002b09: ("WSA_QOS_EFLOWSPEC", "An invalid or inconsistent flowspec was found in the QOS structure."),
        0x00002b0a: ("WSA_QOS_EPROVSPECBUF", "Invalid QOS provider-specific buffer."),
        0x00002b0b: ("WSA_QOS_EFILTERSTYLE", "An invalid QOS filter style was used."),
        0x00002b0c: ("WSA_QOS_EFILTERTYPE", "An invalid QOS filter type was used."),
        0x00002b0d: ("WSA_QOS_EFILTERCOUNT", "An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR."),
        0x00002b0e: ("WSA_QOS_EOBJLENGTH", "An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer."),
        0x00002b0f: ("WSA_QOS_EFLOWCOUNT", "An incorrect number of flow descriptors was specified in the QOS structure."),
        0x00002b10: ("WSA_QOS_EUNKOWNPSOBJ", "An unrecognized object was found in the QOS provider-specific buffer."),
        0x00002b11: ("WSA_QOS_EPOLICYOBJ", "An invalid policy object was found in the QOS provider-specific buffer."),
        0x00002b12: ("WSA_QOS_EFLOWDESC", "An invalid QOS flow descriptor was found in the flow descriptor list."),
        0x00002b13: ("WSA_QOS_EPSFLOWSPEC", "An invalid or inconsistent flowspec was found in the QOS provider specific buffer."),
        0x00002b14: ("WSA_QOS_EPSFILTERSPEC", "An invalid FILTERSPEC was found in the QOS provider-specific buffer."),
        0x00002b15: ("WSA_QOS_ESDMODEOBJ", "An invalid shape discard mode object was found in the QOS provider specific buffer."),
        0x00002b16: ("WSA_QOS_ESHAPERATEOBJ", "An invalid shaping rate object was found in the QOS provider-specific buffer."),
        0x00002b17: ("WSA_QOS_RESERVED_PETYPE", "A reserved policy element was found in the QOS provider-specific buffer."),
        0x00002b18: ("WSA_SECURE_HOST_NOT_FOUND", "No such host is known securely."),
        0x00002b19: ("WSA_IPSEC_NAME_POLICY_ERROR", "Name based IPSEC policy could not be added."),
        0x000032c8: ("ERROR_IPSEC_QM_POLICY_EXISTS", "The specified quick mode policy already exists."),
        0x000032c9: ("ERROR_IPSEC_QM_POLICY_NOT_FOUND", "The specified quick mode policy was not found."),
        0x000032ca: ("ERROR_IPSEC_QM_POLICY_IN_USE", "The specified quick mode policy is being used."),
        0x000032cb: ("ERROR_IPSEC_MM_POLICY_EXISTS", "The specified main mode policy already exists."),
        0x000032cc: ("ERROR_IPSEC_MM_POLICY_NOT_FOUND", "The specified main mode policy was not found"),
        0x000032cd: ("ERROR_IPSEC_MM_POLICY_IN_USE", "The specified main mode policy is being used."),
        0x000032ce: ("ERROR_IPSEC_MM_FILTER_EXISTS", "The specified main mode filter already exists."),
        0x000032cf: ("ERROR_IPSEC_MM_FILTER_NOT_FOUND", "The specified main mode filter was not found."),
        0x000032d0: ("ERROR_IPSEC_TRANSPORT_FILTER_EXISTS", "The specified transport mode filter already exists."),
        0x000032d1: ("ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND", "The specified transport mode filter does not exist."),
        0x000032d2: ("ERROR_IPSEC_MM_AUTH_EXISTS", "The specified main mode authentication list exists."),
        0x000032d3: ("ERROR_IPSEC_MM_AUTH_NOT_FOUND", "The specified main mode authentication list was not found."),
        0x000032d4: ("ERROR_IPSEC_MM_AUTH_IN_USE", "The specified main mode authentication list is being used."),
        0x000032d5: ("ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND", "The specified default main mode policy was not found."),
        0x000032d6: ("ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND", "The specified default main mode authentication list was not found."),
        0x000032d7: ("ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND", "The specified default quick mode policy was not found."),
        0x000032d8: ("ERROR_IPSEC_TUNNEL_FILTER_EXISTS", "The specified tunnel mode filter exists."),
        0x000032d9: ("ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND", "The specified tunnel mode filter was not found."),
        0x000032da: ("ERROR_IPSEC_MM_FILTER_PENDING_DELETION", "The Main Mode filter is pending deletion."),
        0x000032db: ("ERROR_IPSEC_TRANSPORT_FILTER_PENDING_DELETION", "The transport filter is pending deletion."),
        0x000032dc: ("ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION", "The tunnel filter is pending deletion."),
        0x000032dd: ("ERROR_IPSEC_MM_POLICY_PENDING_DELETION", "The Main Mode policy is pending deletion."),
        0x000032de: ("ERROR_IPSEC_MM_AUTH_PENDING_DELETION", "The Main Mode authentication bundle is pending deletion."),
        0x000032df: ("ERROR_IPSEC_QM_POLICY_PENDING_DELETION", "The Quick Mode policy is pending deletion."),
        0x000032e0: ("WARNING_IPSEC_MM_POLICY_PRUNED", "The Main Mode policy was successfully added, but some of the requested offers are not supported."),
        0x000032e1: ("WARNING_IPSEC_QM_POLICY_PRUNED", "The Quick Mode policy was successfully added, but some of the requested offers are not supported."),
        0x000035e8: ("ERROR_IPSEC_IKE_NEG_STATUS_BEGIN", " ERROR_IPSEC_IKE_NEG_STATUS_BEGIN"),
        0x000035e9: ("ERROR_IPSEC_IKE_AUTH_FAIL", "IKE authentication credentials are unacceptable"),
        0x000035ea: ("ERROR_IPSEC_IKE_ATTRIB_FAIL", "IKE security attributes are unacceptable"),
        0x000035eb: ("ERROR_IPSEC_IKE_NEGOTIATION_PENDING", "IKE Negotiation in progress"),
        0x000035ec: ("ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR", "General processing error"),
        0x000035ed: ("ERROR_IPSEC_IKE_TIMED_OUT", "Negotiation timed out"),
        0x000035ee: ("ERROR_IPSEC_IKE_NO_CERT", "IKE failed to find valid machine certificate. Contact your Network Security Administrator about installing a valid certificate in the appropriate Certificate Store."),
        0x000035ef: ("ERROR_IPSEC_IKE_SA_DELETED", "IKE SA deleted by peer before establishment completed"),
        0x000035f0: ("ERROR_IPSEC_IKE_SA_REAPED", "IKE SA deleted before establishment completed"),
        0x000035f1: ("ERROR_IPSEC_IKE_MM_ACQUIRE_DROP", "Negotiation request sat in Queue too long"),
        0x000035f2: ("ERROR_IPSEC_IKE_QM_ACQUIRE_DROP", "Negotiation request sat in Queue too long"),
        0x000035f3: ("ERROR_IPSEC_IKE_QUEUE_DROP_MM", "Negotiation request sat in Queue too long"),
        0x000035f4: ("ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM", "Negotiation request sat in Queue too long"),
        0x000035f5: ("ERROR_IPSEC_IKE_DROP_NO_RESPONSE", "No response from peer"),
        0x000035f6: ("ERROR_IPSEC_IKE_MM_DELAY_DROP", "Negotiation took too long"),
        0x000035f7: ("ERROR_IPSEC_IKE_QM_DELAY_DROP", "Negotiation took too long"),
        0x000035f8: ("ERROR_IPSEC_IKE_ERROR", "Unknown error occurred"),
        0x000035f9: ("ERROR_IPSEC_IKE_CRL_FAILED", "Certificate Revocation Check failed"),
        0x000035fa: ("ERROR_IPSEC_IKE_INVALID_KEY_USAGE", "Invalid certificate key usage"),
        0x000035fb: ("ERROR_IPSEC_IKE_INVALID_CERT_TYPE", "Invalid certificate type"),
        0x000035fc: ("ERROR_IPSEC_IKE_NO_PRIVATE_KEY", "IKE negotiation failed because the machine certificate used does not have a private key. IPsec certificates require a private key. Contact your Network Security administrator about replacing with a certificate that has a private key."),
        0x000035fd: ("ERROR_IPSEC_IKE_SIMULTANEOUS_REKEY", "Simultaneous rekeys were detected."),
        0x000035fe: ("ERROR_IPSEC_IKE_DH_FAIL", "Failure in Diffie-Hellman computation"),
        0x000035ff: ("ERROR_IPSEC_IKE_CRITICAL_PAYLOAD_NOT_RECOGNIZED", "Don't know how to process critical payload"),
        0x00003600: ("ERROR_IPSEC_IKE_INVALID_HEADER", "Invalid header"),
        0x00003601: ("ERROR_IPSEC_IKE_NO_POLICY", "No policy configured"),
        0x00003602: ("ERROR_IPSEC_IKE_INVALID_SIGNATURE", "Failed to verify signature"),
        0x00003603: ("ERROR_IPSEC_IKE_KERBEROS_ERROR", "Failed to authenticate using Kerberos"),
        0x00003604: ("ERROR_IPSEC_IKE_NO_PUBLIC_KEY", "Peer's certificate did not have a public key"),
        0x00003605: ("ERROR_IPSEC_IKE_PROCESS_ERR", "Error processing error payload"),
        0x00003606: ("ERROR_IPSEC_IKE_PROCESS_ERR_SA", "Error processing SA payload"),
        0x00003607: ("ERROR_IPSEC_IKE_PROCESS_ERR_PROP", "Error processing Proposal payload"),
        0x00003608: ("ERROR_IPSEC_IKE_PROCESS_ERR_TRANS", "Error processing Transform payload"),
        0x00003609: ("ERROR_IPSEC_IKE_PROCESS_ERR_KE", "Error processing KE payload"),
        0x0000360a: ("ERROR_IPSEC_IKE_PROCESS_ERR_ID", "Error processing ID payload"),
        0x0000360b: ("ERROR_IPSEC_IKE_PROCESS_ERR_CERT", "Error processing Cert payload"),
        0x0000360c: ("ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ", "Error processing Certificate Request payload"),
        0x0000360d: ("ERROR_IPSEC_IKE_PROCESS_ERR_HASH", "Error processing Hash payload"),
        0x0000360e: ("ERROR_IPSEC_IKE_PROCESS_ERR_SIG", "Error processing Signature payload"),
        0x0000360f: ("ERROR_IPSEC_IKE_PROCESS_ERR_NONCE", "Error processing Nonce payload"),
        0x00003610: ("ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY", "Error processing Notify payload"),
        0x00003611: ("ERROR_IPSEC_IKE_PROCESS_ERR_DELETE", "Error processing Delete Payload"),
        0x00003612: ("ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR", "Error processing VendorId payload"),
        0x00003613: ("ERROR_IPSEC_IKE_INVALID_PAYLOAD", "Invalid payload received"),
        0x00003614: ("ERROR_IPSEC_IKE_LOAD_SOFT_SA", "Soft SA loaded"),
        0x00003615: ("ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN", "Soft SA torn down"),
        0x00003616: ("ERROR_IPSEC_IKE_INVALID_COOKIE", "Invalid cookie received."),
        0x00003617: ("ERROR_IPSEC_IKE_NO_PEER_CERT", "Peer failed to send valid machine certificate"),
        0x00003618: ("ERROR_IPSEC_IKE_PEER_CRL_FAILED", "Certification Revocation check of peer's certificate failed"),
        0x00003619: ("ERROR_IPSEC_IKE_POLICY_CHANGE", "New policy invalidated SAs formed with old policy"),
        0x0000361a: ("ERROR_IPSEC_IKE_NO_MM_POLICY", "There is no available Main Mode IKE policy."),
        0x0000361b: ("ERROR_IPSEC_IKE_NOTCBPRIV", "Failed to enabled TCB privilege."),
        0x0000361c: ("ERROR_IPSEC_IKE_SECLOADFAIL", "Failed to load SECURITY.DLL."),
        0x0000361d: ("ERROR_IPSEC_IKE_FAILSSPINIT", "Failed to obtain security function table dispatch address from SSPI."),
        0x0000361e: ("ERROR_IPSEC_IKE_FAILQUERYSSP", "Failed to query Kerberos package to obtain max token size."),
        0x0000361f: ("ERROR_IPSEC_IKE_SRVACQFAIL", "Failed to obtain Kerberos server credentials for ISAKMP/ERROR_IPSEC_IKE service. Kerberos authentication will not function. The most likely reason for this is lack of domain membership. This is normal if your computer is a member of a workgroup."),
        0x00003620: ("ERROR_IPSEC_IKE_SRVQUERYCRED", "Failed to determine SSPI principal name for ISAKMP/ERROR_IPSEC_IKE service (QueryCredentialsAttributes)."),
        0x00003621: ("ERROR_IPSEC_IKE_GETSPIFAIL", "Failed to obtain new SPI for the inbound SA from IPsec driver. The most common cause for this is that the driver does not have the correct filter. Check your policy to verify the filters."),
        0x00003622: ("ERROR_IPSEC_IKE_INVALID_FILTER", "Given filter is invalid"),
        0x00003623: ("ERROR_IPSEC_IKE_OUT_OF_MEMORY", "Memory allocation failed."),
        0x00003624: ("ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED", "Failed to add Security Association to IPsec Driver. The most common cause for this is if the IKE negotiation took too long to complete. If the problem persists, reduce the load on the faulting machine."),
        0x00003625: ("ERROR_IPSEC_IKE_INVALID_POLICY", "Invalid policy"),
        0x00003626: ("ERROR_IPSEC_IKE_UNKNOWN_DOI", "Invalid DOI"),
        0x00003627: ("ERROR_IPSEC_IKE_INVALID_SITUATION", "Invalid situation"),
        0x00003628: ("ERROR_IPSEC_IKE_DH_FAILURE", "Diffie-Hellman failure"),
        0x00003629: ("ERROR_IPSEC_IKE_INVALID_GROUP", "Invalid Diffie-Hellman group"),
        0x0000362a: ("ERROR_IPSEC_IKE_ENCRYPT", "Error encrypting payload"),
        0x0000362b: ("ERROR_IPSEC_IKE_DECRYPT", "Error decrypting payload"),
        0x0000362c: ("ERROR_IPSEC_IKE_POLICY_MATCH", "Policy match error"),
        0x0000362d: ("ERROR_IPSEC_IKE_UNSUPPORTED_ID", "Unsupported ID"),
        0x0000362e: ("ERROR_IPSEC_IKE_INVALID_HASH", "Hash verification failed"),
        0x0000362f: ("ERROR_IPSEC_IKE_INVALID_HASH_ALG", "Invalid hash algorithm"),
        0x00003630: ("ERROR_IPSEC_IKE_INVALID_HASH_SIZE", "Invalid hash size"),
        0x00003631: ("ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG", "Invalid encryption algorithm"),
        0x00003632: ("ERROR_IPSEC_IKE_INVALID_AUTH_ALG", "Invalid authentication algorithm"),
        0x00003633: ("ERROR_IPSEC_IKE_INVALID_SIG", "Invalid certificate signature"),
        0x00003634: ("ERROR_IPSEC_IKE_LOAD_FAILED", "Load failed"),
        0x00003635: ("ERROR_IPSEC_IKE_RPC_DELETE", "Deleted via RPC call"),
        0x00003636: ("ERROR_IPSEC_IKE_BENIGN_REINIT", "Temporary state created to perform reinitialization. This is not a real failure."),
        0x00003637: ("ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY", "The lifetime value received in the Responder Lifetime Notify is below the Windows 2000 configured minimum value. Please fix the policy on the peer machine."),
        0x00003638: ("ERROR_IPSEC_IKE_INVALID_MAJOR_VERSION", "The recipient cannot handle version of IKE specified in the header."),
        0x00003639: ("ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN", "Key length in certificate is too small for configured security requirements."),
        0x0000363a: ("ERROR_IPSEC_IKE_MM_LIMIT", "Max number of established MM SAs to peer exceeded."),
        0x0000363b: ("ERROR_IPSEC_IKE_NEGOTIATION_DISABLED", "IKE received a policy that disables negotiation."),
        0x0000363c: ("ERROR_IPSEC_IKE_QM_LIMIT", "Reached maximum quick mode limit for the main mode. New main mode will be started."),
        0x0000363d: ("ERROR_IPSEC_IKE_MM_EXPIRED", "Main mode SA lifetime expired or peer sent a main mode delete."),
        0x0000363e: ("ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID", "Main mode SA assumed to be invalid because peer stopped responding."),
        0x0000363f: ("ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH", "Certificate doesn't chain to a trusted root in IPsec policy."),
        0x00003640: ("ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID", "Received unexpected message ID."),
        0x00003641: ("ERROR_IPSEC_IKE_INVALID_AUTH_PAYLOAD", "Received invalid authentication offers."),
        0x00003642: ("ERROR_IPSEC_IKE_DOS_COOKIE_SENT", "Sent DoS cookie notify to initiator."),
        0x00003643: ("ERROR_IPSEC_IKE_SHUTTING_DOWN", "IKE service is shutting down."),
        0x00003644: ("ERROR_IPSEC_IKE_CGA_AUTH_FAILED", "Could not verify binding between CGA address and certificate."),
        0x00003645: ("ERROR_IPSEC_IKE_PROCESS_ERR_NATOA", "Error processing NatOA payload."),
        0x00003646: ("ERROR_IPSEC_IKE_INVALID_MM_FOR_QM", "Parameters of the main mode are invalid for this quick mode."),
        0x00003647: ("ERROR_IPSEC_IKE_QM_EXPIRED", "Quick mode SA was expired by IPsec driver."),
        0x00003648: ("ERROR_IPSEC_IKE_TOO_MANY_FILTERS", "Too many dynamically added IKEEXT filters were detected."),
        0x00003649: ("ERROR_IPSEC_IKE_NEG_STATUS_END", " ERROR_IPSEC_IKE_NEG_STATUS_END"),
        0x0000364a: ("ERROR_IPSEC_IKE_KILL_DUMMY_NAP_TUNNEL", "NAP reauth succeeded and must delete the dummy NAP IKEv2 tunnel."),
        0x0000364b: ("ERROR_IPSEC_IKE_INNER_IP_ASSIGNMENT_FAILURE", "Error in assigning inner IP address to initiator in tunnel mode."),
        0x0000364c: ("ERROR_IPSEC_IKE_REQUIRE_CP_PAYLOAD_MISSING", "Require configuration payload missing."),
        0x0000364d: ("ERROR_IPSEC_KEY_MODULE_IMPERSONATION_NEGOTIATION_PENDING", "A negotiation running as the security principle who issued the connection is in progress"),
        0x0000364e: ("ERROR_IPSEC_IKE_COEXISTENCE_SUPPRESS", "SA was deleted due to IKEv1/AuthIP co-existence suppress check."),
        0x0000364f: ("ERROR_IPSEC_IKE_RATELIMIT_DROP", "Incoming SA request was dropped due to peer IP address rate limiting."),
        0x00003650: ("ERROR_IPSEC_IKE_PEER_DOESNT_SUPPORT_MOBIKE", "Peer does not support MOBIKE."),
        0x00003651: ("ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE", "SA establishment is not authorized."),
        0x00003652: ("ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_FAILURE", "SA establishment is not authorized because there is not a sufficiently strong PKINIT-based credential."),
        0x00003653: ("ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE_WITH_OPTIONAL_RETRY", "SA establishment is not authorized.  You may need to enter updated or different credentials such as a smartcard."),
        0x00003654: ("ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_AND_CERTMAP_FAILURE", "SA establishment is not authorized because there is not a sufficiently strong PKINIT-based credential. This might be related to certificate-to-account mapping failure for the SA."),
        0x00003655: ("ERROR_IPSEC_IKE_NEG_STATUS_EXTENDED_END", " ERROR_IPSEC_IKE_NEG_STATUS_EXTENDED_END"),
        0x00003656: ("ERROR_IPSEC_BAD_SPI", "The SPI in the packet does not match a valid IPsec SA."),
        0x00003657: ("ERROR_IPSEC_SA_LIFETIME_EXPIRED", "Packet was received on an IPsec SA whose lifetime has expired."),
        0x00003658: ("ERROR_IPSEC_WRONG_SA", "Packet was received on an IPsec SA that does not match the packet characteristics."),
        0x00003659: ("ERROR_IPSEC_REPLAY_CHECK_FAILED", "Packet sequence number replay check failed."),
        0x0000365a: ("ERROR_IPSEC_INVALID_PACKET", "IPsec header and/or trailer in the packet is invalid."),
        0x0000365b: ("ERROR_IPSEC_INTEGRITY_CHECK_FAILED", "IPsec integrity check failed."),
        0x0000365c: ("ERROR_IPSEC_CLEAR_TEXT_DROP", "IPsec dropped a clear text packet."),
        0x0000365d: ("ERROR_IPSEC_AUTH_FIREWALL_DROP", "IPsec dropped an incoming ESP packet in authenticated firewall mode. This drop is benign."),
        0x0000365e: ("ERROR_IPSEC_THROTTLE_DROP", "IPsec dropped a packet due to DoS throttling."),
        0x00003665: ("ERROR_IPSEC_DOSP_BLOCK", "IPsec DoS Protection matched an explicit block rule."),
        0x00003666: ("ERROR_IPSEC_DOSP_RECEIVED_MULTICAST", "IPsec DoS Protection received an IPsec specific multicast packet which is not allowed."),
        0x00003667: ("ERROR_IPSEC_DOSP_INVALID_PACKET", "IPsec DoS Protection received an incorrectly formatted packet."),
        0x00003668: ("ERROR_IPSEC_DOSP_STATE_LOOKUP_FAILED", "IPsec DoS Protection failed to look up state."),
        0x00003669: ("ERROR_IPSEC_DOSP_MAX_ENTRIES", "IPsec DoS Protection failed to create state because the maximum number of entries allowed by policy has been reached."),
        0x0000366a: ("ERROR_IPSEC_DOSP_KEYMOD_NOT_ALLOWED", "IPsec DoS Protection received an IPsec negotiation packet for a keying module which is not allowed by policy."),
        0x0000366b: ("ERROR_IPSEC_DOSP_NOT_INSTALLED", "IPsec DoS Protection has not been enabled."),
        0x0000366c: ("ERROR_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES", "IPsec DoS Protection failed to create a per internal IP rate limit queue because the maximum number of queues allowed by policy has been reached."),
        0x000036b0: ("ERROR_SXS_SECTION_NOT_FOUND", "The requested section was not present in the activation context."),
        0x000036b1: ("ERROR_SXS_CANT_GEN_ACTCTX", "The application has failed to start because its side-by-side configuration is incorrect. Please see the application event log or use the command-line sxstrace.exe tool for more detail."),
        0x000036b2: ("ERROR_SXS_INVALID_ACTCTXDATA_FORMAT", "The application binding data format is invalid."),
        0x000036b3: ("ERROR_SXS_ASSEMBLY_NOT_FOUND", "The referenced assembly is not installed on your system."),
        0x000036b4: ("ERROR_SXS_MANIFEST_FORMAT_ERROR", "The manifest file does not begin with the required tag and format information."),
        0x000036b5: ("ERROR_SXS_MANIFEST_PARSE_ERROR", "The manifest file contains one or more syntax errors."),
        0x000036b6: ("ERROR_SXS_ACTIVATION_CONTEXT_DISABLED", "The application attempted to activate a disabled activation context."),
        0x000036b7: ("ERROR_SXS_KEY_NOT_FOUND", "The requested lookup key was not found in any active activation context."),
        0x000036b8: ("ERROR_SXS_VERSION_CONFLICT", "A component version required by the application conflicts with another component version already active."),
        0x000036b9: ("ERROR_SXS_WRONG_SECTION_TYPE", "The type requested activation context section does not match the query API used."),
        0x000036ba: ("ERROR_SXS_THREAD_QUERIES_DISABLED", "Lack of system resources has required isolated activation to be disabled for the current thread of execution."),
        0x000036bb: ("ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET", "An attempt to set the process default activation context failed because the process default activation context was already set."),
        0x000036bc: ("ERROR_SXS_UNKNOWN_ENCODING_GROUP", "The encoding group identifier specified is not recognized."),
        0x000036bd: ("ERROR_SXS_UNKNOWN_ENCODING", "The encoding requested is not recognized."),
        0x000036be: ("ERROR_SXS_INVALID_XML_NAMESPACE_URI", "The manifest contains a reference to an invalid URI."),
        0x000036bf: ("ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_NOT_INSTALLED", "The application manifest contains a reference to a dependent assembly which is not installed"),
        0x000036c0: ("ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED", "The manifest for an assembly used by the application has a reference to a dependent assembly which is not installed"),
        0x000036c1: ("ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE", "The manifest contains an attribute for the assembly identity which is not valid."),
        0x000036c2: ("ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE", "The manifest is missing the required default namespace specification on the assembly element."),
        0x000036c3: ("ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE", "The manifest has a default namespace specified on the assembly element but its value is not 'urn:schemas-microsoft-com:asm.v1'."),
        0x000036c4: ("ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT", "The private manifest probed has crossed a path with an unsupported reparse point."),
        0x000036c5: ("ERROR_SXS_DUPLICATE_DLL_NAME", "Two or more components referenced directly or indirectly by the application manifest have files by the same name."),
        0x000036c6: ("ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME", "Two or more components referenced directly or indirectly by the application manifest have window classes with the same name."),
        0x000036c7: ("ERROR_SXS_DUPLICATE_CLSID", "Two or more components referenced directly or indirectly by the application manifest have the same COM server CLSIDs."),
        0x000036c8: ("ERROR_SXS_DUPLICATE_IID", "Two or more components referenced directly or indirectly by the application manifest have proxies for the same COM interface IIDs."),
        0x000036c9: ("ERROR_SXS_DUPLICATE_TLBID", "Two or more components referenced directly or indirectly by the application manifest have the same COM type library TLBIDs."),
        0x000036ca: ("ERROR_SXS_DUPLICATE_PROGID", "Two or more components referenced directly or indirectly by the application manifest have the same COM ProgIDs."),
        0x000036cb: ("ERROR_SXS_DUPLICATE_ASSEMBLY_NAME", "Two or more components referenced directly or indirectly by the application manifest are different versions of the same component which is not permitted."),
        0x000036cc: ("ERROR_SXS_FILE_HASH_MISMATCH", "A component's file does not match the verification information present in the component manifest."),
        0x000036cd: ("ERROR_SXS_POLICY_PARSE_ERROR", "The policy manifest contains one or more syntax errors."),
        0x000036ce: ("ERROR_SXS_XML_E_MISSINGQUOTE", "Manifest Parse Error : A string literal was expected, but no opening quote character was found."),
        0x000036cf: ("ERROR_SXS_XML_E_COMMENTSYNTAX", "Manifest Parse Error : Incorrect syntax was used in a comment."),
        0x000036d0: ("ERROR_SXS_XML_E_BADSTARTNAMECHAR", "Manifest Parse Error : A name was started with an invalid character."),
        0x000036d1: ("ERROR_SXS_XML_E_BADNAMECHAR", "Manifest Parse Error : A name contained an invalid character."),
        0x000036d2: ("ERROR_SXS_XML_E_BADCHARINSTRING", "Manifest Parse Error : A string literal contained an invalid character."),
        0x000036d3: ("ERROR_SXS_XML_E_XMLDECLSYNTAX", "Manifest Parse Error : Invalid syntax for an xml declaration."),
        0x000036d4: ("ERROR_SXS_XML_E_BADCHARDATA", "Manifest Parse Error : An Invalid character was found in text content."),
        0x000036d5: ("ERROR_SXS_XML_E_MISSINGWHITESPACE", "Manifest Parse Error : Required white space was missing."),
        0x000036d6: ("ERROR_SXS_XML_E_EXPECTINGTAGEND", "Manifest Parse Error : The character '>' was expected."),
        0x000036d7: ("ERROR_SXS_XML_E_MISSINGSEMICOLON", "Manifest Parse Error : A semi colon character was expected."),
        0x000036d8: ("ERROR_SXS_XML_E_UNBALANCEDPAREN", "Manifest Parse Error : Unbalanced parentheses."),
        0x000036d9: ("ERROR_SXS_XML_E_INTERNALERROR", "Manifest Parse Error : Internal error."),
        0x000036da: ("ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE", "Manifest Parse Error : Whitespace is not allowed at this location."),
        0x000036db: ("ERROR_SXS_XML_E_INCOMPLETE_ENCODING", "Manifest Parse Error : End of file reached in invalid state for current encoding."),
        0x000036dc: ("ERROR_SXS_XML_E_MISSING_PAREN", "Manifest Parse Error : Missing parenthesis."),
        0x000036dd: ("ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE", "Manifest Parse Error : A single or double closing quote character (\' or \") is missing."),
        0x000036de: ("ERROR_SXS_XML_E_MULTIPLE_COLONS", "Manifest Parse Error : Multiple colons are not allowed in a name."),
        0x000036df: ("ERROR_SXS_XML_E_INVALID_DECIMAL", "Manifest Parse Error : Invalid character for decimal digit."),
        0x000036e0: ("ERROR_SXS_XML_E_INVALID_HEXIDECIMAL", "Manifest Parse Error : Invalid character for hexadecimal digit."),
        0x000036e1: ("ERROR_SXS_XML_E_INVALID_UNICODE", "Manifest Parse Error : Invalid unicode character value for this platform."),
        0x000036e2: ("ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK", "Manifest Parse Error : Expecting whitespace or '?'."),
        0x000036e3: ("ERROR_SXS_XML_E_UNEXPECTEDENDTAG", "Manifest Parse Error : End tag was not expected at this location."),
        0x000036e4: ("ERROR_SXS_XML_E_UNCLOSEDTAG", "Manifest Parse Error : The following tags were not closed: %1."),
        0x000036e5: ("ERROR_SXS_XML_E_DUPLICATEATTRIBUTE", "Manifest Parse Error : Duplicate attribute."),
        0x000036e6: ("ERROR_SXS_XML_E_MULTIPLEROOTS", "Manifest Parse Error : Only one top level element is allowed in an XML document."),
        0x000036e7: ("ERROR_SXS_XML_E_INVALIDATROOTLEVEL", "Manifest Parse Error : Invalid at the top level of the document."),
        0x000036e8: ("ERROR_SXS_XML_E_BADXMLDECL", "Manifest Parse Error : Invalid xml declaration."),
        0x000036e9: ("ERROR_SXS_XML_E_MISSINGROOT", "Manifest Parse Error : XML document must have a top level element."),
        0x000036ea: ("ERROR_SXS_XML_E_UNEXPECTEDEOF", "Manifest Parse Error : Unexpected end of file."),
        0x000036eb: ("ERROR_SXS_XML_E_BADPEREFINSUBSET", "Manifest Parse Error : Parameter entities cannot be used inside markup declarations in an internal subset."),
        0x000036ec: ("ERROR_SXS_XML_E_UNCLOSEDSTARTTAG", "Manifest Parse Error : Element was not closed."),
        0x000036ed: ("ERROR_SXS_XML_E_UNCLOSEDENDTAG", "Manifest Parse Error : End element was missing the character '>'."),
        0x000036ee: ("ERROR_SXS_XML_E_UNCLOSEDSTRING", "Manifest Parse Error : A string literal was not closed."),
        0x000036ef: ("ERROR_SXS_XML_E_UNCLOSEDCOMMENT", "Manifest Parse Error : A comment was not closed."),
        0x000036f0: ("ERROR_SXS_XML_E_UNCLOSEDDECL", "Manifest Parse Error : A declaration was not closed."),
        0x000036f1: ("ERROR_SXS_XML_E_UNCLOSEDCDATA", "Manifest Parse Error : A CDATA section was not closed."),
        0x000036f2: ("ERROR_SXS_XML_E_RESERVEDNAMESPACE", "Manifest Parse Error : The namespace prefix is not allowed to start with the reserved string 'xml'."),
        0x000036f3: ("ERROR_SXS_XML_E_INVALIDENCODING", "Manifest Parse Error : System does not support the specified encoding."),
        0x000036f4: ("ERROR_SXS_XML_E_INVALIDSWITCH", "Manifest Parse Error : Switch from current encoding to specified encoding not supported."),
        0x000036f5: ("ERROR_SXS_XML_E_BADXMLCASE", "Manifest Parse Error : The name 'xml' is reserved and must be lower case."),
        0x000036f6: ("ERROR_SXS_XML_E_INVALID_STANDALONE", "Manifest Parse Error : The standalone attribute must have the value 'yes' or 'no'."),
        0x000036f7: ("ERROR_SXS_XML_E_UNEXPECTED_STANDALONE", "Manifest Parse Error : The standalone attribute cannot be used in external entities."),
        0x000036f8: ("ERROR_SXS_XML_E_INVALID_VERSION", "Manifest Parse Error : Invalid version number."),
        0x000036f9: ("ERROR_SXS_XML_E_MISSINGEQUALS", "Manifest Parse Error : Missing equals sign between attribute and attribute value."),
        0x000036fa: ("ERROR_SXS_PROTECTION_RECOVERY_FAILED", "Assembly Protection Error : Unable to recover the specified assembly."),
        0x000036fb: ("ERROR_SXS_PROTECTION_PUBLIC_KEY_TOO_SHORT", "Assembly Protection Error : The public key for an assembly was too short to be allowed."),
        0x000036fc: ("ERROR_SXS_PROTECTION_CATALOG_NOT_VALID", "Assembly Protection Error : The catalog for an assembly is not valid, or does not match the assembly's manifest."),
        0x000036fd: ("ERROR_SXS_UNTRANSLATABLE_HRESULT", "An HRESULT could not be translated to a corresponding Win32 error code."),
        0x000036fe: ("ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING", "Assembly Protection Error : The catalog for an assembly is missing."),
        0x000036ff: ("ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE", "The supplied assembly identity is missing one or more attributes which must be present in this context."),
        0x00003700: ("ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME", "The supplied assembly identity has one or more attribute names that contain characters not permitted in XML names."),
        0x00003701: ("ERROR_SXS_ASSEMBLY_MISSING", "The referenced assembly could not be found."),
        0x00003702: ("ERROR_SXS_CORRUPT_ACTIVATION_STACK", "The activation context activation stack for the running thread of execution is corrupt."),
        0x00003703: ("ERROR_SXS_CORRUPTION", "The application isolation metadata for this process or thread has become corrupt."),
        0x00003704: ("ERROR_SXS_EARLY_DEACTIVATION", "The activation context being deactivated is not the most recently activated one."),
        0x00003705: ("ERROR_SXS_INVALID_DEACTIVATION", "The activation context being deactivated is not active for the current thread of execution."),
        0x00003706: ("ERROR_SXS_MULTIPLE_DEACTIVATION", "The activation context being deactivated has already been deactivated."),
        0x00003707: ("ERROR_SXS_PROCESS_TERMINATION_REQUESTED", "A component used by the isolation facility has requested to terminate the process."),
        0x00003708: ("ERROR_SXS_RELEASE_ACTIVATION_CONTEXT", "A kernel mode component is releasing a reference on an activation context."),
        0x00003709: ("ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY", "The activation context of system default assembly could not be generated."),
        0x0000370a: ("ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE", "The value of an attribute in an identity is not within the legal range."),
        0x0000370b: ("ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME", "The name of an attribute in an identity is not within the legal range."),
        0x0000370c: ("ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE", "An identity contains two definitions for the same attribute."),
        0x0000370d: ("ERROR_SXS_IDENTITY_PARSE_ERROR", "The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, missing attribute name or missing attribute value."),
        0x0000370e: ("ERROR_MALFORMED_SUBSTITUTION_STRING", "A string containing localized substitutable content was malformed. Either a dollar sign ($) was followed by something other than a left parenthesis or another dollar sign or an substitution's right parenthesis was not found."),
        0x0000370f: ("ERROR_SXS_INCORRECT_PUBLIC_KEY_TOKEN", "The public key token does not correspond to the public key specified."),
        0x00003710: ("ERROR_UNMAPPED_SUBSTITUTION_STRING", "A substitution string had no mapping."),
        0x00003711: ("ERROR_SXS_ASSEMBLY_NOT_LOCKED", "The component must be locked before making the request."),
        0x00003712: ("ERROR_SXS_COMPONENT_STORE_CORRUPT", "The component store has been corrupted."),
        0x00003713: ("ERROR_ADVANCED_INSTALLER_FAILED", "An advanced installer failed during setup or servicing."),
        0x00003714: ("ERROR_XML_ENCODING_MISMATCH", "The character encoding in the XML declaration did not match the encoding used in the document."),
        0x00003715: ("ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT", "The identities of the manifests are identical but their contents are different."),
        0x00003716: ("ERROR_SXS_IDENTITIES_DIFFERENT", "The component identities are different."),
        0x00003717: ("ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT", "The assembly is not a deployment."),
        0x00003718: ("ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY", "The file is not a part of the assembly."),
        0x00003719: ("ERROR_SXS_MANIFEST_TOO_BIG", "The size of the manifest exceeds the maximum allowed."),
        0x0000371a: ("ERROR_SXS_SETTING_NOT_REGISTERED", "The setting is not registered."),
        0x0000371b: ("ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE", "One or more required members of the transaction are not present."),
        0x0000371c: ("ERROR_SMI_PRIMITIVE_INSTALLER_FAILED", "The SMI primitive installer failed during setup or servicing."),
        0x0000371d: ("ERROR_GENERIC_COMMAND_FAILED", "A generic command executable returned a result that indicates failure."),
        0x0000371e: ("ERROR_SXS_FILE_HASH_MISSING", "A component is missing file verification information in its manifest."),
        0x00003a98: ("ERROR_EVT_INVALID_CHANNEL_PATH", "The specified channel path is invalid."),
        0x00003a99: ("ERROR_EVT_INVALID_QUERY", "The specified query is invalid."),
        0x00003a9a: ("ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND", "The publisher metadata cannot be found in the resource."),
        0x00003a9b: ("ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND", "The template for an event definition cannot be found in the resource (error = %1)."),
        0x00003a9c: ("ERROR_EVT_INVALID_PUBLISHER_NAME", "The specified publisher name is invalid."),
        0x00003a9d: ("ERROR_EVT_INVALID_EVENT_DATA", "The event data raised by the publisher is not compatible with the event template definition in the publisher's manifest"),
        0x00003a9f: ("ERROR_EVT_CHANNEL_NOT_FOUND", "The specified channel could not be found. Check channel configuration."),
        0x00003aa0: ("ERROR_EVT_MALFORMED_XML_TEXT", "The specified xml text was not well-formed. See Extended Error for more details."),
        0x00003aa1: ("ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL", "The caller is trying to subscribe to a direct channel which is not allowed. The events for a direct channel go directly to a logfile and cannot be subscribed to."),
        0x00003aa2: ("ERROR_EVT_CONFIGURATION_ERROR", "Configuration error."),
        0x00003aa3: ("ERROR_EVT_QUERY_RESULT_STALE", "The query result is stale / invalid. This may be due to the log being cleared or rolling over after the query result was created. Users should handle this code by releasing the query result object and reissuing the query."),
        0x00003aa4: ("ERROR_EVT_QUERY_RESULT_INVALID_POSITION", "Query result is currently at an invalid position."),
        0x00003aa5: ("ERROR_EVT_NON_VALIDATING_MSXML", "Registered MSXML doesn't support validation."),
        0x00003aa6: ("ERROR_EVT_FILTER_ALREADYSCOPED", "An expression can only be followed by a change of scope operation if it itself evaluates to a node set and is not already part of some other change of scope operation."),
        0x00003aa7: ("ERROR_EVT_FILTER_NOTELTSET", "Can't perform a step operation from a term that does not represent an element set."),
        0x00003aa8: ("ERROR_EVT_FILTER_INVARG", "Left hand side arguments to binary operators must be either attributes, nodes or variables and right hand side arguments must be constants."),
        0x00003aa9: ("ERROR_EVT_FILTER_INVTEST", "A step operation must involve either a node test or, in the case of a predicate, an algebraic expression against which to test each node in the node set identified by the preceding node set can be evaluated."),
        0x00003aaa: ("ERROR_EVT_FILTER_INVTYPE", "This data type is currently unsupported."),
        0x00003aab: ("ERROR_EVT_FILTER_PARSEERR", "A syntax error occurred at position %1!d!"),
        0x00003aac: ("ERROR_EVT_FILTER_UNSUPPORTEDOP", "This operator is unsupported by this implementation of the filter."),
        0x00003aad: ("ERROR_EVT_FILTER_UNEXPECTEDTOKEN", "The token encountered was unexpected."),
        0x00003aae: ("ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL", "The requested operation cannot be performed over an enabled direct channel. The channel must first be disabled before performing the requested operation."),
        0x00003aaf: ("ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE", "Channel property %1!s! contains invalid value. The value has invalid type, is outside of valid range, can't be updated or is not supported by this type of channel."),
        0x00003ab0: ("ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE", "Publisher property %1!s! contains invalid value. The value has invalid type, is outside of valid range, can't be updated or is not supported by this type of publisher."),
        0x00003ab1: ("ERROR_EVT_CHANNEL_CANNOT_ACTIVATE", "The channel fails to activate."),
        0x00003ab2: ("ERROR_EVT_FILTER_TOO_COMPLEX", "The xpath expression exceeded supported complexity. Please symplify it or split it into two or more simple expressions."),
        0x00003ab3: ("ERROR_EVT_MESSAGE_NOT_FOUND", "the message resource is present but the message is not found in the string/message table"),
        0x00003ab4: ("ERROR_EVT_MESSAGE_ID_NOT_FOUND", "The message id for the desired message could not be found."),
        0x00003ab5: ("ERROR_EVT_UNRESOLVED_VALUE_INSERT", "The substitution string for insert index (%1) could not be found."),
        0x00003ab6: ("ERROR_EVT_UNRESOLVED_PARAMETER_INSERT", "The description string for parameter reference (%1) could not be found."),
        0x00003ab7: ("ERROR_EVT_MAX_INSERTS_REACHED", "The maximum number of replacements has been reached."),
        0x00003ab8: ("ERROR_EVT_EVENT_DEFINITION_NOT_FOUND", "The event definition could not be found for event id (%1)."),
        0x00003ab9: ("ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND", "The locale specific resource for the desired message is not present."),
        0x00003aba: ("ERROR_EVT_VERSION_TOO_OLD", "The resource is too old to be compatible."),
        0x00003abb: ("ERROR_EVT_VERSION_TOO_NEW", "The resource is too new to be compatible."),
        0x00003abc: ("ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY", "The channel at index %1!d! of the query can't be opened."),
        0x00003abd: ("ERROR_EVT_PUBLISHER_DISABLED", "The publisher has been disabled and its resource is not available. This usually occurs when the publisher is in the process of being uninstalled or upgraded."),
        0x00003abe: ("ERROR_EVT_FILTER_OUT_OF_RANGE", "Attempted to create a numeric type that is outside of its valid range."),
        0x00003ae8: ("ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE", "The subscription fails to activate."),
        0x00003ae9: ("ERROR_EC_LOG_DISABLED", "The log of the subscription is in disabled state, and can not be used to forward events to. The log must first be enabled before the subscription can be activated."),
        0x00003aea: ("ERROR_EC_CIRCULAR_FORWARDING", "When forwarding events from local machine to itself, the query of the subscription can't contain target log of the subscription."),
        0x00003aeb: ("ERROR_EC_CREDSTORE_FULL", "The credential store that is used to save credentials is full."),
        0x00003aec: ("ERROR_EC_CRED_NOT_FOUND", "The credential used by this subscription can't be found in credential store."),
        0x00003aed: ("ERROR_EC_NO_ACTIVE_CHANNEL", "No active channel is found for the query."),
        0x00003afc: ("ERROR_MUI_FILE_NOT_FOUND", "The resource loader failed to find MUI file."),
        0x00003afd: ("ERROR_MUI_INVALID_FILE", "The resource loader failed to load MUI file because the file fail to pass validation."),
        0x00003afe: ("ERROR_MUI_INVALID_RC_CONFIG", "The RC Manifest is corrupted with garbage data or unsupported version or missing required item."),
        0x00003aff: ("ERROR_MUI_INVALID_LOCALE_NAME", "The RC Manifest has invalid culture name."),
        0x00003b00: ("ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME", "The RC Manifest has invalid ultimatefallback name."),
        0x00003b01: ("ERROR_MUI_FILE_NOT_LOADED", "The resource loader cache doesn't have loaded MUI entry."),
        0x00003b02: ("ERROR_RESOURCE_ENUM_USER_STOP", "User stopped resource enumeration."),
        0x00003b03: ("ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED", "UI language installation failed."),
        0x00003b04: ("ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME", "Locale installation failed."),
        0x00003b06: ("ERROR_MRM_RUNTIME_NO_DEFAULT_OR_NEUTRAL_RESOURCE", "A resource does not have default or neutral value."),
        0x00003b07: ("ERROR_MRM_INVALID_PRICONFIG", "Invalid PRI config file."),
        0x00003b08: ("ERROR_MRM_INVALID_FILE_TYPE", "Invalid file type."),
        0x00003b09: ("ERROR_MRM_UNKNOWN_QUALIFIER", "Unknown qualifier."),
        0x00003b0a: ("ERROR_MRM_INVALID_QUALIFIER_VALUE", "Invalid qualifier value."),
        0x00003b0b: ("ERROR_MRM_NO_CANDIDATE", "No Candidate found."),
        0x00003b0c: ("ERROR_MRM_NO_MATCH_OR_DEFAULT_CANDIDATE", "The ResourceMap or NamedResource has an item that does not have default or neutral resource.."),
        0x00003b0d: ("ERROR_MRM_RESOURCE_TYPE_MISMATCH", "Invalid ResourceCandidate type."),
        0x00003b0e: ("ERROR_MRM_DUPLICATE_MAP_NAME", "Duplicate Resource Map."),
        0x00003b0f: ("ERROR_MRM_DUPLICATE_ENTRY", "Duplicate Entry."),
        0x00003b10: ("ERROR_MRM_INVALID_RESOURCE_IDENTIFIER", "Invalid Resource Identifier."),
        0x00003b11: ("ERROR_MRM_FILEPATH_TOO_LONG", "Filepath too long."),
        0x00003b12: ("ERROR_MRM_UNSUPPORTED_DIRECTORY_TYPE", "Unsupported directory type."),
        0x00003b16: ("ERROR_MRM_INVALID_PRI_FILE", "Invalid PRI File."),
        0x00003b17: ("ERROR_MRM_NAMED_RESOURCE_NOT_FOUND", "NamedResource Not Found."),
        0x00003b1f: ("ERROR_MRM_MAP_NOT_FOUND", "ResourceMap Not Found."),
        0x00003b20: ("ERROR_MRM_UNSUPPORTED_PROFILE_TYPE", "Unsupported MRT profile type."),
        0x00003b21: ("ERROR_MRM_INVALID_QUALIFIER_OPERATOR", "Invalid qualifier operator."),
        0x00003b22: ("ERROR_MRM_INDETERMINATE_QUALIFIER_VALUE", "Unable to determine qualifier value or qualifier value has not been set."),
        0x00003b23: ("ERROR_MRM_AUTOMERGE_ENABLED", "Automerge is enabled in the PRI file."),
        0x00003b24: ("ERROR_MRM_TOO_MANY_RESOURCES", "Too many resources defined for package."),
        0x00003b60: ("ERROR_MCA_INVALID_CAPABILITIES_STRING", "The monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1 or MCCS 2 Revision 1 specification."),
        0x00003b61: ("ERROR_MCA_INVALID_VCP_VERSION", "The monitor's VCP Version (0xDF) VCP code returned an invalid version value."),
        0x00003b62: ("ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION", "The monitor does not comply with the MCCS specification it claims to support."),
        0x00003b63: ("ERROR_MCA_MCCS_VERSION_MISMATCH", "The MCCS version in a monitor's mccs_ver capability does not match the MCCS version the monitor reports when the VCP Version (0xDF) VCP code is used."),
        0x00003b64: ("ERROR_MCA_UNSUPPORTED_MCCS_VERSION", "The Monitor Configuration API only works with monitors that support the MCCS 1.0 specification, MCCS 2.0 specification or the MCCS 2.0 Revision 1 specification."),
        0x00003b65: ("ERROR_MCA_INTERNAL_ERROR", "An internal Monitor Configuration API error occurred."),
        0x00003b66: ("ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED", "The monitor returned an invalid monitor technology type. CRT, Plasma and LCD (TFT) are examples of monitor technology types. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification."),
        0x00003b67: ("ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE", "The caller of SetMonitorColorTemperature specified a color temperature that the current monitor did not support. This error implies that the monitor violated the MCCS 2.0 or MCCS 2.0 Revision 1 specification."),
        0x00003b92: ("ERROR_AMBIGUOUS_SYSTEM_DEVICE", "The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria."),
        0x00003bc3: ("ERROR_SYSTEM_DEVICE_NOT_FOUND", "The requested system device cannot be found."),
        0x00003bc4: ("ERROR_HASH_NOT_SUPPORTED", "Hash generation for the specified hash version and hash type is not enabled on the server."),
        0x00003bc5: ("ERROR_HASH_NOT_PRESENT", "The hash requested from the server is not available or no longer valid."),
        0x00003bd9: ("ERROR_SECONDARY_IC_PROVIDER_NOT_REGISTERED", "The secondary interrupt controller instance that manages the specified interrupt is not registered."),
        0x00003bda: ("ERROR_GPIO_CLIENT_INFORMATION_INVALID", "The information supplied by the GPIO client driver is invalid."),
        0x00003bdb: ("ERROR_GPIO_VERSION_NOT_SUPPORTED", "The version specified by the GPIO client driver is not supported."),
        0x00003bdc: ("ERROR_GPIO_INVALID_REGISTRATION_PACKET", "The registration packet supplied by the GPIO client driver is not valid."),
        0x00003bdd: ("ERROR_GPIO_OPERATION_DENIED", "The requested operation is not supported for the specified handle."),
        0x00003bde: ("ERROR_GPIO_INCOMPATIBLE_CONNECT_MODE", "The requested connect mode conflicts with an existing mode on one or more of the specified pins."),
        0x00003bdf: ("ERROR_GPIO_INTERRUPT_ALREADY_UNMASKED", "The interrupt requested to be unmasked is not masked."),
        0x00003c28: ("ERROR_CANNOT_SWITCH_RUNLEVEL", "The requested run level switch cannot be completed successfully."),
        0x00003c29: ("ERROR_INVALID_RUNLEVEL_SETTING", "The service has an invalid run level setting. The run level for a service"),
        0x00003c2a: ("ERROR_RUNLEVEL_SWITCH_TIMEOUT", "The requested run level switch cannot be completed successfully since"),
        0x00003c2b: ("ERROR_RUNLEVEL_SWITCH_AGENT_TIMEOUT", "A run level switch agent did not respond within the specified timeout."),
        0x00003c2c: ("ERROR_RUNLEVEL_SWITCH_IN_PROGRESS", "A run level switch is currently in progress."),
        0x00003c2d: ("ERROR_SERVICES_FAILED_AUTOSTART", "One or more services failed to start during the service startup phase of a run level switch."),
        0x00003c8d: ("ERROR_COM_TASK_STOP_PENDING", "The task stop request cannot be completed immediately since"),
        0x00003cf0: ("ERROR_INSTALL_OPEN_PACKAGE_FAILED", "Package could not be opened."),
        0x00003cf1: ("ERROR_INSTALL_PACKAGE_NOT_FOUND", "Package was not found."),
        0x00003cf2: ("ERROR_INSTALL_INVALID_PACKAGE", "Package data is invalid."),
        0x00003cf3: ("ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED", "Package failed updates, dependency or conflict validation."),
        0x00003cf4: ("ERROR_INSTALL_OUT_OF_DISK_SPACE", "There is not enough disk space on your computer. Please free up some space and try again."),
        0x00003cf5: ("ERROR_INSTALL_NETWORK_FAILURE", "There was a problem downloading your product."),
        0x00003cf6: ("ERROR_INSTALL_REGISTRATION_FAILURE", "Package could not be registered."),
        0x00003cf7: ("ERROR_INSTALL_DEREGISTRATION_FAILURE", "Package could not be unregistered."),
        0x00003cf8: ("ERROR_INSTALL_CANCEL", "User cancelled the install request."),
        0x00003cf9: ("ERROR_INSTALL_FAILED", "Install failed. Please contact your software vendor."),
        0x00003cfa: ("ERROR_REMOVE_FAILED", "Removal failed. Please contact your software vendor."),
        0x00003cfb: ("ERROR_PACKAGE_ALREADY_EXISTS", "The provided package is already installed, and reinstallation of the package was blocked. Check the AppXDeployment-Server event log for details."),
        0x00003cfc: ("ERROR_NEEDS_REMEDIATION", "The application cannot be started. Try reinstalling the application to fix the problem."),
        0x00003cfd: ("ERROR_INSTALL_PREREQUISITE_FAILED", "A Prerequisite for an install could not be satisfied."),
        0x00003cfe: ("ERROR_PACKAGE_REPOSITORY_CORRUPTED", "The package repository is corrupted."),
        0x00003cff: ("ERROR_INSTALL_POLICY_FAILURE", "To install this application you need either a Windows developer license or a sideloading-enabled system."),
        0x00003d00: ("ERROR_PACKAGE_UPDATING", "The application cannot be started because it is currently updating."),
        0x00003d01: ("ERROR_DEPLOYMENT_BLOCKED_BY_POLICY", "The package deployment operation is blocked by policy. Please contact your system administrator."),
        0x00003d02: ("ERROR_PACKAGES_IN_USE", "The package could not be installed because resources it modifies are currently in use."),
        0x00003d03: ("ERROR_RECOVERY_FILE_CORRUPT", "The package could not be recovered because necessary data for recovery have been corrupted."),
        0x00003d04: ("ERROR_INVALID_STAGED_SIGNATURE", "The signature is invalid. To register in developer mode, AppxSignature.p7x and AppxBlockMap.xml must be valid or should not be present."),
        0x00003d05: ("ERROR_DELETING_EXISTING_APPLICATIONDATA_STORE_FAILED", "An error occurred while deleting the package's previously existing application data."),
        0x00003d06: ("ERROR_INSTALL_PACKAGE_DOWNGRADE", "The package could not be installed because a higher version of this package is already installed."),
        0x00003d07: ("ERROR_SYSTEM_NEEDS_REMEDIATION", "An error in a system binary was detected. Try refreshing the PC to fix the problem."),
        0x00003d08: ("ERROR_APPX_INTEGRITY_FAILURE_CLR_NGEN", "A corrupted CLR NGEN binary was detected on the system."),
        0x00003d09: ("ERROR_RESILIENCY_FILE_CORRUPT", "The operation could not be resumed because necessary data for recovery have been corrupted."),
        0x00003d0a: ("ERROR_INSTALL_FIREWALL_SERVICE_NOT_RUNNING", "The package could not be installed because the Windows Firewall service is not running. Enable the Windows Firewall service and try again."),
        0x00003d54: ("APPMODEL_ERROR_NO_PACKAGE", "The process has no package identity."),
        0x00003d55: ("APPMODEL_ERROR_PACKAGE_RUNTIME_CORRUPT", "The package runtime information is corrupted."),
        0x00003d56: ("APPMODEL_ERROR_PACKAGE_IDENTITY_CORRUPT", "The package identity is corrupted."),
        0x00003d57: ("APPMODEL_ERROR_NO_APPLICATION", "The process has no application identity."),
        0x00003db8: ("ERROR_STATE_LOAD_STORE_FAILED", "Loading the state store failed."),
        0x00003db9: ("ERROR_STATE_GET_VERSION_FAILED", "Retrieving the state version for the application failed."),
        0x00003dba: ("ERROR_STATE_SET_VERSION_FAILED", "Setting the state version for the application failed."),
        0x00003dbb: ("ERROR_STATE_STRUCTURED_RESET_FAILED", "Resetting the structured state of the application failed."),
        0x00003dbc: ("ERROR_STATE_OPEN_CONTAINER_FAILED", "State Manager failed to open the container."),
        0x00003dbd: ("ERROR_STATE_CREATE_CONTAINER_FAILED", "State Manager failed to create the container."),
        0x00003dbe: ("ERROR_STATE_DELETE_CONTAINER_FAILED", "State Manager failed to delete the container."),
        0x00003dbf: ("ERROR_STATE_READ_SETTING_FAILED", "State Manager failed to read the setting."),
        0x00003dc0: ("ERROR_STATE_WRITE_SETTING_FAILED", "State Manager failed to write the setting."),
        0x00003dc1: ("ERROR_STATE_DELETE_SETTING_FAILED", "State Manager failed to delete the setting."),
        0x00003dc2: ("ERROR_STATE_QUERY_SETTING_FAILED", "State Manager failed to query the setting."),
        0x00003dc3: ("ERROR_STATE_READ_COMPOSITE_SETTING_FAILED", "State Manager failed to read the composite setting."),
        0x00003dc4: ("ERROR_STATE_WRITE_COMPOSITE_SETTING_FAILED", "State Manager failed to write the composite setting."),
        0x00003dc5: ("ERROR_STATE_ENUMERATE_CONTAINER_FAILED", "State Manager failed to enumerate the containers."),
        0x00003dc6: ("ERROR_STATE_ENUMERATE_SETTINGS_FAILED", "State Manager failed to enumerate the settings."),
        0x00003dc7: ("ERROR_STATE_COMPOSITE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED", "The size of the state manager composite setting value has exceeded the limit."),
        0x00003dc8: ("ERROR_STATE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED", "The size of the state manager setting value has exceeded the limit."),
        0x00003dc9: ("ERROR_STATE_SETTING_NAME_SIZE_LIMIT_EXCEEDED", "The length of the state manager setting name has exceeded the limit."),
        0x00003dca: ("ERROR_STATE_CONTAINER_NAME_SIZE_LIMIT_EXCEEDED", "The length of the state manager container name has exceeded the limit."),
        0x00003de1: ("ERROR_API_UNAVAILABLE", "This API cannot be used in the context of the caller's application type."),
        0x00003df5: ("STORE_ERROR_UNLICENSED", "This PC does not have a valid license for the application or product."),
        0x00003df6: ("STORE_ERROR_UNLICENSED_USER", "The authenticated user does not have a valid license for the application or product."),
}


# Error Codes

ERROR_SUCCESS                                                            = 0x00000000
ERROR_INVALID_FUNCTION                                                   = 0x00000001
ERROR_FILE_NOT_FOUND                                                     = 0x00000002
ERROR_PATH_NOT_FOUND                                                     = 0x00000003
ERROR_TOO_MANY_OPEN_FILES                                                = 0x00000004
ERROR_ACCESS_DENIED                                                      = 0x00000005
ERROR_INVALID_HANDLE                                                     = 0x00000006
ERROR_ARENA_TRASHED                                                      = 0x00000007
ERROR_NOT_ENOUGH_MEMORY                                                  = 0x00000008
ERROR_INVALID_BLOCK                                                      = 0x00000009
ERROR_BAD_ENVIRONMENT                                                    = 0x0000000a
ERROR_BAD_FORMAT                                                         = 0x0000000b
ERROR_INVALID_ACCESS                                                     = 0x0000000c
ERROR_INVALID_DATA                                                       = 0x0000000d
ERROR_OUTOFMEMORY                                                        = 0x0000000e
ERROR_INVALID_DRIVE                                                      = 0x0000000f
ERROR_CURRENT_DIRECTORY                                                  = 0x00000010
ERROR_NOT_SAME_DEVICE                                                    = 0x00000011
ERROR_NO_MORE_FILES                                                      = 0x00000012
ERROR_WRITE_PROTECT                                                      = 0x00000013
ERROR_BAD_UNIT                                                           = 0x00000014
ERROR_NOT_READY                                                          = 0x00000015
ERROR_BAD_COMMAND                                                        = 0x00000016
ERROR_CRC                                                                = 0x00000017
ERROR_BAD_LENGTH                                                         = 0x00000018
ERROR_SEEK                                                               = 0x00000019
ERROR_NOT_DOS_DISK                                                       = 0x0000001a
ERROR_SECTOR_NOT_FOUND                                                   = 0x0000001b
ERROR_OUT_OF_PAPER                                                       = 0x0000001c
ERROR_WRITE_FAULT                                                        = 0x0000001d
ERROR_READ_FAULT                                                         = 0x0000001e
ERROR_GEN_FAILURE                                                        = 0x0000001f
ERROR_SHARING_VIOLATION                                                  = 0x00000020
ERROR_LOCK_VIOLATION                                                     = 0x00000021
ERROR_WRONG_DISK                                                         = 0x00000022
ERROR_SHARING_BUFFER_EXCEEDED                                            = 0x00000024
ERROR_HANDLE_EOF                                                         = 0x00000026
ERROR_HANDLE_DISK_FULL                                                   = 0x00000027
ERROR_NOT_SUPPORTED                                                      = 0x00000032
ERROR_REM_NOT_LIST                                                       = 0x00000033
ERROR_DUP_NAME                                                           = 0x00000034
ERROR_BAD_NETPATH                                                        = 0x00000035
ERROR_NETWORK_BUSY                                                       = 0x00000036
ERROR_DEV_NOT_EXIST                                                      = 0x00000037
ERROR_TOO_MANY_CMDS                                                      = 0x00000038
ERROR_ADAP_HDW_ERR                                                       = 0x00000039
ERROR_BAD_NET_RESP                                                       = 0x0000003a
ERROR_UNEXP_NET_ERR                                                      = 0x0000003b
ERROR_BAD_REM_ADAP                                                       = 0x0000003c
ERROR_PRINTQ_FULL                                                        = 0x0000003d
ERROR_NO_SPOOL_SPACE                                                     = 0x0000003e
ERROR_PRINT_CANCELLED                                                    = 0x0000003f
ERROR_NETNAME_DELETED                                                    = 0x00000040
ERROR_NETWORK_ACCESS_DENIED                                              = 0x00000041
ERROR_BAD_DEV_TYPE                                                       = 0x00000042
ERROR_BAD_NET_NAME                                                       = 0x00000043
ERROR_TOO_MANY_NAMES                                                     = 0x00000044
ERROR_TOO_MANY_SESS                                                      = 0x00000045
ERROR_SHARING_PAUSED                                                     = 0x00000046
ERROR_REQ_NOT_ACCEP                                                      = 0x00000047
ERROR_REDIR_PAUSED                                                       = 0x00000048
ERROR_FILE_EXISTS                                                        = 0x00000050
ERROR_CANNOT_MAKE                                                        = 0x00000052
ERROR_FAIL_I24                                                           = 0x00000053
ERROR_OUT_OF_STRUCTURES                                                  = 0x00000054
ERROR_ALREADY_ASSIGNED                                                   = 0x00000055
ERROR_INVALID_PASSWORD                                                   = 0x00000056
ERROR_INVALID_PARAMETER                                                  = 0x00000057
ERROR_NET_WRITE_FAULT                                                    = 0x00000058
ERROR_NO_PROC_SLOTS                                                      = 0x00000059
ERROR_TOO_MANY_SEMAPHORES                                                = 0x00000064
ERROR_EXCL_SEM_ALREADY_OWNED                                             = 0x00000065
ERROR_SEM_IS_SET                                                         = 0x00000066
ERROR_TOO_MANY_SEM_REQUESTS                                              = 0x00000067
ERROR_INVALID_AT_INTERRUPT_TIME                                          = 0x00000068
ERROR_SEM_OWNER_DIED                                                     = 0x00000069
ERROR_SEM_USER_LIMIT                                                     = 0x0000006a
ERROR_DISK_CHANGE                                                        = 0x0000006b
ERROR_DRIVE_LOCKED                                                       = 0x0000006c
ERROR_BROKEN_PIPE                                                        = 0x0000006d
ERROR_OPEN_FAILED                                                        = 0x0000006e
ERROR_BUFFER_OVERFLOW                                                    = 0x0000006f
ERROR_DISK_FULL                                                          = 0x00000070
ERROR_NO_MORE_SEARCH_HANDLES                                             = 0x00000071
ERROR_INVALID_TARGET_HANDLE                                              = 0x00000072
ERROR_INVALID_CATEGORY                                                   = 0x00000075
ERROR_INVALID_VERIFY_SWITCH                                              = 0x00000076
ERROR_BAD_DRIVER_LEVEL                                                   = 0x00000077
ERROR_CALL_NOT_IMPLEMENTED                                               = 0x00000078
ERROR_SEM_TIMEOUT                                                        = 0x00000079
ERROR_INSUFFICIENT_BUFFER                                                = 0x0000007a
ERROR_INVALID_NAME                                                       = 0x0000007b
ERROR_INVALID_LEVEL                                                      = 0x0000007c
ERROR_NO_VOLUME_LABEL                                                    = 0x0000007d
ERROR_MOD_NOT_FOUND                                                      = 0x0000007e
ERROR_PROC_NOT_FOUND                                                     = 0x0000007f
ERROR_WAIT_NO_CHILDREN                                                   = 0x00000080
ERROR_CHILD_NOT_COMPLETE                                                 = 0x00000081
ERROR_DIRECT_ACCESS_HANDLE                                               = 0x00000082
ERROR_NEGATIVE_SEEK                                                      = 0x00000083
ERROR_SEEK_ON_DEVICE                                                     = 0x00000084
ERROR_IS_JOIN_TARGET                                                     = 0x00000085
ERROR_IS_JOINED                                                          = 0x00000086
ERROR_IS_SUBSTED                                                         = 0x00000087
ERROR_NOT_JOINED                                                         = 0x00000088
ERROR_NOT_SUBSTED                                                        = 0x00000089
ERROR_JOIN_TO_JOIN                                                       = 0x0000008a
ERROR_SUBST_TO_SUBST                                                     = 0x0000008b
ERROR_JOIN_TO_SUBST                                                      = 0x0000008c
ERROR_SUBST_TO_JOIN                                                      = 0x0000008d
ERROR_BUSY_DRIVE                                                         = 0x0000008e
ERROR_SAME_DRIVE                                                         = 0x0000008f
ERROR_DIR_NOT_ROOT                                                       = 0x00000090
ERROR_DIR_NOT_EMPTY                                                      = 0x00000091
ERROR_IS_SUBST_PATH                                                      = 0x00000092
ERROR_IS_JOIN_PATH                                                       = 0x00000093
ERROR_PATH_BUSY                                                          = 0x00000094
ERROR_IS_SUBST_TARGET                                                    = 0x00000095
ERROR_SYSTEM_TRACE                                                       = 0x00000096
ERROR_INVALID_EVENT_COUNT                                                = 0x00000097
ERROR_TOO_MANY_MUXWAITERS                                                = 0x00000098
ERROR_INVALID_LIST_FORMAT                                                = 0x00000099
ERROR_LABEL_TOO_LONG                                                     = 0x0000009a
ERROR_TOO_MANY_TCBS                                                      = 0x0000009b
ERROR_SIGNAL_REFUSED                                                     = 0x0000009c
ERROR_DISCARDED                                                          = 0x0000009d
ERROR_NOT_LOCKED                                                         = 0x0000009e
ERROR_BAD_THREADID_ADDR                                                  = 0x0000009f
ERROR_BAD_ARGUMENTS                                                      = 0x000000a0
ERROR_BAD_PATHNAME                                                       = 0x000000a1
ERROR_SIGNAL_PENDING                                                     = 0x000000a2
ERROR_MAX_THRDS_REACHED                                                  = 0x000000a4
ERROR_LOCK_FAILED                                                        = 0x000000a7
ERROR_BUSY                                                               = 0x000000aa
ERROR_DEVICE_SUPPORT_IN_PROGRESS                                         = 0x000000ab
ERROR_CANCEL_VIOLATION                                                   = 0x000000ad
ERROR_ATOMIC_LOCKS_NOT_SUPPORTED                                         = 0x000000ae
ERROR_INVALID_SEGMENT_NUMBER                                             = 0x000000b4
ERROR_INVALID_ORDINAL                                                    = 0x000000b6
ERROR_ALREADY_EXISTS                                                     = 0x000000b7
ERROR_INVALID_FLAG_NUMBER                                                = 0x000000ba
ERROR_SEM_NOT_FOUND                                                      = 0x000000bb
ERROR_INVALID_STARTING_CODESEG                                           = 0x000000bc
ERROR_INVALID_STACKSEG                                                   = 0x000000bd
ERROR_INVALID_MODULETYPE                                                 = 0x000000be
ERROR_INVALID_EXE_SIGNATURE                                              = 0x000000bf
ERROR_EXE_MARKED_INVALID                                                 = 0x000000c0
ERROR_BAD_EXE_FORMAT                                                     = 0x000000c1
ERROR_ITERATED_DATA_EXCEEDS_64k                                          = 0x000000c2
ERROR_INVALID_MINALLOCSIZE                                               = 0x000000c3
ERROR_DYNLINK_FROM_INVALID_RING                                          = 0x000000c4
ERROR_IOPL_NOT_ENABLED                                                   = 0x000000c5
ERROR_INVALID_SEGDPL                                                     = 0x000000c6
ERROR_AUTODATASEG_EXCEEDS_64k                                            = 0x000000c7
ERROR_RING2SEG_MUST_BE_MOVABLE                                           = 0x000000c8
ERROR_RELOC_CHAIN_XEEDS_SEGLIM                                           = 0x000000c9
ERROR_INFLOOP_IN_RELOC_CHAIN                                             = 0x000000ca
ERROR_ENVVAR_NOT_FOUND                                                   = 0x000000cb
ERROR_NO_SIGNAL_SENT                                                     = 0x000000cd
ERROR_FILENAME_EXCED_RANGE                                               = 0x000000ce
ERROR_RING2_STACK_IN_USE                                                 = 0x000000cf
ERROR_META_EXPANSION_TOO_LONG                                            = 0x000000d0
ERROR_INVALID_SIGNAL_NUMBER                                              = 0x000000d1
ERROR_THREAD_1_INACTIVE                                                  = 0x000000d2
ERROR_LOCKED                                                             = 0x000000d4
ERROR_TOO_MANY_MODULES                                                   = 0x000000d6
ERROR_NESTING_NOT_ALLOWED                                                = 0x000000d7
ERROR_EXE_MACHINE_TYPE_MISMATCH                                          = 0x000000d8
ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY                                    = 0x000000d9
ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY                             = 0x000000da
ERROR_FILE_CHECKED_OUT                                                   = 0x000000dc
ERROR_CHECKOUT_REQUIRED                                                  = 0x000000dd
ERROR_BAD_FILE_TYPE                                                      = 0x000000de
ERROR_FILE_TOO_LARGE                                                     = 0x000000df
ERROR_FORMS_AUTH_REQUIRED                                                = 0x000000e0
ERROR_VIRUS_INFECTED                                                     = 0x000000e1
ERROR_VIRUS_DELETED                                                      = 0x000000e2
ERROR_PIPE_LOCAL                                                         = 0x000000e5
ERROR_BAD_PIPE                                                           = 0x000000e6
ERROR_PIPE_BUSY                                                          = 0x000000e7
ERROR_NO_DATA                                                            = 0x000000e8
ERROR_PIPE_NOT_CONNECTED                                                 = 0x000000e9
ERROR_MORE_DATA                                                          = 0x000000ea
ERROR_VC_DISCONNECTED                                                    = 0x000000f0
ERROR_INVALID_EA_NAME                                                    = 0x000000fe
ERROR_EA_LIST_INCONSISTENT                                               = 0x000000ff
WAIT_TIMEOUT                                                             = 0x00000102
ERROR_NO_MORE_ITEMS                                                      = 0x00000103
ERROR_CANNOT_COPY                                                        = 0x0000010a
ERROR_DIRECTORY                                                          = 0x0000010b
ERROR_EAS_DIDNT_FIT                                                      = 0x00000113
ERROR_EA_FILE_CORRUPT                                                    = 0x00000114
ERROR_EA_TABLE_FULL                                                      = 0x00000115
ERROR_INVALID_EA_HANDLE                                                  = 0x00000116
ERROR_EAS_NOT_SUPPORTED                                                  = 0x0000011a
ERROR_NOT_OWNER                                                          = 0x00000120
ERROR_TOO_MANY_POSTS                                                     = 0x0000012a
ERROR_PARTIAL_COPY                                                       = 0x0000012b
ERROR_OPLOCK_NOT_GRANTED                                                 = 0x0000012c
ERROR_INVALID_OPLOCK_PROTOCOL                                            = 0x0000012d
ERROR_DISK_TOO_FRAGMENTED                                                = 0x0000012e
ERROR_DELETE_PENDING                                                     = 0x0000012f
ERROR_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING               = 0x00000130
ERROR_SHORT_NAMES_NOT_ENABLED_ON_VOLUME                                  = 0x00000131
ERROR_SECURITY_STREAM_IS_INCONSISTENT                                    = 0x00000132
ERROR_INVALID_LOCK_RANGE                                                 = 0x00000133
ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT                                        = 0x00000134
ERROR_NOTIFICATION_GUID_ALREADY_DEFINED                                  = 0x00000135
ERROR_INVALID_EXCEPTION_HANDLER                                          = 0x00000136
ERROR_DUPLICATE_PRIVILEGES                                               = 0x00000137
ERROR_NO_RANGES_PROCESSED                                                = 0x00000138
ERROR_NOT_ALLOWED_ON_SYSTEM_FILE                                         = 0x00000139
ERROR_DISK_RESOURCES_EXHAUSTED                                           = 0x0000013a
ERROR_INVALID_TOKEN                                                      = 0x0000013b
ERROR_DEVICE_FEATURE_NOT_SUPPORTED                                       = 0x0000013c
ERROR_MR_MID_NOT_FOUND                                                   = 0x0000013d
ERROR_SCOPE_NOT_FOUND                                                    = 0x0000013e
ERROR_UNDEFINED_SCOPE                                                    = 0x0000013f
ERROR_INVALID_CAP                                                        = 0x00000140
ERROR_DEVICE_UNREACHABLE                                                 = 0x00000141
ERROR_DEVICE_NO_RESOURCES                                                = 0x00000142
ERROR_DATA_CHECKSUM_ERROR                                                = 0x00000143
ERROR_INTERMIXED_KERNEL_EA_OPERATION                                     = 0x00000144
ERROR_FILE_LEVEL_TRIM_NOT_SUPPORTED                                      = 0x00000146
ERROR_OFFSET_ALIGNMENT_VIOLATION                                         = 0x00000147
ERROR_INVALID_FIELD_IN_PARAMETER_LIST                                    = 0x00000148
ERROR_OPERATION_IN_PROGRESS                                              = 0x00000149
ERROR_BAD_DEVICE_PATH                                                    = 0x0000014a
ERROR_TOO_MANY_DESCRIPTORS                                               = 0x0000014b
ERROR_SCRUB_DATA_DISABLED                                                = 0x0000014c
ERROR_NOT_REDUNDANT_STORAGE                                              = 0x0000014d
ERROR_RESIDENT_FILE_NOT_SUPPORTED                                        = 0x0000014e
ERROR_COMPRESSED_FILE_NOT_SUPPORTED                                      = 0x0000014f
ERROR_DIRECTORY_NOT_SUPPORTED                                            = 0x00000150
ERROR_NOT_READ_FROM_COPY                                                 = 0x00000151
ERROR_FT_WRITE_FAILURE                                                   = 0x00000152
ERROR_FT_DI_SCAN_REQUIRED                                                = 0x00000153
ERROR_INVALID_KERNEL_INFO_VERSION                                        = 0x00000154
ERROR_INVALID_PEP_INFO_VERSION                                           = 0x00000155
ERROR_FAIL_NOACTION_REBOOT                                               = 0x0000015e
ERROR_FAIL_SHUTDOWN                                                      = 0x0000015f
ERROR_FAIL_RESTART                                                       = 0x00000160
ERROR_MAX_SESSIONS_REACHED                                               = 0x00000161
ERROR_THREAD_MODE_ALREADY_BACKGROUND                                     = 0x00000190
ERROR_THREAD_MODE_NOT_BACKGROUND                                         = 0x00000191
ERROR_PROCESS_MODE_ALREADY_BACKGROUND                                    = 0x00000192
ERROR_PROCESS_MODE_NOT_BACKGROUND                                        = 0x00000193
ERROR_INVALID_ADDRESS                                                    = 0x000001e7
ERROR_USER_PROFILE_LOAD                                                  = 0x000001f4
ERROR_ARITHMETIC_OVERFLOW                                                = 0x00000216
ERROR_PIPE_CONNECTED                                                     = 0x00000217
ERROR_PIPE_LISTENING                                                     = 0x00000218
ERROR_VERIFIER_STOP                                                      = 0x00000219
ERROR_ABIOS_ERROR                                                        = 0x0000021a
ERROR_WX86_WARNING                                                       = 0x0000021b
ERROR_WX86_ERROR                                                         = 0x0000021c
ERROR_TIMER_NOT_CANCELED                                                 = 0x0000021d
ERROR_UNWIND                                                             = 0x0000021e
ERROR_BAD_STACK                                                          = 0x0000021f
ERROR_INVALID_UNWIND_TARGET                                              = 0x00000220
ERROR_INVALID_PORT_ATTRIBUTES                                            = 0x00000221
ERROR_PORT_MESSAGE_TOO_LONG                                              = 0x00000222
ERROR_INVALID_QUOTA_LOWER                                                = 0x00000223
ERROR_DEVICE_ALREADY_ATTACHED                                            = 0x00000224
ERROR_INSTRUCTION_MISALIGNMENT                                           = 0x00000225
ERROR_PROFILING_NOT_STARTED                                              = 0x00000226
ERROR_PROFILING_NOT_STOPPED                                              = 0x00000227
ERROR_COULD_NOT_INTERPRET                                                = 0x00000228
ERROR_PROFILING_AT_LIMIT                                                 = 0x00000229
ERROR_CANT_WAIT                                                          = 0x0000022a
ERROR_CANT_TERMINATE_SELF                                                = 0x0000022b
ERROR_UNEXPECTED_MM_CREATE_ERR                                           = 0x0000022c
ERROR_UNEXPECTED_MM_MAP_ERROR                                            = 0x0000022d
ERROR_UNEXPECTED_MM_EXTEND_ERR                                           = 0x0000022e
ERROR_BAD_FUNCTION_TABLE                                                 = 0x0000022f
ERROR_NO_GUID_TRANSLATION                                                = 0x00000230
ERROR_INVALID_LDT_SIZE                                                   = 0x00000231
ERROR_INVALID_LDT_OFFSET                                                 = 0x00000233
ERROR_INVALID_LDT_DESCRIPTOR                                             = 0x00000234
ERROR_TOO_MANY_THREADS                                                   = 0x00000235
ERROR_THREAD_NOT_IN_PROCESS                                              = 0x00000236
ERROR_PAGEFILE_QUOTA_EXCEEDED                                            = 0x00000237
ERROR_LOGON_SERVER_CONFLICT                                              = 0x00000238
ERROR_SYNCHRONIZATION_REQUIRED                                           = 0x00000239
ERROR_NET_OPEN_FAILED                                                    = 0x0000023a
ERROR_IO_PRIVILEGE_FAILED                                                = 0x0000023b
ERROR_CONTROL_C_EXIT                                                     = 0x0000023c
ERROR_MISSING_SYSTEMFILE                                                 = 0x0000023d
ERROR_UNHANDLED_EXCEPTION                                                = 0x0000023e
ERROR_APP_INIT_FAILURE                                                   = 0x0000023f
ERROR_PAGEFILE_CREATE_FAILED                                             = 0x00000240
ERROR_INVALID_IMAGE_HASH                                                 = 0x00000241
ERROR_NO_PAGEFILE                                                        = 0x00000242
ERROR_ILLEGAL_FLOAT_CONTEXT                                              = 0x00000243
ERROR_NO_EVENT_PAIR                                                      = 0x00000244
ERROR_DOMAIN_CTRLR_CONFIG_ERROR                                          = 0x00000245
ERROR_ILLEGAL_CHARACTER                                                  = 0x00000246
ERROR_UNDEFINED_CHARACTER                                                = 0x00000247
ERROR_FLOPPY_VOLUME                                                      = 0x00000248
ERROR_BIOS_FAILED_TO_CONNECT_INTERRUPT                                   = 0x00000249
ERROR_BACKUP_CONTROLLER                                                  = 0x0000024a
ERROR_MUTANT_LIMIT_EXCEEDED                                              = 0x0000024b
ERROR_FS_DRIVER_REQUIRED                                                 = 0x0000024c
ERROR_CANNOT_LOAD_REGISTRY_FILE                                          = 0x0000024d
ERROR_DEBUG_ATTACH_FAILED                                                = 0x0000024e
ERROR_SYSTEM_PROCESS_TERMINATED                                          = 0x0000024f
ERROR_DATA_NOT_ACCEPTED                                                  = 0x00000250
ERROR_VDM_HARD_ERROR                                                     = 0x00000251
ERROR_DRIVER_CANCEL_TIMEOUT                                              = 0x00000252
ERROR_REPLY_MESSAGE_MISMATCH                                             = 0x00000253
ERROR_LOST_WRITEBEHIND_DATA                                              = 0x00000254
ERROR_CLIENT_SERVER_PARAMETERS_INVALID                                   = 0x00000255
ERROR_NOT_TINY_STREAM                                                    = 0x00000256
ERROR_STACK_OVERFLOW_READ                                                = 0x00000257
ERROR_CONVERT_TO_LARGE                                                   = 0x00000258
ERROR_FOUND_OUT_OF_SCOPE                                                 = 0x00000259
ERROR_ALLOCATE_BUCKET                                                    = 0x0000025a
ERROR_MARSHALL_OVERFLOW                                                  = 0x0000025b
ERROR_INVALID_VARIANT                                                    = 0x0000025c
ERROR_BAD_COMPRESSION_BUFFER                                             = 0x0000025d
ERROR_AUDIT_FAILED                                                       = 0x0000025e
ERROR_TIMER_RESOLUTION_NOT_SET                                           = 0x0000025f
ERROR_INSUFFICIENT_LOGON_INFO                                            = 0x00000260
ERROR_BAD_DLL_ENTRYPOINT                                                 = 0x00000261
ERROR_BAD_SERVICE_ENTRYPOINT                                             = 0x00000262
ERROR_IP_ADDRESS_CONFLICT1                                               = 0x00000263
ERROR_IP_ADDRESS_CONFLICT2                                               = 0x00000264
ERROR_REGISTRY_QUOTA_LIMIT                                               = 0x00000265
ERROR_NO_CALLBACK_ACTIVE                                                 = 0x00000266
ERROR_PWD_TOO_SHORT                                                      = 0x00000267
ERROR_PWD_TOO_RECENT                                                     = 0x00000268
ERROR_PWD_HISTORY_CONFLICT                                               = 0x00000269
ERROR_UNSUPPORTED_COMPRESSION                                            = 0x0000026a
ERROR_INVALID_HW_PROFILE                                                 = 0x0000026b
ERROR_INVALID_PLUGPLAY_DEVICE_PATH                                       = 0x0000026c
ERROR_QUOTA_LIST_INCONSISTENT                                            = 0x0000026d
ERROR_EVALUATION_EXPIRATION                                              = 0x0000026e
ERROR_ILLEGAL_DLL_RELOCATION                                             = 0x0000026f
ERROR_DLL_INIT_FAILED_LOGOFF                                             = 0x00000270
ERROR_VALIDATE_CONTINUE                                                  = 0x00000271
ERROR_NO_MORE_MATCHES                                                    = 0x00000272
ERROR_RANGE_LIST_CONFLICT                                                = 0x00000273
ERROR_SERVER_SID_MISMATCH                                                = 0x00000274
ERROR_CANT_ENABLE_DENY_ONLY                                              = 0x00000275
ERROR_FLOAT_MULTIPLE_FAULTS                                              = 0x00000276
ERROR_FLOAT_MULTIPLE_TRAPS                                               = 0x00000277
ERROR_NOINTERFACE                                                        = 0x00000278
ERROR_DRIVER_FAILED_SLEEP                                                = 0x00000279
ERROR_CORRUPT_SYSTEM_FILE                                                = 0x0000027a
ERROR_COMMITMENT_MINIMUM                                                 = 0x0000027b
ERROR_PNP_RESTART_ENUMERATION                                            = 0x0000027c
ERROR_SYSTEM_IMAGE_BAD_SIGNATURE                                         = 0x0000027d
ERROR_PNP_REBOOT_REQUIRED                                                = 0x0000027e
ERROR_INSUFFICIENT_POWER                                                 = 0x0000027f
ERROR_MULTIPLE_FAULT_VIOLATION                                           = 0x00000280
ERROR_SYSTEM_SHUTDOWN                                                    = 0x00000281
ERROR_PORT_NOT_SET                                                       = 0x00000282
ERROR_DS_VERSION_CHECK_FAILURE                                           = 0x00000283
ERROR_RANGE_NOT_FOUND                                                    = 0x00000284
ERROR_NOT_SAFE_MODE_DRIVER                                               = 0x00000286
ERROR_FAILED_DRIVER_ENTRY                                                = 0x00000287
ERROR_DEVICE_ENUMERATION_ERROR                                           = 0x00000288
ERROR_MOUNT_POINT_NOT_RESOLVED                                           = 0x00000289
ERROR_INVALID_DEVICE_OBJECT_PARAMETER                                    = 0x0000028a
ERROR_MCA_OCCURED                                                        = 0x0000028b
ERROR_DRIVER_DATABASE_ERROR                                              = 0x0000028c
ERROR_SYSTEM_HIVE_TOO_LARGE                                              = 0x0000028d
ERROR_DRIVER_FAILED_PRIOR_UNLOAD                                         = 0x0000028e
ERROR_VOLSNAP_PREPARE_HIBERNATE                                          = 0x0000028f
ERROR_HIBERNATION_FAILURE                                                = 0x00000290
ERROR_PWD_TOO_LONG                                                       = 0x00000291
ERROR_FILE_SYSTEM_LIMITATION                                             = 0x00000299
ERROR_ASSERTION_FAILURE                                                  = 0x0000029c
ERROR_ACPI_ERROR                                                         = 0x0000029d
ERROR_WOW_ASSERTION                                                      = 0x0000029e
ERROR_PNP_BAD_MPS_TABLE                                                  = 0x0000029f
ERROR_PNP_TRANSLATION_FAILED                                             = 0x000002a0
ERROR_PNP_IRQ_TRANSLATION_FAILED                                         = 0x000002a1
ERROR_PNP_INVALID_ID                                                     = 0x000002a2
ERROR_WAKE_SYSTEM_DEBUGGER                                               = 0x000002a3
ERROR_HANDLES_CLOSED                                                     = 0x000002a4
ERROR_EXTRANEOUS_INFORMATION                                             = 0x000002a5
ERROR_RXACT_COMMIT_NECESSARY                                             = 0x000002a6
ERROR_MEDIA_CHECK                                                        = 0x000002a7
ERROR_GUID_SUBSTITUTION_MADE                                             = 0x000002a8
ERROR_STOPPED_ON_SYMLINK                                                 = 0x000002a9
ERROR_LONGJUMP                                                           = 0x000002aa
ERROR_PLUGPLAY_QUERY_VETOED                                              = 0x000002ab
ERROR_UNWIND_CONSOLIDATE                                                 = 0x000002ac
ERROR_REGISTRY_HIVE_RECOVERED                                            = 0x000002ad
ERROR_DLL_MIGHT_BE_INSECURE                                              = 0x000002ae
ERROR_DLL_MIGHT_BE_INCOMPATIBLE                                          = 0x000002af
ERROR_DBG_EXCEPTION_NOT_HANDLED                                          = 0x000002b0
ERROR_DBG_REPLY_LATER                                                    = 0x000002b1
ERROR_DBG_UNABLE_TO_PROVIDE_HANDLE                                       = 0x000002b2
ERROR_DBG_TERMINATE_THREAD                                               = 0x000002b3
ERROR_DBG_TERMINATE_PROCESS                                              = 0x000002b4
ERROR_DBG_CONTROL_C                                                      = 0x000002b5
ERROR_DBG_PRINTEXCEPTION_C                                               = 0x000002b6
ERROR_DBG_RIPEXCEPTION                                                   = 0x000002b7
ERROR_DBG_CONTROL_BREAK                                                  = 0x000002b8
ERROR_DBG_COMMAND_EXCEPTION                                              = 0x000002b9
ERROR_OBJECT_NAME_EXISTS                                                 = 0x000002ba
ERROR_THREAD_WAS_SUSPENDED                                               = 0x000002bb
ERROR_IMAGE_NOT_AT_BASE                                                  = 0x000002bc
ERROR_RXACT_STATE_CREATED                                                = 0x000002bd
ERROR_SEGMENT_NOTIFICATION                                               = 0x000002be
ERROR_BAD_CURRENT_DIRECTORY                                              = 0x000002bf
ERROR_FT_READ_RECOVERY_FROM_BACKUP                                       = 0x000002c0
ERROR_FT_WRITE_RECOVERY                                                  = 0x000002c1
ERROR_IMAGE_MACHINE_TYPE_MISMATCH                                        = 0x000002c2
ERROR_RECEIVE_PARTIAL                                                    = 0x000002c3
ERROR_RECEIVE_EXPEDITED                                                  = 0x000002c4
ERROR_RECEIVE_PARTIAL_EXPEDITED                                          = 0x000002c5
ERROR_EVENT_DONE                                                         = 0x000002c6
ERROR_EVENT_PENDING                                                      = 0x000002c7
ERROR_CHECKING_FILE_SYSTEM                                               = 0x000002c8
ERROR_FATAL_APP_EXIT                                                     = 0x000002c9
ERROR_PREDEFINED_HANDLE                                                  = 0x000002ca
ERROR_WAS_UNLOCKED                                                       = 0x000002cb
ERROR_SERVICE_NOTIFICATION                                               = 0x000002cc
ERROR_WAS_LOCKED                                                         = 0x000002cd
ERROR_LOG_HARD_ERROR                                                     = 0x000002ce
ERROR_ALREADY_WIN32                                                      = 0x000002cf
ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE                                    = 0x000002d0
ERROR_NO_YIELD_PERFORMED                                                 = 0x000002d1
ERROR_TIMER_RESUME_IGNORED                                               = 0x000002d2
ERROR_ARBITRATION_UNHANDLED                                              = 0x000002d3
ERROR_CARDBUS_NOT_SUPPORTED                                              = 0x000002d4
ERROR_MP_PROCESSOR_MISMATCH                                              = 0x000002d5
ERROR_HIBERNATED                                                         = 0x000002d6
ERROR_RESUME_HIBERNATION                                                 = 0x000002d7
ERROR_FIRMWARE_UPDATED                                                   = 0x000002d8
ERROR_DRIVERS_LEAKING_LOCKED_PAGES                                       = 0x000002d9
ERROR_WAKE_SYSTEM                                                        = 0x000002da
ERROR_WAIT_1                                                             = 0x000002db
ERROR_WAIT_2                                                             = 0x000002dc
ERROR_WAIT_3                                                             = 0x000002dd
ERROR_WAIT_63                                                            = 0x000002de
ERROR_ABANDONED_WAIT_0                                                   = 0x000002df
ERROR_ABANDONED_WAIT_63                                                  = 0x000002e0
ERROR_USER_APC                                                           = 0x000002e1
ERROR_KERNEL_APC                                                         = 0x000002e2
ERROR_ALERTED                                                            = 0x000002e3
ERROR_ELEVATION_REQUIRED                                                 = 0x000002e4
ERROR_REPARSE                                                            = 0x000002e5
ERROR_OPLOCK_BREAK_IN_PROGRESS                                           = 0x000002e6
ERROR_VOLUME_MOUNTED                                                     = 0x000002e7
ERROR_RXACT_COMMITTED                                                    = 0x000002e8
ERROR_NOTIFY_CLEANUP                                                     = 0x000002e9
ERROR_PRIMARY_TRANSPORT_CONNECT_FAILED                                   = 0x000002ea
ERROR_PAGE_FAULT_TRANSITION                                              = 0x000002eb
ERROR_PAGE_FAULT_DEMAND_ZERO                                             = 0x000002ec
ERROR_PAGE_FAULT_COPY_ON_WRITE                                           = 0x000002ed
ERROR_PAGE_FAULT_GUARD_PAGE                                              = 0x000002ee
ERROR_PAGE_FAULT_PAGING_FILE                                             = 0x000002ef
ERROR_CACHE_PAGE_LOCKED                                                  = 0x000002f0
ERROR_CRASH_DUMP                                                         = 0x000002f1
ERROR_BUFFER_ALL_ZEROS                                                   = 0x000002f2
ERROR_REPARSE_OBJECT                                                     = 0x000002f3
ERROR_RESOURCE_REQUIREMENTS_CHANGED                                      = 0x000002f4
ERROR_TRANSLATION_COMPLETE                                               = 0x000002f5
ERROR_NOTHING_TO_TERMINATE                                               = 0x000002f6
ERROR_PROCESS_NOT_IN_JOB                                                 = 0x000002f7
ERROR_PROCESS_IN_JOB                                                     = 0x000002f8
ERROR_VOLSNAP_HIBERNATE_READY                                            = 0x000002f9
ERROR_FSFILTER_OP_COMPLETED_SUCCESSFULLY                                 = 0x000002fa
ERROR_INTERRUPT_VECTOR_ALREADY_CONNECTED                                 = 0x000002fb
ERROR_INTERRUPT_STILL_CONNECTED                                          = 0x000002fc
ERROR_WAIT_FOR_OPLOCK                                                    = 0x000002fd
ERROR_DBG_EXCEPTION_HANDLED                                              = 0x000002fe
ERROR_DBG_CONTINUE                                                       = 0x000002ff
ERROR_CALLBACK_POP_STACK                                                 = 0x00000300
ERROR_COMPRESSION_DISABLED                                               = 0x00000301
ERROR_CANTFETCHBACKWARDS                                                 = 0x00000302
ERROR_CANTSCROLLBACKWARDS                                                = 0x00000303
ERROR_ROWSNOTRELEASED                                                    = 0x00000304
ERROR_BAD_ACCESSOR_FLAGS                                                 = 0x00000305
ERROR_ERRORS_ENCOUNTERED                                                 = 0x00000306
ERROR_NOT_CAPABLE                                                        = 0x00000307
ERROR_REQUEST_OUT_OF_SEQUENCE                                            = 0x00000308
ERROR_VERSION_PARSE_ERROR                                                = 0x00000309
ERROR_BADSTARTPOSITION                                                   = 0x0000030a
ERROR_MEMORY_HARDWARE                                                    = 0x0000030b
ERROR_DISK_REPAIR_DISABLED                                               = 0x0000030c
ERROR_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE            = 0x0000030d
ERROR_SYSTEM_POWERSTATE_TRANSITION                                       = 0x0000030e
ERROR_SYSTEM_POWERSTATE_COMPLEX_TRANSITION                               = 0x0000030f
ERROR_MCA_EXCEPTION                                                      = 0x00000310
ERROR_ACCESS_AUDIT_BY_POLICY                                             = 0x00000311
ERROR_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY                              = 0x00000312
ERROR_ABANDON_HIBERFILE                                                  = 0x00000313
ERROR_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED                         = 0x00000314
ERROR_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR                         = 0x00000315
ERROR_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR                             = 0x00000316
ERROR_BAD_MCFG_TABLE                                                     = 0x00000317
ERROR_DISK_REPAIR_REDIRECTED                                             = 0x00000318
ERROR_DISK_REPAIR_UNSUCCESSFUL                                           = 0x00000319
ERROR_CORRUPT_LOG_OVERFULL                                               = 0x0000031a
ERROR_CORRUPT_LOG_CORRUPTED                                              = 0x0000031b
ERROR_CORRUPT_LOG_UNAVAILABLE                                            = 0x0000031c
ERROR_CORRUPT_LOG_DELETED_FULL                                           = 0x0000031d
ERROR_CORRUPT_LOG_CLEARED                                                = 0x0000031e
ERROR_ORPHAN_NAME_EXHAUSTED                                              = 0x0000031f
ERROR_OPLOCK_SWITCHED_TO_NEW_HANDLE                                      = 0x00000320
ERROR_CANNOT_GRANT_REQUESTED_OPLOCK                                      = 0x00000321
ERROR_CANNOT_BREAK_OPLOCK                                                = 0x00000322
ERROR_OPLOCK_HANDLE_CLOSED                                               = 0x00000323
ERROR_NO_ACE_CONDITION                                                   = 0x00000324
ERROR_INVALID_ACE_CONDITION                                              = 0x00000325
ERROR_FILE_HANDLE_REVOKED                                                = 0x00000326
ERROR_IMAGE_AT_DIFFERENT_BASE                                            = 0x00000327
ERROR_EA_ACCESS_DENIED                                                   = 0x000003e2
ERROR_OPERATION_ABORTED                                                  = 0x000003e3
ERROR_IO_INCOMPLETE                                                      = 0x000003e4
ERROR_IO_PENDING                                                         = 0x000003e5
ERROR_NOACCESS                                                           = 0x000003e6
ERROR_SWAPERROR                                                          = 0x000003e7
ERROR_STACK_OVERFLOW                                                     = 0x000003e9
ERROR_INVALID_MESSAGE                                                    = 0x000003ea
ERROR_CAN_NOT_COMPLETE                                                   = 0x000003eb
ERROR_INVALID_FLAGS                                                      = 0x000003ec
ERROR_UNRECOGNIZED_VOLUME                                                = 0x000003ed
ERROR_FILE_INVALID                                                       = 0x000003ee
ERROR_FULLSCREEN_MODE                                                    = 0x000003ef
ERROR_NO_TOKEN                                                           = 0x000003f0
ERROR_BADDB                                                              = 0x000003f1
ERROR_BADKEY                                                             = 0x000003f2
ERROR_CANTOPEN                                                           = 0x000003f3
ERROR_CANTREAD                                                           = 0x000003f4
ERROR_CANTWRITE                                                          = 0x000003f5
ERROR_REGISTRY_RECOVERED                                                 = 0x000003f6
ERROR_REGISTRY_CORRUPT                                                   = 0x000003f7
ERROR_REGISTRY_IO_FAILED                                                 = 0x000003f8
ERROR_NOT_REGISTRY_FILE                                                  = 0x000003f9
ERROR_KEY_DELETED                                                        = 0x000003fa
ERROR_NO_LOG_SPACE                                                       = 0x000003fb
ERROR_KEY_HAS_CHILDREN                                                   = 0x000003fc
ERROR_CHILD_MUST_BE_VOLATILE                                             = 0x000003fd
ERROR_NOTIFY_ENUM_DIR                                                    = 0x000003fe
ERROR_DEPENDENT_SERVICES_RUNNING                                         = 0x0000041b
ERROR_INVALID_SERVICE_CONTROL                                            = 0x0000041c
ERROR_SERVICE_REQUEST_TIMEOUT                                            = 0x0000041d
ERROR_SERVICE_NO_THREAD                                                  = 0x0000041e
ERROR_SERVICE_DATABASE_LOCKED                                            = 0x0000041f
ERROR_SERVICE_ALREADY_RUNNING                                            = 0x00000420
ERROR_INVALID_SERVICE_ACCOUNT                                            = 0x00000421
ERROR_SERVICE_DISABLED                                                   = 0x00000422
ERROR_CIRCULAR_DEPENDENCY                                                = 0x00000423
ERROR_SERVICE_DOES_NOT_EXIST                                             = 0x00000424
ERROR_SERVICE_CANNOT_ACCEPT_CTRL                                         = 0x00000425
ERROR_SERVICE_NOT_ACTIVE                                                 = 0x00000426
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT                                  = 0x00000427
ERROR_EXCEPTION_IN_SERVICE                                               = 0x00000428
ERROR_DATABASE_DOES_NOT_EXIST                                            = 0x00000429
ERROR_SERVICE_SPECIFIC_ERROR                                             = 0x0000042a
ERROR_PROCESS_ABORTED                                                    = 0x0000042b
ERROR_SERVICE_DEPENDENCY_FAIL                                            = 0x0000042c
ERROR_SERVICE_LOGON_FAILED                                               = 0x0000042d
ERROR_SERVICE_START_HANG                                                 = 0x0000042e
ERROR_INVALID_SERVICE_LOCK                                               = 0x0000042f
ERROR_SERVICE_MARKED_FOR_DELETE                                          = 0x00000430
ERROR_SERVICE_EXISTS                                                     = 0x00000431
ERROR_ALREADY_RUNNING_LKG                                                = 0x00000432
ERROR_SERVICE_DEPENDENCY_DELETED                                         = 0x00000433
ERROR_BOOT_ALREADY_ACCEPTED                                              = 0x00000434
ERROR_SERVICE_NEVER_STARTED                                              = 0x00000435
ERROR_DUPLICATE_SERVICE_NAME                                             = 0x00000436
ERROR_DIFFERENT_SERVICE_ACCOUNT                                          = 0x00000437
ERROR_CANNOT_DETECT_DRIVER_FAILURE                                       = 0x00000438
ERROR_CANNOT_DETECT_PROCESS_ABORT                                        = 0x00000439
ERROR_NO_RECOVERY_PROGRAM                                                = 0x0000043a
ERROR_SERVICE_NOT_IN_EXE                                                 = 0x0000043b
ERROR_NOT_SAFEBOOT_SERVICE                                               = 0x0000043c
ERROR_END_OF_MEDIA                                                       = 0x0000044c
ERROR_FILEMARK_DETECTED                                                  = 0x0000044d
ERROR_BEGINNING_OF_MEDIA                                                 = 0x0000044e
ERROR_SETMARK_DETECTED                                                   = 0x0000044f
ERROR_NO_DATA_DETECTED                                                   = 0x00000450
ERROR_PARTITION_FAILURE                                                  = 0x00000451
ERROR_INVALID_BLOCK_LENGTH                                               = 0x00000452
ERROR_DEVICE_NOT_PARTITIONED                                             = 0x00000453
ERROR_UNABLE_TO_LOCK_MEDIA                                               = 0x00000454
ERROR_UNABLE_TO_UNLOAD_MEDIA                                             = 0x00000455
ERROR_MEDIA_CHANGED                                                      = 0x00000456
ERROR_BUS_RESET                                                          = 0x00000457
ERROR_NO_MEDIA_IN_DRIVE                                                  = 0x00000458
ERROR_NO_UNICODE_TRANSLATION                                             = 0x00000459
ERROR_DLL_INIT_FAILED                                                    = 0x0000045a
ERROR_SHUTDOWN_IN_PROGRESS                                               = 0x0000045b
ERROR_NO_SHUTDOWN_IN_PROGRESS                                            = 0x0000045c
ERROR_IO_DEVICE                                                          = 0x0000045d
ERROR_SERIAL_NO_DEVICE                                                   = 0x0000045e
ERROR_IRQ_BUSY                                                           = 0x0000045f
ERROR_MORE_WRITES                                                        = 0x00000460
ERROR_COUNTER_TIMEOUT                                                    = 0x00000461
ERROR_FLOPPY_ID_MARK_NOT_FOUND                                           = 0x00000462
ERROR_FLOPPY_WRONG_CYLINDER                                              = 0x00000463
ERROR_FLOPPY_UNKNOWN_ERROR                                               = 0x00000464
ERROR_FLOPPY_BAD_REGISTERS                                               = 0x00000465
ERROR_DISK_RECALIBRATE_FAILED                                            = 0x00000466
ERROR_DISK_OPERATION_FAILED                                              = 0x00000467
ERROR_DISK_RESET_FAILED                                                  = 0x00000468
ERROR_EOM_OVERFLOW                                                       = 0x00000469
ERROR_NOT_ENOUGH_SERVER_MEMORY                                           = 0x0000046a
ERROR_POSSIBLE_DEADLOCK                                                  = 0x0000046b
ERROR_MAPPED_ALIGNMENT                                                   = 0x0000046c
ERROR_SET_POWER_STATE_VETOED                                             = 0x00000474
ERROR_SET_POWER_STATE_FAILED                                             = 0x00000475
ERROR_TOO_MANY_LINKS                                                     = 0x00000476
ERROR_OLD_WIN_VERSION                                                    = 0x0000047e
ERROR_APP_WRONG_OS                                                       = 0x0000047f
ERROR_SINGLE_INSTANCE_APP                                                = 0x00000480
ERROR_RMODE_APP                                                          = 0x00000481
ERROR_INVALID_DLL                                                        = 0x00000482
ERROR_NO_ASSOCIATION                                                     = 0x00000483
ERROR_DDE_FAIL                                                           = 0x00000484
ERROR_DLL_NOT_FOUND                                                      = 0x00000485
ERROR_NO_MORE_USER_HANDLES                                               = 0x00000486
ERROR_MESSAGE_SYNC_ONLY                                                  = 0x00000487
ERROR_SOURCE_ELEMENT_EMPTY                                               = 0x00000488
ERROR_DESTINATION_ELEMENT_FULL                                           = 0x00000489
ERROR_ILLEGAL_ELEMENT_ADDRESS                                            = 0x0000048a
ERROR_MAGAZINE_NOT_PRESENT                                               = 0x0000048b
ERROR_DEVICE_REINITIALIZATION_NEEDED                                     = 0x0000048c
ERROR_DEVICE_REQUIRES_CLEANING                                           = 0x0000048d
ERROR_DEVICE_DOOR_OPEN                                                   = 0x0000048e
ERROR_DEVICE_NOT_CONNECTED                                               = 0x0000048f
ERROR_NOT_FOUND                                                          = 0x00000490
ERROR_NO_MATCH                                                           = 0x00000491
ERROR_SET_NOT_FOUND                                                      = 0x00000492
ERROR_POINT_NOT_FOUND                                                    = 0x00000493
ERROR_NO_TRACKING_SERVICE                                                = 0x00000494
ERROR_NO_VOLUME_ID                                                       = 0x00000495
ERROR_UNABLE_TO_REMOVE_REPLACED                                          = 0x00000497
ERROR_UNABLE_TO_MOVE_REPLACEMENT                                         = 0x00000498
ERROR_UNABLE_TO_MOVE_REPLACEMENT_2                                       = 0x00000499
ERROR_JOURNAL_DELETE_IN_PROGRESS                                         = 0x0000049a
ERROR_JOURNAL_NOT_ACTIVE                                                 = 0x0000049b
ERROR_POTENTIAL_FILE_FOUND                                               = 0x0000049c
ERROR_JOURNAL_ENTRY_DELETED                                              = 0x0000049d
ERROR_SHUTDOWN_IS_SCHEDULED                                              = 0x000004a6
ERROR_SHUTDOWN_USERS_LOGGED_ON                                           = 0x000004a7
ERROR_BAD_DEVICE                                                         = 0x000004b0
ERROR_CONNECTION_UNAVAIL                                                 = 0x000004b1
ERROR_DEVICE_ALREADY_REMEMBERED                                          = 0x000004b2
ERROR_NO_NET_OR_BAD_PATH                                                 = 0x000004b3
ERROR_BAD_PROVIDER                                                       = 0x000004b4
ERROR_CANNOT_OPEN_PROFILE                                                = 0x000004b5
ERROR_BAD_PROFILE                                                        = 0x000004b6
ERROR_NOT_CONTAINER                                                      = 0x000004b7
ERROR_EXTENDED_ERROR                                                     = 0x000004b8
ERROR_INVALID_GROUPNAME                                                  = 0x000004b9
ERROR_INVALID_COMPUTERNAME                                               = 0x000004ba
ERROR_INVALID_EVENTNAME                                                  = 0x000004bb
ERROR_INVALID_DOMAINNAME                                                 = 0x000004bc
ERROR_INVALID_SERVICENAME                                                = 0x000004bd
ERROR_INVALID_NETNAME                                                    = 0x000004be
ERROR_INVALID_SHARENAME                                                  = 0x000004bf
ERROR_INVALID_PASSWORDNAME                                               = 0x000004c0
ERROR_INVALID_MESSAGENAME                                                = 0x000004c1
ERROR_INVALID_MESSAGEDEST                                                = 0x000004c2
ERROR_SESSION_CREDENTIAL_CONFLICT                                        = 0x000004c3
ERROR_REMOTE_SESSION_LIMIT_EXCEEDED                                      = 0x000004c4
ERROR_DUP_DOMAINNAME                                                     = 0x000004c5
ERROR_NO_NETWORK                                                         = 0x000004c6
ERROR_CANCELLED                                                          = 0x000004c7
ERROR_USER_MAPPED_FILE                                                   = 0x000004c8
ERROR_CONNECTION_REFUSED                                                 = 0x000004c9
ERROR_GRACEFUL_DISCONNECT                                                = 0x000004ca
ERROR_ADDRESS_ALREADY_ASSOCIATED                                         = 0x000004cb
ERROR_ADDRESS_NOT_ASSOCIATED                                             = 0x000004cc
ERROR_CONNECTION_INVALID                                                 = 0x000004cd
ERROR_CONNECTION_ACTIVE                                                  = 0x000004ce
ERROR_NETWORK_UNREACHABLE                                                = 0x000004cf
ERROR_HOST_UNREACHABLE                                                   = 0x000004d0
ERROR_PROTOCOL_UNREACHABLE                                               = 0x000004d1
ERROR_PORT_UNREACHABLE                                                   = 0x000004d2
ERROR_REQUEST_ABORTED                                                    = 0x000004d3
ERROR_CONNECTION_ABORTED                                                 = 0x000004d4
ERROR_RETRY                                                              = 0x000004d5
ERROR_CONNECTION_COUNT_LIMIT                                             = 0x000004d6
ERROR_LOGIN_TIME_RESTRICTION                                             = 0x000004d7
ERROR_LOGIN_WKSTA_RESTRICTION                                            = 0x000004d8
ERROR_INCORRECT_ADDRESS                                                  = 0x000004d9
ERROR_ALREADY_REGISTERED                                                 = 0x000004da
ERROR_SERVICE_NOT_FOUND                                                  = 0x000004db
ERROR_NOT_AUTHENTICATED                                                  = 0x000004dc
ERROR_NOT_LOGGED_ON                                                      = 0x000004dd
ERROR_CONTINUE                                                           = 0x000004de
ERROR_ALREADY_INITIALIZED                                                = 0x000004df
ERROR_NO_MORE_DEVICES                                                    = 0x000004e0
ERROR_NO_SUCH_SITE                                                       = 0x000004e1
ERROR_DOMAIN_CONTROLLER_EXISTS                                           = 0x000004e2
ERROR_ONLY_IF_CONNECTED                                                  = 0x000004e3
ERROR_OVERRIDE_NOCHANGES                                                 = 0x000004e4
ERROR_BAD_USER_PROFILE                                                   = 0x000004e5
ERROR_NOT_SUPPORTED_ON_SBS                                               = 0x000004e6
ERROR_SERVER_SHUTDOWN_IN_PROGRESS                                        = 0x000004e7
ERROR_HOST_DOWN                                                          = 0x000004e8
ERROR_NON_ACCOUNT_SID                                                    = 0x000004e9
ERROR_NON_DOMAIN_SID                                                     = 0x000004ea
ERROR_APPHELP_BLOCK                                                      = 0x000004eb
ERROR_ACCESS_DISABLED_BY_POLICY                                          = 0x000004ec
ERROR_REG_NAT_CONSUMPTION                                                = 0x000004ed
ERROR_CSCSHARE_OFFLINE                                                   = 0x000004ee
ERROR_PKINIT_FAILURE                                                     = 0x000004ef
ERROR_SMARTCARD_SUBSYSTEM_FAILURE                                        = 0x000004f0
ERROR_DOWNGRADE_DETECTED                                                 = 0x000004f1
ERROR_MACHINE_LOCKED                                                     = 0x000004f7
ERROR_CALLBACK_SUPPLIED_INVALID_DATA                                     = 0x000004f9
ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED                                   = 0x000004fa
ERROR_DRIVER_BLOCKED                                                     = 0x000004fb
ERROR_INVALID_IMPORT_OF_NON_DLL                                          = 0x000004fc
ERROR_ACCESS_DISABLED_WEBBLADE                                           = 0x000004fd
ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER                                    = 0x000004fe
ERROR_RECOVERY_FAILURE                                                   = 0x000004ff
ERROR_ALREADY_FIBER                                                      = 0x00000500
ERROR_ALREADY_THREAD                                                     = 0x00000501
ERROR_STACK_BUFFER_OVERRUN                                               = 0x00000502
ERROR_PARAMETER_QUOTA_EXCEEDED                                           = 0x00000503
ERROR_DEBUGGER_INACTIVE                                                  = 0x00000504
ERROR_DELAY_LOAD_FAILED                                                  = 0x00000505
ERROR_VDM_DISALLOWED                                                     = 0x00000506
ERROR_UNIDENTIFIED_ERROR                                                 = 0x00000507
ERROR_INVALID_CRUNTIME_PARAMETER                                         = 0x00000508
ERROR_BEYOND_VDL                                                         = 0x00000509
ERROR_INCOMPATIBLE_SERVICE_SID_TYPE                                      = 0x0000050a
ERROR_DRIVER_PROCESS_TERMINATED                                          = 0x0000050b
ERROR_IMPLEMENTATION_LIMIT                                               = 0x0000050c
ERROR_PROCESS_IS_PROTECTED                                               = 0x0000050d
ERROR_SERVICE_NOTIFY_CLIENT_LAGGING                                      = 0x0000050e
ERROR_DISK_QUOTA_EXCEEDED                                                = 0x0000050f
ERROR_CONTENT_BLOCKED                                                    = 0x00000510
ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE                                     = 0x00000511
ERROR_APP_HANG                                                           = 0x00000512
ERROR_INVALID_LABEL                                                      = 0x00000513
ERROR_NOT_ALL_ASSIGNED                                                   = 0x00000514
ERROR_SOME_NOT_MAPPED                                                    = 0x00000515
ERROR_NO_QUOTAS_FOR_ACCOUNT                                              = 0x00000516
ERROR_LOCAL_USER_SESSION_KEY                                             = 0x00000517
ERROR_NULL_LM_PASSWORD                                                   = 0x00000518
ERROR_UNKNOWN_REVISION                                                   = 0x00000519
ERROR_REVISION_MISMATCH                                                  = 0x0000051a
ERROR_INVALID_OWNER                                                      = 0x0000051b
ERROR_INVALID_PRIMARY_GROUP                                              = 0x0000051c
ERROR_NO_IMPERSONATION_TOKEN                                             = 0x0000051d
ERROR_CANT_DISABLE_MANDATORY                                             = 0x0000051e
ERROR_NO_LOGON_SERVERS                                                   = 0x0000051f
ERROR_NO_SUCH_LOGON_SESSION                                              = 0x00000520
ERROR_NO_SUCH_PRIVILEGE                                                  = 0x00000521
ERROR_PRIVILEGE_NOT_HELD                                                 = 0x00000522
ERROR_INVALID_ACCOUNT_NAME                                               = 0x00000523
ERROR_USER_EXISTS                                                        = 0x00000524
ERROR_NO_SUCH_USER                                                       = 0x00000525
ERROR_GROUP_EXISTS                                                       = 0x00000526
ERROR_NO_SUCH_GROUP                                                      = 0x00000527
ERROR_MEMBER_IN_GROUP                                                    = 0x00000528
ERROR_MEMBER_NOT_IN_GROUP                                                = 0x00000529
ERROR_LAST_ADMIN                                                         = 0x0000052a
ERROR_WRONG_PASSWORD                                                     = 0x0000052b
ERROR_ILL_FORMED_PASSWORD                                                = 0x0000052c
ERROR_PASSWORD_RESTRICTION                                               = 0x0000052d
ERROR_LOGON_FAILURE                                                      = 0x0000052e
ERROR_ACCOUNT_RESTRICTION                                                = 0x0000052f
ERROR_INVALID_LOGON_HOURS                                                = 0x00000530
ERROR_INVALID_WORKSTATION                                                = 0x00000531
ERROR_PASSWORD_EXPIRED                                                   = 0x00000532
ERROR_ACCOUNT_DISABLED                                                   = 0x00000533
ERROR_NONE_MAPPED                                                        = 0x00000534
ERROR_TOO_MANY_LUIDS_REQUESTED                                           = 0x00000535
ERROR_LUIDS_EXHAUSTED                                                    = 0x00000536
ERROR_INVALID_SUB_AUTHORITY                                              = 0x00000537
ERROR_INVALID_ACL                                                        = 0x00000538
ERROR_INVALID_SID                                                        = 0x00000539
ERROR_INVALID_SECURITY_DESCR                                             = 0x0000053a
ERROR_BAD_INHERITANCE_ACL                                                = 0x0000053c
ERROR_SERVER_DISABLED                                                    = 0x0000053d
ERROR_SERVER_NOT_DISABLED                                                = 0x0000053e
ERROR_INVALID_ID_AUTHORITY                                               = 0x0000053f
ERROR_ALLOTTED_SPACE_EXCEEDED                                            = 0x00000540
ERROR_INVALID_GROUP_ATTRIBUTES                                           = 0x00000541
ERROR_BAD_IMPERSONATION_LEVEL                                            = 0x00000542
ERROR_CANT_OPEN_ANONYMOUS                                                = 0x00000543
ERROR_BAD_VALIDATION_CLASS                                               = 0x00000544
ERROR_BAD_TOKEN_TYPE                                                     = 0x00000545
ERROR_NO_SECURITY_ON_OBJECT                                              = 0x00000546
ERROR_CANT_ACCESS_DOMAIN_INFO                                            = 0x00000547
ERROR_INVALID_SERVER_STATE                                               = 0x00000548
ERROR_INVALID_DOMAIN_STATE                                               = 0x00000549
ERROR_INVALID_DOMAIN_ROLE                                                = 0x0000054a
ERROR_NO_SUCH_DOMAIN                                                     = 0x0000054b
ERROR_DOMAIN_EXISTS                                                      = 0x0000054c
ERROR_DOMAIN_LIMIT_EXCEEDED                                              = 0x0000054d
ERROR_INTERNAL_DB_CORRUPTION                                             = 0x0000054e
ERROR_INTERNAL_ERROR                                                     = 0x0000054f
ERROR_GENERIC_NOT_MAPPED                                                 = 0x00000550
ERROR_BAD_DESCRIPTOR_FORMAT                                              = 0x00000551
ERROR_NOT_LOGON_PROCESS                                                  = 0x00000552
ERROR_LOGON_SESSION_EXISTS                                               = 0x00000553
ERROR_NO_SUCH_PACKAGE                                                    = 0x00000554
ERROR_BAD_LOGON_SESSION_STATE                                            = 0x00000555
ERROR_LOGON_SESSION_COLLISION                                            = 0x00000556
ERROR_INVALID_LOGON_TYPE                                                 = 0x00000557
ERROR_CANNOT_IMPERSONATE                                                 = 0x00000558
ERROR_RXACT_INVALID_STATE                                                = 0x00000559
ERROR_RXACT_COMMIT_FAILURE                                               = 0x0000055a
ERROR_SPECIAL_ACCOUNT                                                    = 0x0000055b
ERROR_SPECIAL_GROUP                                                      = 0x0000055c
ERROR_SPECIAL_USER                                                       = 0x0000055d
ERROR_MEMBERS_PRIMARY_GROUP                                              = 0x0000055e
ERROR_TOKEN_ALREADY_IN_USE                                               = 0x0000055f
ERROR_NO_SUCH_ALIAS                                                      = 0x00000560
ERROR_MEMBER_NOT_IN_ALIAS                                                = 0x00000561
ERROR_MEMBER_IN_ALIAS                                                    = 0x00000562
ERROR_ALIAS_EXISTS                                                       = 0x00000563
ERROR_LOGON_NOT_GRANTED                                                  = 0x00000564
ERROR_TOO_MANY_SECRETS                                                   = 0x00000565
ERROR_SECRET_TOO_LONG                                                    = 0x00000566
ERROR_INTERNAL_DB_ERROR                                                  = 0x00000567
ERROR_TOO_MANY_CONTEXT_IDS                                               = 0x00000568
ERROR_LOGON_TYPE_NOT_GRANTED                                             = 0x00000569
ERROR_NT_CROSS_ENCRYPTION_REQUIRED                                       = 0x0000056a
ERROR_NO_SUCH_MEMBER                                                     = 0x0000056b
ERROR_INVALID_MEMBER                                                     = 0x0000056c
ERROR_TOO_MANY_SIDS                                                      = 0x0000056d
ERROR_LM_CROSS_ENCRYPTION_REQUIRED                                       = 0x0000056e
ERROR_NO_INHERITANCE                                                     = 0x0000056f
ERROR_FILE_CORRUPT                                                       = 0x00000570
ERROR_DISK_CORRUPT                                                       = 0x00000571
ERROR_NO_USER_SESSION_KEY                                                = 0x00000572
ERROR_LICENSE_QUOTA_EXCEEDED                                             = 0x00000573
ERROR_WRONG_TARGET_NAME                                                  = 0x00000574
ERROR_MUTUAL_AUTH_FAILED                                                 = 0x00000575
ERROR_TIME_SKEW                                                          = 0x00000576
ERROR_CURRENT_DOMAIN_NOT_ALLOWED                                         = 0x00000577
ERROR_INVALID_WINDOW_HANDLE                                              = 0x00000578
ERROR_INVALID_MENU_HANDLE                                                = 0x00000579
ERROR_INVALID_CURSOR_HANDLE                                              = 0x0000057a
ERROR_INVALID_ACCEL_HANDLE                                               = 0x0000057b
ERROR_INVALID_HOOK_HANDLE                                                = 0x0000057c
ERROR_INVALID_DWP_HANDLE                                                 = 0x0000057d
ERROR_TLW_WITH_WSCHILD                                                   = 0x0000057e
ERROR_CANNOT_FIND_WND_CLASS                                              = 0x0000057f
ERROR_WINDOW_OF_OTHER_THREAD                                             = 0x00000580
ERROR_HOTKEY_ALREADY_REGISTERED                                          = 0x00000581
ERROR_CLASS_ALREADY_EXISTS                                               = 0x00000582
ERROR_CLASS_DOES_NOT_EXIST                                               = 0x00000583
ERROR_CLASS_HAS_WINDOWS                                                  = 0x00000584
ERROR_INVALID_INDEX                                                      = 0x00000585
ERROR_INVALID_ICON_HANDLE                                                = 0x00000586
ERROR_PRIVATE_DIALOG_INDEX                                               = 0x00000587
ERROR_LISTBOX_ID_NOT_FOUND                                               = 0x00000588
ERROR_NO_WILDCARD_CHARACTERS                                             = 0x00000589
ERROR_CLIPBOARD_NOT_OPEN                                                 = 0x0000058a
ERROR_HOTKEY_NOT_REGISTERED                                              = 0x0000058b
ERROR_WINDOW_NOT_DIALOG                                                  = 0x0000058c
ERROR_CONTROL_ID_NOT_FOUND                                               = 0x0000058d
ERROR_INVALID_COMBOBOX_MESSAGE                                           = 0x0000058e
ERROR_WINDOW_NOT_COMBOBOX                                                = 0x0000058f
ERROR_INVALID_EDIT_HEIGHT                                                = 0x00000590
ERROR_DC_NOT_FOUND                                                       = 0x00000591
ERROR_INVALID_HOOK_FILTER                                                = 0x00000592
ERROR_INVALID_FILTER_PROC                                                = 0x00000593
ERROR_HOOK_NEEDS_HMOD                                                    = 0x00000594
ERROR_GLOBAL_ONLY_HOOK                                                   = 0x00000595
ERROR_JOURNAL_HOOK_SET                                                   = 0x00000596
ERROR_HOOK_NOT_INSTALLED                                                 = 0x00000597
ERROR_INVALID_LB_MESSAGE                                                 = 0x00000598
ERROR_SETCOUNT_ON_BAD_LB                                                 = 0x00000599
ERROR_LB_WITHOUT_TABSTOPS                                                = 0x0000059a
ERROR_DESTROY_OBJECT_OF_OTHER_THREAD                                     = 0x0000059b
ERROR_CHILD_WINDOW_MENU                                                  = 0x0000059c
ERROR_NO_SYSTEM_MENU                                                     = 0x0000059d
ERROR_INVALID_MSGBOX_STYLE                                               = 0x0000059e
ERROR_INVALID_SPI_VALUE                                                  = 0x0000059f
ERROR_SCREEN_ALREADY_LOCKED                                              = 0x000005a0
ERROR_HWNDS_HAVE_DIFF_PARENT                                             = 0x000005a1
ERROR_NOT_CHILD_WINDOW                                                   = 0x000005a2
ERROR_INVALID_GW_COMMAND                                                 = 0x000005a3
ERROR_INVALID_THREAD_ID                                                  = 0x000005a4
ERROR_NON_MDICHILD_WINDOW                                                = 0x000005a5
ERROR_POPUP_ALREADY_ACTIVE                                               = 0x000005a6
ERROR_NO_SCROLLBARS                                                      = 0x000005a7
ERROR_INVALID_SCROLLBAR_RANGE                                            = 0x000005a8
ERROR_INVALID_SHOWWIN_COMMAND                                            = 0x000005a9
ERROR_NO_SYSTEM_RESOURCES                                                = 0x000005aa
ERROR_NONPAGED_SYSTEM_RESOURCES                                          = 0x000005ab
ERROR_PAGED_SYSTEM_RESOURCES                                             = 0x000005ac
ERROR_WORKING_SET_QUOTA                                                  = 0x000005ad
ERROR_PAGEFILE_QUOTA                                                     = 0x000005ae
ERROR_COMMITMENT_LIMIT                                                   = 0x000005af
ERROR_MENU_ITEM_NOT_FOUND                                                = 0x000005b0
ERROR_INVALID_KEYBOARD_HANDLE                                            = 0x000005b1
ERROR_HOOK_TYPE_NOT_ALLOWED                                              = 0x000005b2
ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION                                 = 0x000005b3
ERROR_TIMEOUT                                                            = 0x000005b4
ERROR_INVALID_MONITOR_HANDLE                                             = 0x000005b5
ERROR_INCORRECT_SIZE                                                     = 0x000005b6
ERROR_SYMLINK_CLASS_DISABLED                                             = 0x000005b7
ERROR_SYMLINK_NOT_SUPPORTED                                              = 0x000005b8
ERROR_XML_PARSE_ERROR                                                    = 0x000005b9
ERROR_XMLDSIG_ERROR                                                      = 0x000005ba
ERROR_RESTART_APPLICATION                                                = 0x000005bb
ERROR_WRONG_COMPARTMENT                                                  = 0x000005bc
ERROR_AUTHIP_FAILURE                                                     = 0x000005bd
ERROR_NO_NVRAM_RESOURCES                                                 = 0x000005be
ERROR_NOT_GUI_PROCESS                                                    = 0x000005bf
ERROR_EVENTLOG_FILE_CORRUPT                                              = 0x000005dc
ERROR_EVENTLOG_CANT_START                                                = 0x000005dd
ERROR_LOG_FILE_FULL                                                      = 0x000005de
ERROR_EVENTLOG_FILE_CHANGED                                              = 0x000005df
ERROR_INVALID_TASK_NAME                                                  = 0x0000060e
ERROR_INVALID_TASK_INDEX                                                 = 0x0000060f
ERROR_THREAD_ALREADY_IN_TASK                                             = 0x00000610
ERROR_INSTALL_SERVICE_FAILURE                                            = 0x00000641
ERROR_INSTALL_USEREXIT                                                   = 0x00000642
ERROR_INSTALL_FAILURE                                                    = 0x00000643
ERROR_INSTALL_SUSPEND                                                    = 0x00000644
ERROR_UNKNOWN_PRODUCT                                                    = 0x00000645
ERROR_UNKNOWN_FEATURE                                                    = 0x00000646
ERROR_UNKNOWN_COMPONENT                                                  = 0x00000647
ERROR_UNKNOWN_PROPERTY                                                   = 0x00000648
ERROR_INVALID_HANDLE_STATE                                               = 0x00000649
ERROR_BAD_CONFIGURATION                                                  = 0x0000064a
ERROR_INDEX_ABSENT                                                       = 0x0000064b
ERROR_INSTALL_SOURCE_ABSENT                                              = 0x0000064c
ERROR_INSTALL_PACKAGE_VERSION                                            = 0x0000064d
ERROR_PRODUCT_UNINSTALLED                                                = 0x0000064e
ERROR_BAD_QUERY_SYNTAX                                                   = 0x0000064f
ERROR_INVALID_FIELD                                                      = 0x00000650
ERROR_DEVICE_REMOVED                                                     = 0x00000651
ERROR_INSTALL_ALREADY_RUNNING                                            = 0x00000652
ERROR_INSTALL_PACKAGE_OPEN_FAILED                                        = 0x00000653
ERROR_INSTALL_PACKAGE_INVALID                                            = 0x00000654
ERROR_INSTALL_UI_FAILURE                                                 = 0x00000655
ERROR_INSTALL_LOG_FAILURE                                                = 0x00000656
ERROR_INSTALL_LANGUAGE_UNSUPPORTED                                       = 0x00000657
ERROR_INSTALL_TRANSFORM_FAILURE                                          = 0x00000658
ERROR_INSTALL_PACKAGE_REJECTED                                           = 0x00000659
ERROR_FUNCTION_NOT_CALLED                                                = 0x0000065a
ERROR_FUNCTION_FAILED                                                    = 0x0000065b
ERROR_INVALID_TABLE                                                      = 0x0000065c
ERROR_DATATYPE_MISMATCH                                                  = 0x0000065d
ERROR_UNSUPPORTED_TYPE                                                   = 0x0000065e
ERROR_CREATE_FAILED                                                      = 0x0000065f
ERROR_INSTALL_TEMP_UNWRITABLE                                            = 0x00000660
ERROR_INSTALL_PLATFORM_UNSUPPORTED                                       = 0x00000661
ERROR_INSTALL_NOTUSED                                                    = 0x00000662
ERROR_PATCH_PACKAGE_OPEN_FAILED                                          = 0x00000663
ERROR_PATCH_PACKAGE_INVALID                                              = 0x00000664
ERROR_PATCH_PACKAGE_UNSUPPORTED                                          = 0x00000665
ERROR_PRODUCT_VERSION                                                    = 0x00000666
ERROR_INVALID_COMMAND_LINE                                               = 0x00000667
ERROR_INSTALL_REMOTE_DISALLOWED                                          = 0x00000668
ERROR_SUCCESS_REBOOT_INITIATED                                           = 0x00000669
ERROR_PATCH_TARGET_NOT_FOUND                                             = 0x0000066a
ERROR_PATCH_PACKAGE_REJECTED                                             = 0x0000066b
ERROR_INSTALL_TRANSFORM_REJECTED                                         = 0x0000066c
ERROR_INSTALL_REMOTE_PROHIBITED                                          = 0x0000066d
ERROR_PATCH_REMOVAL_UNSUPPORTED                                          = 0x0000066e
ERROR_UNKNOWN_PATCH                                                      = 0x0000066f
ERROR_PATCH_NO_SEQUENCE                                                  = 0x00000670
ERROR_PATCH_REMOVAL_DISALLOWED                                           = 0x00000671
ERROR_INVALID_PATCH_XML                                                  = 0x00000672
ERROR_PATCH_MANAGED_ADVERTISED_PRODUCT                                   = 0x00000673
ERROR_INSTALL_SERVICE_SAFEBOOT                                           = 0x00000674
ERROR_FAIL_FAST_EXCEPTION                                                = 0x00000675
ERROR_INSTALL_REJECTED                                                   = 0x00000676
RPC_S_INVALID_STRING_BINDING                                             = 0x000006a4
RPC_S_WRONG_KIND_OF_BINDING                                              = 0x000006a5
RPC_S_INVALID_BINDING                                                    = 0x000006a6
RPC_S_PROTSEQ_NOT_SUPPORTED                                              = 0x000006a7
RPC_S_INVALID_RPC_PROTSEQ                                                = 0x000006a8
RPC_S_INVALID_STRING_UUID                                                = 0x000006a9
RPC_S_INVALID_ENDPOINT_FORMAT                                            = 0x000006aa
RPC_S_INVALID_NET_ADDR                                                   = 0x000006ab
RPC_S_NO_ENDPOINT_FOUND                                                  = 0x000006ac
RPC_S_INVALID_TIMEOUT                                                    = 0x000006ad
RPC_S_OBJECT_NOT_FOUND                                                   = 0x000006ae
RPC_S_ALREADY_REGISTERED                                                 = 0x000006af
RPC_S_TYPE_ALREADY_REGISTERED                                            = 0x000006b0
RPC_S_ALREADY_LISTENING                                                  = 0x000006b1
RPC_S_NO_PROTSEQS_REGISTERED                                             = 0x000006b2
RPC_S_NOT_LISTENING                                                      = 0x000006b3
RPC_S_UNKNOWN_MGR_TYPE                                                   = 0x000006b4
RPC_S_UNKNOWN_IF                                                         = 0x000006b5
RPC_S_NO_BINDINGS                                                        = 0x000006b6
RPC_S_NO_PROTSEQS                                                        = 0x000006b7
RPC_S_CANT_CREATE_ENDPOINT                                               = 0x000006b8
RPC_S_OUT_OF_RESOURCES                                                   = 0x000006b9
RPC_S_SERVER_UNAVAILABLE                                                 = 0x000006ba
RPC_S_SERVER_TOO_BUSY                                                    = 0x000006bb
RPC_S_INVALID_NETWORK_OPTIONS                                            = 0x000006bc
RPC_S_NO_CALL_ACTIVE                                                     = 0x000006bd
RPC_S_CALL_FAILED                                                        = 0x000006be
RPC_S_CALL_FAILED_DNE                                                    = 0x000006bf
RPC_S_PROTOCOL_ERROR                                                     = 0x000006c0
RPC_S_PROXY_ACCESS_DENIED                                                = 0x000006c1
RPC_S_UNSUPPORTED_TRANS_SYN                                              = 0x000006c2
RPC_S_UNSUPPORTED_TYPE                                                   = 0x000006c4
RPC_S_INVALID_TAG                                                        = 0x000006c5
RPC_S_INVALID_BOUND                                                      = 0x000006c6
RPC_S_NO_ENTRY_NAME                                                      = 0x000006c7
RPC_S_INVALID_NAME_SYNTAX                                                = 0x000006c8
RPC_S_UNSUPPORTED_NAME_SYNTAX                                            = 0x000006c9
RPC_S_UUID_NO_ADDRESS                                                    = 0x000006cb
RPC_S_DUPLICATE_ENDPOINT                                                 = 0x000006cc
RPC_S_UNKNOWN_AUTHN_TYPE                                                 = 0x000006cd
RPC_S_MAX_CALLS_TOO_SMALL                                                = 0x000006ce
RPC_S_STRING_TOO_LONG                                                    = 0x000006cf
RPC_S_PROTSEQ_NOT_FOUND                                                  = 0x000006d0
RPC_S_PROCNUM_OUT_OF_RANGE                                               = 0x000006d1
RPC_S_BINDING_HAS_NO_AUTH                                                = 0x000006d2
RPC_S_UNKNOWN_AUTHN_SERVICE                                              = 0x000006d3
RPC_S_UNKNOWN_AUTHN_LEVEL                                                = 0x000006d4
RPC_S_INVALID_AUTH_IDENTITY                                              = 0x000006d5
RPC_S_UNKNOWN_AUTHZ_SERVICE                                              = 0x000006d6
EPT_S_INVALID_ENTRY                                                      = 0x000006d7
EPT_S_CANT_PERFORM_OP                                                    = 0x000006d8
EPT_S_NOT_REGISTERED                                                     = 0x000006d9
RPC_S_NOTHING_TO_EXPORT                                                  = 0x000006da
RPC_S_INCOMPLETE_NAME                                                    = 0x000006db
RPC_S_INVALID_VERS_OPTION                                                = 0x000006dc
RPC_S_NO_MORE_MEMBERS                                                    = 0x000006dd
RPC_S_NOT_ALL_OBJS_UNEXPORTED                                            = 0x000006de
RPC_S_INTERFACE_NOT_FOUND                                                = 0x000006df
RPC_S_ENTRY_ALREADY_EXISTS                                               = 0x000006e0
RPC_S_ENTRY_NOT_FOUND                                                    = 0x000006e1
RPC_S_NAME_SERVICE_UNAVAILABLE                                           = 0x000006e2
RPC_S_INVALID_NAF_ID                                                     = 0x000006e3
RPC_S_CANNOT_SUPPORT                                                     = 0x000006e4
RPC_S_NO_CONTEXT_AVAILABLE                                               = 0x000006e5
RPC_S_INTERNAL_ERROR                                                     = 0x000006e6
RPC_S_ZERO_DIVIDE                                                        = 0x000006e7
RPC_S_ADDRESS_ERROR                                                      = 0x000006e8
RPC_S_FP_DIV_ZERO                                                        = 0x000006e9
RPC_S_FP_UNDERFLOW                                                       = 0x000006ea
RPC_S_FP_OVERFLOW                                                        = 0x000006eb
RPC_X_NO_MORE_ENTRIES                                                    = 0x000006ec
RPC_X_SS_CHAR_TRANS_OPEN_FAIL                                            = 0x000006ed
RPC_X_SS_CHAR_TRANS_SHORT_FILE                                           = 0x000006ee
RPC_X_SS_IN_NULL_CONTEXT                                                 = 0x000006ef
RPC_X_SS_CONTEXT_DAMAGED                                                 = 0x000006f1
RPC_X_SS_HANDLES_MISMATCH                                                = 0x000006f2
RPC_X_SS_CANNOT_GET_CALL_HANDLE                                          = 0x000006f3
RPC_X_NULL_REF_POINTER                                                   = 0x000006f4
RPC_X_ENUM_VALUE_OUT_OF_RANGE                                            = 0x000006f5
RPC_X_BYTE_COUNT_TOO_SMALL                                               = 0x000006f6
RPC_X_BAD_STUB_DATA                                                      = 0x000006f7
ERROR_INVALID_USER_BUFFER                                                = 0x000006f8
ERROR_UNRECOGNIZED_MEDIA                                                 = 0x000006f9
ERROR_NO_TRUST_LSA_SECRET                                                = 0x000006fa
ERROR_NO_TRUST_SAM_ACCOUNT                                               = 0x000006fb
ERROR_TRUSTED_DOMAIN_FAILURE                                             = 0x000006fc
ERROR_TRUSTED_RELATIONSHIP_FAILURE                                       = 0x000006fd
ERROR_TRUST_FAILURE                                                      = 0x000006fe
RPC_S_CALL_IN_PROGRESS                                                   = 0x000006ff
ERROR_NETLOGON_NOT_STARTED                                               = 0x00000700
ERROR_ACCOUNT_EXPIRED                                                    = 0x00000701
ERROR_REDIRECTOR_HAS_OPEN_HANDLES                                        = 0x00000702
ERROR_PRINTER_DRIVER_ALREADY_INSTALLED                                   = 0x00000703
ERROR_UNKNOWN_PORT                                                       = 0x00000704
ERROR_UNKNOWN_PRINTER_DRIVER                                             = 0x00000705
ERROR_UNKNOWN_PRINTPROCESSOR                                             = 0x00000706
ERROR_INVALID_SEPARATOR_FILE                                             = 0x00000707
ERROR_INVALID_PRIORITY                                                   = 0x00000708
ERROR_INVALID_PRINTER_NAME                                               = 0x00000709
ERROR_PRINTER_ALREADY_EXISTS                                             = 0x0000070a
ERROR_INVALID_PRINTER_COMMAND                                            = 0x0000070b
ERROR_INVALID_DATATYPE                                                   = 0x0000070c
ERROR_INVALID_ENVIRONMENT                                                = 0x0000070d
RPC_S_NO_MORE_BINDINGS                                                   = 0x0000070e
ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT                                  = 0x0000070f
ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT                                  = 0x00000710
ERROR_NOLOGON_SERVER_TRUST_ACCOUNT                                       = 0x00000711
ERROR_DOMAIN_TRUST_INCONSISTENT                                          = 0x00000712
ERROR_SERVER_HAS_OPEN_HANDLES                                            = 0x00000713
ERROR_RESOURCE_DATA_NOT_FOUND                                            = 0x00000714
ERROR_RESOURCE_TYPE_NOT_FOUND                                            = 0x00000715
ERROR_RESOURCE_NAME_NOT_FOUND                                            = 0x00000716
ERROR_RESOURCE_LANG_NOT_FOUND                                            = 0x00000717
ERROR_NOT_ENOUGH_QUOTA                                                   = 0x00000718
RPC_S_NO_INTERFACES                                                      = 0x00000719
RPC_S_CALL_CANCELLED                                                     = 0x0000071a
RPC_S_BINDING_INCOMPLETE                                                 = 0x0000071b
RPC_S_COMM_FAILURE                                                       = 0x0000071c
RPC_S_UNSUPPORTED_AUTHN_LEVEL                                            = 0x0000071d
RPC_S_NO_PRINC_NAME                                                      = 0x0000071e
RPC_S_NOT_RPC_ERROR                                                      = 0x0000071f
RPC_S_UUID_LOCAL_ONLY                                                    = 0x00000720
RPC_S_SEC_PKG_ERROR                                                      = 0x00000721
RPC_S_NOT_CANCELLED                                                      = 0x00000722
RPC_X_INVALID_ES_ACTION                                                  = 0x00000723
RPC_X_WRONG_ES_VERSION                                                   = 0x00000724
RPC_X_WRONG_STUB_VERSION                                                 = 0x00000725
RPC_X_INVALID_PIPE_OBJECT                                                = 0x00000726
RPC_X_WRONG_PIPE_ORDER                                                   = 0x00000727
RPC_X_WRONG_PIPE_VERSION                                                 = 0x00000728
RPC_S_COOKIE_AUTH_FAILED                                                 = 0x00000729
RPC_S_GROUP_MEMBER_NOT_FOUND                                             = 0x0000076a
EPT_S_CANT_CREATE                                                        = 0x0000076b
RPC_S_INVALID_OBJECT                                                     = 0x0000076c
ERROR_INVALID_TIME                                                       = 0x0000076d
ERROR_INVALID_FORM_NAME                                                  = 0x0000076e
ERROR_INVALID_FORM_SIZE                                                  = 0x0000076f
ERROR_ALREADY_WAITING                                                    = 0x00000770
ERROR_PRINTER_DELETED                                                    = 0x00000771
ERROR_INVALID_PRINTER_STATE                                              = 0x00000772
ERROR_PASSWORD_MUST_CHANGE                                               = 0x00000773
ERROR_DOMAIN_CONTROLLER_NOT_FOUND                                        = 0x00000774
ERROR_ACCOUNT_LOCKED_OUT                                                 = 0x00000775
OR_INVALID_OXID                                                          = 0x00000776
OR_INVALID_OID                                                           = 0x00000777
OR_INVALID_SET                                                           = 0x00000778
RPC_S_SEND_INCOMPLETE                                                    = 0x00000779
RPC_S_INVALID_ASYNC_HANDLE                                               = 0x0000077a
RPC_S_INVALID_ASYNC_CALL                                                 = 0x0000077b
RPC_X_PIPE_CLOSED                                                        = 0x0000077c
RPC_X_PIPE_DISCIPLINE_ERROR                                              = 0x0000077d
RPC_X_PIPE_EMPTY                                                         = 0x0000077e
ERROR_NO_SITENAME                                                        = 0x0000077f
ERROR_CANT_ACCESS_FILE                                                   = 0x00000780
ERROR_CANT_RESOLVE_FILENAME                                              = 0x00000781
RPC_S_ENTRY_TYPE_MISMATCH                                                = 0x00000782
RPC_S_NOT_ALL_OBJS_EXPORTED                                              = 0x00000783
RPC_S_INTERFACE_NOT_EXPORTED                                             = 0x00000784
RPC_S_PROFILE_NOT_ADDED                                                  = 0x00000785
RPC_S_PRF_ELT_NOT_ADDED                                                  = 0x00000786
RPC_S_PRF_ELT_NOT_REMOVED                                                = 0x00000787
RPC_S_GRP_ELT_NOT_ADDED                                                  = 0x00000788
RPC_S_GRP_ELT_NOT_REMOVED                                                = 0x00000789
ERROR_KM_DRIVER_BLOCKED                                                  = 0x0000078a
ERROR_CONTEXT_EXPIRED                                                    = 0x0000078b
ERROR_PER_USER_TRUST_QUOTA_EXCEEDED                                      = 0x0000078c
ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED                                      = 0x0000078d
ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED                                   = 0x0000078e
ERROR_AUTHENTICATION_FIREWALL_FAILED                                     = 0x0000078f
ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED                                   = 0x00000790
ERROR_NTLM_BLOCKED                                                       = 0x00000791
ERROR_PASSWORD_CHANGE_REQUIRED                                           = 0x00000792
ERROR_INVALID_PIXEL_FORMAT                                               = 0x000007d0
ERROR_BAD_DRIVER                                                         = 0x000007d1
ERROR_INVALID_WINDOW_STYLE                                               = 0x000007d2
ERROR_METAFILE_NOT_SUPPORTED                                             = 0x000007d3
ERROR_TRANSFORM_NOT_SUPPORTED                                            = 0x000007d4
ERROR_CLIPPING_NOT_SUPPORTED                                             = 0x000007d5
ERROR_INVALID_CMM                                                        = 0x000007da
ERROR_INVALID_PROFILE                                                    = 0x000007db
ERROR_TAG_NOT_FOUND                                                      = 0x000007dc
ERROR_TAG_NOT_PRESENT                                                    = 0x000007dd
ERROR_DUPLICATE_TAG                                                      = 0x000007de
ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE                                 = 0x000007df
ERROR_PROFILE_NOT_FOUND                                                  = 0x000007e0
ERROR_INVALID_COLORSPACE                                                 = 0x000007e1
ERROR_ICM_NOT_ENABLED                                                    = 0x000007e2
ERROR_DELETING_ICM_XFORM                                                 = 0x000007e3
ERROR_INVALID_TRANSFORM                                                  = 0x000007e4
ERROR_COLORSPACE_MISMATCH                                                = 0x000007e5
ERROR_INVALID_COLORINDEX                                                 = 0x000007e6
ERROR_PROFILE_DOES_NOT_MATCH_DEVICE                                      = 0x000007e7
ERROR_CONNECTED_OTHER_PASSWORD                                           = 0x0000083c
ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT                                   = 0x0000083d
ERROR_BAD_USERNAME                                                       = 0x0000089a
ERROR_NOT_CONNECTED                                                      = 0x000008ca
ERROR_OPEN_FILES                                                         = 0x00000961
ERROR_ACTIVE_CONNECTIONS                                                 = 0x00000962
ERROR_DEVICE_IN_USE                                                      = 0x00000964
ERROR_UNKNOWN_PRINT_MONITOR                                              = 0x00000bb8
ERROR_PRINTER_DRIVER_IN_USE                                              = 0x00000bb9
ERROR_SPOOL_FILE_NOT_FOUND                                               = 0x00000bba
ERROR_SPL_NO_STARTDOC                                                    = 0x00000bbb
ERROR_SPL_NO_ADDJOB                                                      = 0x00000bbc
ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED                                  = 0x00000bbd
ERROR_PRINT_MONITOR_ALREADY_INSTALLED                                    = 0x00000bbe
ERROR_INVALID_PRINT_MONITOR                                              = 0x00000bbf
ERROR_PRINT_MONITOR_IN_USE                                               = 0x00000bc0
ERROR_PRINTER_HAS_JOBS_QUEUED                                            = 0x00000bc1
ERROR_SUCCESS_REBOOT_REQUIRED                                            = 0x00000bc2
ERROR_SUCCESS_RESTART_REQUIRED                                           = 0x00000bc3
ERROR_PRINTER_NOT_FOUND                                                  = 0x00000bc4
ERROR_PRINTER_DRIVER_WARNED                                              = 0x00000bc5
ERROR_PRINTER_DRIVER_BLOCKED                                             = 0x00000bc6
ERROR_PRINTER_DRIVER_PACKAGE_IN_USE                                      = 0x00000bc7
ERROR_CORE_DRIVER_PACKAGE_NOT_FOUND                                      = 0x00000bc8
ERROR_FAIL_REBOOT_REQUIRED                                               = 0x00000bc9
ERROR_FAIL_REBOOT_INITIATED                                              = 0x00000bca
ERROR_PRINTER_DRIVER_DOWNLOAD_NEEDED                                     = 0x00000bcb
ERROR_PRINT_JOB_RESTART_REQUIRED                                         = 0x00000bcc
ERROR_INVALID_PRINTER_DRIVER_MANIFEST                                    = 0x00000bcd
ERROR_PRINTER_NOT_SHAREABLE                                              = 0x00000bce
ERROR_REQUEST_PAUSED                                                     = 0x00000bea
ERROR_IO_REISSUE_AS_CACHED                                               = 0x00000f6e
ERROR_WINS_INTERNAL                                                      = 0x00000fa0
ERROR_CAN_NOT_DEL_LOCAL_WINS                                             = 0x00000fa1
ERROR_STATIC_INIT                                                        = 0x00000fa2
ERROR_INC_BACKUP                                                         = 0x00000fa3
ERROR_FULL_BACKUP                                                        = 0x00000fa4
ERROR_REC_NON_EXISTENT                                                   = 0x00000fa5
ERROR_RPL_NOT_ALLOWED                                                    = 0x00000fa6
PEERDIST_ERROR_CONTENTINFO_VERSION_UNSUPPORTED                           = 0x00000fd2
PEERDIST_ERROR_CANNOT_PARSE_CONTENTINFO                                  = 0x00000fd3
PEERDIST_ERROR_MISSING_DATA                                              = 0x00000fd4
PEERDIST_ERROR_NO_MORE                                                   = 0x00000fd5
PEERDIST_ERROR_NOT_INITIALIZED                                           = 0x00000fd6
PEERDIST_ERROR_ALREADY_INITIALIZED                                       = 0x00000fd7
PEERDIST_ERROR_SHUTDOWN_IN_PROGRESS                                      = 0x00000fd8
PEERDIST_ERROR_INVALIDATED                                               = 0x00000fd9
PEERDIST_ERROR_ALREADY_EXISTS                                            = 0x00000fda
PEERDIST_ERROR_OPERATION_NOTFOUND                                        = 0x00000fdb
PEERDIST_ERROR_ALREADY_COMPLETED                                         = 0x00000fdc
PEERDIST_ERROR_OUT_OF_BOUNDS                                             = 0x00000fdd
PEERDIST_ERROR_VERSION_UNSUPPORTED                                       = 0x00000fde
PEERDIST_ERROR_INVALID_CONFIGURATION                                     = 0x00000fdf
PEERDIST_ERROR_NOT_LICENSED                                              = 0x00000fe0
PEERDIST_ERROR_SERVICE_UNAVAILABLE                                       = 0x00000fe1
PEERDIST_ERROR_TRUST_FAILURE                                             = 0x00000fe2
ERROR_DHCP_ADDRESS_CONFLICT                                              = 0x00001004
ERROR_WMI_GUID_NOT_FOUND                                                 = 0x00001068
ERROR_WMI_INSTANCE_NOT_FOUND                                             = 0x00001069
ERROR_WMI_ITEMID_NOT_FOUND                                               = 0x0000106a
ERROR_WMI_TRY_AGAIN                                                      = 0x0000106b
ERROR_WMI_DP_NOT_FOUND                                                   = 0x0000106c
ERROR_WMI_UNRESOLVED_INSTANCE_REF                                        = 0x0000106d
ERROR_WMI_ALREADY_ENABLED                                                = 0x0000106e
ERROR_WMI_GUID_DISCONNECTED                                              = 0x0000106f
ERROR_WMI_SERVER_UNAVAILABLE                                             = 0x00001070
ERROR_WMI_DP_FAILED                                                      = 0x00001071
ERROR_WMI_INVALID_MOF                                                    = 0x00001072
ERROR_WMI_INVALID_REGINFO                                                = 0x00001073
ERROR_WMI_ALREADY_DISABLED                                               = 0x00001074
ERROR_WMI_READ_ONLY                                                      = 0x00001075
ERROR_WMI_SET_FAILURE                                                    = 0x00001076
ERROR_NOT_APPCONTAINER                                                   = 0x0000109a
ERROR_APPCONTAINER_REQUIRED                                              = 0x0000109b
ERROR_NOT_SUPPORTED_IN_APPCONTAINER                                      = 0x0000109c
ERROR_INVALID_PACKAGE_SID_LENGTH                                         = 0x0000109d
ERROR_INVALID_MEDIA                                                      = 0x000010cc
ERROR_INVALID_LIBRARY                                                    = 0x000010cd
ERROR_INVALID_MEDIA_POOL                                                 = 0x000010ce
ERROR_DRIVE_MEDIA_MISMATCH                                               = 0x000010cf
ERROR_MEDIA_OFFLINE                                                      = 0x000010d0
ERROR_LIBRARY_OFFLINE                                                    = 0x000010d1
ERROR_EMPTY                                                              = 0x000010d2
ERROR_NOT_EMPTY                                                          = 0x000010d3
ERROR_MEDIA_UNAVAILABLE                                                  = 0x000010d4
ERROR_RESOURCE_DISABLED                                                  = 0x000010d5
ERROR_INVALID_CLEANER                                                    = 0x000010d6
ERROR_UNABLE_TO_CLEAN                                                    = 0x000010d7
ERROR_OBJECT_NOT_FOUND                                                   = 0x000010d8
ERROR_DATABASE_FAILURE                                                   = 0x000010d9
ERROR_DATABASE_FULL                                                      = 0x000010da
ERROR_MEDIA_INCOMPATIBLE                                                 = 0x000010db
ERROR_RESOURCE_NOT_PRESENT                                               = 0x000010dc
ERROR_INVALID_OPERATION                                                  = 0x000010dd
ERROR_MEDIA_NOT_AVAILABLE                                                = 0x000010de
ERROR_DEVICE_NOT_AVAILABLE                                               = 0x000010df
ERROR_REQUEST_REFUSED                                                    = 0x000010e0
ERROR_INVALID_DRIVE_OBJECT                                               = 0x000010e1
ERROR_LIBRARY_FULL                                                       = 0x000010e2
ERROR_MEDIUM_NOT_ACCESSIBLE                                              = 0x000010e3
ERROR_UNABLE_TO_LOAD_MEDIUM                                              = 0x000010e4
ERROR_UNABLE_TO_INVENTORY_DRIVE                                          = 0x000010e5
ERROR_UNABLE_TO_INVENTORY_SLOT                                           = 0x000010e6
ERROR_UNABLE_TO_INVENTORY_TRANSPORT                                      = 0x000010e7
ERROR_TRANSPORT_FULL                                                     = 0x000010e8
ERROR_CONTROLLING_IEPORT                                                 = 0x000010e9
ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA                                      = 0x000010ea
ERROR_CLEANER_SLOT_SET                                                   = 0x000010eb
ERROR_CLEANER_SLOT_NOT_SET                                               = 0x000010ec
ERROR_CLEANER_CARTRIDGE_SPENT                                            = 0x000010ed
ERROR_UNEXPECTED_OMID                                                    = 0x000010ee
ERROR_CANT_DELETE_LAST_ITEM                                              = 0x000010ef
ERROR_MESSAGE_EXCEEDS_MAX_SIZE                                           = 0x000010f0
ERROR_VOLUME_CONTAINS_SYS_FILES                                          = 0x000010f1
ERROR_INDIGENOUS_TYPE                                                    = 0x000010f2
ERROR_NO_SUPPORTING_DRIVES                                               = 0x000010f3
ERROR_CLEANER_CARTRIDGE_INSTALLED                                        = 0x000010f4
ERROR_IEPORT_FULL                                                        = 0x000010f5
ERROR_FILE_OFFLINE                                                       = 0x000010fe
ERROR_REMOTE_STORAGE_NOT_ACTIVE                                          = 0x000010ff
ERROR_REMOTE_STORAGE_MEDIA_ERROR                                         = 0x00001100
ERROR_NOT_A_REPARSE_POINT                                                = 0x00001126
ERROR_REPARSE_ATTRIBUTE_CONFLICT                                         = 0x00001127
ERROR_INVALID_REPARSE_DATA                                               = 0x00001128
ERROR_REPARSE_TAG_INVALID                                                = 0x00001129
ERROR_REPARSE_TAG_MISMATCH                                               = 0x0000112a
ERROR_APP_DATA_NOT_FOUND                                                 = 0x00001130
ERROR_APP_DATA_EXPIRED                                                   = 0x00001131
ERROR_APP_DATA_CORRUPT                                                   = 0x00001132
ERROR_APP_DATA_LIMIT_EXCEEDED                                            = 0x00001133
ERROR_APP_DATA_REBOOT_REQUIRED                                           = 0x00001134
ERROR_SECUREBOOT_ROLLBACK_DETECTED                                       = 0x00001144
ERROR_SECUREBOOT_POLICY_VIOLATION                                        = 0x00001145
ERROR_SECUREBOOT_INVALID_POLICY                                          = 0x00001146
ERROR_SECUREBOOT_POLICY_PUBLISHER_NOT_FOUND                              = 0x00001147
ERROR_SECUREBOOT_POLICY_NOT_SIGNED                                       = 0x00001148
ERROR_SECUREBOOT_NOT_ENABLED                                             = 0x00001149
ERROR_SECUREBOOT_FILE_REPLACED                                           = 0x0000114a
ERROR_OFFLOAD_READ_FLT_NOT_SUPPORTED                                     = 0x00001158
ERROR_OFFLOAD_WRITE_FLT_NOT_SUPPORTED                                    = 0x00001159
ERROR_OFFLOAD_READ_FILE_NOT_SUPPORTED                                    = 0x0000115a
ERROR_OFFLOAD_WRITE_FILE_NOT_SUPPORTED                                   = 0x0000115b
ERROR_VOLUME_NOT_SIS_ENABLED                                             = 0x00001194
ERROR_DEPENDENT_RESOURCE_EXISTS                                          = 0x00001389
ERROR_DEPENDENCY_NOT_FOUND                                               = 0x0000138a
ERROR_DEPENDENCY_ALREADY_EXISTS                                          = 0x0000138b
ERROR_RESOURCE_NOT_ONLINE                                                = 0x0000138c
ERROR_HOST_NODE_NOT_AVAILABLE                                            = 0x0000138d
ERROR_RESOURCE_NOT_AVAILABLE                                             = 0x0000138e
ERROR_RESOURCE_NOT_FOUND                                                 = 0x0000138f
ERROR_SHUTDOWN_CLUSTER                                                   = 0x00001390
ERROR_CANT_EVICT_ACTIVE_NODE                                             = 0x00001391
ERROR_OBJECT_ALREADY_EXISTS                                              = 0x00001392
ERROR_OBJECT_IN_LIST                                                     = 0x00001393
ERROR_GROUP_NOT_AVAILABLE                                                = 0x00001394
ERROR_GROUP_NOT_FOUND                                                    = 0x00001395
ERROR_GROUP_NOT_ONLINE                                                   = 0x00001396
ERROR_HOST_NODE_NOT_RESOURCE_OWNER                                       = 0x00001397
ERROR_HOST_NODE_NOT_GROUP_OWNER                                          = 0x00001398
ERROR_RESMON_CREATE_FAILED                                               = 0x00001399
ERROR_RESMON_ONLINE_FAILED                                               = 0x0000139a
ERROR_RESOURCE_ONLINE                                                    = 0x0000139b
ERROR_QUORUM_RESOURCE                                                    = 0x0000139c
ERROR_NOT_QUORUM_CAPABLE                                                 = 0x0000139d
ERROR_CLUSTER_SHUTTING_DOWN                                              = 0x0000139e
ERROR_INVALID_STATE                                                      = 0x0000139f
ERROR_RESOURCE_PROPERTIES_STORED                                         = 0x000013a0
ERROR_NOT_QUORUM_CLASS                                                   = 0x000013a1
ERROR_CORE_RESOURCE                                                      = 0x000013a2
ERROR_QUORUM_RESOURCE_ONLINE_FAILED                                      = 0x000013a3
ERROR_QUORUMLOG_OPEN_FAILED                                              = 0x000013a4
ERROR_CLUSTERLOG_CORRUPT                                                 = 0x000013a5
ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE                                  = 0x000013a6
ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE                                         = 0x000013a7
ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND                                      = 0x000013a8
ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE                                        = 0x000013a9
ERROR_QUORUM_OWNER_ALIVE                                                 = 0x000013aa
ERROR_NETWORK_NOT_AVAILABLE                                              = 0x000013ab
ERROR_NODE_NOT_AVAILABLE                                                 = 0x000013ac
ERROR_ALL_NODES_NOT_AVAILABLE                                            = 0x000013ad
ERROR_RESOURCE_FAILED                                                    = 0x000013ae
ERROR_CLUSTER_INVALID_NODE                                               = 0x000013af
ERROR_CLUSTER_NODE_EXISTS                                                = 0x000013b0
ERROR_CLUSTER_JOIN_IN_PROGRESS                                           = 0x000013b1
ERROR_CLUSTER_NODE_NOT_FOUND                                             = 0x000013b2
ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND                                       = 0x000013b3
ERROR_CLUSTER_NETWORK_EXISTS                                             = 0x000013b4
ERROR_CLUSTER_NETWORK_NOT_FOUND                                          = 0x000013b5
ERROR_CLUSTER_NETINTERFACE_EXISTS                                        = 0x000013b6
ERROR_CLUSTER_NETINTERFACE_NOT_FOUND                                     = 0x000013b7
ERROR_CLUSTER_INVALID_REQUEST                                            = 0x000013b8
ERROR_CLUSTER_INVALID_NETWORK_PROVIDER                                   = 0x000013b9
ERROR_CLUSTER_NODE_DOWN                                                  = 0x000013ba
ERROR_CLUSTER_NODE_UNREACHABLE                                           = 0x000013bb
ERROR_CLUSTER_NODE_NOT_MEMBER                                            = 0x000013bc
ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS                                       = 0x000013bd
ERROR_CLUSTER_INVALID_NETWORK                                            = 0x000013be
ERROR_CLUSTER_NODE_UP                                                    = 0x000013c0
ERROR_CLUSTER_IPADDR_IN_USE                                              = 0x000013c1
ERROR_CLUSTER_NODE_NOT_PAUSED                                            = 0x000013c2
ERROR_CLUSTER_NO_SECURITY_CONTEXT                                        = 0x000013c3
ERROR_CLUSTER_NETWORK_NOT_INTERNAL                                       = 0x000013c4
ERROR_CLUSTER_NODE_ALREADY_UP                                            = 0x000013c5
ERROR_CLUSTER_NODE_ALREADY_DOWN                                          = 0x000013c6
ERROR_CLUSTER_NETWORK_ALREADY_ONLINE                                     = 0x000013c7
ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE                                    = 0x000013c8
ERROR_CLUSTER_NODE_ALREADY_MEMBER                                        = 0x000013c9
ERROR_CLUSTER_LAST_INTERNAL_NETWORK                                      = 0x000013ca
ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS                                     = 0x000013cb
ERROR_INVALID_OPERATION_ON_QUORUM                                        = 0x000013cc
ERROR_DEPENDENCY_NOT_ALLOWED                                             = 0x000013cd
ERROR_CLUSTER_NODE_PAUSED                                                = 0x000013ce
ERROR_NODE_CANT_HOST_RESOURCE                                            = 0x000013cf
ERROR_CLUSTER_NODE_NOT_READY                                             = 0x000013d0
ERROR_CLUSTER_NODE_SHUTTING_DOWN                                         = 0x000013d1
ERROR_CLUSTER_JOIN_ABORTED                                               = 0x000013d2
ERROR_CLUSTER_INCOMPATIBLE_VERSIONS                                      = 0x000013d3
ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED                               = 0x000013d4
ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED                                      = 0x000013d5
ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND                                    = 0x000013d6
ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED                                      = 0x000013d7
ERROR_CLUSTER_RESNAME_NOT_FOUND                                          = 0x000013d8
ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED                                 = 0x000013d9
ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST                                      = 0x000013da
ERROR_CLUSTER_DATABASE_SEQMISMATCH                                       = 0x000013db
ERROR_RESMON_INVALID_STATE                                               = 0x000013dc
ERROR_CLUSTER_GUM_NOT_LOCKER                                             = 0x000013dd
ERROR_QUORUM_DISK_NOT_FOUND                                              = 0x000013de
ERROR_DATABASE_BACKUP_CORRUPT                                            = 0x000013df
ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT                                  = 0x000013e0
ERROR_RESOURCE_PROPERTY_UNCHANGEABLE                                     = 0x000013e1
ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE                                   = 0x00001702
ERROR_CLUSTER_QUORUMLOG_NOT_FOUND                                        = 0x00001703
ERROR_CLUSTER_MEMBERSHIP_HALT                                            = 0x00001704
ERROR_CLUSTER_INSTANCE_ID_MISMATCH                                       = 0x00001705
ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP                                   = 0x00001706
ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH                                = 0x00001707
ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP                                      = 0x00001708
ERROR_CLUSTER_PARAMETER_MISMATCH                                         = 0x00001709
ERROR_NODE_CANNOT_BE_CLUSTERED                                           = 0x0000170a
ERROR_CLUSTER_WRONG_OS_VERSION                                           = 0x0000170b
ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME                               = 0x0000170c
ERROR_CLUSCFG_ALREADY_COMMITTED                                          = 0x0000170d
ERROR_CLUSCFG_ROLLBACK_FAILED                                            = 0x0000170e
ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT                          = 0x0000170f
ERROR_CLUSTER_OLD_VERSION                                                = 0x00001710
ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME                              = 0x00001711
ERROR_CLUSTER_NO_NET_ADAPTERS                                            = 0x00001712
ERROR_CLUSTER_POISONED                                                   = 0x00001713
ERROR_CLUSTER_GROUP_MOVING                                               = 0x00001714
ERROR_CLUSTER_RESOURCE_TYPE_BUSY                                         = 0x00001715
ERROR_RESOURCE_CALL_TIMED_OUT                                            = 0x00001716
ERROR_INVALID_CLUSTER_IPV6_ADDRESS                                       = 0x00001717
ERROR_CLUSTER_INTERNAL_INVALID_FUNCTION                                  = 0x00001718
ERROR_CLUSTER_PARAMETER_OUT_OF_BOUNDS                                    = 0x00001719
ERROR_CLUSTER_PARTIAL_SEND                                               = 0x0000171a
ERROR_CLUSTER_REGISTRY_INVALID_FUNCTION                                  = 0x0000171b
ERROR_CLUSTER_INVALID_STRING_TERMINATION                                 = 0x0000171c
ERROR_CLUSTER_INVALID_STRING_FORMAT                                      = 0x0000171d
ERROR_CLUSTER_DATABASE_TRANSACTION_IN_PROGRESS                           = 0x0000171e
ERROR_CLUSTER_DATABASE_TRANSACTION_NOT_IN_PROGRESS                       = 0x0000171f
ERROR_CLUSTER_NULL_DATA                                                  = 0x00001720
ERROR_CLUSTER_PARTIAL_READ                                               = 0x00001721
ERROR_CLUSTER_PARTIAL_WRITE                                              = 0x00001722
ERROR_CLUSTER_CANT_DESERIALIZE_DATA                                      = 0x00001723
ERROR_DEPENDENT_RESOURCE_PROPERTY_CONFLICT                               = 0x00001724
ERROR_CLUSTER_NO_QUORUM                                                  = 0x00001725
ERROR_CLUSTER_INVALID_IPV6_NETWORK                                       = 0x00001726
ERROR_CLUSTER_INVALID_IPV6_TUNNEL_NETWORK                                = 0x00001727
ERROR_QUORUM_NOT_ALLOWED_IN_THIS_GROUP                                   = 0x00001728
ERROR_DEPENDENCY_TREE_TOO_COMPLEX                                        = 0x00001729
ERROR_EXCEPTION_IN_RESOURCE_CALL                                         = 0x0000172a
ERROR_CLUSTER_RHS_FAILED_INITIALIZATION                                  = 0x0000172b
ERROR_CLUSTER_NOT_INSTALLED                                              = 0x0000172c
ERROR_CLUSTER_RESOURCES_MUST_BE_ONLINE_ON_THE_SAME_NODE                  = 0x0000172d
ERROR_CLUSTER_MAX_NODES_IN_CLUSTER                                       = 0x0000172e
ERROR_CLUSTER_TOO_MANY_NODES                                             = 0x0000172f
ERROR_CLUSTER_OBJECT_ALREADY_USED                                        = 0x00001730
ERROR_NONCORE_GROUPS_FOUND                                               = 0x00001731
ERROR_FILE_SHARE_RESOURCE_CONFLICT                                       = 0x00001732
ERROR_CLUSTER_EVICT_INVALID_REQUEST                                      = 0x00001733
ERROR_CLUSTER_SINGLETON_RESOURCE                                         = 0x00001734
ERROR_CLUSTER_GROUP_SINGLETON_RESOURCE                                   = 0x00001735
ERROR_CLUSTER_RESOURCE_PROVIDER_FAILED                                   = 0x00001736
ERROR_CLUSTER_RESOURCE_CONFIGURATION_ERROR                               = 0x00001737
ERROR_CLUSTER_GROUP_BUSY                                                 = 0x00001738
ERROR_CLUSTER_NOT_SHARED_VOLUME                                          = 0x00001739
ERROR_CLUSTER_INVALID_SECURITY_DESCRIPTOR                                = 0x0000173a
ERROR_CLUSTER_SHARED_VOLUMES_IN_USE                                      = 0x0000173b
ERROR_CLUSTER_USE_SHARED_VOLUMES_API                                     = 0x0000173c
ERROR_CLUSTER_BACKUP_IN_PROGRESS                                         = 0x0000173d
ERROR_NON_CSV_PATH                                                       = 0x0000173e
ERROR_CSV_VOLUME_NOT_LOCAL                                               = 0x0000173f
ERROR_CLUSTER_WATCHDOG_TERMINATING                                       = 0x00001740
ERROR_CLUSTER_RESOURCE_VETOED_MOVE_INCOMPATIBLE_NODES                    = 0x00001741
ERROR_CLUSTER_INVALID_NODE_WEIGHT                                        = 0x00001742
ERROR_CLUSTER_RESOURCE_VETOED_CALL                                       = 0x00001743
ERROR_RESMON_SYSTEM_RESOURCES_LACKING                                    = 0x00001744
ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_DESTINATION   = 0x00001745
ERROR_CLUSTER_RESOURCE_VETOED_MOVE_NOT_ENOUGH_RESOURCES_ON_SOURCE        = 0x00001746
ERROR_CLUSTER_GROUP_QUEUED                                               = 0x00001747
ERROR_CLUSTER_RESOURCE_LOCKED_STATUS                                     = 0x00001748
ERROR_CLUSTER_SHARED_VOLUME_FAILOVER_NOT_ALLOWED                         = 0x00001749
ERROR_CLUSTER_NODE_DRAIN_IN_PROGRESS                                     = 0x0000174a
ERROR_CLUSTER_DISK_NOT_CONNECTED                                         = 0x0000174b
ERROR_DISK_NOT_CSV_CAPABLE                                               = 0x0000174c
ERROR_RESOURCE_NOT_IN_AVAILABLE_STORAGE                                  = 0x0000174d
ERROR_CLUSTER_SHARED_VOLUME_REDIRECTED                                   = 0x0000174e
ERROR_CLUSTER_SHARED_VOLUME_NOT_REDIRECTED                               = 0x0000174f
ERROR_CLUSTER_CANNOT_RETURN_PROPERTIES                                   = 0x00001750
ERROR_CLUSTER_RESOURCE_CONTAINS_UNSUPPORTED_DIFF_AREA_FOR_SHARED_VOLUMES = 0x00001751
ERROR_CLUSTER_RESOURCE_IS_IN_MAINTENANCE_MODE                            = 0x00001752
ERROR_CLUSTER_AFFINITY_CONFLICT                                          = 0x00001753
ERROR_CLUSTER_RESOURCE_IS_REPLICA_VIRTUAL_MACHINE                        = 0x00001754
ERROR_ENCRYPTION_FAILED                                                  = 0x00001770
ERROR_DECRYPTION_FAILED                                                  = 0x00001771
ERROR_FILE_ENCRYPTED                                                     = 0x00001772
ERROR_NO_RECOVERY_POLICY                                                 = 0x00001773
ERROR_NO_EFS                                                             = 0x00001774
ERROR_WRONG_EFS                                                          = 0x00001775
ERROR_NO_USER_KEYS                                                       = 0x00001776
ERROR_FILE_NOT_ENCRYPTED                                                 = 0x00001777
ERROR_NOT_EXPORT_FORMAT                                                  = 0x00001778
ERROR_FILE_READ_ONLY                                                     = 0x00001779
ERROR_DIR_EFS_DISALLOWED                                                 = 0x0000177a
ERROR_EFS_SERVER_NOT_TRUSTED                                             = 0x0000177b
ERROR_BAD_RECOVERY_POLICY                                                = 0x0000177c
ERROR_EFS_ALG_BLOB_TOO_BIG                                               = 0x0000177d
ERROR_VOLUME_NOT_SUPPORT_EFS                                             = 0x0000177e
ERROR_EFS_DISABLED                                                       = 0x0000177f
ERROR_EFS_VERSION_NOT_SUPPORT                                            = 0x00001780
ERROR_CS_ENCRYPTION_INVALID_SERVER_RESPONSE                              = 0x00001781
ERROR_CS_ENCRYPTION_UNSUPPORTED_SERVER                                   = 0x00001782
ERROR_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE                              = 0x00001783
ERROR_CS_ENCRYPTION_NEW_ENCRYPTED_FILE                                   = 0x00001784
ERROR_CS_ENCRYPTION_FILE_NOT_CSE                                         = 0x00001785
ERROR_ENCRYPTION_POLICY_DENIES_OPERATION                                 = 0x00001786
ERROR_NO_BROWSER_SERVERS_FOUND                                           = 0x000017e6
SCHED_E_SERVICE_NOT_LOCALSYSTEM                                          = 0x00001838
ERROR_LOG_SECTOR_INVALID                                                 = 0x000019c8
ERROR_LOG_SECTOR_PARITY_INVALID                                          = 0x000019c9
ERROR_LOG_SECTOR_REMAPPED                                                = 0x000019ca
ERROR_LOG_BLOCK_INCOMPLETE                                               = 0x000019cb
ERROR_LOG_INVALID_RANGE                                                  = 0x000019cc
ERROR_LOG_BLOCKS_EXHAUSTED                                               = 0x000019cd
ERROR_LOG_READ_CONTEXT_INVALID                                           = 0x000019ce
ERROR_LOG_RESTART_INVALID                                                = 0x000019cf
ERROR_LOG_BLOCK_VERSION                                                  = 0x000019d0
ERROR_LOG_BLOCK_INVALID                                                  = 0x000019d1
ERROR_LOG_READ_MODE_INVALID                                              = 0x000019d2
ERROR_LOG_NO_RESTART                                                     = 0x000019d3
ERROR_LOG_METADATA_CORRUPT                                               = 0x000019d4
ERROR_LOG_METADATA_INVALID                                               = 0x000019d5
ERROR_LOG_METADATA_INCONSISTENT                                          = 0x000019d6
ERROR_LOG_RESERVATION_INVALID                                            = 0x000019d7
ERROR_LOG_CANT_DELETE                                                    = 0x000019d8
ERROR_LOG_CONTAINER_LIMIT_EXCEEDED                                       = 0x000019d9
ERROR_LOG_START_OF_LOG                                                   = 0x000019da
ERROR_LOG_POLICY_ALREADY_INSTALLED                                       = 0x000019db
ERROR_LOG_POLICY_NOT_INSTALLED                                           = 0x000019dc
ERROR_LOG_POLICY_INVALID                                                 = 0x000019dd
ERROR_LOG_POLICY_CONFLICT                                                = 0x000019de
ERROR_LOG_PINNED_ARCHIVE_TAIL                                            = 0x000019df
ERROR_LOG_RECORD_NONEXISTENT                                             = 0x000019e0
ERROR_LOG_RECORDS_RESERVED_INVALID                                       = 0x000019e1
ERROR_LOG_SPACE_RESERVED_INVALID                                         = 0x000019e2
ERROR_LOG_TAIL_INVALID                                                   = 0x000019e3
ERROR_LOG_FULL                                                           = 0x000019e4
ERROR_COULD_NOT_RESIZE_LOG                                               = 0x000019e5
ERROR_LOG_MULTIPLEXED                                                    = 0x000019e6
ERROR_LOG_DEDICATED                                                      = 0x000019e7
ERROR_LOG_ARCHIVE_NOT_IN_PROGRESS                                        = 0x000019e8
ERROR_LOG_ARCHIVE_IN_PROGRESS                                            = 0x000019e9
ERROR_LOG_EPHEMERAL                                                      = 0x000019ea
ERROR_LOG_NOT_ENOUGH_CONTAINERS                                          = 0x000019eb
ERROR_LOG_CLIENT_ALREADY_REGISTERED                                      = 0x000019ec
ERROR_LOG_CLIENT_NOT_REGISTERED                                          = 0x000019ed
ERROR_LOG_FULL_HANDLER_IN_PROGRESS                                       = 0x000019ee
ERROR_LOG_CONTAINER_READ_FAILED                                          = 0x000019ef
ERROR_LOG_CONTAINER_WRITE_FAILED                                         = 0x000019f0
ERROR_LOG_CONTAINER_OPEN_FAILED                                          = 0x000019f1
ERROR_LOG_CONTAINER_STATE_INVALID                                        = 0x000019f2
ERROR_LOG_STATE_INVALID                                                  = 0x000019f3
ERROR_LOG_PINNED                                                         = 0x000019f4
ERROR_LOG_METADATA_FLUSH_FAILED                                          = 0x000019f5
ERROR_LOG_INCONSISTENT_SECURITY                                          = 0x000019f6
ERROR_LOG_APPENDED_FLUSH_FAILED                                          = 0x000019f7
ERROR_LOG_PINNED_RESERVATION                                             = 0x000019f8
ERROR_INVALID_TRANSACTION                                                = 0x00001a2c
ERROR_TRANSACTION_NOT_ACTIVE                                             = 0x00001a2d
ERROR_TRANSACTION_REQUEST_NOT_VALID                                      = 0x00001a2e
ERROR_TRANSACTION_NOT_REQUESTED                                          = 0x00001a2f
ERROR_TRANSACTION_ALREADY_ABORTED                                        = 0x00001a30
ERROR_TRANSACTION_ALREADY_COMMITTED                                      = 0x00001a31
ERROR_TM_INITIALIZATION_FAILED                                           = 0x00001a32
ERROR_RESOURCEMANAGER_READ_ONLY                                          = 0x00001a33
ERROR_TRANSACTION_NOT_JOINED                                             = 0x00001a34
ERROR_TRANSACTION_SUPERIOR_EXISTS                                        = 0x00001a35
ERROR_CRM_PROTOCOL_ALREADY_EXISTS                                        = 0x00001a36
ERROR_TRANSACTION_PROPAGATION_FAILED                                     = 0x00001a37
ERROR_CRM_PROTOCOL_NOT_FOUND                                             = 0x00001a38
ERROR_TRANSACTION_INVALID_MARSHALL_BUFFER                                = 0x00001a39
ERROR_CURRENT_TRANSACTION_NOT_VALID                                      = 0x00001a3a
ERROR_TRANSACTION_NOT_FOUND                                              = 0x00001a3b
ERROR_RESOURCEMANAGER_NOT_FOUND                                          = 0x00001a3c
ERROR_ENLISTMENT_NOT_FOUND                                               = 0x00001a3d
ERROR_TRANSACTIONMANAGER_NOT_FOUND                                       = 0x00001a3e
ERROR_TRANSACTIONMANAGER_NOT_ONLINE                                      = 0x00001a3f
ERROR_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION                         = 0x00001a40
ERROR_TRANSACTION_NOT_ROOT                                               = 0x00001a41
ERROR_TRANSACTION_OBJECT_EXPIRED                                         = 0x00001a42
ERROR_TRANSACTION_RESPONSE_NOT_ENLISTED                                  = 0x00001a43
ERROR_TRANSACTION_RECORD_TOO_LONG                                        = 0x00001a44
ERROR_IMPLICIT_TRANSACTION_NOT_SUPPORTED                                 = 0x00001a45
ERROR_TRANSACTION_INTEGRITY_VIOLATED                                     = 0x00001a46
ERROR_TRANSACTIONMANAGER_IDENTITY_MISMATCH                               = 0x00001a47
ERROR_RM_CANNOT_BE_FROZEN_FOR_SNAPSHOT                                   = 0x00001a48
ERROR_TRANSACTION_MUST_WRITETHROUGH                                      = 0x00001a49
ERROR_TRANSACTION_NO_SUPERIOR                                            = 0x00001a4a
ERROR_HEURISTIC_DAMAGE_POSSIBLE                                          = 0x00001a4b
ERROR_TRANSACTIONAL_CONFLICT                                             = 0x00001a90
ERROR_RM_NOT_ACTIVE                                                      = 0x00001a91
ERROR_RM_METADATA_CORRUPT                                                = 0x00001a92
ERROR_DIRECTORY_NOT_RM                                                   = 0x00001a93
ERROR_TRANSACTIONS_UNSUPPORTED_REMOTE                                    = 0x00001a95
ERROR_LOG_RESIZE_INVALID_SIZE                                            = 0x00001a96
ERROR_OBJECT_NO_LONGER_EXISTS                                            = 0x00001a97
ERROR_STREAM_MINIVERSION_NOT_FOUND                                       = 0x00001a98
ERROR_STREAM_MINIVERSION_NOT_VALID                                       = 0x00001a99
ERROR_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION                = 0x00001a9a
ERROR_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT                           = 0x00001a9b
ERROR_CANT_CREATE_MORE_STREAM_MINIVERSIONS                               = 0x00001a9c
ERROR_REMOTE_FILE_VERSION_MISMATCH                                       = 0x00001a9e
ERROR_HANDLE_NO_LONGER_VALID                                             = 0x00001a9f
ERROR_NO_TXF_METADATA                                                    = 0x00001aa0
ERROR_LOG_CORRUPTION_DETECTED                                            = 0x00001aa1
ERROR_CANT_RECOVER_WITH_HANDLE_OPEN                                      = 0x00001aa2
ERROR_RM_DISCONNECTED                                                    = 0x00001aa3
ERROR_ENLISTMENT_NOT_SUPERIOR                                            = 0x00001aa4
ERROR_RECOVERY_NOT_NEEDED                                                = 0x00001aa5
ERROR_RM_ALREADY_STARTED                                                 = 0x00001aa6
ERROR_FILE_IDENTITY_NOT_PERSISTENT                                       = 0x00001aa7
ERROR_CANT_BREAK_TRANSACTIONAL_DEPENDENCY                                = 0x00001aa8
ERROR_CANT_CROSS_RM_BOUNDARY                                             = 0x00001aa9
ERROR_TXF_DIR_NOT_EMPTY                                                  = 0x00001aaa
ERROR_INDOUBT_TRANSACTIONS_EXIST                                         = 0x00001aab
ERROR_TM_VOLATILE                                                        = 0x00001aac
ERROR_ROLLBACK_TIMER_EXPIRED                                             = 0x00001aad
ERROR_TXF_ATTRIBUTE_CORRUPT                                              = 0x00001aae
ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION                                     = 0x00001aaf
ERROR_TRANSACTIONAL_OPEN_NOT_ALLOWED                                     = 0x00001ab0
ERROR_LOG_GROWTH_FAILED                                                  = 0x00001ab1
ERROR_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE                              = 0x00001ab2
ERROR_TXF_METADATA_ALREADY_PRESENT                                       = 0x00001ab3
ERROR_TRANSACTION_SCOPE_CALLBACKS_NOT_SET                                = 0x00001ab4
ERROR_TRANSACTION_REQUIRED_PROMOTION                                     = 0x00001ab5
ERROR_CANNOT_EXECUTE_FILE_IN_TRANSACTION                                 = 0x00001ab6
ERROR_TRANSACTIONS_NOT_FROZEN                                            = 0x00001ab7
ERROR_TRANSACTION_FREEZE_IN_PROGRESS                                     = 0x00001ab8
ERROR_NOT_SNAPSHOT_VOLUME                                                = 0x00001ab9
ERROR_NO_SAVEPOINT_WITH_OPEN_FILES                                       = 0x00001aba
ERROR_DATA_LOST_REPAIR                                                   = 0x00001abb
ERROR_SPARSE_NOT_ALLOWED_IN_TRANSACTION                                  = 0x00001abc
ERROR_TM_IDENTITY_MISMATCH                                               = 0x00001abd
ERROR_FLOATED_SECTION                                                    = 0x00001abe
ERROR_CANNOT_ACCEPT_TRANSACTED_WORK                                      = 0x00001abf
ERROR_CANNOT_ABORT_TRANSACTIONS                                          = 0x00001ac0
ERROR_BAD_CLUSTERS                                                       = 0x00001ac1
ERROR_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION                             = 0x00001ac2
ERROR_VOLUME_DIRTY                                                       = 0x00001ac3
ERROR_NO_LINK_TRACKING_IN_TRANSACTION                                    = 0x00001ac4
ERROR_OPERATION_NOT_SUPPORTED_IN_TRANSACTION                             = 0x00001ac5
ERROR_EXPIRED_HANDLE                                                     = 0x00001ac6
ERROR_TRANSACTION_NOT_ENLISTED                                           = 0x00001ac7
ERROR_CTX_WINSTATION_NAME_INVALID                                        = 0x00001b59
ERROR_CTX_INVALID_PD                                                     = 0x00001b5a
ERROR_CTX_PD_NOT_FOUND                                                   = 0x00001b5b
ERROR_CTX_WD_NOT_FOUND                                                   = 0x00001b5c
ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY                                     = 0x00001b5d
ERROR_CTX_SERVICE_NAME_COLLISION                                         = 0x00001b5e
ERROR_CTX_CLOSE_PENDING                                                  = 0x00001b5f
ERROR_CTX_NO_OUTBUF                                                      = 0x00001b60
ERROR_CTX_MODEM_INF_NOT_FOUND                                            = 0x00001b61
ERROR_CTX_INVALID_MODEMNAME                                              = 0x00001b62
ERROR_CTX_MODEM_RESPONSE_ERROR                                           = 0x00001b63
ERROR_CTX_MODEM_RESPONSE_TIMEOUT                                         = 0x00001b64
ERROR_CTX_MODEM_RESPONSE_NO_CARRIER                                      = 0x00001b65
ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE                                     = 0x00001b66
ERROR_CTX_MODEM_RESPONSE_BUSY                                            = 0x00001b67
ERROR_CTX_MODEM_RESPONSE_VOICE                                           = 0x00001b68
ERROR_CTX_TD_ERROR                                                       = 0x00001b69
ERROR_CTX_WINSTATION_NOT_FOUND                                           = 0x00001b6e
ERROR_CTX_WINSTATION_ALREADY_EXISTS                                      = 0x00001b6f
ERROR_CTX_WINSTATION_BUSY                                                = 0x00001b70
ERROR_CTX_BAD_VIDEO_MODE                                                 = 0x00001b71
ERROR_CTX_GRAPHICS_INVALID                                               = 0x00001b7b
ERROR_CTX_LOGON_DISABLED                                                 = 0x00001b7d
ERROR_CTX_NOT_CONSOLE                                                    = 0x00001b7e
ERROR_CTX_CLIENT_QUERY_TIMEOUT                                           = 0x00001b80
ERROR_CTX_CONSOLE_DISCONNECT                                             = 0x00001b81
ERROR_CTX_CONSOLE_CONNECT                                                = 0x00001b82
ERROR_CTX_SHADOW_DENIED                                                  = 0x00001b84
ERROR_CTX_WINSTATION_ACCESS_DENIED                                       = 0x00001b85
ERROR_CTX_INVALID_WD                                                     = 0x00001b89
ERROR_CTX_SHADOW_INVALID                                                 = 0x00001b8a
ERROR_CTX_SHADOW_DISABLED                                                = 0x00001b8b
ERROR_CTX_CLIENT_LICENSE_IN_USE                                          = 0x00001b8c
ERROR_CTX_CLIENT_LICENSE_NOT_SET                                         = 0x00001b8d
ERROR_CTX_LICENSE_NOT_AVAILABLE                                          = 0x00001b8e
ERROR_CTX_LICENSE_CLIENT_INVALID                                         = 0x00001b8f
ERROR_CTX_LICENSE_EXPIRED                                                = 0x00001b90
ERROR_CTX_SHADOW_NOT_RUNNING                                             = 0x00001b91
ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE                                    = 0x00001b92
ERROR_ACTIVATION_COUNT_EXCEEDED                                          = 0x00001b93
ERROR_CTX_WINSTATIONS_DISABLED                                           = 0x00001b94
ERROR_CTX_ENCRYPTION_LEVEL_REQUIRED                                      = 0x00001b95
ERROR_CTX_SESSION_IN_USE                                                 = 0x00001b96
ERROR_CTX_NO_FORCE_LOGOFF                                                = 0x00001b97
ERROR_CTX_ACCOUNT_RESTRICTION                                            = 0x00001b98
ERROR_RDP_PROTOCOL_ERROR                                                 = 0x00001b99
ERROR_CTX_CDM_CONNECT                                                    = 0x00001b9a
ERROR_CTX_CDM_DISCONNECT                                                 = 0x00001b9b
ERROR_CTX_SECURITY_LAYER_ERROR                                           = 0x00001b9c
ERROR_TS_INCOMPATIBLE_SESSIONS                                           = 0x00001b9d
ERROR_TS_VIDEO_SUBSYSTEM_ERROR                                           = 0x00001b9e
FRS_ERR_INVALID_API_SEQUENCE                                             = 0x00001f41
FRS_ERR_STARTING_SERVICE                                                 = 0x00001f42
FRS_ERR_STOPPING_SERVICE                                                 = 0x00001f43
FRS_ERR_INTERNAL_API                                                     = 0x00001f44
FRS_ERR_INTERNAL                                                         = 0x00001f45
FRS_ERR_SERVICE_COMM                                                     = 0x00001f46
FRS_ERR_INSUFFICIENT_PRIV                                                = 0x00001f47
FRS_ERR_AUTHENTICATION                                                   = 0x00001f48
FRS_ERR_PARENT_INSUFFICIENT_PRIV                                         = 0x00001f49
FRS_ERR_PARENT_AUTHENTICATION                                            = 0x00001f4a
FRS_ERR_CHILD_TO_PARENT_COMM                                             = 0x00001f4b
FRS_ERR_PARENT_TO_CHILD_COMM                                             = 0x00001f4c
FRS_ERR_SYSVOL_POPULATE                                                  = 0x00001f4d
FRS_ERR_SYSVOL_POPULATE_TIMEOUT                                          = 0x00001f4e
FRS_ERR_SYSVOL_IS_BUSY                                                   = 0x00001f4f
FRS_ERR_SYSVOL_DEMOTE                                                    = 0x00001f50
FRS_ERR_INVALID_SERVICE_PARAMETER                                        = 0x00001f51
ERROR_DS_NOT_INSTALLED                                                   = 0x00002008
ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY                                    = 0x00002009
ERROR_DS_NO_ATTRIBUTE_OR_VALUE                                           = 0x0000200a
ERROR_DS_INVALID_ATTRIBUTE_SYNTAX                                        = 0x0000200b
ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED                                        = 0x0000200c
ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS                                       = 0x0000200d
ERROR_DS_BUSY                                                            = 0x0000200e
ERROR_DS_UNAVAILABLE                                                     = 0x0000200f
ERROR_DS_NO_RIDS_ALLOCATED                                               = 0x00002010
ERROR_DS_NO_MORE_RIDS                                                    = 0x00002011
ERROR_DS_INCORRECT_ROLE_OWNER                                            = 0x00002012
ERROR_DS_RIDMGR_INIT_ERROR                                               = 0x00002013
ERROR_DS_OBJ_CLASS_VIOLATION                                             = 0x00002014
ERROR_DS_CANT_ON_NON_LEAF                                                = 0x00002015
ERROR_DS_CANT_ON_RDN                                                     = 0x00002016
ERROR_DS_CANT_MOD_OBJ_CLASS                                              = 0x00002017
ERROR_DS_CROSS_DOM_MOVE_ERROR                                            = 0x00002018
ERROR_DS_GC_NOT_AVAILABLE                                                = 0x00002019
ERROR_SHARED_POLICY                                                      = 0x0000201a
ERROR_POLICY_OBJECT_NOT_FOUND                                            = 0x0000201b
ERROR_POLICY_ONLY_IN_DS                                                  = 0x0000201c
ERROR_PROMOTION_ACTIVE                                                   = 0x0000201d
ERROR_NO_PROMOTION_ACTIVE                                                = 0x0000201e
ERROR_DS_OPERATIONS_ERROR                                                = 0x00002020
ERROR_DS_PROTOCOL_ERROR                                                  = 0x00002021
ERROR_DS_TIMELIMIT_EXCEEDED                                              = 0x00002022
ERROR_DS_SIZELIMIT_EXCEEDED                                              = 0x00002023
ERROR_DS_ADMIN_LIMIT_EXCEEDED                                            = 0x00002024
ERROR_DS_COMPARE_FALSE                                                   = 0x00002025
ERROR_DS_COMPARE_TRUE                                                    = 0x00002026
ERROR_DS_AUTH_METHOD_NOT_SUPPORTED                                       = 0x00002027
ERROR_DS_STRONG_AUTH_REQUIRED                                            = 0x00002028
ERROR_DS_INAPPROPRIATE_AUTH                                              = 0x00002029
ERROR_DS_AUTH_UNKNOWN                                                    = 0x0000202a
ERROR_DS_REFERRAL                                                        = 0x0000202b
ERROR_DS_UNAVAILABLE_CRIT_EXTENSION                                      = 0x0000202c
ERROR_DS_CONFIDENTIALITY_REQUIRED                                        = 0x0000202d
ERROR_DS_INAPPROPRIATE_MATCHING                                          = 0x0000202e
ERROR_DS_CONSTRAINT_VIOLATION                                            = 0x0000202f
ERROR_DS_NO_SUCH_OBJECT                                                  = 0x00002030
ERROR_DS_ALIAS_PROBLEM                                                   = 0x00002031
ERROR_DS_INVALID_DN_SYNTAX                                               = 0x00002032
ERROR_DS_IS_LEAF                                                         = 0x00002033
ERROR_DS_ALIAS_DEREF_PROBLEM                                             = 0x00002034
ERROR_DS_UNWILLING_TO_PERFORM                                            = 0x00002035
ERROR_DS_LOOP_DETECT                                                     = 0x00002036
ERROR_DS_NAMING_VIOLATION                                                = 0x00002037
ERROR_DS_OBJECT_RESULTS_TOO_LARGE                                        = 0x00002038
ERROR_DS_AFFECTS_MULTIPLE_DSAS                                           = 0x00002039
ERROR_DS_SERVER_DOWN                                                     = 0x0000203a
ERROR_DS_LOCAL_ERROR                                                     = 0x0000203b
ERROR_DS_ENCODING_ERROR                                                  = 0x0000203c
ERROR_DS_DECODING_ERROR                                                  = 0x0000203d
ERROR_DS_FILTER_UNKNOWN                                                  = 0x0000203e
ERROR_DS_PARAM_ERROR                                                     = 0x0000203f
ERROR_DS_NOT_SUPPORTED                                                   = 0x00002040
ERROR_DS_NO_RESULTS_RETURNED                                             = 0x00002041
ERROR_DS_CONTROL_NOT_FOUND                                               = 0x00002042
ERROR_DS_CLIENT_LOOP                                                     = 0x00002043
ERROR_DS_REFERRAL_LIMIT_EXCEEDED                                         = 0x00002044
ERROR_DS_SORT_CONTROL_MISSING                                            = 0x00002045
ERROR_DS_OFFSET_RANGE_ERROR                                              = 0x00002046
ERROR_DS_RIDMGR_DISABLED                                                 = 0x00002047
ERROR_DS_ROOT_MUST_BE_NC                                                 = 0x0000206d
ERROR_DS_ADD_REPLICA_INHIBITED                                           = 0x0000206e
ERROR_DS_ATT_NOT_DEF_IN_SCHEMA                                           = 0x0000206f
ERROR_DS_MAX_OBJ_SIZE_EXCEEDED                                           = 0x00002070
ERROR_DS_OBJ_STRING_NAME_EXISTS                                          = 0x00002071
ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA                                        = 0x00002072
ERROR_DS_RDN_DOESNT_MATCH_SCHEMA                                         = 0x00002073
ERROR_DS_NO_REQUESTED_ATTS_FOUND                                         = 0x00002074
ERROR_DS_USER_BUFFER_TO_SMALL                                            = 0x00002075
ERROR_DS_ATT_IS_NOT_ON_OBJ                                               = 0x00002076
ERROR_DS_ILLEGAL_MOD_OPERATION                                           = 0x00002077
ERROR_DS_OBJ_TOO_LARGE                                                   = 0x00002078
ERROR_DS_BAD_INSTANCE_TYPE                                               = 0x00002079
ERROR_DS_MASTERDSA_REQUIRED                                              = 0x0000207a
ERROR_DS_OBJECT_CLASS_REQUIRED                                           = 0x0000207b
ERROR_DS_MISSING_REQUIRED_ATT                                            = 0x0000207c
ERROR_DS_ATT_NOT_DEF_FOR_CLASS                                           = 0x0000207d
ERROR_DS_ATT_ALREADY_EXISTS                                              = 0x0000207e
ERROR_DS_CANT_ADD_ATT_VALUES                                             = 0x00002080
ERROR_DS_SINGLE_VALUE_CONSTRAINT                                         = 0x00002081
ERROR_DS_RANGE_CONSTRAINT                                                = 0x00002082
ERROR_DS_ATT_VAL_ALREADY_EXISTS                                          = 0x00002083
ERROR_DS_CANT_REM_MISSING_ATT                                            = 0x00002084
ERROR_DS_CANT_REM_MISSING_ATT_VAL                                        = 0x00002085
ERROR_DS_ROOT_CANT_BE_SUBREF                                             = 0x00002086
ERROR_DS_NO_CHAINING                                                     = 0x00002087
ERROR_DS_NO_CHAINED_EVAL                                                 = 0x00002088
ERROR_DS_NO_PARENT_OBJECT                                                = 0x00002089
ERROR_DS_PARENT_IS_AN_ALIAS                                              = 0x0000208a
ERROR_DS_CANT_MIX_MASTER_AND_REPS                                        = 0x0000208b
ERROR_DS_CHILDREN_EXIST                                                  = 0x0000208c
ERROR_DS_OBJ_NOT_FOUND                                                   = 0x0000208d
ERROR_DS_ALIASED_OBJ_MISSING                                             = 0x0000208e
ERROR_DS_BAD_NAME_SYNTAX                                                 = 0x0000208f
ERROR_DS_ALIAS_POINTS_TO_ALIAS                                           = 0x00002090
ERROR_DS_CANT_DEREF_ALIAS                                                = 0x00002091
ERROR_DS_OUT_OF_SCOPE                                                    = 0x00002092
ERROR_DS_OBJECT_BEING_REMOVED                                            = 0x00002093
ERROR_DS_CANT_DELETE_DSA_OBJ                                             = 0x00002094
ERROR_DS_GENERIC_ERROR                                                   = 0x00002095
ERROR_DS_DSA_MUST_BE_INT_MASTER                                          = 0x00002096
ERROR_DS_CLASS_NOT_DSA                                                   = 0x00002097
ERROR_DS_INSUFF_ACCESS_RIGHTS                                            = 0x00002098
ERROR_DS_ILLEGAL_SUPERIOR                                                = 0x00002099
ERROR_DS_ATTRIBUTE_OWNED_BY_SAM                                          = 0x0000209a
ERROR_DS_NAME_TOO_MANY_PARTS                                             = 0x0000209b
ERROR_DS_NAME_TOO_LONG                                                   = 0x0000209c
ERROR_DS_NAME_VALUE_TOO_LONG                                             = 0x0000209d
ERROR_DS_NAME_UNPARSEABLE                                                = 0x0000209e
ERROR_DS_NAME_TYPE_UNKNOWN                                               = 0x0000209f
ERROR_DS_NOT_AN_OBJECT                                                   = 0x000020a0
ERROR_DS_SEC_DESC_TOO_SHORT                                              = 0x000020a1
ERROR_DS_SEC_DESC_INVALID                                                = 0x000020a2
ERROR_DS_NO_DELETED_NAME                                                 = 0x000020a3
ERROR_DS_SUBREF_MUST_HAVE_PARENT                                         = 0x000020a4
ERROR_DS_NCNAME_MUST_BE_NC                                               = 0x000020a5
ERROR_DS_CANT_ADD_SYSTEM_ONLY                                            = 0x000020a6
ERROR_DS_CLASS_MUST_BE_CONCRETE                                          = 0x000020a7
ERROR_DS_INVALID_DMD                                                     = 0x000020a8
ERROR_DS_OBJ_GUID_EXISTS                                                 = 0x000020a9
ERROR_DS_NOT_ON_BACKLINK                                                 = 0x000020aa
ERROR_DS_NO_CROSSREF_FOR_NC                                              = 0x000020ab
ERROR_DS_SHUTTING_DOWN                                                   = 0x000020ac
ERROR_DS_UNKNOWN_OPERATION                                               = 0x000020ad
ERROR_DS_INVALID_ROLE_OWNER                                              = 0x000020ae
ERROR_DS_COULDNT_CONTACT_FSMO                                            = 0x000020af
ERROR_DS_CROSS_NC_DN_RENAME                                              = 0x000020b0
ERROR_DS_CANT_MOD_SYSTEM_ONLY                                            = 0x000020b1
ERROR_DS_REPLICATOR_ONLY                                                 = 0x000020b2
ERROR_DS_OBJ_CLASS_NOT_DEFINED                                           = 0x000020b3
ERROR_DS_OBJ_CLASS_NOT_SUBCLASS                                          = 0x000020b4
ERROR_DS_NAME_REFERENCE_INVALID                                          = 0x000020b5
ERROR_DS_CROSS_REF_EXISTS                                                = 0x000020b6
ERROR_DS_CANT_DEL_MASTER_CROSSREF                                        = 0x000020b7
ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD                                      = 0x000020b8
ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX                                       = 0x000020b9
ERROR_DS_DUP_RDN                                                         = 0x000020ba
ERROR_DS_DUP_OID                                                         = 0x000020bb
ERROR_DS_DUP_MAPI_ID                                                     = 0x000020bc
ERROR_DS_DUP_SCHEMA_ID_GUID                                              = 0x000020bd
ERROR_DS_DUP_LDAP_DISPLAY_NAME                                           = 0x000020be
ERROR_DS_SEMANTIC_ATT_TEST                                               = 0x000020bf
ERROR_DS_SYNTAX_MISMATCH                                                 = 0x000020c0
ERROR_DS_EXISTS_IN_MUST_HAVE                                             = 0x000020c1
ERROR_DS_EXISTS_IN_MAY_HAVE                                              = 0x000020c2
ERROR_DS_NONEXISTENT_MAY_HAVE                                            = 0x000020c3
ERROR_DS_NONEXISTENT_MUST_HAVE                                           = 0x000020c4
ERROR_DS_AUX_CLS_TEST_FAIL                                               = 0x000020c5
ERROR_DS_NONEXISTENT_POSS_SUP                                            = 0x000020c6
ERROR_DS_SUB_CLS_TEST_FAIL                                               = 0x000020c7
ERROR_DS_BAD_RDN_ATT_ID_SYNTAX                                           = 0x000020c8
ERROR_DS_EXISTS_IN_AUX_CLS                                               = 0x000020c9
ERROR_DS_EXISTS_IN_SUB_CLS                                               = 0x000020ca
ERROR_DS_EXISTS_IN_POSS_SUP                                              = 0x000020cb
ERROR_DS_RECALCSCHEMA_FAILED                                             = 0x000020cc
ERROR_DS_TREE_DELETE_NOT_FINISHED                                        = 0x000020cd
ERROR_DS_CANT_DELETE                                                     = 0x000020ce
ERROR_DS_ATT_SCHEMA_REQ_ID                                               = 0x000020cf
ERROR_DS_BAD_ATT_SCHEMA_SYNTAX                                           = 0x000020d0
ERROR_DS_CANT_CACHE_ATT                                                  = 0x000020d1
ERROR_DS_CANT_CACHE_CLASS                                                = 0x000020d2
ERROR_DS_CANT_REMOVE_ATT_CACHE                                           = 0x000020d3
ERROR_DS_CANT_REMOVE_CLASS_CACHE                                         = 0x000020d4
ERROR_DS_CANT_RETRIEVE_DN                                                = 0x000020d5
ERROR_DS_MISSING_SUPREF                                                  = 0x000020d6
ERROR_DS_CANT_RETRIEVE_INSTANCE                                          = 0x000020d7
ERROR_DS_CODE_INCONSISTENCY                                              = 0x000020d8
ERROR_DS_DATABASE_ERROR                                                  = 0x000020d9
ERROR_DS_GOVERNSID_MISSING                                               = 0x000020da
ERROR_DS_MISSING_EXPECTED_ATT                                            = 0x000020db
ERROR_DS_NCNAME_MISSING_CR_REF                                           = 0x000020dc
ERROR_DS_SECURITY_CHECKING_ERROR                                         = 0x000020dd
ERROR_DS_SCHEMA_NOT_LOADED                                               = 0x000020de
ERROR_DS_SCHEMA_ALLOC_FAILED                                             = 0x000020df
ERROR_DS_ATT_SCHEMA_REQ_SYNTAX                                           = 0x000020e0
ERROR_DS_GCVERIFY_ERROR                                                  = 0x000020e1
ERROR_DS_DRA_SCHEMA_MISMATCH                                             = 0x000020e2
ERROR_DS_CANT_FIND_DSA_OBJ                                               = 0x000020e3
ERROR_DS_CANT_FIND_EXPECTED_NC                                           = 0x000020e4
ERROR_DS_CANT_FIND_NC_IN_CACHE                                           = 0x000020e5
ERROR_DS_CANT_RETRIEVE_CHILD                                             = 0x000020e6
ERROR_DS_SECURITY_ILLEGAL_MODIFY                                         = 0x000020e7
ERROR_DS_CANT_REPLACE_HIDDEN_REC                                         = 0x000020e8
ERROR_DS_BAD_HIERARCHY_FILE                                              = 0x000020e9
ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED                                    = 0x000020ea
ERROR_DS_CONFIG_PARAM_MISSING                                            = 0x000020eb
ERROR_DS_COUNTING_AB_INDICES_FAILED                                      = 0x000020ec
ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED                                   = 0x000020ed
ERROR_DS_INTERNAL_FAILURE                                                = 0x000020ee
ERROR_DS_UNKNOWN_ERROR                                                   = 0x000020ef
ERROR_DS_ROOT_REQUIRES_CLASS_TOP                                         = 0x000020f0
ERROR_DS_REFUSING_FSMO_ROLES                                             = 0x000020f1
ERROR_DS_MISSING_FSMO_SETTINGS                                           = 0x000020f2
ERROR_DS_UNABLE_TO_SURRENDER_ROLES                                       = 0x000020f3
ERROR_DS_DRA_GENERIC                                                     = 0x000020f4
ERROR_DS_DRA_INVALID_PARAMETER                                           = 0x000020f5
ERROR_DS_DRA_BUSY                                                        = 0x000020f6
ERROR_DS_DRA_BAD_DN                                                      = 0x000020f7
ERROR_DS_DRA_BAD_NC                                                      = 0x000020f8
ERROR_DS_DRA_DN_EXISTS                                                   = 0x000020f9
ERROR_DS_DRA_INTERNAL_ERROR                                              = 0x000020fa
ERROR_DS_DRA_INCONSISTENT_DIT                                            = 0x000020fb
ERROR_DS_DRA_CONNECTION_FAILED                                           = 0x000020fc
ERROR_DS_DRA_BAD_INSTANCE_TYPE                                           = 0x000020fd
ERROR_DS_DRA_OUT_OF_MEM                                                  = 0x000020fe
ERROR_DS_DRA_MAIL_PROBLEM                                                = 0x000020ff
ERROR_DS_DRA_REF_ALREADY_EXISTS                                          = 0x00002100
ERROR_DS_DRA_REF_NOT_FOUND                                               = 0x00002101
ERROR_DS_DRA_OBJ_IS_REP_SOURCE                                           = 0x00002102
ERROR_DS_DRA_DB_ERROR                                                    = 0x00002103
ERROR_DS_DRA_NO_REPLICA                                                  = 0x00002104
ERROR_DS_DRA_ACCESS_DENIED                                               = 0x00002105
ERROR_DS_DRA_NOT_SUPPORTED                                               = 0x00002106
ERROR_DS_DRA_RPC_CANCELLED                                               = 0x00002107
ERROR_DS_DRA_SOURCE_DISABLED                                             = 0x00002108
ERROR_DS_DRA_SINK_DISABLED                                               = 0x00002109
ERROR_DS_DRA_NAME_COLLISION                                              = 0x0000210a
ERROR_DS_DRA_SOURCE_REINSTALLED                                          = 0x0000210b
ERROR_DS_DRA_MISSING_PARENT                                              = 0x0000210c
ERROR_DS_DRA_PREEMPTED                                                   = 0x0000210d
ERROR_DS_DRA_ABANDON_SYNC                                                = 0x0000210e
ERROR_DS_DRA_SHUTDOWN                                                    = 0x0000210f
ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET                                    = 0x00002110
ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA                                   = 0x00002111
ERROR_DS_DRA_EXTN_CONNECTION_FAILED                                      = 0x00002112
ERROR_DS_INSTALL_SCHEMA_MISMATCH                                         = 0x00002113
ERROR_DS_DUP_LINK_ID                                                     = 0x00002114
ERROR_DS_NAME_ERROR_RESOLVING                                            = 0x00002115
ERROR_DS_NAME_ERROR_NOT_FOUND                                            = 0x00002116
ERROR_DS_NAME_ERROR_NOT_UNIQUE                                           = 0x00002117
ERROR_DS_NAME_ERROR_NO_MAPPING                                           = 0x00002118
ERROR_DS_NAME_ERROR_DOMAIN_ONLY                                          = 0x00002119
ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING                               = 0x0000211a
ERROR_DS_CONSTRUCTED_ATT_MOD                                             = 0x0000211b
ERROR_DS_WRONG_OM_OBJ_CLASS                                              = 0x0000211c
ERROR_DS_DRA_REPL_PENDING                                                = 0x0000211d
ERROR_DS_DS_REQUIRED                                                     = 0x0000211e
ERROR_DS_INVALID_LDAP_DISPLAY_NAME                                       = 0x0000211f
ERROR_DS_NON_BASE_SEARCH                                                 = 0x00002120
ERROR_DS_CANT_RETRIEVE_ATTS                                              = 0x00002121
ERROR_DS_BACKLINK_WITHOUT_LINK                                           = 0x00002122
ERROR_DS_EPOCH_MISMATCH                                                  = 0x00002123
ERROR_DS_SRC_NAME_MISMATCH                                               = 0x00002124
ERROR_DS_SRC_AND_DST_NC_IDENTICAL                                        = 0x00002125
ERROR_DS_DST_NC_MISMATCH                                                 = 0x00002126
ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC                                      = 0x00002127
ERROR_DS_SRC_GUID_MISMATCH                                               = 0x00002128
ERROR_DS_CANT_MOVE_DELETED_OBJECT                                        = 0x00002129
ERROR_DS_PDC_OPERATION_IN_PROGRESS                                       = 0x0000212a
ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD                                       = 0x0000212b
ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION                                     = 0x0000212c
ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS                                 = 0x0000212d
ERROR_DS_NC_MUST_HAVE_NC_PARENT                                          = 0x0000212e
ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE                                       = 0x0000212f
ERROR_DS_DST_DOMAIN_NOT_NATIVE                                           = 0x00002130
ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER                                = 0x00002131
ERROR_DS_CANT_MOVE_ACCOUNT_GROUP                                         = 0x00002132
ERROR_DS_CANT_MOVE_RESOURCE_GROUP                                        = 0x00002133
ERROR_DS_INVALID_SEARCH_FLAG                                             = 0x00002134
ERROR_DS_NO_TREE_DELETE_ABOVE_NC                                         = 0x00002135
ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE                                    = 0x00002136
ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE                        = 0x00002137
ERROR_DS_SAM_INIT_FAILURE                                                = 0x00002138
ERROR_DS_SENSITIVE_GROUP_VIOLATION                                       = 0x00002139
ERROR_DS_CANT_MOD_PRIMARYGROUPID                                         = 0x0000213a
ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD                                         = 0x0000213b
ERROR_DS_NONSAFE_SCHEMA_CHANGE                                           = 0x0000213c
ERROR_DS_SCHEMA_UPDATE_DISALLOWED                                        = 0x0000213d
ERROR_DS_CANT_CREATE_UNDER_SCHEMA                                        = 0x0000213e
ERROR_DS_INSTALL_NO_SRC_SCH_VERSION                                      = 0x0000213f
ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE                               = 0x00002140
ERROR_DS_INVALID_GROUP_TYPE                                              = 0x00002141
ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN                              = 0x00002142
ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN                               = 0x00002143
ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER                                   = 0x00002144
ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER                               = 0x00002145
ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER                                = 0x00002146
ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER                             = 0x00002147
ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER                        = 0x00002148
ERROR_DS_HAVE_PRIMARY_MEMBERS                                            = 0x00002149
ERROR_DS_STRING_SD_CONVERSION_FAILED                                     = 0x0000214a
ERROR_DS_NAMING_MASTER_GC                                                = 0x0000214b
ERROR_DS_DNS_LOOKUP_FAILURE                                              = 0x0000214c
ERROR_DS_COULDNT_UPDATE_SPNS                                             = 0x0000214d
ERROR_DS_CANT_RETRIEVE_SD                                                = 0x0000214e
ERROR_DS_KEY_NOT_UNIQUE                                                  = 0x0000214f
ERROR_DS_WRONG_LINKED_ATT_SYNTAX                                         = 0x00002150
ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD                                       = 0x00002151
ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY                                         = 0x00002152
ERROR_DS_CANT_START                                                      = 0x00002153
ERROR_DS_INIT_FAILURE                                                    = 0x00002154
ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION                                    = 0x00002155
ERROR_DS_SOURCE_DOMAIN_IN_FOREST                                         = 0x00002156
ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST                                = 0x00002157
ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED                                = 0x00002158
ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN                                     = 0x00002159
ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER                                       = 0x0000215a
ERROR_DS_SRC_SID_EXISTS_IN_FOREST                                        = 0x0000215b
ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH                               = 0x0000215c
ERROR_SAM_INIT_FAILURE                                                   = 0x0000215d
ERROR_DS_DRA_SCHEMA_INFO_SHIP                                            = 0x0000215e
ERROR_DS_DRA_SCHEMA_CONFLICT                                             = 0x0000215f
ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT                                     = 0x00002160
ERROR_DS_DRA_OBJ_NC_MISMATCH                                             = 0x00002161
ERROR_DS_NC_STILL_HAS_DSAS                                               = 0x00002162
ERROR_DS_GC_REQUIRED                                                     = 0x00002163
ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY                                      = 0x00002164
ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS                                      = 0x00002165
ERROR_DS_CANT_ADD_TO_GC                                                  = 0x00002166
ERROR_DS_NO_CHECKPOINT_WITH_PDC                                          = 0x00002167
ERROR_DS_SOURCE_AUDITING_NOT_ENABLED                                     = 0x00002168
ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC                                     = 0x00002169
ERROR_DS_INVALID_NAME_FOR_SPN                                            = 0x0000216a
ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS                                    = 0x0000216b
ERROR_DS_UNICODEPWD_NOT_IN_QUOTES                                        = 0x0000216c
ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED                                  = 0x0000216d
ERROR_DS_MUST_BE_RUN_ON_DST_DC                                           = 0x0000216e
ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER                                   = 0x0000216f
ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ                                   = 0x00002170
ERROR_DS_INIT_FAILURE_CONSOLE                                            = 0x00002171
ERROR_DS_SAM_INIT_FAILURE_CONSOLE                                        = 0x00002172
ERROR_DS_FOREST_VERSION_TOO_HIGH                                         = 0x00002173
ERROR_DS_DOMAIN_VERSION_TOO_HIGH                                         = 0x00002174
ERROR_DS_FOREST_VERSION_TOO_LOW                                          = 0x00002175
ERROR_DS_DOMAIN_VERSION_TOO_LOW                                          = 0x00002176
ERROR_DS_INCOMPATIBLE_VERSION                                            = 0x00002177
ERROR_DS_LOW_DSA_VERSION                                                 = 0x00002178
ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN                              = 0x00002179
ERROR_DS_NOT_SUPPORTED_SORT_ORDER                                        = 0x0000217a
ERROR_DS_NAME_NOT_UNIQUE                                                 = 0x0000217b
ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4                                  = 0x0000217c
ERROR_DS_OUT_OF_VERSION_STORE                                            = 0x0000217d
ERROR_DS_INCOMPATIBLE_CONTROLS_USED                                      = 0x0000217e
ERROR_DS_NO_REF_DOMAIN                                                   = 0x0000217f
ERROR_DS_RESERVED_LINK_ID                                                = 0x00002180
ERROR_DS_LINK_ID_NOT_AVAILABLE                                           = 0x00002181
ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER                                   = 0x00002182
ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE                            = 0x00002183
ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC                                     = 0x00002184
ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG                                     = 0x00002185
ERROR_DS_MODIFYDN_WRONG_GRANDPARENT                                      = 0x00002186
ERROR_DS_NAME_ERROR_TRUST_REFERRAL                                       = 0x00002187
ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER                                   = 0x00002188
ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD                                   = 0x00002189
ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2                                    = 0x0000218a
ERROR_DS_THREAD_LIMIT_EXCEEDED                                           = 0x0000218b
ERROR_DS_NOT_CLOSEST                                                     = 0x0000218c
ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF                              = 0x0000218d
ERROR_DS_SINGLE_USER_MODE_FAILED                                         = 0x0000218e
ERROR_DS_NTDSCRIPT_SYNTAX_ERROR                                          = 0x0000218f
ERROR_DS_NTDSCRIPT_PROCESS_ERROR                                         = 0x00002190
ERROR_DS_DIFFERENT_REPL_EPOCHS                                           = 0x00002191
ERROR_DS_DRS_EXTENSIONS_CHANGED                                          = 0x00002192
ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR                   = 0x00002193
ERROR_DS_NO_MSDS_INTID                                                   = 0x00002194
ERROR_DS_DUP_MSDS_INTID                                                  = 0x00002195
ERROR_DS_EXISTS_IN_RDNATTID                                              = 0x00002196
ERROR_DS_AUTHORIZATION_FAILED                                            = 0x00002197
ERROR_DS_INVALID_SCRIPT                                                  = 0x00002198
ERROR_DS_REMOTE_CROSSREF_OP_FAILED                                       = 0x00002199
ERROR_DS_CROSS_REF_BUSY                                                  = 0x0000219a
ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN                              = 0x0000219b
ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC                                   = 0x0000219c
ERROR_DS_DUPLICATE_ID_FOUND                                              = 0x0000219d
ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT                              = 0x0000219e
ERROR_DS_GROUP_CONVERSION_ERROR                                          = 0x0000219f
ERROR_DS_CANT_MOVE_APP_BASIC_GROUP                                       = 0x000021a0
ERROR_DS_CANT_MOVE_APP_QUERY_GROUP                                       = 0x000021a1
ERROR_DS_ROLE_NOT_VERIFIED                                               = 0x000021a2
ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL                                 = 0x000021a3
ERROR_DS_DOMAIN_RENAME_IN_PROGRESS                                       = 0x000021a4
ERROR_DS_EXISTING_AD_CHILD_NC                                            = 0x000021a5
ERROR_DS_REPL_LIFETIME_EXCEEDED                                          = 0x000021a6
ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER                                  = 0x000021a7
ERROR_DS_LDAP_SEND_QUEUE_FULL                                            = 0x000021a8
ERROR_DS_DRA_OUT_SCHEDULE_WINDOW                                         = 0x000021a9
ERROR_DS_POLICY_NOT_KNOWN                                                = 0x000021aa
ERROR_NO_SITE_SETTINGS_OBJECT                                            = 0x000021ab
ERROR_NO_SECRETS                                                         = 0x000021ac
ERROR_NO_WRITABLE_DC_FOUND                                               = 0x000021ad
ERROR_DS_NO_SERVER_OBJECT                                                = 0x000021ae
ERROR_DS_NO_NTDSA_OBJECT                                                 = 0x000021af
ERROR_DS_NON_ASQ_SEARCH                                                  = 0x000021b0
ERROR_DS_AUDIT_FAILURE                                                   = 0x000021b1
ERROR_DS_INVALID_SEARCH_FLAG_SUBTREE                                     = 0x000021b2
ERROR_DS_INVALID_SEARCH_FLAG_TUPLE                                       = 0x000021b3
ERROR_DS_HIERARCHY_TABLE_TOO_DEEP                                        = 0x000021b4
ERROR_DS_DRA_CORRUPT_UTD_VECTOR                                          = 0x000021b5
ERROR_DS_DRA_SECRETS_DENIED                                              = 0x000021b6
ERROR_DS_RESERVED_MAPI_ID                                                = 0x000021b7
ERROR_DS_MAPI_ID_NOT_AVAILABLE                                           = 0x000021b8
ERROR_DS_DRA_MISSING_KRBTGT_SECRET                                       = 0x000021b9
ERROR_DS_DOMAIN_NAME_EXISTS_IN_FOREST                                    = 0x000021ba
ERROR_DS_FLAT_NAME_EXISTS_IN_FOREST                                      = 0x000021bb
ERROR_INVALID_USER_PRINCIPAL_NAME                                        = 0x000021bc
ERROR_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS                              = 0x000021bd
ERROR_DS_OID_NOT_FOUND                                                   = 0x000021be
ERROR_DS_DRA_RECYCLED_TARGET                                             = 0x000021bf
ERROR_DS_DISALLOWED_NC_REDIRECT                                          = 0x000021c0
ERROR_DS_HIGH_ADLDS_FFL                                                  = 0x000021c1
ERROR_DS_HIGH_DSA_VERSION                                                = 0x000021c2
ERROR_DS_LOW_ADLDS_FFL                                                   = 0x000021c3
ERROR_DOMAIN_SID_SAME_AS_LOCAL_WORKSTATION                               = 0x000021c4
ERROR_DS_UNDELETE_SAM_VALIDATION_FAILED                                  = 0x000021c5
ERROR_INCORRECT_ACCOUNT_TYPE                                             = 0x000021c6
DNS_ERROR_RCODE_FORMAT_ERROR                                             = 0x00002329
DNS_ERROR_RCODE_SERVER_FAILURE                                           = 0x0000232a
DNS_ERROR_RCODE_NAME_ERROR                                               = 0x0000232b
DNS_ERROR_RCODE_NOT_IMPLEMENTED                                          = 0x0000232c
DNS_ERROR_RCODE_REFUSED                                                  = 0x0000232d
DNS_ERROR_RCODE_YXDOMAIN                                                 = 0x0000232e
DNS_ERROR_RCODE_YXRRSET                                                  = 0x0000232f
DNS_ERROR_RCODE_NXRRSET                                                  = 0x00002330
DNS_ERROR_RCODE_NOTAUTH                                                  = 0x00002331
DNS_ERROR_RCODE_NOTZONE                                                  = 0x00002332
DNS_ERROR_RCODE_BADSIG                                                   = 0x00002338
DNS_ERROR_RCODE_BADKEY                                                   = 0x00002339
DNS_ERROR_RCODE_BADTIME                                                  = 0x0000233a
DNS_ERROR_KEYMASTER_REQUIRED                                             = 0x0000238d
DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE                                     = 0x0000238e
DNS_ERROR_NSEC3_INCOMPATIBLE_WITH_RSA_SHA1                               = 0x0000238f
DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS                             = 0x00002390
DNS_ERROR_UNSUPPORTED_ALGORITHM                                          = 0x00002391
DNS_ERROR_INVALID_KEY_SIZE                                               = 0x00002392
DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE                                     = 0x00002393
DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION                                = 0x00002394
DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR                               = 0x00002395
DNS_ERROR_UNEXPECTED_CNG_ERROR                                           = 0x00002396
DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION                              = 0x00002397
DNS_ERROR_KSP_NOT_ACCESSIBLE                                             = 0x00002398
DNS_ERROR_TOO_MANY_SKDS                                                  = 0x00002399
DNS_ERROR_INVALID_ROLLOVER_PERIOD                                        = 0x0000239a
DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET                                = 0x0000239b
DNS_ERROR_ROLLOVER_IN_PROGRESS                                           = 0x0000239c
DNS_ERROR_STANDBY_KEY_NOT_PRESENT                                        = 0x0000239d
DNS_ERROR_NOT_ALLOWED_ON_ZSK                                             = 0x0000239e
DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD                                      = 0x0000239f
DNS_ERROR_ROLLOVER_ALREADY_QUEUED                                        = 0x000023a0
DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE                                   = 0x000023a1
DNS_ERROR_BAD_KEYMASTER                                                  = 0x000023a2
DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD                              = 0x000023a3
DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT                                  = 0x000023a4
DNS_ERROR_DNSSEC_IS_DISABLED                                             = 0x000023a5
DNS_ERROR_INVALID_XML                                                    = 0x000023a6
DNS_ERROR_NO_VALID_TRUST_ANCHORS                                         = 0x000023a7
DNS_ERROR_ROLLOVER_NOT_POKEABLE                                          = 0x000023a8
DNS_ERROR_NSEC3_NAME_COLLISION                                           = 0x000023a9
DNS_ERROR_NSEC_INCOMPATIBLE_WITH_NSEC3_RSA_SHA1                          = 0x000023aa
DNS_INFO_NO_RECORDS                                                      = 0x0000251d
DNS_ERROR_BAD_PACKET                                                     = 0x0000251e
DNS_ERROR_NO_PACKET                                                      = 0x0000251f
DNS_ERROR_RCODE                                                          = 0x00002520
DNS_ERROR_UNSECURE_PACKET                                                = 0x00002521
DNS_REQUEST_PENDING                                                      = 0x00002522
DNS_ERROR_INVALID_TYPE                                                   = 0x0000254f
DNS_ERROR_INVALID_IP_ADDRESS                                             = 0x00002550
DNS_ERROR_INVALID_PROPERTY                                               = 0x00002551
DNS_ERROR_TRY_AGAIN_LATER                                                = 0x00002552
DNS_ERROR_NOT_UNIQUE                                                     = 0x00002553
DNS_ERROR_NON_RFC_NAME                                                   = 0x00002554
DNS_STATUS_FQDN                                                          = 0x00002555
DNS_STATUS_DOTTED_NAME                                                   = 0x00002556
DNS_STATUS_SINGLE_PART_NAME                                              = 0x00002557
DNS_ERROR_INVALID_NAME_CHAR                                              = 0x00002558
DNS_ERROR_NUMERIC_NAME                                                   = 0x00002559
DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER                                     = 0x0000255a
DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION                                   = 0x0000255b
DNS_ERROR_CANNOT_FIND_ROOT_HINTS                                         = 0x0000255c
DNS_ERROR_INCONSISTENT_ROOT_HINTS                                        = 0x0000255d
DNS_ERROR_DWORD_VALUE_TOO_SMALL                                          = 0x0000255e
DNS_ERROR_DWORD_VALUE_TOO_LARGE                                          = 0x0000255f
DNS_ERROR_BACKGROUND_LOADING                                             = 0x00002560
DNS_ERROR_NOT_ALLOWED_ON_RODC                                            = 0x00002561
DNS_ERROR_NOT_ALLOWED_UNDER_DNAME                                        = 0x00002562
DNS_ERROR_DELEGATION_REQUIRED                                            = 0x00002563
DNS_ERROR_INVALID_POLICY_TABLE                                           = 0x00002564
DNS_ERROR_ZONE_DOES_NOT_EXIST                                            = 0x00002581
DNS_ERROR_NO_ZONE_INFO                                                   = 0x00002582
DNS_ERROR_INVALID_ZONE_OPERATION                                         = 0x00002583
DNS_ERROR_ZONE_CONFIGURATION_ERROR                                       = 0x00002584
DNS_ERROR_ZONE_HAS_NO_SOA_RECORD                                         = 0x00002585
DNS_ERROR_ZONE_HAS_NO_NS_RECORDS                                         = 0x00002586
DNS_ERROR_ZONE_LOCKED                                                    = 0x00002587
DNS_ERROR_ZONE_CREATION_FAILED                                           = 0x00002588
DNS_ERROR_ZONE_ALREADY_EXISTS                                            = 0x00002589
DNS_ERROR_AUTOZONE_ALREADY_EXISTS                                        = 0x0000258a
DNS_ERROR_INVALID_ZONE_TYPE                                              = 0x0000258b
DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP                                   = 0x0000258c
DNS_ERROR_ZONE_NOT_SECONDARY                                             = 0x0000258d
DNS_ERROR_NEED_SECONDARY_ADDRESSES                                       = 0x0000258e
DNS_ERROR_WINS_INIT_FAILED                                               = 0x0000258f
DNS_ERROR_NEED_WINS_SERVERS                                              = 0x00002590
DNS_ERROR_NBSTAT_INIT_FAILED                                             = 0x00002591
DNS_ERROR_SOA_DELETE_INVALID                                             = 0x00002592
DNS_ERROR_FORWARDER_ALREADY_EXISTS                                       = 0x00002593
DNS_ERROR_ZONE_REQUIRES_MASTER_IP                                        = 0x00002594
DNS_ERROR_ZONE_IS_SHUTDOWN                                               = 0x00002595
DNS_ERROR_ZONE_LOCKED_FOR_SIGNING                                        = 0x00002596
DNS_ERROR_PRIMARY_REQUIRES_DATAFILE                                      = 0x000025b3
DNS_ERROR_INVALID_DATAFILE_NAME                                          = 0x000025b4
DNS_ERROR_DATAFILE_OPEN_FAILURE                                          = 0x000025b5
DNS_ERROR_FILE_WRITEBACK_FAILED                                          = 0x000025b6
DNS_ERROR_DATAFILE_PARSING                                               = 0x000025b7
DNS_ERROR_RECORD_DOES_NOT_EXIST                                          = 0x000025e5
DNS_ERROR_RECORD_FORMAT                                                  = 0x000025e6
DNS_ERROR_NODE_CREATION_FAILED                                           = 0x000025e7
DNS_ERROR_UNKNOWN_RECORD_TYPE                                            = 0x000025e8
DNS_ERROR_RECORD_TIMED_OUT                                               = 0x000025e9
DNS_ERROR_NAME_NOT_IN_ZONE                                               = 0x000025ea
DNS_ERROR_CNAME_LOOP                                                     = 0x000025eb
DNS_ERROR_NODE_IS_CNAME                                                  = 0x000025ec
DNS_ERROR_CNAME_COLLISION                                                = 0x000025ed
DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT                                       = 0x000025ee
DNS_ERROR_RECORD_ALREADY_EXISTS                                          = 0x000025ef
DNS_ERROR_SECONDARY_DATA                                                 = 0x000025f0
DNS_ERROR_NO_CREATE_CACHE_DATA                                           = 0x000025f1
DNS_ERROR_NAME_DOES_NOT_EXIST                                            = 0x000025f2
DNS_WARNING_PTR_CREATE_FAILED                                            = 0x000025f3
DNS_WARNING_DOMAIN_UNDELETED                                             = 0x000025f4
DNS_ERROR_DS_UNAVAILABLE                                                 = 0x000025f5
DNS_ERROR_DS_ZONE_ALREADY_EXISTS                                         = 0x000025f6
DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE                                         = 0x000025f7
DNS_ERROR_NODE_IS_DNAME                                                  = 0x000025f8
DNS_ERROR_DNAME_COLLISION                                                = 0x000025f9
DNS_ERROR_ALIAS_LOOP                                                     = 0x000025fa
DNS_INFO_AXFR_COMPLETE                                                   = 0x00002617
DNS_ERROR_AXFR                                                           = 0x00002618
DNS_INFO_ADDED_LOCAL_WINS                                                = 0x00002619
DNS_STATUS_CONTINUE_NEEDED                                               = 0x00002649
DNS_ERROR_NO_TCPIP                                                       = 0x0000267b
DNS_ERROR_NO_DNS_SERVERS                                                 = 0x0000267c
DNS_ERROR_DP_DOES_NOT_EXIST                                              = 0x000026ad
DNS_ERROR_DP_ALREADY_EXISTS                                              = 0x000026ae
DNS_ERROR_DP_NOT_ENLISTED                                                = 0x000026af
DNS_ERROR_DP_ALREADY_ENLISTED                                            = 0x000026b0
DNS_ERROR_DP_NOT_AVAILABLE                                               = 0x000026b1
DNS_ERROR_DP_FSMO_ERROR                                                  = 0x000026b2
WSAEINTR                                                                 = 0x00002714
WSAEBADF                                                                 = 0x00002719
WSAEACCES                                                                = 0x0000271d
WSAEFAULT                                                                = 0x0000271e
WSAEINVAL                                                                = 0x00002726
WSAEMFILE                                                                = 0x00002728
WSAEWOULDBLOCK                                                           = 0x00002733
WSAEINPROGRESS                                                           = 0x00002734
WSAEALREADY                                                              = 0x00002735
WSAENOTSOCK                                                              = 0x00002736
WSAEDESTADDRREQ                                                          = 0x00002737
WSAEMSGSIZE                                                              = 0x00002738
WSAEPROTOTYPE                                                            = 0x00002739
WSAENOPROTOOPT                                                           = 0x0000273a
WSAEPROTONOSUPPORT                                                       = 0x0000273b
WSAESOCKTNOSUPPORT                                                       = 0x0000273c
WSAEOPNOTSUPP                                                            = 0x0000273d
WSAEPFNOSUPPORT                                                          = 0x0000273e
WSAEAFNOSUPPORT                                                          = 0x0000273f
WSAEADDRINUSE                                                            = 0x00002740
WSAEADDRNOTAVAIL                                                         = 0x00002741
WSAENETDOWN                                                              = 0x00002742
WSAENETUNREACH                                                           = 0x00002743
WSAENETRESET                                                             = 0x00002744
WSAECONNABORTED                                                          = 0x00002745
WSAECONNRESET                                                            = 0x00002746
WSAENOBUFS                                                               = 0x00002747
WSAEISCONN                                                               = 0x00002748
WSAENOTCONN                                                              = 0x00002749
WSAESHUTDOWN                                                             = 0x0000274a
WSAETOOMANYREFS                                                          = 0x0000274b
WSAETIMEDOUT                                                             = 0x0000274c
WSAECONNREFUSED                                                          = 0x0000274d
WSAELOOP                                                                 = 0x0000274e
WSAENAMETOOLONG                                                          = 0x0000274f
WSAEHOSTDOWN                                                             = 0x00002750
WSAEHOSTUNREACH                                                          = 0x00002751
WSAENOTEMPTY                                                             = 0x00002752
WSAEPROCLIM                                                              = 0x00002753
WSAEUSERS                                                                = 0x00002754
WSAEDQUOT                                                                = 0x00002755
WSAESTALE                                                                = 0x00002756
WSAEREMOTE                                                               = 0x00002757
WSASYSNOTREADY                                                           = 0x0000276b
WSAVERNOTSUPPORTED                                                       = 0x0000276c
WSANOTINITIALISED                                                        = 0x0000276d
WSAEDISCON                                                               = 0x00002775
WSAENOMORE                                                               = 0x00002776
WSAECANCELLED                                                            = 0x00002777
WSAEINVALIDPROCTABLE                                                     = 0x00002778
WSAEINVALIDPROVIDER                                                      = 0x00002779
WSAEPROVIDERFAILEDINIT                                                   = 0x0000277a
WSASYSCALLFAILURE                                                        = 0x0000277b
WSASERVICE_NOT_FOUND                                                     = 0x0000277c
WSATYPE_NOT_FOUND                                                        = 0x0000277d
WSA_E_NO_MORE                                                            = 0x0000277e
WSA_E_CANCELLED                                                          = 0x0000277f
WSAEREFUSED                                                              = 0x00002780
WSAHOST_NOT_FOUND                                                        = 0x00002af9
WSATRY_AGAIN                                                             = 0x00002afa
WSANO_RECOVERY                                                           = 0x00002afb
WSANO_DATA                                                               = 0x00002afc
WSA_QOS_RECEIVERS                                                        = 0x00002afd
WSA_QOS_SENDERS                                                          = 0x00002afe
WSA_QOS_NO_SENDERS                                                       = 0x00002aff
WSA_QOS_NO_RECEIVERS                                                     = 0x00002b00
WSA_QOS_REQUEST_CONFIRMED                                                = 0x00002b01
WSA_QOS_ADMISSION_FAILURE                                                = 0x00002b02
WSA_QOS_POLICY_FAILURE                                                   = 0x00002b03
WSA_QOS_BAD_STYLE                                                        = 0x00002b04
WSA_QOS_BAD_OBJECT                                                       = 0x00002b05
WSA_QOS_TRAFFIC_CTRL_ERROR                                               = 0x00002b06
WSA_QOS_GENERIC_ERROR                                                    = 0x00002b07
WSA_QOS_ESERVICETYPE                                                     = 0x00002b08
WSA_QOS_EFLOWSPEC                                                        = 0x00002b09
WSA_QOS_EPROVSPECBUF                                                     = 0x00002b0a
WSA_QOS_EFILTERSTYLE                                                     = 0x00002b0b
WSA_QOS_EFILTERTYPE                                                      = 0x00002b0c
WSA_QOS_EFILTERCOUNT                                                     = 0x00002b0d
WSA_QOS_EOBJLENGTH                                                       = 0x00002b0e
WSA_QOS_EFLOWCOUNT                                                       = 0x00002b0f
WSA_QOS_EUNKOWNPSOBJ                                                     = 0x00002b10
WSA_QOS_EPOLICYOBJ                                                       = 0x00002b11
WSA_QOS_EFLOWDESC                                                        = 0x00002b12
WSA_QOS_EPSFLOWSPEC                                                      = 0x00002b13
WSA_QOS_EPSFILTERSPEC                                                    = 0x00002b14
WSA_QOS_ESDMODEOBJ                                                       = 0x00002b15
WSA_QOS_ESHAPERATEOBJ                                                    = 0x00002b16
WSA_QOS_RESERVED_PETYPE                                                  = 0x00002b17
WSA_SECURE_HOST_NOT_FOUND                                                = 0x00002b18
WSA_IPSEC_NAME_POLICY_ERROR                                              = 0x00002b19
ERROR_IPSEC_QM_POLICY_EXISTS                                             = 0x000032c8
ERROR_IPSEC_QM_POLICY_NOT_FOUND                                          = 0x000032c9
ERROR_IPSEC_QM_POLICY_IN_USE                                             = 0x000032ca
ERROR_IPSEC_MM_POLICY_EXISTS                                             = 0x000032cb
ERROR_IPSEC_MM_POLICY_NOT_FOUND                                          = 0x000032cc
ERROR_IPSEC_MM_POLICY_IN_USE                                             = 0x000032cd
ERROR_IPSEC_MM_FILTER_EXISTS                                             = 0x000032ce
ERROR_IPSEC_MM_FILTER_NOT_FOUND                                          = 0x000032cf
ERROR_IPSEC_TRANSPORT_FILTER_EXISTS                                      = 0x000032d0
ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND                                   = 0x000032d1
ERROR_IPSEC_MM_AUTH_EXISTS                                               = 0x000032d2
ERROR_IPSEC_MM_AUTH_NOT_FOUND                                            = 0x000032d3
ERROR_IPSEC_MM_AUTH_IN_USE                                               = 0x000032d4
ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND                                  = 0x000032d5
ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND                                    = 0x000032d6
ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND                                  = 0x000032d7
ERROR_IPSEC_TUNNEL_FILTER_EXISTS                                         = 0x000032d8
ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND                                      = 0x000032d9
ERROR_IPSEC_MM_FILTER_PENDING_DELETION                                   = 0x000032da
ERROR_IPSEC_TRANSPORT_FILTER_PENDING_DELETION                            = 0x000032db
ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION                               = 0x000032dc
ERROR_IPSEC_MM_POLICY_PENDING_DELETION                                   = 0x000032dd
ERROR_IPSEC_MM_AUTH_PENDING_DELETION                                     = 0x000032de
ERROR_IPSEC_QM_POLICY_PENDING_DELETION                                   = 0x000032df
WARNING_IPSEC_MM_POLICY_PRUNED                                           = 0x000032e0
WARNING_IPSEC_QM_POLICY_PRUNED                                           = 0x000032e1
ERROR_IPSEC_IKE_NEG_STATUS_BEGIN                                         = 0x000035e8
ERROR_IPSEC_IKE_AUTH_FAIL                                                = 0x000035e9
ERROR_IPSEC_IKE_ATTRIB_FAIL                                              = 0x000035ea
ERROR_IPSEC_IKE_NEGOTIATION_PENDING                                      = 0x000035eb
ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR                                 = 0x000035ec
ERROR_IPSEC_IKE_TIMED_OUT                                                = 0x000035ed
ERROR_IPSEC_IKE_NO_CERT                                                  = 0x000035ee
ERROR_IPSEC_IKE_SA_DELETED                                               = 0x000035ef
ERROR_IPSEC_IKE_SA_REAPED                                                = 0x000035f0
ERROR_IPSEC_IKE_MM_ACQUIRE_DROP                                          = 0x000035f1
ERROR_IPSEC_IKE_QM_ACQUIRE_DROP                                          = 0x000035f2
ERROR_IPSEC_IKE_QUEUE_DROP_MM                                            = 0x000035f3
ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM                                         = 0x000035f4
ERROR_IPSEC_IKE_DROP_NO_RESPONSE                                         = 0x000035f5
ERROR_IPSEC_IKE_MM_DELAY_DROP                                            = 0x000035f6
ERROR_IPSEC_IKE_QM_DELAY_DROP                                            = 0x000035f7
ERROR_IPSEC_IKE_ERROR                                                    = 0x000035f8
ERROR_IPSEC_IKE_CRL_FAILED                                               = 0x000035f9
ERROR_IPSEC_IKE_INVALID_KEY_USAGE                                        = 0x000035fa
ERROR_IPSEC_IKE_INVALID_CERT_TYPE                                        = 0x000035fb
ERROR_IPSEC_IKE_NO_PRIVATE_KEY                                           = 0x000035fc
ERROR_IPSEC_IKE_SIMULTANEOUS_REKEY                                       = 0x000035fd
ERROR_IPSEC_IKE_DH_FAIL                                                  = 0x000035fe
ERROR_IPSEC_IKE_CRITICAL_PAYLOAD_NOT_RECOGNIZED                          = 0x000035ff
ERROR_IPSEC_IKE_INVALID_HEADER                                           = 0x00003600
ERROR_IPSEC_IKE_NO_POLICY                                                = 0x00003601
ERROR_IPSEC_IKE_INVALID_SIGNATURE                                        = 0x00003602
ERROR_IPSEC_IKE_KERBEROS_ERROR                                           = 0x00003603
ERROR_IPSEC_IKE_NO_PUBLIC_KEY                                            = 0x00003604
ERROR_IPSEC_IKE_PROCESS_ERR                                              = 0x00003605
ERROR_IPSEC_IKE_PROCESS_ERR_SA                                           = 0x00003606
ERROR_IPSEC_IKE_PROCESS_ERR_PROP                                         = 0x00003607
ERROR_IPSEC_IKE_PROCESS_ERR_TRANS                                        = 0x00003608
ERROR_IPSEC_IKE_PROCESS_ERR_KE                                           = 0x00003609
ERROR_IPSEC_IKE_PROCESS_ERR_ID                                           = 0x0000360a
ERROR_IPSEC_IKE_PROCESS_ERR_CERT                                         = 0x0000360b
ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ                                     = 0x0000360c
ERROR_IPSEC_IKE_PROCESS_ERR_HASH                                         = 0x0000360d
ERROR_IPSEC_IKE_PROCESS_ERR_SIG                                          = 0x0000360e
ERROR_IPSEC_IKE_PROCESS_ERR_NONCE                                        = 0x0000360f
ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY                                       = 0x00003610
ERROR_IPSEC_IKE_PROCESS_ERR_DELETE                                       = 0x00003611
ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR                                       = 0x00003612
ERROR_IPSEC_IKE_INVALID_PAYLOAD                                          = 0x00003613
ERROR_IPSEC_IKE_LOAD_SOFT_SA                                             = 0x00003614
ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN                                        = 0x00003615
ERROR_IPSEC_IKE_INVALID_COOKIE                                           = 0x00003616
ERROR_IPSEC_IKE_NO_PEER_CERT                                             = 0x00003617
ERROR_IPSEC_IKE_PEER_CRL_FAILED                                          = 0x00003618
ERROR_IPSEC_IKE_POLICY_CHANGE                                            = 0x00003619
ERROR_IPSEC_IKE_NO_MM_POLICY                                             = 0x0000361a
ERROR_IPSEC_IKE_NOTCBPRIV                                                = 0x0000361b
ERROR_IPSEC_IKE_SECLOADFAIL                                              = 0x0000361c
ERROR_IPSEC_IKE_FAILSSPINIT                                              = 0x0000361d
ERROR_IPSEC_IKE_FAILQUERYSSP                                             = 0x0000361e
ERROR_IPSEC_IKE_SRVACQFAIL                                               = 0x0000361f
ERROR_IPSEC_IKE_SRVQUERYCRED                                             = 0x00003620
ERROR_IPSEC_IKE_GETSPIFAIL                                               = 0x00003621
ERROR_IPSEC_IKE_INVALID_FILTER                                           = 0x00003622
ERROR_IPSEC_IKE_OUT_OF_MEMORY                                            = 0x00003623
ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED                                    = 0x00003624
ERROR_IPSEC_IKE_INVALID_POLICY                                           = 0x00003625
ERROR_IPSEC_IKE_UNKNOWN_DOI                                              = 0x00003626
ERROR_IPSEC_IKE_INVALID_SITUATION                                        = 0x00003627
ERROR_IPSEC_IKE_DH_FAILURE                                               = 0x00003628
ERROR_IPSEC_IKE_INVALID_GROUP                                            = 0x00003629
ERROR_IPSEC_IKE_ENCRYPT                                                  = 0x0000362a
ERROR_IPSEC_IKE_DECRYPT                                                  = 0x0000362b
ERROR_IPSEC_IKE_POLICY_MATCH                                             = 0x0000362c
ERROR_IPSEC_IKE_UNSUPPORTED_ID                                           = 0x0000362d
ERROR_IPSEC_IKE_INVALID_HASH                                             = 0x0000362e
ERROR_IPSEC_IKE_INVALID_HASH_ALG                                         = 0x0000362f
ERROR_IPSEC_IKE_INVALID_HASH_SIZE                                        = 0x00003630
ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG                                      = 0x00003631
ERROR_IPSEC_IKE_INVALID_AUTH_ALG                                         = 0x00003632
ERROR_IPSEC_IKE_INVALID_SIG                                              = 0x00003633
ERROR_IPSEC_IKE_LOAD_FAILED                                              = 0x00003634
ERROR_IPSEC_IKE_RPC_DELETE                                               = 0x00003635
ERROR_IPSEC_IKE_BENIGN_REINIT                                            = 0x00003636
ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY                        = 0x00003637
ERROR_IPSEC_IKE_INVALID_MAJOR_VERSION                                    = 0x00003638
ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN                                      = 0x00003639
ERROR_IPSEC_IKE_MM_LIMIT                                                 = 0x0000363a
ERROR_IPSEC_IKE_NEGOTIATION_DISABLED                                     = 0x0000363b
ERROR_IPSEC_IKE_QM_LIMIT                                                 = 0x0000363c
ERROR_IPSEC_IKE_MM_EXPIRED                                               = 0x0000363d
ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID                                  = 0x0000363e
ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH                               = 0x0000363f
ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID                                    = 0x00003640
ERROR_IPSEC_IKE_INVALID_AUTH_PAYLOAD                                     = 0x00003641
ERROR_IPSEC_IKE_DOS_COOKIE_SENT                                          = 0x00003642
ERROR_IPSEC_IKE_SHUTTING_DOWN                                            = 0x00003643
ERROR_IPSEC_IKE_CGA_AUTH_FAILED                                          = 0x00003644
ERROR_IPSEC_IKE_PROCESS_ERR_NATOA                                        = 0x00003645
ERROR_IPSEC_IKE_INVALID_MM_FOR_QM                                        = 0x00003646
ERROR_IPSEC_IKE_QM_EXPIRED                                               = 0x00003647
ERROR_IPSEC_IKE_TOO_MANY_FILTERS                                         = 0x00003648
ERROR_IPSEC_IKE_NEG_STATUS_END                                           = 0x00003649
ERROR_IPSEC_IKE_KILL_DUMMY_NAP_TUNNEL                                    = 0x0000364a
ERROR_IPSEC_IKE_INNER_IP_ASSIGNMENT_FAILURE                              = 0x0000364b
ERROR_IPSEC_IKE_REQUIRE_CP_PAYLOAD_MISSING                               = 0x0000364c
ERROR_IPSEC_KEY_MODULE_IMPERSONATION_NEGOTIATION_PENDING                 = 0x0000364d
ERROR_IPSEC_IKE_COEXISTENCE_SUPPRESS                                     = 0x0000364e
ERROR_IPSEC_IKE_RATELIMIT_DROP                                           = 0x0000364f
ERROR_IPSEC_IKE_PEER_DOESNT_SUPPORT_MOBIKE                               = 0x00003650
ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE                                    = 0x00003651
ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_FAILURE                        = 0x00003652
ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE_WITH_OPTIONAL_RETRY                = 0x00003653
ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_AND_CERTMAP_FAILURE            = 0x00003654
ERROR_IPSEC_IKE_NEG_STATUS_EXTENDED_END                                  = 0x00003655
ERROR_IPSEC_BAD_SPI                                                      = 0x00003656
ERROR_IPSEC_SA_LIFETIME_EXPIRED                                          = 0x00003657
ERROR_IPSEC_WRONG_SA                                                     = 0x00003658
ERROR_IPSEC_REPLAY_CHECK_FAILED                                          = 0x00003659
ERROR_IPSEC_INVALID_PACKET                                               = 0x0000365a
ERROR_IPSEC_INTEGRITY_CHECK_FAILED                                       = 0x0000365b
ERROR_IPSEC_CLEAR_TEXT_DROP                                              = 0x0000365c
ERROR_IPSEC_AUTH_FIREWALL_DROP                                           = 0x0000365d
ERROR_IPSEC_THROTTLE_DROP                                                = 0x0000365e
ERROR_IPSEC_DOSP_BLOCK                                                   = 0x00003665
ERROR_IPSEC_DOSP_RECEIVED_MULTICAST                                      = 0x00003666
ERROR_IPSEC_DOSP_INVALID_PACKET                                          = 0x00003667
ERROR_IPSEC_DOSP_STATE_LOOKUP_FAILED                                     = 0x00003668
ERROR_IPSEC_DOSP_MAX_ENTRIES                                             = 0x00003669
ERROR_IPSEC_DOSP_KEYMOD_NOT_ALLOWED                                      = 0x0000366a
ERROR_IPSEC_DOSP_NOT_INSTALLED                                           = 0x0000366b
ERROR_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES                             = 0x0000366c
ERROR_SXS_SECTION_NOT_FOUND                                              = 0x000036b0
ERROR_SXS_CANT_GEN_ACTCTX                                                = 0x000036b1
ERROR_SXS_INVALID_ACTCTXDATA_FORMAT                                      = 0x000036b2
ERROR_SXS_ASSEMBLY_NOT_FOUND                                             = 0x000036b3
ERROR_SXS_MANIFEST_FORMAT_ERROR                                          = 0x000036b4
ERROR_SXS_MANIFEST_PARSE_ERROR                                           = 0x000036b5
ERROR_SXS_ACTIVATION_CONTEXT_DISABLED                                    = 0x000036b6
ERROR_SXS_KEY_NOT_FOUND                                                  = 0x000036b7
ERROR_SXS_VERSION_CONFLICT                                               = 0x000036b8
ERROR_SXS_WRONG_SECTION_TYPE                                             = 0x000036b9
ERROR_SXS_THREAD_QUERIES_DISABLED                                        = 0x000036ba
ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET                                    = 0x000036bb
ERROR_SXS_UNKNOWN_ENCODING_GROUP                                         = 0x000036bc
ERROR_SXS_UNKNOWN_ENCODING                                               = 0x000036bd
ERROR_SXS_INVALID_XML_NAMESPACE_URI                                      = 0x000036be
ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_NOT_INSTALLED                         = 0x000036bf
ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED                         = 0x000036c0
ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE                            = 0x000036c1
ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE                    = 0x000036c2
ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE                    = 0x000036c3
ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT                 = 0x000036c4
ERROR_SXS_DUPLICATE_DLL_NAME                                             = 0x000036c5
ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME                                     = 0x000036c6
ERROR_SXS_DUPLICATE_CLSID                                                = 0x000036c7
ERROR_SXS_DUPLICATE_IID                                                  = 0x000036c8
ERROR_SXS_DUPLICATE_TLBID                                                = 0x000036c9
ERROR_SXS_DUPLICATE_PROGID                                               = 0x000036ca
ERROR_SXS_DUPLICATE_ASSEMBLY_NAME                                        = 0x000036cb
ERROR_SXS_FILE_HASH_MISMATCH                                             = 0x000036cc
ERROR_SXS_POLICY_PARSE_ERROR                                             = 0x000036cd
ERROR_SXS_XML_E_MISSINGQUOTE                                             = 0x000036ce
ERROR_SXS_XML_E_COMMENTSYNTAX                                            = 0x000036cf
ERROR_SXS_XML_E_BADSTARTNAMECHAR                                         = 0x000036d0
ERROR_SXS_XML_E_BADNAMECHAR                                              = 0x000036d1
ERROR_SXS_XML_E_BADCHARINSTRING                                          = 0x000036d2
ERROR_SXS_XML_E_XMLDECLSYNTAX                                            = 0x000036d3
ERROR_SXS_XML_E_BADCHARDATA                                              = 0x000036d4
ERROR_SXS_XML_E_MISSINGWHITESPACE                                        = 0x000036d5
ERROR_SXS_XML_E_EXPECTINGTAGEND                                          = 0x000036d6
ERROR_SXS_XML_E_MISSINGSEMICOLON                                         = 0x000036d7
ERROR_SXS_XML_E_UNBALANCEDPAREN                                          = 0x000036d8
ERROR_SXS_XML_E_INTERNALERROR                                            = 0x000036d9
ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE                                    = 0x000036da
ERROR_SXS_XML_E_INCOMPLETE_ENCODING                                      = 0x000036db
ERROR_SXS_XML_E_MISSING_PAREN                                            = 0x000036dc
ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE                                      = 0x000036dd
ERROR_SXS_XML_E_MULTIPLE_COLONS                                          = 0x000036de
ERROR_SXS_XML_E_INVALID_DECIMAL                                          = 0x000036df
ERROR_SXS_XML_E_INVALID_HEXIDECIMAL                                      = 0x000036e0
ERROR_SXS_XML_E_INVALID_UNICODE                                          = 0x000036e1
ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK                                 = 0x000036e2
ERROR_SXS_XML_E_UNEXPECTEDENDTAG                                         = 0x000036e3
ERROR_SXS_XML_E_UNCLOSEDTAG                                              = 0x000036e4
ERROR_SXS_XML_E_DUPLICATEATTRIBUTE                                       = 0x000036e5
ERROR_SXS_XML_E_MULTIPLEROOTS                                            = 0x000036e6
ERROR_SXS_XML_E_INVALIDATROOTLEVEL                                       = 0x000036e7
ERROR_SXS_XML_E_BADXMLDECL                                               = 0x000036e8
ERROR_SXS_XML_E_MISSINGROOT                                              = 0x000036e9
ERROR_SXS_XML_E_UNEXPECTEDEOF                                            = 0x000036ea
ERROR_SXS_XML_E_BADPEREFINSUBSET                                         = 0x000036eb
ERROR_SXS_XML_E_UNCLOSEDSTARTTAG                                         = 0x000036ec
ERROR_SXS_XML_E_UNCLOSEDENDTAG                                           = 0x000036ed
ERROR_SXS_XML_E_UNCLOSEDSTRING                                           = 0x000036ee
ERROR_SXS_XML_E_UNCLOSEDCOMMENT                                          = 0x000036ef
ERROR_SXS_XML_E_UNCLOSEDDECL                                             = 0x000036f0
ERROR_SXS_XML_E_UNCLOSEDCDATA                                            = 0x000036f1
ERROR_SXS_XML_E_RESERVEDNAMESPACE                                        = 0x000036f2
ERROR_SXS_XML_E_INVALIDENCODING                                          = 0x000036f3
ERROR_SXS_XML_E_INVALIDSWITCH                                            = 0x000036f4
ERROR_SXS_XML_E_BADXMLCASE                                               = 0x000036f5
ERROR_SXS_XML_E_INVALID_STANDALONE                                       = 0x000036f6
ERROR_SXS_XML_E_UNEXPECTED_STANDALONE                                    = 0x000036f7
ERROR_SXS_XML_E_INVALID_VERSION                                          = 0x000036f8
ERROR_SXS_XML_E_MISSINGEQUALS                                            = 0x000036f9
ERROR_SXS_PROTECTION_RECOVERY_FAILED                                     = 0x000036fa
ERROR_SXS_PROTECTION_PUBLIC_KEY_TOO_SHORT                                = 0x000036fb
ERROR_SXS_PROTECTION_CATALOG_NOT_VALID                                   = 0x000036fc
ERROR_SXS_UNTRANSLATABLE_HRESULT                                         = 0x000036fd
ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING                                = 0x000036fe
ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE                            = 0x000036ff
ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME                       = 0x00003700
ERROR_SXS_ASSEMBLY_MISSING                                               = 0x00003701
ERROR_SXS_CORRUPT_ACTIVATION_STACK                                       = 0x00003702
ERROR_SXS_CORRUPTION                                                     = 0x00003703
ERROR_SXS_EARLY_DEACTIVATION                                             = 0x00003704
ERROR_SXS_INVALID_DEACTIVATION                                           = 0x00003705
ERROR_SXS_MULTIPLE_DEACTIVATION                                          = 0x00003706
ERROR_SXS_PROCESS_TERMINATION_REQUESTED                                  = 0x00003707
ERROR_SXS_RELEASE_ACTIVATION_CONTEXT                                     = 0x00003708
ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY                        = 0x00003709
ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE                               = 0x0000370a
ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME                                = 0x0000370b
ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE                                   = 0x0000370c
ERROR_SXS_IDENTITY_PARSE_ERROR                                           = 0x0000370d
ERROR_MALFORMED_SUBSTITUTION_STRING                                      = 0x0000370e
ERROR_SXS_INCORRECT_PUBLIC_KEY_TOKEN                                     = 0x0000370f
ERROR_UNMAPPED_SUBSTITUTION_STRING                                       = 0x00003710
ERROR_SXS_ASSEMBLY_NOT_LOCKED                                            = 0x00003711
ERROR_SXS_COMPONENT_STORE_CORRUPT                                        = 0x00003712
ERROR_ADVANCED_INSTALLER_FAILED                                          = 0x00003713
ERROR_XML_ENCODING_MISMATCH                                              = 0x00003714
ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT                  = 0x00003715
ERROR_SXS_IDENTITIES_DIFFERENT                                           = 0x00003716
ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT                                   = 0x00003717
ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY                                      = 0x00003718
ERROR_SXS_MANIFEST_TOO_BIG                                               = 0x00003719
ERROR_SXS_SETTING_NOT_REGISTERED                                         = 0x0000371a
ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE                                 = 0x0000371b
ERROR_SMI_PRIMITIVE_INSTALLER_FAILED                                     = 0x0000371c
ERROR_GENERIC_COMMAND_FAILED                                             = 0x0000371d
ERROR_SXS_FILE_HASH_MISSING                                              = 0x0000371e
ERROR_EVT_INVALID_CHANNEL_PATH                                           = 0x00003a98
ERROR_EVT_INVALID_QUERY                                                  = 0x00003a99
ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND                                   = 0x00003a9a
ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND                                       = 0x00003a9b
ERROR_EVT_INVALID_PUBLISHER_NAME                                         = 0x00003a9c
ERROR_EVT_INVALID_EVENT_DATA                                             = 0x00003a9d
ERROR_EVT_CHANNEL_NOT_FOUND                                              = 0x00003a9f
ERROR_EVT_MALFORMED_XML_TEXT                                             = 0x00003aa0
ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL                                 = 0x00003aa1
ERROR_EVT_CONFIGURATION_ERROR                                            = 0x00003aa2
ERROR_EVT_QUERY_RESULT_STALE                                             = 0x00003aa3
ERROR_EVT_QUERY_RESULT_INVALID_POSITION                                  = 0x00003aa4
ERROR_EVT_NON_VALIDATING_MSXML                                           = 0x00003aa5
ERROR_EVT_FILTER_ALREADYSCOPED                                           = 0x00003aa6
ERROR_EVT_FILTER_NOTELTSET                                               = 0x00003aa7
ERROR_EVT_FILTER_INVARG                                                  = 0x00003aa8
ERROR_EVT_FILTER_INVTEST                                                 = 0x00003aa9
ERROR_EVT_FILTER_INVTYPE                                                 = 0x00003aaa
ERROR_EVT_FILTER_PARSEERR                                                = 0x00003aab
ERROR_EVT_FILTER_UNSUPPORTEDOP                                           = 0x00003aac
ERROR_EVT_FILTER_UNEXPECTEDTOKEN                                         = 0x00003aad
ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL                  = 0x00003aae
ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE                                 = 0x00003aaf
ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE                               = 0x00003ab0
ERROR_EVT_CHANNEL_CANNOT_ACTIVATE                                        = 0x00003ab1
ERROR_EVT_FILTER_TOO_COMPLEX                                             = 0x00003ab2
ERROR_EVT_MESSAGE_NOT_FOUND                                              = 0x00003ab3
ERROR_EVT_MESSAGE_ID_NOT_FOUND                                           = 0x00003ab4
ERROR_EVT_UNRESOLVED_VALUE_INSERT                                        = 0x00003ab5
ERROR_EVT_UNRESOLVED_PARAMETER_INSERT                                    = 0x00003ab6
ERROR_EVT_MAX_INSERTS_REACHED                                            = 0x00003ab7
ERROR_EVT_EVENT_DEFINITION_NOT_FOUND                                     = 0x00003ab8
ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND                                       = 0x00003ab9
ERROR_EVT_VERSION_TOO_OLD                                                = 0x00003aba
ERROR_EVT_VERSION_TOO_NEW                                                = 0x00003abb
ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY                                   = 0x00003abc
ERROR_EVT_PUBLISHER_DISABLED                                             = 0x00003abd
ERROR_EVT_FILTER_OUT_OF_RANGE                                            = 0x00003abe
ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE                                    = 0x00003ae8
ERROR_EC_LOG_DISABLED                                                    = 0x00003ae9
ERROR_EC_CIRCULAR_FORWARDING                                             = 0x00003aea
ERROR_EC_CREDSTORE_FULL                                                  = 0x00003aeb
ERROR_EC_CRED_NOT_FOUND                                                  = 0x00003aec
ERROR_EC_NO_ACTIVE_CHANNEL                                               = 0x00003aed
ERROR_MUI_FILE_NOT_FOUND                                                 = 0x00003afc
ERROR_MUI_INVALID_FILE                                                   = 0x00003afd
ERROR_MUI_INVALID_RC_CONFIG                                              = 0x00003afe
ERROR_MUI_INVALID_LOCALE_NAME                                            = 0x00003aff
ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME                                  = 0x00003b00
ERROR_MUI_FILE_NOT_LOADED                                                = 0x00003b01
ERROR_RESOURCE_ENUM_USER_STOP                                            = 0x00003b02
ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED                              = 0x00003b03
ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME                               = 0x00003b04
ERROR_MRM_RUNTIME_NO_DEFAULT_OR_NEUTRAL_RESOURCE                         = 0x00003b06
ERROR_MRM_INVALID_PRICONFIG                                              = 0x00003b07
ERROR_MRM_INVALID_FILE_TYPE                                              = 0x00003b08
ERROR_MRM_UNKNOWN_QUALIFIER                                              = 0x00003b09
ERROR_MRM_INVALID_QUALIFIER_VALUE                                        = 0x00003b0a
ERROR_MRM_NO_CANDIDATE                                                   = 0x00003b0b
ERROR_MRM_NO_MATCH_OR_DEFAULT_CANDIDATE                                  = 0x00003b0c
ERROR_MRM_RESOURCE_TYPE_MISMATCH                                         = 0x00003b0d
ERROR_MRM_DUPLICATE_MAP_NAME                                             = 0x00003b0e
ERROR_MRM_DUPLICATE_ENTRY                                                = 0x00003b0f
ERROR_MRM_INVALID_RESOURCE_IDENTIFIER                                    = 0x00003b10
ERROR_MRM_FILEPATH_TOO_LONG                                              = 0x00003b11
ERROR_MRM_UNSUPPORTED_DIRECTORY_TYPE                                     = 0x00003b12
ERROR_MRM_INVALID_PRI_FILE                                               = 0x00003b16
ERROR_MRM_NAMED_RESOURCE_NOT_FOUND                                       = 0x00003b17
ERROR_MRM_MAP_NOT_FOUND                                                  = 0x00003b1f
ERROR_MRM_UNSUPPORTED_PROFILE_TYPE                                       = 0x00003b20
ERROR_MRM_INVALID_QUALIFIER_OPERATOR                                     = 0x00003b21
ERROR_MRM_INDETERMINATE_QUALIFIER_VALUE                                  = 0x00003b22
ERROR_MRM_AUTOMERGE_ENABLED                                              = 0x00003b23
ERROR_MRM_TOO_MANY_RESOURCES                                             = 0x00003b24
ERROR_MCA_INVALID_CAPABILITIES_STRING                                    = 0x00003b60
ERROR_MCA_INVALID_VCP_VERSION                                            = 0x00003b61
ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION                            = 0x00003b62
ERROR_MCA_MCCS_VERSION_MISMATCH                                          = 0x00003b63
ERROR_MCA_UNSUPPORTED_MCCS_VERSION                                       = 0x00003b64
ERROR_MCA_INTERNAL_ERROR                                                 = 0x00003b65
ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED                               = 0x00003b66
ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE                                  = 0x00003b67
ERROR_AMBIGUOUS_SYSTEM_DEVICE                                            = 0x00003b92
ERROR_SYSTEM_DEVICE_NOT_FOUND                                            = 0x00003bc3
ERROR_HASH_NOT_SUPPORTED                                                 = 0x00003bc4
ERROR_HASH_NOT_PRESENT                                                   = 0x00003bc5
ERROR_SECONDARY_IC_PROVIDER_NOT_REGISTERED                               = 0x00003bd9
ERROR_GPIO_CLIENT_INFORMATION_INVALID                                    = 0x00003bda
ERROR_GPIO_VERSION_NOT_SUPPORTED                                         = 0x00003bdb
ERROR_GPIO_INVALID_REGISTRATION_PACKET                                   = 0x00003bdc
ERROR_GPIO_OPERATION_DENIED                                              = 0x00003bdd
ERROR_GPIO_INCOMPATIBLE_CONNECT_MODE                                     = 0x00003bde
ERROR_GPIO_INTERRUPT_ALREADY_UNMASKED                                    = 0x00003bdf
ERROR_CANNOT_SWITCH_RUNLEVEL                                             = 0x00003c28
ERROR_INVALID_RUNLEVEL_SETTING                                           = 0x00003c29
ERROR_RUNLEVEL_SWITCH_TIMEOUT                                            = 0x00003c2a
ERROR_RUNLEVEL_SWITCH_AGENT_TIMEOUT                                      = 0x00003c2b
ERROR_RUNLEVEL_SWITCH_IN_PROGRESS                                        = 0x00003c2c
ERROR_SERVICES_FAILED_AUTOSTART                                          = 0x00003c2d
ERROR_COM_TASK_STOP_PENDING                                              = 0x00003c8d
ERROR_INSTALL_OPEN_PACKAGE_FAILED                                        = 0x00003cf0
ERROR_INSTALL_PACKAGE_NOT_FOUND                                          = 0x00003cf1
ERROR_INSTALL_INVALID_PACKAGE                                            = 0x00003cf2
ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED                                  = 0x00003cf3
ERROR_INSTALL_OUT_OF_DISK_SPACE                                          = 0x00003cf4
ERROR_INSTALL_NETWORK_FAILURE                                            = 0x00003cf5
ERROR_INSTALL_REGISTRATION_FAILURE                                       = 0x00003cf6
ERROR_INSTALL_DEREGISTRATION_FAILURE                                     = 0x00003cf7
ERROR_INSTALL_CANCEL                                                     = 0x00003cf8
ERROR_INSTALL_FAILED                                                     = 0x00003cf9
ERROR_REMOVE_FAILED                                                      = 0x00003cfa
ERROR_PACKAGE_ALREADY_EXISTS                                             = 0x00003cfb
ERROR_NEEDS_REMEDIATION                                                  = 0x00003cfc
ERROR_INSTALL_PREREQUISITE_FAILED                                        = 0x00003cfd
ERROR_PACKAGE_REPOSITORY_CORRUPTED                                       = 0x00003cfe
ERROR_INSTALL_POLICY_FAILURE                                             = 0x00003cff
ERROR_PACKAGE_UPDATING                                                   = 0x00003d00
ERROR_DEPLOYMENT_BLOCKED_BY_POLICY                                       = 0x00003d01
ERROR_PACKAGES_IN_USE                                                    = 0x00003d02
ERROR_RECOVERY_FILE_CORRUPT                                              = 0x00003d03
ERROR_INVALID_STAGED_SIGNATURE                                           = 0x00003d04
ERROR_DELETING_EXISTING_APPLICATIONDATA_STORE_FAILED                     = 0x00003d05
ERROR_INSTALL_PACKAGE_DOWNGRADE                                          = 0x00003d06
ERROR_SYSTEM_NEEDS_REMEDIATION                                           = 0x00003d07
ERROR_APPX_INTEGRITY_FAILURE_CLR_NGEN                                    = 0x00003d08
ERROR_RESILIENCY_FILE_CORRUPT                                            = 0x00003d09
ERROR_INSTALL_FIREWALL_SERVICE_NOT_RUNNING                               = 0x00003d0a
APPMODEL_ERROR_NO_PACKAGE                                                = 0x00003d54
APPMODEL_ERROR_PACKAGE_RUNTIME_CORRUPT                                   = 0x00003d55
APPMODEL_ERROR_PACKAGE_IDENTITY_CORRUPT                                  = 0x00003d56
APPMODEL_ERROR_NO_APPLICATION                                            = 0x00003d57
ERROR_STATE_LOAD_STORE_FAILED                                            = 0x00003db8
ERROR_STATE_GET_VERSION_FAILED                                           = 0x00003db9
ERROR_STATE_SET_VERSION_FAILED                                           = 0x00003dba
ERROR_STATE_STRUCTURED_RESET_FAILED                                      = 0x00003dbb
ERROR_STATE_OPEN_CONTAINER_FAILED                                        = 0x00003dbc
ERROR_STATE_CREATE_CONTAINER_FAILED                                      = 0x00003dbd
ERROR_STATE_DELETE_CONTAINER_FAILED                                      = 0x00003dbe
ERROR_STATE_READ_SETTING_FAILED                                          = 0x00003dbf
ERROR_STATE_WRITE_SETTING_FAILED                                         = 0x00003dc0
ERROR_STATE_DELETE_SETTING_FAILED                                        = 0x00003dc1
ERROR_STATE_QUERY_SETTING_FAILED                                         = 0x00003dc2
ERROR_STATE_READ_COMPOSITE_SETTING_FAILED                                = 0x00003dc3
ERROR_STATE_WRITE_COMPOSITE_SETTING_FAILED                               = 0x00003dc4
ERROR_STATE_ENUMERATE_CONTAINER_FAILED                                   = 0x00003dc5
ERROR_STATE_ENUMERATE_SETTINGS_FAILED                                    = 0x00003dc6
ERROR_STATE_COMPOSITE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED                  = 0x00003dc7
ERROR_STATE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED                            = 0x00003dc8
ERROR_STATE_SETTING_NAME_SIZE_LIMIT_EXCEEDED                             = 0x00003dc9
ERROR_STATE_CONTAINER_NAME_SIZE_LIMIT_EXCEEDED                           = 0x00003dca
ERROR_API_UNAVAILABLE                                                    = 0x00003de1
STORE_ERROR_UNLICENSED                                                   = 0x00003df5
STORE_ERROR_UNLICENSED_USER                                              = 0x00003df6
