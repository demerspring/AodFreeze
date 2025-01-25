#pragma once

#include <Ntifs.h>
#include <srb.h>
#include <scsi.h>
#include "Public.h"

#define PRINTLOG

#ifdef DBG
#define PRINTLOG
#endif

#ifdef PRINTLOG
#define LogInfo(...) (DbgPrint("DiskFilter [INFO] [%S] ", __FUNCTIONW__), DbgPrint(__VA_ARGS__))
#define LogWarn(...) (DbgPrint("DiskFilter [WARN] [%S] ", __FUNCTIONW__), DbgPrint(__VA_ARGS__))
#define LogErr(...) (DbgPrint("DiskFilter [ERR] [%S] ", __FUNCTIONW__), DbgPrint(__VA_ARGS__))
#else
#define LogInfo(...) 0
#define LogWarn(...) 0
#define LogErr(...) 0
#endif

#define TRY_START __try {
#define TRY_END(RetStatus) } __except (1) { LogErr("Unknown error: 0x%.8x", GetExceptionCode()); }; return RetStatus;
#define TRY_END_NOSTATUS } __except (1) { LogErr("Unknown error: 0x%.8x", GetExceptionCode()); }; return;
