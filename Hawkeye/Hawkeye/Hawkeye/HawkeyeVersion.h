#pragma once

// Single source of truth for Hawkeye Community release metadata.
// Bump here before shipping; Hawkeye.rc and QApplication::applicationVersion() follow this file.

#define HAWKEYE_VERSION_MAJOR 1
#define HAWKEYE_VERSION_MINOR 0
#define HAWKEYE_VERSION_PATCH 0
#define HAWKEYE_VERSION_BUILD 0

#define HAWKEYE_VERSION_STRING      "1.0.0"
#define HAWKEYE_VERSION_STRING_FULL "1.0.0.0"

#define HAWKEYE_PRODUCT_NAME         "Hawkeye Community"
#define HAWKEYE_PRODUCT_TAGLINE      "Open-source Windows lab console for authorized security research"
#define HAWKEYE_FILE_DESCRIPTION     "Hawkeye Community - Windows Kernel Security Research Console"
#define HAWKEYE_COMPANY_NAME         "Hawkeye Community"
#define HAWKEYE_LEGAL_COPYRIGHT      "Copyright (C) 2026 Hawkeye Community. GPL-3.0-or-later."
#define HAWKEYE_SUPPORT_EMAIL        "hawkeye18485@gmail.com"
#define HAWKEYE_WEBSITE_URL          "https://hawkeye-leo.github.io/hawkeye/"
#define HAWKEYE_OPENSOURCE_URL       "https://github.com/hawkeye-Leo/hawkeye-community"
#define HAWKEYE_INTERNAL_NAME        "Hawkeye"
#define HAWKEYE_ORIGINAL_FILENAME    "Hawkeye.exe"

#define HAWKEYE_VERSION_RC_FILEVER    HAWKEYE_VERSION_MAJOR, HAWKEYE_VERSION_MINOR, HAWKEYE_VERSION_PATCH, HAWKEYE_VERSION_BUILD
#define HAWKEYE_VERSION_RC_PRODUCTVER HAWKEYE_VERSION_RC_FILEVER
