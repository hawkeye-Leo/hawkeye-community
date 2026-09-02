#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

class CertVerifier
{
public:
    struct Result
    {
        std::wstring filePath;
        bool        isPe          = false;
        bool        hasSignature  = false;
        bool        verified      = false;
        std::string signer;
        std::string issuer;
        std::string failureReason;
        std::uint32_t winTrustError = 0;
    };

    struct Summary
    {
        std::uint32_t totalFiles     = 0;
        std::uint32_t peFiles        = 0;
        std::uint32_t signedFiles    = 0;
        std::uint32_t verifiedFiles  = 0;
        std::uint32_t brokenFiles    = 0;
        std::uint32_t unsignedFiles  = 0;
    };

    static Result verifyFile(const std::wstring& filePath);

    static bool isManagedAssembly(const std::wstring& filePath);

    using ProgressCallback = std::function<void(const Result& result,
                                                 std::uint32_t processedCount,
                                                 std::uint32_t totalCount)>;

    using StopCallback     = std::function<bool()>;

    static void verifyByPid(std::uint32_t pid,
                            std::vector<Result>& results,
                            Summary& summary,
                            ProgressCallback progress = {},
                            StopCallback     stop     = {});

    static void verifyByDir(const std::wstring& dirPath,
                            std::vector<Result>& results,
                            Summary& summary,
                            ProgressCallback progress = {},
                            StopCallback     stop     = {});

private:
    static bool isPeFile(HANDLE hFile);
    static std::string extractCertName(const struct _CERT_CONTEXT* pCertContext, DWORD flag);
    static Result verifyEmbeddedSignature(HANDLE hFile, const std::wstring& filePath);
    static Result verifyCatalogSignature(HANDLE hFile, const std::wstring& filePath);
    static bool isNonFatalTrustError(LONG trustStatus);
    static std::string trustErrorToString(LONG trustStatus);
};
