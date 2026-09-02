#include <Windows.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <Psapi.h>
#include <shlwapi.h>
#include <imagehlp.h>

#include "CertVerifier.h"
#include "process.h"

#include <memory>
#include <mutex>
#include <map>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "imagehlp.lib")

namespace {

struct CertContextDeleter
{
    void operator()(const CERT_CONTEXT* p) const
    {
        if (p) CertFreeCertificateContext(p);
    }
};
using CertContextPtr = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

struct CertStoreCloser
{
    void operator()(HCERTSTORE h) const
    {
        if (h) CertCloseStore(h, CERT_CLOSE_STORE_FORCE_FLAG);
    }
};
using CertStorePtr = std::unique_ptr<void, CertStoreCloser>;

struct CryptMsgCloser
{
    void operator()(HCRYPTMSG h) const
    {
        if (h) CryptMsgClose(h);
    }
};
using CryptMsgPtr = std::unique_ptr<void, CryptMsgCloser>;

struct CatAdminReleaser
{
    void operator()(HCATADMIN h) const
    {
        if (h) CryptCATAdminReleaseContext(h, 0);
    }
};
using CatAdminPtr = std::unique_ptr<void, CatAdminReleaser>;

struct CatInfoReleaser
{
    HCATADMIN owner = nullptr;
    void operator()(HCATINFO h) const
    {
        if (h && owner) CryptCATAdminReleaseCatalogContext(owner, h, 0);
    }
};
using CatInfoPtr = std::unique_ptr<void, CatInfoReleaser>;

struct LocalMemoryDeleter
{
    void operator()(LPVOID p) const
    {
        if (p) LocalFree(p);
    }
};
using LocalMemoryPtr = std::unique_ptr<void, LocalMemoryDeleter>;

struct CachedEntry
{
    CertVerifier::Result result;
    DWORD    fileSize   = 0;
    FILETIME lastWrite  = {};
};

std::mutex g_cacheMutex;
std::map<std::wstring, CachedEntry> g_resultCache;

std::wstring normalizePath(const std::wstring& path)
{
    std::wstring lowered = path;
    for (wchar_t& c : lowered)
    {
        c = static_cast<wchar_t>(towlower(c));
    }
    return lowered;
}

bool getFileState(HANDLE hFile, DWORD& outSize, FILETIME& outWrite)
{
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li))
    {
        return false;
    }
    outSize = static_cast<DWORD>(li.QuadPart);
    return GetFileTime(hFile, nullptr, nullptr, &outWrite) != FALSE;
}

} // namespace

bool CertVerifier::isPeFile(HANDLE hFile)
{
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD bytesRead = 0;
    WORD dosMagic = 0;
    if (SetFilePointer(hFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        return false;
    }
    if (!ReadFile(hFile, &dosMagic, sizeof(dosMagic), &bytesRead, nullptr) ||
        bytesRead < sizeof(dosMagic))
    {
        return false;
    }

    return dosMagic == IMAGE_DOS_SIGNATURE;
}

bool CertVerifier::isManagedAssembly(const std::wstring& filePath)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (!isPeFile(hFile))
    {
        CloseHandle(hFile);
        return false;
    }

    IMAGE_DOS_HEADER dosHeader{};
    DWORD bytesRead = 0;
    if (SetFilePointer(hFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER
        || !ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr)
        || bytesRead < sizeof(dosHeader)
        || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        CloseHandle(hFile);
        return false;
    }

    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        CloseHandle(hFile);
        return false;
    }

    DWORD peSignature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    WORD optionalMagic = 0;
    if (!ReadFile(hFile, &peSignature, sizeof(peSignature), &bytesRead, nullptr)
        || peSignature != IMAGE_NT_SIGNATURE
        || !ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr)
        || !ReadFile(hFile, &optionalMagic, sizeof(optionalMagic), &bytesRead, nullptr))
    {
        CloseHandle(hFile);
        return false;
    }

    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        CloseHandle(hFile);
        return false;
    }

    DWORD comRva = 0;
    DWORD comSize = 0;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr))
        {
            CloseHandle(hFile);
            return false;
        }
        comRva = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        comSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_NT_HEADERS32 ntHeaders{};
        if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr))
        {
            CloseHandle(hFile);
            return false;
        }
        comRva = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        comSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    }
    else
    {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return comRva != 0 && comSize != 0;
}

std::string CertVerifier::extractCertName(PCCERT_CONTEXT pCertContext, DWORD flag)
{
    if (!pCertContext)
    {
        return {};
    }

    const DWORD needed = CertGetNameStringW(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        flag,
        nullptr,
        nullptr,
        0);
    if (needed == 0)
    {
        return {};
    }

    std::wstring buf(needed, L'\0');
    const DWORD written = CertGetNameStringW(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        flag,
        nullptr,
        &buf[0],
        needed);
    if (written == 0)
    {
        return {};
    }

    if (!buf.empty() && buf.back() == L'\0')
    {
        buf.pop_back();
    }

    const int utf8Len = WideCharToMultiByte(CP_UTF8, 0, buf.c_str(),
        static_cast<int>(buf.size()), nullptr, 0, nullptr, nullptr);
    if (utf8Len <= 0)
    {
        return {};
    }
    std::string out(static_cast<size_t>(utf8Len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf.c_str(),
        static_cast<int>(buf.size()), &out[0], utf8Len, nullptr, nullptr);
    return out;
}

bool CertVerifier::isNonFatalTrustError(LONG trustStatus)
{
    
    switch (trustStatus)
    {
    case TRUST_E_TIME_STAMP:
    case CERT_E_CHAINING:
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_REVOCATION_FAILURE:
    case static_cast<LONG>(0x800B011C): /* CERT_E_REVOCATION_CHECK_OFFLINE */
    case CRYPT_E_REVOCATION_OFFLINE:
    case CERT_E_EXPIRED:
        return true;
    default:
        return false;
    }
}

std::string CertVerifier::trustErrorToString(LONG trustStatus)
{
    switch (trustStatus)
    {
    case 0:                               return "OK";
    case TRUST_E_NOSIGNATURE:             return "no signature";
    case CERT_E_EXPIRED:                  return "cert expired";
    case CERT_E_PURPOSE:                  return "cert purpose mismatch";
    case CERT_E_UNTRUSTEDROOT:            return "untrusted root";
    case CERT_E_CHAINING:                 return "chain incomplete";
    case TRUST_E_TIME_STAMP:              return "timestamp invalid";
    case CERT_E_REVOCATION_FAILURE:       return "revocation check failed";
    case static_cast<LONG>(0x800B011C):   return "revocation offline";  /* CERT_E_REVOCATION_CHECK_OFFLINE */
    case CRYPT_E_REVOCATION_OFFLINE:      return "revocation info unavailable";
    case TRUST_E_BAD_DIGEST:              return "digest mismatch (tampered)";
    case TRUST_E_NO_SIGNER_CERT:          return "no signer cert";
    case TRUST_E_COUNTER_SIGNER:          return "counter signer error";
    case TRUST_E_CERT_SIGNATURE:          return "cert signature invalid";
    default:
    {
        char buf[32];
        sprintf_s(buf, "0x%08X", static_cast<unsigned int>(trustStatus));
        return buf;
    }
    }
}

CertVerifier::Result CertVerifier::verifyEmbeddedSignature(
    HANDLE hFile, const std::wstring& filePath)
{
    Result r;
    r.filePath = filePath;
    r.hasSignature = true; 

    DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;

    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding, &dwContentType, &dwFormatType,
        &hStore, &hMsg, nullptr);

    if (!ok)
    {
        r.failureReason = "CryptQueryObject failed";
        r.winTrustError = GetLastError();
        return r;
    }

    CertStorePtr storeGuard(hStore);
    CryptMsgPtr  msgGuard(hMsg);

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize))
    {
        r.failureReason = "get signer info size failed";
        return r;
    }

    LocalMemoryPtr signerGuard(LocalAlloc(LPTR, signerInfoSize));
    if (!signerGuard)
    {
        r.failureReason = "out of memory";
        return r;
    }
    PCMSG_SIGNER_INFO pSignerInfo = static_cast<PCMSG_SIGNER_INFO>(signerGuard.get());

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize))
    {
        r.failureReason = "get signer info failed";
        return r;
    }

    CERT_INFO certInfo{};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pSignerCert = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        &certInfo,
        nullptr);

    if (!pSignerCert)
    {
        r.failureReason = "signer cert not found in store";
        return r;
    }
    CertContextPtr certGuard(pSignerCert);

    r.signer = extractCertName(pSignerCert, 0);
    r.issuer = extractCertName(pSignerCert, CERT_NAME_ISSUER_FLAG);

    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();
    fileData.hFile = hFile;
    fileData.pgKnownSubject = nullptr;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtData{};
    wtData.cbStruct = sizeof(WINTRUST_DATA);
    wtData.dwUIChoice = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice = WTD_CHOICE_FILE;
    wtData.dwStateAction = WTD_STATEACTION_VERIFY;
    wtData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;   
    wtData.pFile = &fileData;

    LONG trustStatus = WinVerifyTrust(NULL, &policyGuid, &wtData);

    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wtData);

    r.winTrustError = static_cast<std::uint32_t>(trustStatus);

    if (trustStatus == ERROR_SUCCESS)
    {
        r.verified = true;
    }
    else
    {
        if (isNonFatalTrustError(trustStatus))
        {
            
            r.verified = false;
            r.failureReason = "non-fatal: " + trustErrorToString(trustStatus);
        }
        else
        {
            
            r.verified = false;
            r.failureReason = "broken: " + trustErrorToString(trustStatus);
        }
    }

    return r;
}

CertVerifier::Result CertVerifier::verifyCatalogSignature(
    HANDLE hFile, const std::wstring& filePath)
{
    Result r;
    r.filePath = filePath;

    const GUID policies[] = {
        DRIVER_ACTION_VERIFY,
        WINTRUST_ACTION_GENERIC_VERIFY_V2
    };

    for (int attempt = 0; attempt < 2; ++attempt)
    {
        GUID curPolicy = policies[attempt];

        HCATADMIN hCatAdmin = nullptr;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, &curPolicy, 0))
        {
            continue;
        }
        CatAdminPtr adminGuard(hCatAdmin);

        BYTE hashBuf[BUFSIZ];
        DWORD hashSize = BUFSIZ;
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashBuf, 0))
        {
            continue;
        }

        HCATINFO hPrevCat = nullptr;
        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hashBuf, hashSize, 0, &hPrevCat);
        if (!hCatInfo)
        {
            continue;  
        }

        CatInfoPtr infoGuard;
        infoGuard.get_deleter().owner = hCatAdmin;
        infoGuard.reset(hCatInfo);

        r.hasSignature = true;

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(CATALOG_INFO);
        if (!CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
        {
            r.failureReason = "get catalog info failed";
            continue;
        }

        std::wstring fileName = filePath;
        LPCWSTR pName = ::PathFindFileNameW(fileName.c_str());
        std::wstring memberTag = pName;
        for (wchar_t& c : memberTag)
        {
            c = static_cast<wchar_t>(towlower(c));
        }

        WINTRUST_CATALOG_INFO catData{};
        catData.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
        catData.dwCatalogVersion = 0;
        catData.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        catData.pcwszMemberTag = memberTag.c_str();
        catData.pcwszMemberFilePath = filePath.c_str();
        catData.hMemberFile = hFile;
        catData.pbCalculatedFileHash = hashBuf;
        catData.cbCalculatedFileHash = hashSize;
        catData.pcCatalogContext = nullptr;

        WINTRUST_DATA wtData{};
        wtData.cbStruct = sizeof(WINTRUST_DATA);
        wtData.dwUIChoice = WTD_UI_NONE;
        wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtData.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtData.dwStateAction = WTD_STATEACTION_VERIFY;
        wtData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;  
        wtData.pCatalog = &catData;

        LONG trustStatus = WinVerifyTrust(
            (HWND)INVALID_HANDLE_VALUE, &curPolicy, &wtData);

        wtData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &curPolicy, &wtData);

        r.winTrustError = static_cast<std::uint32_t>(trustStatus);

        if (trustStatus == ERROR_SUCCESS)
        {
            
            CRYPT_PROVIDER_DATA* pProvData =
                WTHelperProvDataFromStateData(wtData.hWVTStateData);
            if (pProvData)
            {
                CRYPT_PROVIDER_SGNR* pSigner =
                    WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
                if (pSigner)
                {
                    CRYPT_PROVIDER_CERT* pCert =
                        WTHelperGetProvCertFromChain(pSigner, 0);
                    if (pCert && pCert->pCert)
                    {
                        r.signer = extractCertName(pCert->pCert, 0);
                        r.issuer = extractCertName(pCert->pCert, CERT_NAME_ISSUER_FLAG);
                    }
                }
            }
            r.verified = true;
            return r;
        }
        else
        {
            if (isNonFatalTrustError(trustStatus))
            {
                r.verified = false;
                r.failureReason = "non-fatal: " + trustErrorToString(trustStatus);
                return r;  
            }
            
            r.failureReason = "broken: " + trustErrorToString(trustStatus);
        }
    }

    return r;
}

CertVerifier::Result CertVerifier::verifyFile(const std::wstring& filePath)
{
    
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_resultCache.find(normalizePath(filePath));
        if (it != g_resultCache.end())
        {
            
            HANDLE h = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE)
            {
                DWORD sz = 0;
                FILETIME wt{};
                if (getFileState(h, sz, wt) &&
                    sz == it->second.fileSize &&
                    CompareFileTime(&wt, &it->second.lastWrite) == 0)
                {
                    CloseHandle(h);
                    return it->second.result;
                }
                CloseHandle(h);
            }
        }
    }

    Result r;
    r.filePath = filePath;

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        r.failureReason = "cannot open file";
        return r;
    }

    if (!isPeFile(hFile))
    {
        CloseHandle(hFile);
        r.isPe = false;
        return r;
    }
    r.isPe = true;

    WIN_CERTIFICATE certHead{};
    certHead.dwLength = 0;
    certHead.wRevision = WIN_CERT_REVISION_1_0;
    BOOL hasEmbedded = ImageGetCertificateHeader(hFile, 0, &certHead);

    if (hasEmbedded)
    {
        r = verifyEmbeddedSignature(hFile, filePath);
    }
    else
    {
        r = verifyCatalogSignature(hFile, filePath);
    }

    r.isPe = true;
    r.filePath = filePath;

    DWORD sz = 0;
    FILETIME wt{};
    if (getFileState(hFile, sz, wt))
    {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        CachedEntry entry;
        entry.result = r;
        entry.fileSize = sz;
        entry.lastWrite = wt;
        g_resultCache[normalizePath(filePath)] = entry;
    }

    CloseHandle(hFile);
    return r;
}

void CertVerifier::verifyByPid(std::uint32_t pid,
                               std::vector<Result>& results,
                               Summary& summary,
                               ProgressCallback progress,
                               StopCallback     stop)
{
    results.clear();
    summary = Summary{};

    const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(pid);
    const std::uint32_t total = static_cast<std::uint32_t>(modules.size());
    summary.totalFiles = total;

    std::uint32_t processed = 0;
    for (const Process::ModuleInfo& mod : modules)
    {
        
        if (stop && stop())
        {
            break;
        }

        if (mod.path.empty())
        {
            ++processed;
            continue;
        }

        Result r = verifyFile(mod.path);

        if (r.isPe)
        {
            summary.peFiles++;
            if (r.hasSignature)
            {
                summary.signedFiles++;
                if (r.verified)
                {
                    summary.verifiedFiles++;
                }
                else
                {
                    summary.brokenFiles++;
                }
            }
            else
            {
                summary.unsignedFiles++;
            }
        }

        results.push_back(r);
        ++processed;

        if (progress)
        {
            progress(r, processed, total);
        }
    }
}

void CertVerifier::verifyByDir(const std::wstring& dirPath,
                               std::vector<Result>& results,
                               Summary& summary,
                               ProgressCallback progress,
                               StopCallback     stop)
{
    
    results.clear();
    summary = Summary{};

    std::wstring searchPattern = dirPath;
    if (!searchPattern.empty() && searchPattern.back() != L'\\')
    {
        searchPattern += L'\\';
    }
    searchPattern += L'*';

    WIN32_FIND_DATAW findData{};
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return;
    }

    std::uint32_t runningProcessed = 0;

    do
    {
        
        if (stop && stop())
        {
            break;
        }

        if (wcscmp(findData.cFileName, L".") == 0 ||
            wcscmp(findData.cFileName, L"..") == 0)
        {
            continue;
        }

        std::wstring fullPath = dirPath;
        if (!fullPath.empty() && fullPath.back() != L'\\')
        {
            fullPath += L'\\';
        }
        fullPath += findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            std::vector<Result> subResults;
            Summary subSummary;
            
            verifyByDir(fullPath, subResults, subSummary,
                
                [&](const Result& r, std::uint32_t /*subProc*/, std::uint32_t /*subTotal*/) {
                    ++runningProcessed;
                    if (progress) progress(r, runningProcessed, 0);
                },
                stop);

            summary.totalFiles    += subSummary.totalFiles;
            summary.peFiles       += subSummary.peFiles;
            summary.signedFiles   += subSummary.signedFiles;
            summary.verifiedFiles += subSummary.verifiedFiles;
            summary.brokenFiles   += subSummary.brokenFiles;
            summary.unsignedFiles += subSummary.unsignedFiles;

            for (auto& r : subResults)
            {
                results.push_back(std::move(r));
            }
            continue;
        }

        summary.totalFiles++;

        Result r = verifyFile(fullPath);

        if (r.isPe)
        {
            summary.peFiles++;
            if (r.hasSignature)
            {
                summary.signedFiles++;
                if (r.verified)
                {
                    summary.verifiedFiles++;
                }
                else
                {
                    summary.brokenFiles++;
                }
            }
            else
            {
                summary.unsignedFiles++;
            }
        }

        results.push_back(r);
        ++runningProcessed;

        if (progress)
        {
            
            progress(r, runningProcessed, 0);
        }

    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}
