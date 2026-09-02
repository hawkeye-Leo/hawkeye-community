#pragma once

#include <QByteArray>
#include <QHash>
#include <QString>
#include <cstdint>
#include <vector>

struct MemoryViewBuildInput
{
    std::vector<unsigned char> allData;
    std::vector<unsigned char> rawData;
    quint64 allDataBaseAddr = 0;
    int disasmStartOffset = 0;
    int statsFromOffset = -1;   
    bool disasmB64 = true;
    bool emitStats = false;
    QHash<quint64, QString> symbolAnnotationCache;
    QHash<quint64, QString> branchTargetSymbolCache;
};

struct MemoryViewBuildResult
{
    QString disasmHtml;
    QByteArray hexData;
    int lastCompleteInstrEnd = 0;
    QString statsText;
    bool hasStats = false;
};

MemoryViewBuildResult buildMemoryViewDocument(const MemoryViewBuildInput& input);

struct MemoryPageInstructionStats
{
    int totalInstr = 0;
    int totalDecoded = 0;
    int simdCount = 0;
    int invlpgCount = 0;
    int movCr3Count = 0;
    int vtCount = 0;
    int junkCount = 0;
};

// Same bddisasm rules as Memory Viewer ReadMemory stats (emitStats path).
MemoryPageInstructionStats analyzeInstructionStatsInBuffer(
    const unsigned char* data,
    std::size_t size,
    bool is64Bit = true);

// Count FP/SIMD instructions (XMM/YMM/ZMM via ND_REG_SSE) using the same bddisasm rules as the memory view.
int countSimdInstructionsInBuffer(const unsigned char* data, std::size_t size, bool is64Bit = true);
