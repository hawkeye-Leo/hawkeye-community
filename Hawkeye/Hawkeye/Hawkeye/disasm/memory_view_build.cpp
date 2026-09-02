#include "memory_view_build.h"

#include <QMap>
#include <Windows.h>
extern "C" {
#include "bddisasm/bddisasm.h"
}

namespace {

QString formatListingAddr(quint64 addr)
{
    return QString("%1").arg(addr, 16, 16, QChar('0'));
}

quint64 resolveCallTargetAddress(const INSTRUX& ix, quint64 rip)
{
    if (ix.Category != ND_CAT_CALL) {
        return 0;
    }

    for (int opIndex = 0; opIndex < ix.OperandsCount; ++opIndex) {
        const ND_OPERAND& op = ix.Operands[opIndex];
        if (op.Type == ND_OP_OFFS) {
            quint64 dest = rip + ix.Length + op.Info.RelativeOffset.Rel;
            switch (ix.WordLength) {
            case 2:
                dest &= 0xFFFF;
                break;
            case 4:
                dest &= 0xFFFFFFFF;
                break;
            default:
                break;
            }
            return dest;
        }
        if (op.Type == ND_OP_IMM) {
            return static_cast<quint64>(op.Info.Immediate.Imm);
        }
    }

    return 0;
}

QString htmlEscape(const QString& text)
{
    QString escaped;
    escaped.reserve(text.size() + 8);
    for (QChar ch : text) {
        switch (ch.unicode()) {
        case '&': escaped += QStringLiteral("&amp;"); break;
        case '<': escaped += QStringLiteral("&lt;"); break;
        case '>': escaped += QStringLiteral("&gt;"); break;
        default: escaped += ch; break;
        }
    }
    return escaped;
}

void appendSpan(QString& html, const QString& color, const QString& text)
{
    html += QStringLiteral("<span style=\"color:%1\">").arg(color);
    html += htmlEscape(text);
    html += QStringLiteral("</span>");
}

void appendListingLine(QString& html, bool& firstLine, quint64 curAddr, const QString& binStr,
                       const QString& mnem, const QString& symComment, const QString& targetComment)
{
    if (!firstLine) {
        html += QChar('\n');
    }
    firstLine = false;

    appendSpan(html, QStringLiteral("#1B5E20"), formatListingAddr(curAddr));
    html += QStringLiteral("&nbsp;&nbsp;");
    appendSpan(html, QStringLiteral("#5A5A5A"), binStr);
    html += QStringLiteral("&nbsp;&nbsp;");
    appendSpan(html, QStringLiteral("#8E2452"), mnem);
    if (!symComment.isEmpty()) {
        html += QStringLiteral("&nbsp;&nbsp;");
        appendSpan(html, QStringLiteral("#2E7D32"), symComment);
    }
    if (!targetComment.isEmpty()) {
        html += QStringLiteral("&nbsp;&nbsp;");
        appendSpan(html, QStringLiteral("#1B5E20"), targetComment);
    }
}

} // namespace

static bool instructionUsesSimdRegister(const INSTRUX& ix)
{
    for (int operandIndex = 0; operandIndex < ix.OperandsCount; ++operandIndex) {
        const ND_OPERAND& operand = ix.Operands[operandIndex];
        if (operand.Type == ND_OP_REG && operand.Info.Register.Type == ND_REG_SSE) {
            return true;
        }
    }
    return false;
}

MemoryViewBuildResult buildMemoryViewDocument(const MemoryViewBuildInput& input)
{
    MemoryViewBuildResult result;
    result.hexData = QByteArray(reinterpret_cast<const char*>(input.rawData.data()), static_cast<int>(input.rawData.size()));
    const bool emitStats = input.emitStats;

        NDSTATUS status;
    INSTRUX ix;
    char text[ND_MIN_BUF_SIZE] = { 0 };

    bool firstLine = true;
    QString html;
    html.reserve(static_cast<int>(input.allData.size()));
    html += QStringLiteral("<pre style=\"font-family:Consolas,'Courier New',monospace; white-space:pre; margin:0;\">");

    int lastCompleteInstrEnd = input.disasmStartOffset;
    const unsigned char* pInst = input.allData.data() + lastCompleteInstrEnd;
    const unsigned char* pEnd = input.allData.data() + input.allData.size();
    DWORD64 curAddr = static_cast<DWORD64>(input.allDataBaseAddr + lastCompleteInstrEnd);

    const int statsFromOffset = input.statsFromOffset >= 0 ? input.statsFromOffset : input.disasmStartOffset;
    const DWORD64 statsStartAddr = static_cast<DWORD64>(input.allDataBaseAddr + statsFromOffset);
    auto shouldCountStats = [&](const unsigned char* instrPtr) -> bool {
        return emitStats && static_cast<int>(instrPtr - input.allData.data()) >= statsFromOffset;
    };

    QMap<QString, int> stats;
    int totalInstr = 0;       
    int totalDecoded = 0;     
    int junkInstr = 0;        
    int simdInstr = 0;        

    auto formatBytes = [](const unsigned char* data, int len) -> QString {
        const int MAX_BYTES = 8;
        const int COL_WIDTH = MAX_BYTES * 3;  
        QString s;
        if (len <= MAX_BYTES)
        {
            for (int i = 0; i < len; ++i)
            {
                if (i > 0) s += " ";
                s += QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper();
            }
            s = s.leftJustified(COL_WIDTH, ' ');
        }
        else
        {
            
            for (int i = 0; i < MAX_BYTES - 2; ++i)
            {
                if (i > 0) s += " ";
                s += QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper();
            }
            s += " ..";
            s = s.leftJustified(COL_WIDTH, ' ');
        }
        return s;
    };

    while (pInst < pEnd)
    {
        ULONG remainSize = (ULONG)(pEnd - pInst);

        ZeroMemory(&ix, sizeof(ix));
        if (input.disasmB64)
        {
            status = NdDecodeEx(&ix, pInst, remainSize, ND_CODE_64, ND_DATA_64);
        }
        else
        {
            status = NdDecodeEx(&ix, pInst, remainSize, ND_CODE_32, ND_DATA_32);
        }

        if (!ND_SUCCESS(status))
        {
            
            if (remainSize < 15)
            {
                
                break;
            }

            QString dbLine = QString("db %1")
                .arg(static_cast<quint8>(*pInst), 2, 16, QChar('0')).toUpper();
            QString binStr = formatBytes(pInst, 1);

            appendListingLine(html, firstLine, curAddr, binStr, dbLine, QString(), QString());

            if (shouldCountStats(pInst)) {
                totalInstr++;
                stats["db"]++;
            }

            pInst += 1;
            curAddr += 1;
            lastCompleteInstrEnd = (int)(pInst - input.allData.data());
            continue;
        }

        ZeroMemory(text, ND_MIN_BUF_SIZE);
        status = NdToText(&ix, curAddr, sizeof(text), text);
        if (!ND_SUCCESS(status))
        {
            
            if (remainSize < 15)
            {
                break;
            }

            QString dbLine = QString("db %1")
                .arg(static_cast<quint8>(*pInst), 2, 16, QChar('0')).toUpper();
            QString binStr = formatBytes(pInst, 1);

            appendListingLine(html, firstLine, curAddr, binStr, dbLine, QString(), QString());

            if (shouldCountStats(pInst)) {
                totalInstr++;
                stats["db"]++;
            }

            pInst += 1;
            curAddr += 1;
            lastCompleteInstrEnd = (int)(pInst - input.allData.data());
            continue;
        }

        QString symComment = input.symbolAnnotationCache.value(curAddr);
        QString targetComment;
        if (ix.Category == ND_CAT_CALL) {
            const quint64 callTarget = resolveCallTargetAddress(ix, curAddr);
            if (callTarget != 0) {
                targetComment = input.branchTargetSymbolCache.value(callTarget);
            }
        }
        appendListingLine(html, firstLine, curAddr, formatBytes(pInst, (int)ix.Length),
                          QString::fromLatin1(text), symComment, targetComment);

        if (shouldCountStats(pInst)) {

        totalInstr++;
        totalDecoded++;

        bool hasCr3 = false;
        for (int oi = 0; oi < ix.OperandsCount; ++oi)
        {
            const auto& op = ix.Operands[oi];
            if (op.Type == ND_OP_REG &&
                op.Info.Register.Type == ND_REG_CR &&
                op.Info.Register.Reg == NDR_CR3)
            {
                hasCr3 = true;
                break;
            }
        }

        switch (ix.Instruction)
        {
        case ND_INS_INVLPG:   stats["invlpg"]++;   break;
        case ND_INS_SWAPGS:   stats["swapgs"]++;   break;
        case ND_INS_SYSRET:   stats["sysret"]++;   break;
        case ND_INS_SYSEXIT:  stats["sysexit"]++;  break;
        case ND_INS_SYSCALL:  stats["syscall"]++;  break;
        case ND_INS_SYSENTER: stats["sysenter"]++; break;
        case ND_INS_RDMSR:    stats["rdmsr"]++;    break;
        case ND_INS_WRMSR:    stats["wrmsr"]++;    break;
        case ND_INS_CPUID:    stats["cpuid"]++;    break;
        case ND_INS_RDTSC:    stats["rdtsc"]++;    break;
        case ND_INS_RDTSCP:   stats["rdtscp"]++;   break;
        case ND_INS_RDRAND:   stats["rdrand"]++;   break;
        case ND_INS_RDSEED:   stats["rdseed"]++;   break;
        case ND_INS_CLI:      stats["cli"]++;      break;
        case ND_INS_STI:      stats["sti"]++;      break;
        case ND_INS_HLT:      stats["hlt"]++;      break;
        case ND_INS_CLTS:     stats["clts"]++;     break;
        case ND_INS_WBINVD:   stats["wbinvd"]++;   break;
        case ND_INS_INVD:     stats["invd"]++;     break;
        case ND_INS_LGDT:     stats["lgdt"]++;     break;
        case ND_INS_LIDT:     stats["lidt"]++;     break;
        case ND_INS_LMSW:     stats["lmsw"]++;     break;
        case ND_INS_INT3:     stats["int3"]++;     break;
        case ND_INS_IRET:     stats["iret"]++;     break;
        case ND_INS_RSM:      stats["rsm"]++;      break;
        case ND_INS_VMWRITE:  stats["vmwrite"]++;  break;
        case ND_INS_VMREAD:   stats["vmread"]++;   break;
        case ND_INS_VMCALL:   stats["vmcall"]++;   break;
        case ND_INS_VMRUN:    stats["vmrun"]++;    break;
        case ND_INS_VMLOAD:   stats["vmload"]++;   break;
        case ND_INS_VMSAVE:   stats["vmsave"]++;   break;
        case ND_INS_STGI:     stats["stgi"]++;     break;
        case ND_INS_CLGI:     stats["clgi"]++;     break;
        case ND_INS_INVLPGA:  stats["invlpga"]++;  break;
        case ND_INS_MOV_CR:
            if (hasCr3) stats["mov_cr3"]++;
            else        stats["mov_cr"]++;
            break;
        default: break;
        }

        bool isJmpDollar5 = false;  // JMP $+5 (E9 rel32=0)
        bool isCallDollar5 = false; // CALL $+5 (E8 rel32=0)
        switch (ix.Category)
        {
        case ND_CAT_NOP:        stats["nop"]++;   break;
        case ND_CAT_UNCOND_BR:
            stats["jmp"]++;
            
            if (ix.OperandsCount >= 1 &&
                ix.Operands[0].Type == ND_OP_OFFS &&
                *pInst == 0xE9)
            {
                int32_t relOffset = (int32_t)ix.Operands[0].Info.RelativeOffset.Rel;
                if (relOffset == 0)
                {
                    stats["jmp$5"]++;
                    junkInstr++;
                    isJmpDollar5 = true;
                }
            }
            break;
        case ND_CAT_COND_BR:    stats["jcc"]++;   break;
        case ND_CAT_CALL:
            stats["call"]++;
            
            if (ix.OperandsCount >= 1 &&
                ix.Operands[0].Type == ND_OP_OFFS &&
                *pInst == 0xE8)
            {
                int32_t relOffset = (int32_t)ix.Operands[0].Info.RelativeOffset.Rel;
                if (relOffset == 0)
                {
                    stats["call$5"]++;
                    junkInstr++;
                    isCallDollar5 = true;
                }
            }
            break;
        case ND_CAT_RET:        stats["ret"]++;   break;
        default: break;
        }

        switch (ix.Instruction)
        {
        case ND_INS_PUSH: stats["push"]++; break;
        case ND_INS_POP:  stats["pop"]++;  break;
        case ND_INS_XCHG: stats["xchg"]++; break;
        default: break;
        }

        bool isJunk = false;
        switch (ix.Instruction)
        {
        case ND_INS_BSWAP: stats["bswap"]++; isJunk = true; break;
        case ND_INS_ROR:   stats["ror"]++;   isJunk = true; break;
        case ND_INS_ROL:   stats["rol"]++;   isJunk = true; break;
        case ND_INS_CWDE:  stats["cwde"]++;  isJunk = true; break;
        case ND_INS_STC:   stats["stc"]++;   isJunk = true; break;
        case ND_INS_CDQ:   stats["cdq"]++;   isJunk = true; break;
        case ND_INS_CMC:   stats["cmc"]++;   isJunk = true; break;
        case ND_INS_CLC:   stats["clc"]++;   isJunk = true; break;
        case ND_INS_CWD:   stats["cwd"]++;   isJunk = true; break;
        case ND_INS_CQO:   stats["cqo"]++;   isJunk = true; break;
        case ND_INS_CBW:   stats["cbw"]++;   isJunk = true; break;
        case ND_INS_BTS:   stats["bts"]++;   isJunk = true; break;
        default: break;
        }
        if (isJunk || isJmpDollar5 || isCallDollar5)
        {
            junkInstr++;
        }

        if (instructionUsesSimdRegister(ix))
        {
            simdInstr++;
            stats["simd"]++;
        }
        } // shouldCountStats

        pInst += ix.Length;
        curAddr += ix.Length;
        lastCompleteInstrEnd = (int)(pInst - input.allData.data());
    }

    html += QStringLiteral("</pre>");

    if (emitStats && totalInstr > 0)
    {
        QString statsText;
        statsText += QString("         VA:0x%1  decoded:%2/%3")
            .arg(statsStartAddr, 0, 16)
            .arg(totalDecoded)
            .arg(totalInstr);

        QStringList highRiskKeys = {
            "invlpg",
            "vmwrite", "vmread", "vmcall",
            "vmrun", "vmload", "vmsave", "stgi", "clgi", "invlpga",
            "mov_cr3", "mov_cr", "swapgs",
            "sysret", "sysexit", "syscall", "sysenter",
            "rdmsr", "wrmsr", "cpuid", "rdtsc", "rdtscp",
            "rdrand", "rdseed", "cli", "sti", "hlt",
            "clts", "wbinvd", "invd", "lgdt", "lidt", "lmsw",
            "int3", "iret", "rsm"
        };
        QStringList ctrlKeys = { "nop", "jmp", "jcc", "xchg", "push", "pop", "call", "ret" };

        for (const QString& k : highRiskKeys)
        {
            if (stats.value(k, 0) > 0)
            {
                statsText += QString("\n             %1:%2").arg(k).arg(stats[k]);
            }
        }

        QStringList ctrlParts;
        for (const QString& k : ctrlKeys)
        {
            if (stats.value(k, 0) > 0)
            {
                ctrlParts << QString("%1:%2").arg(k).arg(stats[k]);
            }
        }
        if (!ctrlParts.isEmpty())
        {
            statsText += "\n             [ctrl] " + ctrlParts.join("  ");
        }

        if (simdInstr > 0)
        {
            statsText += QString("\n             [simd] %1").arg(simdInstr);
        }

        QStringList junkKeys2 = {
            "bswap", "ror", "rol", "cwde", "stc", "cdq",
            "cmc", "clc", "cwd", "cqo", "cbw", "bts", "jmp$5", "call$5"
        };
        QStringList junkParts;
        for (const QString& k : junkKeys2)
        {
            if (stats.value(k, 0) > 0)
            {
                junkParts << QString("%1:%2").arg(k).arg(stats[k]);
            }
        }
        if (!junkParts.isEmpty())
        {
            statsText += "\n             [junk] " + junkParts.join("  ");
        }

        if (stats.value("db", 0) > 0)
        {
            statsText += QString("\n             [invalid] db:%1").arg(stats["db"]);
        }

        if (totalDecoded > 0)
        {
            double junkRatio = (double)junkInstr / (double)totalDecoded;
            double dbRatio = (double)stats.value("db", 0) / (double)totalInstr;
            int invlpgCnt   = stats.value("invlpg", 0);
            int sysretCnt = stats.value("sysret", 0);
            int vmwriteCnt  = stats.value("vmwrite", 0);
            int vmreadCnt   = stats.value("vmread", 0);
            int vmcallCnt   = stats.value("vmcall", 0);
            int vmrunCnt    = stats.value("vmrun", 0);
            int vmloadCnt   = stats.value("vmload", 0);
            int vmsaveCnt   = stats.value("vmsave", 0);
            int stgiCnt     = stats.value("stgi", 0);
            int clgiCnt     = stats.value("clgi", 0);
            int invlpgaCnt  = stats.value("invlpga", 0);
            int simdCnt     = simdInstr;
            int movCr3Cnt   = stats.value("mov_cr3", 0);

            QString level = "low";
            QString reason;
            
            if (invlpgCnt > 0)
            {
                level = "HIGH";
                reason = QString("invlpg:%1 (TLB invalidation detected. Unauthorized programs may use this to read arbitrary physical memory)").arg(invlpgCnt);
            }
            else if (sysretCnt > 0)
            {
                level = "HIGH";
                reason = QString("sysret:%1   (The kernel invokes user-mode routines, leveraging the DWM context as an anti-screenshot mechanism)")
                    .arg(sysretCnt);
            }
            else if (vmwriteCnt > 0 || vmreadCnt > 0 || vmcallCnt > 0)
            {
                level = "HIGH";
                reason = QString("vmwrite:%1  vmread:%2  vmcall:%3 (VT-x virtualization code detected)")
                    .arg(vmwriteCnt).arg(vmreadCnt).arg(vmcallCnt);
            }
            else if (vmrunCnt > 0 || vmloadCnt > 0 || vmsaveCnt > 0 ||
                     stgiCnt > 0 || clgiCnt > 0 || invlpgaCnt > 0)
            {
                level = "HIGH";
                reason = QString("vmrun:%1  vmload:%2  vmsave:%3  (AMD SVM virtualization code detected)")
                    .arg(vmrunCnt).arg(vmloadCnt).arg(vmsaveCnt);
            }
            else if (junkInstr > 50)
            {
                level = "MEDIUM";
                reason = QString("junk:%1 (obfuscation shell suspected)").arg(junkInstr);
            }
            else if (simdCnt > 20)
            {
                level = "MEDIUM";
                reason = QString("simd:%1 (FP/SIMD heavy code)").arg(simdCnt);
            }
            else if (movCr3Cnt > 0)
            {
                level = "MEDIUM";
                reason = QString("mov_cr3:%1 (CR3 manipulation detected)").arg(movCr3Cnt);
            }
            else
            {
                level = "low";
                reason = "no high-risk indicators";
            }
            statsText += QString("\n             [risk] %1  - %2  (junk:%3%  invalid:%4%)")
                .arg(level)
                .arg(reason)
                .arg((int)(junkRatio * 100))
                .arg((int)(dbRatio * 100));
        }

        result.hasStats = true;
        result.statsText = statsText;
    }

    result.disasmHtml = html;
    result.lastCompleteInstrEnd = lastCompleteInstrEnd;
    return result;
}

int countSimdInstructionsInBuffer(const unsigned char* data, std::size_t size, bool is64Bit)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    int simdInstr = 0;
    const unsigned char* pInst = data;
    const unsigned char* pEnd = data + size;
    INSTRUX ix = {};

    while (pInst < pEnd) {
        const ULONG remainSize = static_cast<ULONG>(pEnd - pInst);
        ZeroMemory(&ix, sizeof(ix));
        const NDSTATUS status = is64Bit
            ? NdDecodeEx(&ix, pInst, remainSize, ND_CODE_64, ND_DATA_64)
            : NdDecodeEx(&ix, pInst, remainSize, ND_CODE_32, ND_DATA_32);
        if (!ND_SUCCESS(status)) {
            if (remainSize < 15) {
                break;
            }
            ++pInst;
            continue;
        }

        if (instructionUsesSimdRegister(ix)) {
            ++simdInstr;
        }

        pInst += ix.Length;
    }

    return simdInstr;
}

namespace {

void accumulateInstructionStatsFromInstrux(
    const INSTRUX& ix,
    const unsigned char* pInst,
    MemoryPageInstructionStats& stats)
{
    stats.totalInstr++;
    stats.totalDecoded++;

    bool hasCr3 = false;
    for (int operandIndex = 0; operandIndex < ix.OperandsCount; ++operandIndex) {
        const ND_OPERAND& operand = ix.Operands[operandIndex];
        if (operand.Type == ND_OP_REG
            && operand.Info.Register.Type == ND_REG_CR
            && operand.Info.Register.Reg == NDR_CR3) {
            hasCr3 = true;
            break;
        }
    }

    switch (ix.Instruction) {
    case ND_INS_INVLPG:
        ++stats.invlpgCount;
        break;
    case ND_INS_VMWRITE:
    case ND_INS_VMREAD:
    case ND_INS_VMCALL:
    case ND_INS_VMRUN:
    case ND_INS_VMLOAD:
    case ND_INS_VMSAVE:
    case ND_INS_STGI:
    case ND_INS_CLGI:
    case ND_INS_INVLPGA:
        ++stats.vtCount;
        break;
    case ND_INS_MOV_CR:
        if (hasCr3) {
            ++stats.movCr3Count;
        }
        break;
    default:
        break;
    }

    bool isJmpDollar5 = false;
    bool isCallDollar5 = false;
    switch (ix.Category) {
    case ND_CAT_UNCOND_BR:
        if (ix.OperandsCount >= 1
            && ix.Operands[0].Type == ND_OP_OFFS
            && *pInst == 0xE9
            && static_cast<int32_t>(ix.Operands[0].Info.RelativeOffset.Rel) == 0) {
            isJmpDollar5 = true;
        }
        break;
    case ND_CAT_CALL:
        if (ix.OperandsCount >= 1
            && ix.Operands[0].Type == ND_OP_OFFS
            && *pInst == 0xE8
            && static_cast<int32_t>(ix.Operands[0].Info.RelativeOffset.Rel) == 0) {
            isCallDollar5 = true;
        }
        break;
    default:
        break;
    }

    bool isJunk = false;
    switch (ix.Instruction) {
    case ND_INS_BSWAP:
    case ND_INS_ROR:
    case ND_INS_ROL:
    case ND_INS_CWDE:
    case ND_INS_STC:
    case ND_INS_CDQ:
    case ND_INS_CMC:
    case ND_INS_CLC:
    case ND_INS_CWD:
    case ND_INS_CQO:
    case ND_INS_CBW:
    case ND_INS_BTS:
        isJunk = true;
        break;
    default:
        break;
    }
    if (isJunk || isJmpDollar5 || isCallDollar5) {
        ++stats.junkCount;
    }

    if (instructionUsesSimdRegister(ix)) {
        ++stats.simdCount;
    }
}

} // namespace

MemoryPageInstructionStats analyzeInstructionStatsInBuffer(
    const unsigned char* data,
    std::size_t size,
    bool is64Bit)
{
    MemoryPageInstructionStats stats;
    if (data == nullptr || size == 0) {
        return stats;
    }

    const unsigned char* pInst = data;
    const unsigned char* pEnd = data + size;
    INSTRUX ix = {};

    while (pInst < pEnd) {
        const ULONG remainSize = static_cast<ULONG>(pEnd - pInst);
        ZeroMemory(&ix, sizeof(ix));
        const NDSTATUS status = is64Bit
            ? NdDecodeEx(&ix, pInst, remainSize, ND_CODE_64, ND_DATA_64)
            : NdDecodeEx(&ix, pInst, remainSize, ND_CODE_32, ND_DATA_32);
        if (!ND_SUCCESS(status)) {
            if (remainSize < 15) {
                break;
            }
            ++stats.totalInstr;
            ++pInst;
            continue;
        }

        accumulateInstructionStatsFromInstrux(ix, pInst, stats);
        pInst += ix.Length;
    }

    return stats;
}

