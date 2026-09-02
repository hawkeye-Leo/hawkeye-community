#include "memory.h"
#include "disasm/memory_view_build.h"
#include "HawkeyeStyle.h"
#include "HawkeyeTitleBar.h"
#include "PathConvert.h"
#include "symmanager.h"
#include <QFont>
#include <QHash>
#include <QThread>
#include <memory>
#include <QString>
#include <QTextCursor>
#include <QTextBlock>
#include <QTextCharFormat>
#include <QColor>
#include <QMenu>
#include <QScrollBar>
#include <QTimer>
#include <QKeyEvent>
#include <QLineEdit>
#include <QEvent>
#include "Driver.h"
#include "common.h"
extern "C" {
#include "bddisasm/bddisasm.h"
}

QString GetKernelMemoryRegionName(DWORD64 va);

bool MemoryDialog::navigateInputHistory(
    QLineEdit* edit, QStringList& history, int& index, QString& draft, bool up)
{
    if (edit == nullptr || history.isEmpty()) {
        return false;
    }

    if (up) {
        if (index == -1) {
            draft = edit->text();
            index = history.size() - 1;
            if (index > 0
                && history.at(index).compare(draft.trimmed(), Qt::CaseInsensitive) == 0) {
                --index;
            }
        }
        else if (index > 0) {
            --index;
        }
    }
    else {
        if (index == -1) {
            return false;
        }

        if (index < history.size() - 1) {
            ++index;
        }
        else {
            index = -1;
            edit->setText(draft);
            edit->setCursorPosition(draft.length());
            return true;
        }
    }

    edit->setText(history.at(index));
    edit->setCursorPosition(history.at(index).length());
    return true;
}

void MemoryDialog::rememberSuccessfulInput(const QString& pid, const QString& address)
{
    auto appendUnique = [](QStringList& list, const QString& value) {
        if (value.isEmpty()) {
            return;
        }
        list.removeAll(value);
        list.append(value);
        while (list.size() > kMaxInputHistory) {
            list.removeFirst();
        }
    };

    appendUnique(m_pidHistory, pid);
    appendUnique(m_addressHistory, address);
    m_pidHistoryIndex = -1;
    m_addressHistoryIndex = -1;
    m_pidHistoryDraft.clear();
    m_addressHistoryDraft.clear();
}

namespace {

QString formatKernelReadError(UCHAR errStep, LONG status)
{
    switch (errStep)
    {
    case READ_PAGE_ERR_PHYS_INVALID:
        return QStringLiteral("Error: MmIsAddressValid failed");
    case READ_PAGE_ERR_PHYS_NO_PA:
        return QStringLiteral("Error: MmGetPhysicalAddress failed");
    case READ_PAGE_ERR_PHYS_COPY:
        return QString("Error: MmCopyMemory failed (status=0x%1)").arg(static_cast<ULONG>(status), 0, 16);
    case READ_PAGE_ERR_PTE_BASE:
        return QStringLiteral("Error: PTE base unavailable");
    case READ_PAGE_ERR_PTE_LOOKUP:
        return QStringLiteral("Error: kernel PTE slot read failed");
    case READ_PAGE_ERR_PTE_INVALID:
        return QStringLiteral("Error: kernel PTE not present");
    case READ_PAGE_ERR_PTE_REMAP:
        return QStringLiteral("Error: unsupported kernel read method");
    case READ_PAGE_ERR_MAP_IO:
        return QStringLiteral("Error: MmMapIoSpaceEx failed");
    case READ_PAGE_ERR_VA_RANGE:
        return QStringLiteral("Error: Memory address out of bounds");
    default:
        return QString();
    }
}

QString kernelReadMethodLabel(UCHAR method)
{
    switch (method)
    {
    case READ_KERNEL_METHOD_MAP_IO:
        return QStringLiteral("MmMapIoSpaceEx");
    case READ_KERNEL_METHOD_MMCOPY:
    default:
        return QStringLiteral("MmCopyMemory");
    }
}

bool parseVirtualAddress(const QString& raw, quint64* va, QString* canonical)
{
    QString text = raw.trimmed();
    text.remove(QLatin1Char('`'));
    text.remove(QLatin1Char('_'));
    text.remove(QLatin1Char(' '));
    if (text.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)) {
        text = text.mid(2);
    }
    if (text.isEmpty() || text.size() > 16) {
        return false;
    }

    for (const QChar& c : text) {
        const ushort u = c.unicode();
        const bool hexDigit =
            (u >= '0' && u <= '9')
            || (u >= 'a' && u <= 'f')
            || (u >= 'A' && u <= 'F');
        if (!hexDigit) {
            return false;
        }
    }

    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 16);
    if (!ok) {
        return false;
    }

    if (va) {
        *va = parsed;
    }
    if (canonical) {
        *canonical = QStringLiteral("0x") + text.toUpper();
    }
    return true;
}

QString formatListingAddr(quint64 addr)
{
    return QString("%1").arg(addr, 16, 16, QChar('0'));
}

QString formatSymbolAnnotation(const std::wstring& moduleName,
                               const std::wstring& symbolName,
                               DWORD64 displacement)
{
    const std::wstring friendlyName = SymbolManager::DemangleSymbolName(symbolName);
    const QString symDisplay = friendlyName.empty()
        ? QString::fromStdWString(symbolName)
        : QString::fromStdWString(friendlyName);

    if (moduleName.empty()) {
        return QString("; %1+0x%2").arg(symDisplay).arg(displacement, 0, 16);
    }

    return QString("; %1!%2+0x%3")
        .arg(QString::fromStdWString(moduleName))
        .arg(symDisplay)
        .arg(displacement, 0, 16);
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

bool isNonModuleMemoryPath(const std::wstring& modulePath)
{
    if (modulePath.empty()) {
        return true;
    }

    // HEAP MEMORY and similar driver placeholders are not PE modules.
    return _wcsicmp(modulePath.c_str(), L"HEAP MEMORY") == 0;
}

bool modulePathSymbolsReady(SymbolManager* symbolManager, DWORD pid, const std::wstring& modulePath)
{
    if (symbolManager == nullptr || modulePath.empty() || isNonModuleMemoryPath(modulePath)) {
        return false;
    }

    bool symBusy = false;
    return symbolManager->IsSymbolLoaded(modulePath, &symBusy) && !symBusy;
}

std::wstring modulePathForVa(DWORD pid, quint64 va)
{
    GET_MODULE_PATH inout = {};
    inout.pid = pid;
    inout.va = static_cast<DWORD64>(va);
    GetModulePathByPid(&inout);
    if (inout.path[0] == L'\0') {
        return {};
    }
    return convertSystemRootPathW(inout.path);
}

} // namespace

bool MemoryDialog::currentModuleSymbolsReady() const
{
    if (m_symbolManager == nullptr || m_currentPid == 0 || m_allData.empty()) {
        return false;
    }

    const quint64 probeVa = m_allDataBaseAddr + static_cast<quint64>(m_disasmStartOffset);
    const std::wstring modulePath = modulePathForVa(m_currentPid, probeVa);
    return modulePathSymbolsReady(m_symbolManager, m_currentPid, modulePath);
}

void MemoryDialog::setSymbolManager(SymbolManager* symbolManager)
{
    m_symbolManager = symbolManager;
}

void MemoryDialog::resetSymbolSession()
{
    m_symbolAnnotationCache.clear();
    m_branchTargetSymbolCache.clear();
    ++m_readSessionId;
}

void MemoryDialog::requestModuleSymbolsAsync(quint64 va)
{
    if (m_symbolManager == nullptr || m_currentPid == 0) {
        return;
    }

    GET_MODULE_PATH inout = {};
    inout.pid = m_currentPid;
    inout.va = static_cast<DWORD64>(va);
    GetModulePathByPid(&inout);
    if (inout.path[0] == L'\0') {
        return;
    }

    const std::wstring modulePath = convertSystemRootPathW(inout.path);
    if (isNonModuleMemoryPath(modulePath)) {
        return;
    }

    const std::wstring moduleKey = SymbolManager::NormalizeFilePathKey(modulePath);
    if (m_symbolLoadFailures.find(moduleKey) != m_symbolLoadFailures.end()) {
        return;
    }
    if (m_symbolLoadInProgress.find(moduleKey) != m_symbolLoadInProgress.end()) {
        return;
    }

    bool symBusy = false;
    if (m_symbolManager->IsSymbolLoaded(modulePath, &symBusy)) {
        return;
    }
    if (symBusy) {
        QTimer::singleShot(500, this, [this, va]() {
            if (!m_allData.empty()) {
                requestModuleSymbolsAsync(va);
            }
        });
        return;
    }

    m_symbolLoadInProgress.insert(moduleKey);

    const DWORD loadPid = (m_currentPid == 4) ? 0u : m_currentPid;
    const quint64 sessionId = m_readSessionId;
    SymbolManager* symbolManager = m_symbolManager;
    auto loadResult = std::make_shared<bool>(false);

    QThread* loadThread = QThread::create([symbolManager, modulePath, loadPid, loadResult]() {
        SymbolLoadOptions loadOptions;
        loadOptions.maxLoadAttempts = 2;

        std::wstring loadError;
        *loadResult = symbolManager->LoadSymbol(modulePath, loadError, loadPid, &loadOptions);
    });

    connect(loadThread, &QThread::finished, this, [this, moduleKey, sessionId, loadResult]() {
        const bool loaded = *loadResult;
        m_symbolLoadInProgress.erase(moduleKey);

        if (!loaded) {
            m_symbolLoadFailures.insert(moduleKey);
            return;
        }

        if (sessionId != m_readSessionId || m_allData.empty()) {
            return;
        }

        m_symbolAnnotationCache.clear();
        m_branchTargetSymbolCache.clear();
        refreshDisasmWithSymbols();
    });
    connect(loadThread, &QThread::finished, loadThread, &QObject::deleteLater);
    loadThread->start();
}

void MemoryDialog::refreshDisasmWithSymbols()
{
    if (m_allData.empty()) {
        return;
    }

    QScrollBar* scrollBar = ui.textEditDisasm->verticalScrollBar();
    if (scrollBar) {
        m_pendingDisasmScrollRestore = scrollBar->value();
    }

    rebuildDisasmView(false);
}

void MemoryDialog::applyMemoryViewBuildResult(const MemoryViewBuildResult& result, quint64 jobId)
{
    if (jobId != m_disasmJobId) {
        return;
    }

    m_lastCompleteInstrEnd = result.lastCompleteInstrEnd;
    m_hexMonitor->setBaseAddr(m_baseAddr);
    m_hexMonitor->setData(result.hexData);

    ui.textEditDisasm->setUpdatesEnabled(false);
    ui.textEditDisasm->setHtml(result.disasmHtml);
    ui.textEditDisasm->setUpdatesEnabled(true);

    if (result.hasStats) {
        emit instructionStatsReady(result.statsText);
    }

    if (m_pendingDisasmScrollRestore >= 0) {
        if (QScrollBar* scrollBar = ui.textEditDisasm->verticalScrollBar()) {
            scrollBar->setValue(qMin(m_pendingDisasmScrollRestore, scrollBar->maximum()));
        }
        m_pendingDisasmScrollRestore = -1;
    }

    if (m_syncHexAfterDisasm) {
        m_syncHexAfterDisasm = false;
        syncHexFromDisasm();
    }
}

void MemoryDialog::rebuildDisasmView(bool emitStats)
{
    if (m_allData.empty()) {
        ui.textEditDisasm->clear();
        m_hexMonitor->setData(QByteArray());
        return;
    }

    const quint64 jobId = ++m_disasmJobId;

    if (currentModuleSymbolsReady()) {
        prefetchDisasmSymbols();
    }

    MemoryViewBuildInput input;
    input.allData = m_allData;
    input.rawData = m_rawData;
    input.allDataBaseAddr = m_allDataBaseAddr;
    input.disasmStartOffset = m_disasmStartOffset;
    input.statsFromOffset = m_statsFromOffset;
    input.disasmB64 = m_disasmB64;
    input.emitStats = emitStats;
    input.symbolAnnotationCache = m_symbolAnnotationCache;
    input.branchTargetSymbolCache = m_branchTargetSymbolCache;

    ui.textEditDisasm->setPlainText(QStringLiteral("Disassembling..."));

    auto resultPtr = std::make_shared<MemoryViewBuildResult>();
    QThread* thread = QThread::create([input, resultPtr]() {
        *resultPtr = buildMemoryViewDocument(input);
    });
    connect(thread, &QThread::finished, this, [this, thread, jobId, resultPtr]() {
        applyMemoryViewBuildResult(*resultPtr, jobId);
        thread->deleteLater();
    });
    thread->start();
}

void MemoryDialog::prefetchDisasmSymbols()
{
    if (m_symbolManager == nullptr || m_allData.empty()) {
        return;
    }

    const unsigned char* pInst = m_allData.data() + m_disasmStartOffset;
    const unsigned char* pEnd = m_allData.data() + m_allData.size();
    DWORD64 curAddr = (DWORD64)m_allDataBaseAddr + m_disasmStartOffset;
    const quint64 rangeLo = curAddr;
    const quint64 rangeHi = (DWORD64)m_allDataBaseAddr + m_allData.size();

    std::set<quint64> entryCandidates;
    std::set<quint64> callTargets;
    entryCandidates.insert(curAddr);

    bool prevWasFunctionEnd = false;
    INSTRUX ix = {};

    while (pInst < pEnd) {
        const ULONG remainSize = (ULONG)(pEnd - pInst);
        ZeroMemory(&ix, sizeof(ix));
        const NDSTATUS status = m_disasmB64
            ? NdDecodeEx(&ix, pInst, remainSize, ND_CODE_64, ND_DATA_64)
            : NdDecodeEx(&ix, pInst, remainSize, ND_CODE_32, ND_DATA_32);

        if (!ND_SUCCESS(status)) {
            if (remainSize < 15) {
                break;
            }
            prevWasFunctionEnd = false;
            pInst += 1;
            curAddr += 1;
            continue;
        }

        if (prevWasFunctionEnd) {
            entryCandidates.insert(curAddr);
        }

        if (ix.Category == ND_CAT_CALL) {
            const quint64 callTarget = resolveCallTargetAddress(ix, curAddr);
            if (callTarget != 0) {
                callTargets.insert(callTarget);
                if (callTarget >= rangeLo && callTarget < rangeHi) {
                    entryCandidates.insert(callTarget);
                }
            }
        }

        prevWasFunctionEnd = (ix.Category == ND_CAT_RET || ix.Instruction == ND_INS_INT3);

        pInst += ix.Length;
        curAddr += ix.Length;
    }

    for (const quint64 addr : entryCandidates) {
        symbolAnnotationForAddress(addr);
    }
    for (const quint64 addr : callTargets) {
        symbolAnnotationForBranchTarget(addr);
    }
}

QString MemoryDialog::symbolAnnotationForAddress(quint64 address)
{
    if (m_symbolManager == nullptr) {
        return QString();
    }

    const auto cached = m_symbolAnnotationCache.constFind(address);
    if (cached != m_symbolAnnotationCache.constEnd()) {
        return cached.value();
    }

    std::wstring symbolName;
    DWORD64 displacement = 0;
    std::wstring moduleName;
    DWORD64 moduleBase = 0;
    bool symBusy = false;
    QString annotation;
    if (m_symbolManager->ResolveAddress(
            address,
            symbolName,
            displacement,
            moduleName,
            moduleBase,
            &symBusy)
        && !symbolName.empty())
    {
        if (displacement != 0) {
            m_symbolAnnotationCache.insert(address, annotation);
            return annotation;
        }

        annotation = formatSymbolAnnotation(moduleName, symbolName, displacement);
        m_symbolAnnotationCache.insert(address, annotation);
        return annotation;
    }

    if (!symBusy) {
        m_symbolAnnotationCache.insert(address, annotation);
    }
    return annotation;
}

QString MemoryDialog::symbolAnnotationForBranchTarget(quint64 address)
{
    if (m_symbolManager == nullptr) {
        return QString();
    }

    const auto cached = m_branchTargetSymbolCache.constFind(address);
    if (cached != m_branchTargetSymbolCache.constEnd()) {
        return cached.value();
    }

    std::wstring symbolName;
    DWORD64 displacement = 0;
    std::wstring moduleName;
    DWORD64 moduleBase = 0;
    bool symBusy = false;
    QString annotation;
    if (m_symbolManager->ResolveAddress(
            address,
            symbolName,
            displacement,
            moduleName,
            moduleBase,
            &symBusy)
        && !symbolName.empty())
    {
        annotation = formatSymbolAnnotation(moduleName, symbolName, displacement);
    }

    if (!symBusy) {
        m_branchTargetSymbolCache.insert(address, annotation);
    }
    return annotation;
}

QString MemoryDialog::cachedSymbolAnnotation(quint64 address) const
{
    return m_symbolAnnotationCache.value(address);
}

QString MemoryDialog::cachedBranchTargetSymbol(quint64 address) const
{
    return m_branchTargetSymbolCache.value(address);
}

MemoryDialog::MemoryDialog(QWidget* parent)
    : QDialog(parent), m_hexMonitor(nullptr), m_baseAddr(0), m_currentPid(0), m_currentVa(0), m_isLoading(false),
      m_allDataBaseAddr(0), m_lastCompleteInstrEnd(0), m_disasmB64(true)
{
    ui.setupUi(this);
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    HawkeyeTitleBar::attach(this, HawkeyeTitleBar::CloseOnly);
    HawkeyeStyle::applyChrome(this);
    ui.pushButtonRead->setCursor(Qt::PointingHandCursor);

    QFont monoFont("Consolas");
    monoFont.setStyleHint(QFont::Monospace);
    ui.textEditDisasm->setFont(monoFont);
    ui.textEditDisasm->setReadOnly(true);
    ui.textEditDisasm->setLineWrapMode(QTextEdit::NoWrap);
    ui.textEditDisasm->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui.textEditDisasm, &QTextEdit::customContextMenuRequested, this, &MemoryDialog::onDisasmContextMenuRequested);

    connect(ui.pushButtonRead, &QPushButton::clicked, this, &MemoryDialog::onPushButtonReadClicked);

    ui.lineEditPid->installEventFilter(this);
    ui.lineEditAddress->installEventFilter(this);

    connect(ui.textEditDisasm->verticalScrollBar(), &QScrollBar::valueChanged, this, &MemoryDialog::onDisasmScrollBarChanged);

    m_hexMonitor = new QHexMonitor(this);
    m_hexMonitor->setFrameShape(QFrame::NoFrame);
    ui.hexContainerLayout->addWidget(m_hexMonitor);
}

MemoryDialog::~MemoryDialog() {}

void MemoryDialog::applyReadStatus(bool ok, const QString& text)
{
    ui.labelStatus->setText(text);
    HawkeyeStyle::applyResultChip(ui.labelStatus, ok);
}

void MemoryDialog::closeEvent(QCloseEvent* event)
{
    event->ignore();
    hide();
}

bool MemoryDialog::eventFilter(QObject* watched, QEvent* event)
{
    if (event->type() == QEvent::KeyPress) {
        auto* keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->key() == Qt::Key_Up || keyEvent->key() == Qt::Key_Down) {
            const bool up = keyEvent->key() == Qt::Key_Up;
            if (watched == ui.lineEditPid) {
                if (navigateInputHistory(ui.lineEditPid, m_pidHistory, m_pidHistoryIndex, m_pidHistoryDraft, up)) {
                    return true;
                }
            }
            else if (watched == ui.lineEditAddress) {
                if (navigateInputHistory(ui.lineEditAddress, m_addressHistory, m_addressHistoryIndex, m_addressHistoryDraft, up)) {
                    return true;
                }
            }
        }
    }

    return QDialog::eventFilter(watched, event);
}

void MemoryDialog::appendRawHexData(quint64 baseAddr, const unsigned char* data, int size)
{
    if (m_rawData.empty())
    {
        m_baseAddr = baseAddr;
        m_rawData.assign(data, data + size);
    }
    else
    {
        m_rawData.insert(m_rawData.end(), data, data + size);
    }
}

void MemoryDialog::displayHexDump(quint64 baseAddr, const unsigned char* data, int size)
{
    appendRawHexData(baseAddr, data, size);
}

void MemoryDialog::onDisasmContextMenuRequested(const QPoint& pos)
{
    QMenu menu(this);
    menu.addAction("Copy", [this]() {
        ui.textEditDisasm->copy();
    });
    menu.exec(ui.textEditDisasm->mapToGlobal(pos));
}

void MemoryDialog::syncHexFromDisasm()
{
    if (m_allData.empty() || m_hexMonitor == nullptr)
    {
        return;
    }

    const QPoint viewportPos(8, 8);
    QTextCursor cursor = ui.textEditDisasm->cursorForPosition(viewportPos);
    if (cursor.isNull())
    {
        return;
    }

    cursor.movePosition(QTextCursor::StartOfLine);
    cursor.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);
    QString line = cursor.selectedText();
    line.replace(QChar(0x2029), QLatin1Char(' '));
    line.replace(QChar(0x00A0), QLatin1Char(' '));
    line = line.trimmed();
    if (line.size() < 16)
    {
        return;
    }

    const QString addrStr = line.left(16);
    bool ok = false;
    const quint64 topAddr = addrStr.toULongLong(&ok, 16);
    if (!ok)
    {
        return;
    }

    qint64 byteOffset = (qint64)topAddr - (qint64)m_baseAddr;
    if (byteOffset < 0)
    {
        byteOffset = 0;
    }
    else if (byteOffset >= (qint64)m_rawData.size())
    {
        byteOffset = (qint64)m_rawData.size() - 1;
    }

    int colCount = m_hexMonitor->getColumn();
    if (colCount <= 0)
    {
        colCount = 16;
    }
    int hexRow = (int)(byteOffset / colCount);

    QScrollBar* hexScrollBar = m_hexMonitor->verticalScrollBar();
    if (hexScrollBar != nullptr)
    {
        
        int hexMax = hexScrollBar->maximum();
        if (hexRow > hexMax) hexRow = hexMax;
        if (hexRow < hexScrollBar->minimum()) hexRow = hexScrollBar->minimum();
        hexScrollBar->setValue(hexRow);
    }
}

void MemoryDialog::onDisasmScrollBarChanged(int value)
{
    if (m_isLoading)
    {
        return;
    }

    QScrollBar* scrollBar = ui.textEditDisasm->verticalScrollBar();
    if (!scrollBar)
    {
        return;
    }

    syncHexFromDisasm();

    int maximum = scrollBar->maximum();
    if (value >= maximum)
    {
        if (m_currentPid == 0 || m_allData.empty())
        {
            return;
        }

        const quint64 nextPageVa = m_allDataBaseAddr + m_allData.size();

        m_isLoading = true;

        READ_MEMORY_PAGES in = { 0 };
        READ_MEMORY_PAGES out = { 0 };
        in.pid = m_currentPid;
        in.va = (DWORD64)nextPageVa;
        in.readMethod = m_currentReadMethod;

        ReadProcessPage(&in, &out);

        if (out.bytesRead == PAGE_SIZE)
        {
            
            int savedValue = scrollBar->value();

            m_statsFromOffset = static_cast<int>(m_allData.size());
            m_allData.insert(m_allData.end(), out.page, out.page + out.bytesRead);

            appendRawHexData(nextPageVa, out.page, (int)out.bytesRead);
            m_pendingDisasmScrollRestore = savedValue;
            m_syncHexAfterDisasm = true;
            rebuildDisasmView(true);
            requestModuleSymbolsAsync(nextPageVa);

            m_currentVa = nextPageVa;
        }

        m_isLoading = false;
    }
}

void MemoryDialog::onPushButtonReadClicked()
{
    
    QString pidText = ui.lineEditPid->text().trimmed();
    bool pidOk = false;
    unsigned long pid = pidText.toULong(&pidOk);
    if (!pidOk || pid == 0 || (pid % 4 != 0))
    {
        ui.labelExtraInfo->setText("Invalid PID");
        applyReadStatus(false, QStringLiteral("Failed"));
        return;
    }

    // 2. Address: 0x optional. Also accepts WinDbg backticks and underscores.
    QString canonicalAddr;
    quint64 va = 0;
    if (!parseVirtualAddress(ui.lineEditAddress->text(), &va, &canonicalAddr))
    {
        ui.labelExtraInfo->setText("Invalid Address");
        applyReadStatus(false, QStringLiteral("Failed"));
        return;
    }
    ui.lineEditAddress->setText(canonicalAddr);

    READ_MEMORY_PAGES in = { 0 };
    READ_MEMORY_PAGES out = { 0 };
    in.pid = (ULONG)pid;
    in.va  = (DWORD64)va;
    {
        const int methodIndex = ui.comboBoxReadMethod->currentIndex();
        in.readMethod = (methodIndex == 1)
            ? READ_KERNEL_METHOD_MAP_IO
            : READ_KERNEL_METHOD_MMCOPY;
    }

    m_isLoading = true;  
    ++m_disasmJobId;
    m_rawData.clear();
    m_allData.clear();
    m_allDataBaseAddr = 0;
    m_disasmStartOffset = 0;
    m_statsFromOffset = 0;
    m_lastCompleteInstrEnd = 0;
    resetSymbolSession();
    ui.textEditDisasm->clear();
    m_hexMonitor->setData(QByteArray());
    m_isLoading = false;

    ReadProcessPage(&in, &out);

    if (out.bytesRead == PAGE_SIZE)
    {
        ULONG offset = va & 0x0fff;
        m_currentPid = (quint32)pid;
        m_currentVa = va;
        m_currentReadMethod = in.readMethod;
        m_disasmB64 = (va >= 0x80000000);

        m_allData.assign(out.page, out.page + out.bytesRead);
        m_allDataBaseAddr = va - offset;
        m_disasmStartOffset = static_cast<int>(offset);
        m_lastCompleteInstrEnd = m_disasmStartOffset;

        appendRawHexData((quint64)va, out.page + offset, (int)out.bytesRead - (int)offset);
        m_statsFromOffset = m_disasmStartOffset;
        m_pendingDisasmScrollRestore = 0;
        m_syncHexAfterDisasm = false;
        rebuildDisasmView(true);
        requestModuleSymbolsAsync(va);
        applyReadStatus(true, QStringLiteral("Success"));
        rememberSuccessfulInput(pidText, canonicalAddr);
        ui.labelExtraInfo->clear();
        {
            GET_MODULE_PATH inout = { 0 };
            inout.pid = pid;
            inout.va = va;
            GetModulePathByPid(&inout);
            QString line = QString("%1").arg(convertSystemRootPath(inout.path));

            if (pid == 4)
            {
                QString regionName = GetKernelMemoryRegionName(va);
                line += QString("  [%1]").arg(regionName);
                line += QString("  read:%1").arg(kernelReadMethodLabel(in.readMethod));
            }
            ui.labelExtraInfo->setText(line);
        }
    }
    else
    {
        
        m_hexMonitor->setData(QByteArray());
        ui.textEditDisasm->clear();
        m_rawData.clear();
        m_currentPid = 0;
        m_currentVa = 0;
        applyReadStatus(false, QStringLiteral("Failed"));
        if (pid == 4)
        {
            const QString errText = formatKernelReadError(out.errStep, out.status);
            if (!errText.isEmpty())
            {
                ui.labelExtraInfo->setText(errText);
            }
        }
        else
        {
            switch (out.errStep)
            {
            case READ_PAGE_ERR_LOOKUP_FAILED:
                ui.labelExtraInfo->setText(QString("Error:PsLookupProcessByProcessId Failure"));
                break;
            case READ_PAGE_ERR_USER_ACCESS:
                ui.labelExtraInfo->setText(QString("Error:User-mode memory access violation"));
                break;
            case READ_PAGE_ERR_VA_RANGE:
                ui.labelExtraInfo->setText(QString("Error:Memory address out of bounds"));
                break;
            case READ_PAGE_ERR_PHYS_INVALID:
            case READ_PAGE_ERR_PHYS_NO_PA:
            case READ_PAGE_ERR_PHYS_COPY:
            case READ_PAGE_ERR_PTE_BASE:
            case READ_PAGE_ERR_PTE_LOOKUP:
            case READ_PAGE_ERR_PTE_INVALID:
            case READ_PAGE_ERR_PTE_REMAP:
            case READ_PAGE_ERR_MAP_IO:
            {
                const QString errText = formatKernelReadError(out.errStep, out.status);
                if (!errText.isEmpty())
                {
                    ui.labelExtraInfo->setText(errText);
                }
                break;
            }
            default:
                break;
            }
        }
    }
}

QString GetKernelMemoryRegionName(DWORD64 va)
{
    QString mtype = "[unknown region]";
    KERNEL_VA_REGION in = { 0 };
    in.va = va;
    KERNEL_VA_REGION out = { 0 };
    GetKernelVaRegion(&in, &out);
    if (out.va)
    {
        switch (out.mRegion)
        {
        case 0:  mtype = "[unknown region]";      break;
        case 1:  mtype = "[section region]";       break;
        case 4:  mtype = "[pte pfn region]";       break;
        case 5:  mtype = "[nonpaged region]";      break;
        case 6:  mtype = "[pagedpool]";            break;
        case 9:  mtype = "[system region]";        break;
        case 12: mtype = "[image region]";         break;
        case 14: mtype = "[stack region]";         break;
        case 7: mtype = "[specialPoolPaged region]";         break;
        default: mtype = QString("[region(%1)]").arg(out.mRegion); break;
        }
    }
    return mtype;
}
