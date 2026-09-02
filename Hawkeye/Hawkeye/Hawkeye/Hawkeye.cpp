#include "Hawkeye.h"
#include "process.h"
#include "CertVerifier.h"
#include "ConsoleBorderGlow.h"
#include "CmdLineScanGlow.h"
#include "memory.h"
#include "driversetupdialog.h"
#include "HawkeyeStyle.h"
#include "HawkeyeVersion.h"
#include "CompatReport.h"
#include "HawkeyeTitleBar.h"
#include <QSet>
#include "hook.h"
#include "Driver.h"
#include "etw.h"
#include "PathConvert.h"
#include "inline_hook_sim.h"
#include "list_pt.h"
#include <QAbstractItemView>
#include <QCompleter>
#include <QLineEdit>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTreeView>
#include <QToolButton>
#include <QWidgetAction>
#include <QApplication>
#include <QCloseEvent>
#include <QEvent>
#include <QKeyEvent>
#include <QMap>
#include <QMetaObject>
#include <QScrollBar>
#include <QTextCursor>
#include <QTextBlock>
#include <QTimer>
#include <QThread>
#include <QColor>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QCoreApplication>
#include <QCoreApplication>
#include <QMessageBox>
#include <QPushButton>
#include <QSettings>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <vector>
extern "C" {
#include "bddisasm/bddisasm.h"
}
#include "..\..\..\common.h"

bool DriverStatusError = false;

// Forward declaration from memory.cpp
QString GetKernelMemoryRegionName(DWORD64 va);

namespace {

class HawkeyeCommandCompleter : public QCompleter
{
public:
    HawkeyeCommandCompleter(QAbstractItemModel* model, QLineEdit* lineEdit)
        : QCompleter(model, lineEdit)
    {
        setCompletionColumn(0);
    }

    QString pathFromIndex(const QModelIndex& index) const override
    {
        const QModelIndex commandIndex = index.sibling(index.row(), 0);
        const QString command = commandIndex.data(Qt::DisplayRole).toString();
        const QLineEdit* lineEdit = qobject_cast<const QLineEdit*>(widget());
        if (!lineEdit) {
            return command;
        }

        const QString line = lineEdit->text();
        const int spaceIndex = line.indexOf(QLatin1Char(' '));
        if (spaceIndex < 0) {
            return command;
        }
        return command + line.mid(spaceIndex);
    }

    QStringList splitPath(const QString& path) const override
    {
        const int spaceIndex = path.indexOf(QLatin1Char(' '));
        if (spaceIndex < 0) {
            return { path };
        }
        return { path.left(spaceIndex) };
    }
};

struct HawkeyeCommandEntry
{
    QString name;
    QString summary;
    QString usage;
};

enum CommandHintRole
{
    SummaryHintRole = Qt::UserRole + 1,
    UsageHintRole = Qt::UserRole + 2,
};

bool shouldShowCommandUsage(const QString& line, const QString& commandName)
{
    const int spaceIndex = line.indexOf(QLatin1Char(' '));
    if (spaceIndex < 0) {
        return false;
    }

    const QString token = line.left(spaceIndex).trimmed();
    return !token.isEmpty()
        && QString::compare(token, commandName, Qt::CaseInsensitive) == 0;
}

class HawkeyeCommandFilterModel : public QSortFilterProxyModel
{
public:
    explicit HawkeyeCommandFilterModel(QLineEdit* lineEdit, QObject* parent = nullptr)
        : QSortFilterProxyModel(parent)
        , m_lineEdit(lineEdit)
    {
    }

    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override
    {
        if (index.column() == 1 && role == Qt::DisplayRole) {
            const QModelIndex sourceRowIndex = mapToSource(index.sibling(index.row(), 0));
            const auto* source = qobject_cast<const QStandardItemModel*>(sourceModel());
            if (!source || !sourceRowIndex.isValid()) {
                return QSortFilterProxyModel::data(index, role);
            }

            const QStandardItem* hintItem = source->item(sourceRowIndex.row(), 1);
            const QStandardItem* nameItem = source->item(sourceRowIndex.row(), 0);
            if (!hintItem || !nameItem) {
                return {};
            }

            const QString line = m_lineEdit ? m_lineEdit->text() : QString();
            const bool showUsage = shouldShowCommandUsage(line, nameItem->text());
            return hintItem->data(showUsage ? UsageHintRole : SummaryHintRole);
        }

        return QSortFilterProxyModel::data(index, role);
    }

    void refreshHintColumn()
    {
        const QString line = m_lineEdit ? m_lineEdit->text() : QString();
        if (line == m_lastLine) {
            return;
        }
        m_lastLine = line;

        const auto* source = qobject_cast<const QStandardItemModel*>(sourceModel());
        if (!source) {
            return;
        }

        for (int sourceRow = 0; sourceRow < source->rowCount(); ++sourceRow) {
            const QStandardItem* nameItem = source->item(sourceRow, 0);
            if (!nameItem) {
                continue;
            }

            const bool showUsage = shouldShowCommandUsage(line, nameItem->text());
            const bool wasShowUsage = m_usageRows.value(sourceRow, false);
            if (wasShowUsage == showUsage) {
                continue;
            }

            m_usageRows[sourceRow] = showUsage;

            const QModelIndex proxyRowIndex = mapFromSource(source->index(sourceRow, 0));
            if (!proxyRowIndex.isValid()) {
                continue;
            }

            const QModelIndex hintIndex = this->index(proxyRowIndex.row(), 1);
            if (hintIndex.isValid()) {
                emit dataChanged(hintIndex, hintIndex, { Qt::DisplayRole });
            }
        }
    }

private:
    QLineEdit* m_lineEdit = nullptr;
    QString m_lastLine;
    QMap<int, bool> m_usageRows;
};

QVector<HawkeyeCommandEntry> hawkeyeCommandCatalog()
{
    return {
        { QStringLiteral("!process"), QStringLiteral("Scan all system processes"), QStringLiteral("!process") },
        { QStringLiteral("!iguard_scan"), QStringLiteral("Scan kernel modules for CFG dispatch tampering (run !iguard_scan for usage)"), QStringLiteral("!iguard_scan -all") },
        { QStringLiteral("!inline_hook"), QStringLiteral("Scan user process modules for inline hooks (run !inline_hook for usage)"), QStringLiteral("!inline_hook -pid:<pid>") },
        { QStringLiteral("!modules"), QStringLiteral("Enumerate kernel or user-mode modules (run !modules for usage)"), QStringLiteral("!modules -pid:<pid>") },
        { QStringLiteral("!check_hwnd"), QStringLiteral("Check whether a window handle is valid (run !check_hwnd for usage)"), QStringLiteral("!check_hwnd -hwnd:<0x...>") },
        { QStringLiteral("!kernel_region"), QStringLiteral("Identify kernel address range type (run !kernel_region for usage)"), QStringLiteral("!kernel_region -va:<0x...> | !kernel_region -list") },
        { QStringLiteral("!inject_sim"), QStringLiteral("Inject unsigned stub DLL via CreateRemoteThread+LoadLibraryW (run !inject_sim for usage)"), QStringLiteral("!inject_sim -pid:<pid> | -stop") },
        { QStringLiteral("!inline_hook_sim"), QStringLiteral("Patch HawkUnsignedStub .text in-memory to stage inline_hook test (run !inline_hook_sim for usage)"), QStringLiteral("!inline_hook_sim -pid:<pid> | -stop") },
        { QStringLiteral("!pte"), QStringLiteral("Inspect page-table entry for an address (run !pte for usage)"), QStringLiteral("!pte -pid:<pid> -va:<0x...>") },
        { QStringLiteral("!dump"), QStringLiteral("Memory page dump to .\\DumpPages (run !dump for usage)"), QStringLiteral("!dump -pid:<pid> -va:<0x...> -pages:<n> -method:<0|2|name>") },
        { QStringLiteral("!pfn"), QStringLiteral("Inspect physical-frame info for an address (run !pfn for usage)"), QStringLiteral("!pfn -pid:<pid> -va:<0x...>") },
        { QStringLiteral("!etw"), QStringLiteral("Live CPU sampling on a process, a thread, or the whole system (run !etw for usage)"), QStringLiteral("!etw -pid:<pid> | -tid:<tid> | -all [options]") },
        { QStringLiteral("!threads"), QStringLiteral("List threads and Win32 start addresses (OEP) for a process (run !threads for usage)"), QStringLiteral("!threads -pid:<pid>") },
        { QStringLiteral("!sym"), QStringLiteral("Download, load, unload, resolve, and list symbol files (run !sym for usage)"), QStringLiteral("!sym -download|-load|-unload -path:<file> ... | !sym -resolve -addr:<0x...> | !sym -list") },
        { QStringLiteral("!probe"), QStringLiteral("Live symbol context on a chosen process or the kernel, for joint analysis against runtime data (run !probe for usage)"), QStringLiteral("!probe -pid:<pid> | -find:<kw> [-mod:...] | -sym:<name> | -status|-stop|-detach") },
        { QStringLiteral("!enable_testsigning"), QStringLiteral("Turn on Windows test signing and trust the Hawkeye test certificate"), QStringLiteral("!enable_testsigning") },
        { QStringLiteral("!disable_testsigning"), QStringLiteral("Turn off test signing and remove the Hawkeye test certificate"), QStringLiteral("!disable_testsigning") },
        { QStringLiteral("!getting-started"), QStringLiteral("Show the Getting started map"), QStringLiteral("!getting-started") },
        { QStringLiteral("!support"), QStringLiteral("Website, email, and a system report to send if something breaks"), QStringLiteral("!support") },
        { QStringLiteral("!check_cert"), QStringLiteral("Verify digital signatures of all modules in a process, or all PE files in a directory (run !check_cert for usage)"), QStringLiteral("!check_cert -pid:<pid> | -dir:<path> | -stop") },
        { QStringLiteral("!license"), QStringLiteral("Edition and website"), QStringLiteral("!license") },
        { QStringLiteral("!help"), QStringLiteral("Show Hawkeye command reference"), QStringLiteral("!help") },
        { QStringLiteral("!search"), QStringLiteral("Highlight matching console lines; omit the keyword to restore default color"), QStringLiteral("!search [<keyword>]") },
        { QStringLiteral("cls"), QStringLiteral("Clear console"), QStringLiteral("cls") },
    };
}

bool isMemoryIntegritySafeCommand(const QString& cmd)
{
    static const QSet<QString> kSafeCommands = {
        QStringLiteral("!help"),
        QStringLiteral("!getting-started"),
        QStringLiteral("!support"),
        QStringLiteral("!compat-report"),
        QStringLiteral("!license"),
        QStringLiteral("!about"),
        QStringLiteral("!sym"),
        QStringLiteral("!probe"),
        QStringLiteral("!etw"),
        QStringLiteral("!search"),
        QStringLiteral("cls"),
        QStringLiteral("!process"),
        QStringLiteral("!modules"),
        QStringLiteral("!threads"),
        QStringLiteral("!check_cert"),
        QStringLiteral("!inject_sim"),
        QStringLiteral("!inline_hook"),
        QStringLiteral("!inline_hook_sim"),
        QStringLiteral("!check_hwnd"),
        QStringLiteral("!enable_testsigning"),
        QStringLiteral("!disable_testsigning"),
    };
    return kSafeCommands.contains(cmd);
}

void setupCommandCompleter(QLineEdit* lineEdit)
{
    if (!lineEdit) {
        return;
    }

    auto* model = new QStandardItemModel(lineEdit);
    model->setColumnCount(2);
    for (const HawkeyeCommandEntry& entry : hawkeyeCommandCatalog()) {
        auto* nameItem = new QStandardItem(entry.name);
        auto* summaryItem = new QStandardItem(entry.summary);
        summaryItem->setData(entry.summary, SummaryHintRole);
        summaryItem->setData(entry.usage, UsageHintRole);
        summaryItem->setForeground(QBrush(QColor("#5A5A5A")));
        summaryItem->setFlags(summaryItem->flags() & ~Qt::ItemIsSelectable);
        model->appendRow({ nameItem, summaryItem });
    }

    auto* filterModel = new HawkeyeCommandFilterModel(lineEdit, lineEdit);
    filterModel->setSourceModel(model);
    filterModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filterModel->setFilterKeyColumn(0);

    auto* completer = new HawkeyeCommandCompleter(filterModel, lineEdit);
    completer->setCaseSensitivity(Qt::CaseInsensitive);
    completer->setCompletionMode(QCompleter::PopupCompletion);
    completer->setFilterMode(Qt::MatchStartsWith);

    auto* popup = new QTreeView(lineEdit);
    popup->setRootIsDecorated(false);
    popup->setUniformRowHeights(true);
    popup->setHeaderHidden(true);
    popup->setSelectionBehavior(QAbstractItemView::SelectRows);
    popup->setAllColumnsShowFocus(false);
    popup->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    popup->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    popup->setMinimumWidth(640);
    popup->setColumnWidth(0, 168);
    popup->setStyleSheet(
        "QTreeView {"
        "  font-family: Consolas, 'Courier New', monospace;"
        "  font-size: 12px;"
        "  background: #fafcfa;"
        "  color: #1B5E20;"
        "  border: 1px solid #008800;"
        "  outline: 0;"
        "  show-decoration-selected: 1;"
        "}"
        "QTreeView::item { padding: 2px 4px; }"
        "QTreeView::item:selected {"
        "  background-color: #003300;"
        "  color: #00FF00;"
        "}"
        "QTreeView::item:selected:active {"
        "  background-color: #003300;"
        "  color: #00FF00;"
        "}");
    completer->setPopup(popup);
    lineEdit->setCompleter(completer);
    QObject::connect(lineEdit, &QLineEdit::textChanged, filterModel, [filterModel]() {
        filterModel->refreshHintColumn();
    });
}

QString iguardExtractFileName(const std::wstring& path)
{
    const size_t pos = path.find_last_of(L"\\/");
    const std::wstring name = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    return QString::fromStdWString(name);
}

quint64 findModuleBaseByFileName(quint32 pid, const wchar_t* moduleFileName)
{
    for (const Process::ModuleInfo& module : Process::enumerateModules(pid))
    {
        if (iguardExtractFileName(module.path).compare(
                QString::fromWCharArray(moduleFileName),
                Qt::CaseInsensitive) == 0)
        {
            return static_cast<quint64>(module.base);
        }
    }

    return 0;
}

QString dmReadMethodLabel(UCHAR method)
{
    switch (method)
    {
    case READ_KERNEL_METHOD_MAP_IO:
        return QStringLiteral("map_io");
    case READ_KERNEL_METHOD_MMCOPY:
    default:
        return QStringLiteral("mmcopy");
    }
}

bool parseDmReadMethod(const QString& rawValue, UCHAR& methodOut, QString& errorOut)
{
    const QString normalized = rawValue.trimmed();
    if (normalized.isEmpty())
    {
        errorOut = QStringLiteral("Error: -method value is empty.");
        return false;
    }

    bool ok = false;
    const int numeric = normalized.toInt(&ok);
    if (ok)
    {
        if (numeric == READ_KERNEL_METHOD_MMCOPY
            || numeric == READ_KERNEL_METHOD_MAP_IO)
        {
            methodOut = static_cast<UCHAR>(numeric);
            return true;
        }

        errorOut = QString("Error: -method value '%1' is invalid (use 0/mmcopy or 2/map_io).").arg(rawValue);
        return false;
    }

    if (normalized.compare(QStringLiteral("mmcopy"), Qt::CaseInsensitive) == 0
        || normalized.compare(QStringLiteral("MmCopyMemory"), Qt::CaseInsensitive) == 0)
    {
        methodOut = READ_KERNEL_METHOD_MMCOPY;
        return true;
    }

    if (normalized.compare(QStringLiteral("map_io"), Qt::CaseInsensitive) == 0
        || normalized.compare(QStringLiteral("mapio"), Qt::CaseInsensitive) == 0
        || normalized.compare(QStringLiteral("MmMapIoSpaceEx"), Qt::CaseInsensitive) == 0)
    {
        methodOut = READ_KERNEL_METHOD_MAP_IO;
        return true;
    }

    errorOut = QString("Error: -method value '%1' is invalid (0/mmcopy, 2/map_io).")
        .arg(rawValue);
    return false;
}

QString formatDmReadError(UCHAR errStep, LONG status)
{
    switch (errStep)
    {
    case READ_PAGE_ERR_LOOKUP_FAILED:
        return QStringLiteral("PsLookupProcessByProcessId failed");
    case READ_PAGE_ERR_USER_ACCESS:
        return QStringLiteral("user-mode memory access violation");
    case READ_PAGE_ERR_VA_RANGE:
        return QStringLiteral("memory address out of bounds");
    case READ_PAGE_ERR_PHYS_INVALID:
        return QStringLiteral("MmIsAddressValid failed");
    case READ_PAGE_ERR_PHYS_NO_PA:
        return QStringLiteral("MmGetPhysicalAddress failed");
    case READ_PAGE_ERR_PHYS_COPY:
        return QString("MmCopyMemory failed (status=0x%1)")
            .arg(static_cast<ULONG>(status), 0, 16);
    case READ_PAGE_ERR_PTE_BASE:
        return QStringLiteral("PTE base unavailable");
    case READ_PAGE_ERR_PTE_LOOKUP:
        return QStringLiteral("kernel PTE slot read failed");
    case READ_PAGE_ERR_PTE_INVALID:
        return QStringLiteral("kernel PTE/PDE not present");
    case READ_PAGE_ERR_PTE_REMAP:
        return QStringLiteral("unsupported kernel read method");
    case READ_PAGE_ERR_MAP_IO:
        return QStringLiteral("MmMapIoSpaceEx failed");
    default:
        return QString("read failed (errStep=%1)").arg(errStep);
    }
}

QString iguardFileNameStem(const QString& fileName)
{
    const int dotIndex = fileName.lastIndexOf('.');
    return (dotIndex > 0) ? fileName.left(dotIndex) : fileName;
}

bool iguardModuleFilterMatches(const std::wstring& modulePath, const QString& filter)
{
    const QString fileName = iguardExtractFileName(modulePath);
    const QString normalizedFilter = filter.trimmed();
    if (normalizedFilter.isEmpty())
    {
        return false;
    }

    if (fileName.compare(normalizedFilter, Qt::CaseInsensitive) == 0)
    {
        return true;
    }

    const QString fileStem = iguardFileNameStem(fileName);
    const QString filterStem = iguardFileNameStem(normalizedFilter);
    return fileStem.compare(filterStem, Qt::CaseInsensitive) == 0;
}

QString iguardFormatRegionLabel(ULONG mRegion, ULONG regionValue)
{
    if (mRegion == 5)
    {
        return QString("nonpaged(%1)").arg(regionValue);
    }
    if (mRegion == 6)
    {
        return QString("paged(%1)").arg(regionValue);
    }
    if (mRegion == 9)
    {
        return QString("system(%1)").arg(regionValue);
    }
    if (mRegion == 12)
    {
        return QString("image(%1)").arg(regionValue);
    }
    return QString("region(%1)").arg(regionValue);
}

QString iguardFormatPteFlags(quint64 pte)
{
    if (pte == 0)
    {
        return QStringLiteral("n/a");
    }

    QStringList flags;
    if (pte & 0x1)
    {
        flags << QStringLiteral("P");
    }
    if (pte & 0x2)
    {
        flags << QStringLiteral("RW");
    }
    else if (pte & 0x1)
    {
        flags << QStringLiteral("R");
    }

    if ((pte & 0x8000000000000000ull) == 0)
    {
        flags << QStringLiteral("X");
    }
    else
    {
        flags << QStringLiteral("NX");
    }

    return flags.join('|');
}

static QString pteEntryTypeLabel(UCHAR entryType)
{
    switch (entryType)
    {
    case VA_PTE_ENTRY_TYPE_PTE: return QStringLiteral("PTE");
    case VA_PTE_ENTRY_TYPE_PDE: return QStringLiteral("PDE (large page)");
    default: return QStringLiteral("unknown");
    }
}

static QString formatHardwarePteDetails(quint64 pte)
{
    const auto bit = [pte](int pos) -> quint64 { return (pte >> pos) & 1ull; };
    const auto bits = [pte](int pos, int width) -> quint64 {
        return (pte >> pos) & ((width >= 64) ? ~0ull : ((1ull << width) - 1ull));
    };

    QStringList lines;
    lines << QStringLiteral("  Valid            : %1").arg(bit(0));
    lines << QStringLiteral("  Write            : %1").arg(bit(1));
    lines << QStringLiteral("  Owner            : %1").arg(bit(2));
    lines << QStringLiteral("  WriteThrough     : %1").arg(bit(3));
    lines << QStringLiteral("  CacheDisable     : %1").arg(bit(4));
    lines << QStringLiteral("  Accessed         : %1").arg(bit(5));
    lines << QStringLiteral("  Dirty            : %1").arg(bit(6));
    lines << QStringLiteral("  LargePage        : %1").arg(bit(7));
    lines << QStringLiteral("  Global           : %1").arg(bit(8));
    lines << QStringLiteral("  CopyOnWrite      : %1").arg(bit(9));
    lines << QStringLiteral("  Prototype        : %1").arg(bit(10));
    lines << QStringLiteral("  reserved0        : %1").arg(bit(11));
    lines << QStringLiteral("  PageFrameNumber  : 0x%1").arg(bits(12, 40), 0, 16);
    lines << QStringLiteral("  SoftwareWsIndex  : 0x%1").arg(bits(52, 11), 0, 16);
    lines << QStringLiteral("  NoExecute        : %1").arg(bit(63));
    return lines.join('\n');
}

static QString pfnPageLocationText(quint32 pageLocation)
{
    switch (pageLocation)
    {
    case 0: return QStringLiteral("ZeroedPage");
    case 1: return QStringLiteral("FreePageList");
    case 2: return QStringLiteral("StandbyPageList");
    case 3: return QStringLiteral("ModifiedPageList");
    case 4: return QStringLiteral("ModifiedNoWritePageList");
    case 5: return QStringLiteral("BadPageList");
    case 6: return QStringLiteral("ActiveAndValid");
    case 7: return QStringLiteral("TransitionPage");
    default: return QStringLiteral("Unknown");
    }
}

static QString pfnErrText(UCHAR errCode)
{
    switch (errCode)
    {
    case VA_PFN_ERR_SUCCESS: return QStringLiteral("success");
    case VA_PFN_ERR_BASE_UNAVAILABLE: return QStringLiteral("pte/pfn base unavailable");
    case VA_PFN_ERR_PTE_NOT_FOUND: return QStringLiteral("pte not found");
    case VA_PFN_ERR_PTE_INVALID: return QStringLiteral("pte not present");
    case VA_PFN_ERR_PFN_READ_FAILED: return QStringLiteral("pfn database read failed");
    default: return QStringLiteral("failed");
    }
}

static quint64 readPfnQword(const UCHAR* data, int offset)
{
    quint64 value = 0;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}

static quint32 readPfnDword(const UCHAR* data, int offset)
{
    quint32 value = 0;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}

static quint16 readPfnWord(const UCHAR* data, int offset)
{
    quint16 value = 0;
    std::memcpy(&value, data + offset, sizeof(value));
    return value;
}

static QString formatMmpfnDetails(const UCHAR* pfnData)
{
    const quint64 listEntry = readPfnQword(pfnData, 0x00);
    const quint64 pteAddress = readPfnQword(pfnData, 0x08);
    const quint64 originalPte = readPfnQword(pfnData, 0x10);
    const quint64 u2 = readPfnQword(pfnData, 0x18);
    const quint32 u3 = readPfnDword(pfnData, 0x20);
    const quint16 nodeBlinkLow = readPfnWord(pfnData, 0x24);
    const quint8 viewCount = pfnData[0x27];
    const quint64 u4 = readPfnQword(pfnData, 0x28);

    const quint16 referenceCount = static_cast<quint16>(u3 & 0xFFFF);
    const quint16 flags = static_cast<quint16>((u3 >> 16) & 0xFFFF);
    const quint64 shareCount = u2 & ((1ull << 62) - 1ull);
    const quint32 deleteBit = static_cast<quint32>((u2 >> 62) & 1);
    const quint32 lockBit = static_cast<quint32>((u2 >> 63) & 1);

    QStringList lines;
    lines << QStringLiteral("  ListEntry        : 0x%1").arg(listEntry, 16, 16, QChar('0'));
    lines << QStringLiteral("  PteAddress       : 0x%1").arg(pteAddress, 16, 16, QChar('0'));
    lines << QStringLiteral("  OriginalPte      : 0x%1").arg(originalPte, 16, 16, QChar('0'));
    lines << QStringLiteral("  u2.ShareCount    : %1").arg(shareCount);
    lines << QStringLiteral("  u2.DeleteBit     : %1").arg(deleteBit);
    lines << QStringLiteral("  u2.LockBit       : %1").arg(lockBit);
    lines << QStringLiteral("  ReferenceCount   : %1").arg(referenceCount);
    lines << QStringLiteral("  Modified         : %1").arg(flags & 0x1);
    lines << QStringLiteral("  ReadInProgress   : %1").arg((flags >> 1) & 0x1);
    lines << QStringLiteral("  WriteInProgress  : %1").arg((flags >> 2) & 0x1);
    lines << QStringLiteral("  PrototypePte     : %1").arg((flags >> 3) & 0x1);
    lines << QStringLiteral("  PageColor        : %1").arg((flags >> 4) & 0xF);
    lines << QStringLiteral("  PageLocation     : %1 (%2)")
        .arg((flags >> 8) & 0x7)
        .arg(pfnPageLocationText((flags >> 8) & 0x7));
    lines << QStringLiteral("  RemovalRequested : %1").arg((flags >> 11) & 0x1);
    lines << QStringLiteral("  CacheAttribute   : %1").arg((flags >> 12) & 0x3);
    lines << QStringLiteral("  Rom              : %1").arg((flags >> 14) & 0x1);
    lines << QStringLiteral("  ParityError      : %1").arg((flags >> 15) & 0x1);
    lines << QStringLiteral("  NodeBlinkLow     : 0x%1").arg(nodeBlinkLow, 4, 16, QChar('0'));
    lines << QStringLiteral("  ViewCount        : %1").arg(viewCount);
    lines << QStringLiteral("  u4               : 0x%1").arg(u4, 16, 16, QChar('0'));
    return lines.join('\n');
}

void iguardPostOutput(Hawkeye* hawkeye, const QString& text);

QString iguardFormatResolvedSymbol(SymbolManager* symbolManager, DWORD64 address)
{
    if (symbolManager == nullptr)
    {
        return QString();
    }

    std::wstring symbolName;
    DWORD64 displacement = 0;
    std::wstring moduleName;
    DWORD64 moduleBase = 0;
    bool symBusy = false;
    if (!symbolManager->ResolveAddress(
            address,
            symbolName,
            displacement,
            moduleName,
            moduleBase,
            &symBusy))
    {
        if (symBusy)
        {
            return QStringLiteral("[sym busy]");
        }
        return QString();
    }

    if (moduleName.empty())
    {
        return QString("%1+0x%2")
            .arg(QString::fromStdWString(symbolName))
            .arg(displacement, 0, 16);
    }

    return QString("%1!%2+0x%3")
        .arg(QString::fromStdWString(moduleName))
        .arg(QString::fromStdWString(symbolName))
        .arg(displacement, 0, 16);
}

bool iguardLoadModuleSymbols(
    SymbolManager* symbolManager,
    Hawkeye* hawkeye,
    const std::wstring& modulePath,
    std::set<std::wstring>& attemptedModuleKeys)
{
    if (symbolManager == nullptr || modulePath.empty())
    {
        return false;
    }

    const std::wstring dosPath = convertSystemRootPathW(modulePath.c_str());
    if (dosPath.empty())
    {
        return false;
    }

    const std::wstring moduleKey = SymbolManager::NormalizeFilePathKey(dosPath);
    if (!attemptedModuleKeys.insert(moduleKey).second)
    {
        return true;
    }

    SymbolLoadOptions loadOptions;
    loadOptions.maxLoadAttempts = 4;
    if (hawkeye != nullptr)
    {
        loadOptions.logFn = [hawkeye](const std::wstring& message) {
            iguardPostOutput(hawkeye, QString::fromStdWString(message));
        };
    }

    std::wstring loadError;
    return symbolManager->LoadSymbol(dosPath, loadError, 0, &loadOptions);
}

bool iguardPreloadNtoskrnlSymbols(
    SymbolManager* symbolManager,
    Hawkeye* hawkeye,
    const std::vector<Process::ModuleInfo>& modules,
    std::set<std::wstring>& attemptedModuleKeys)
{
    for (const Process::ModuleInfo& module : modules)
    {
        if (iguardExtractFileName(module.path).compare(QStringLiteral("ntoskrnl.exe"), Qt::CaseInsensitive) == 0)
        {
            return iguardLoadModuleSymbols(symbolManager, hawkeye, module.path, attemptedModuleKeys);
        }
    }

    iguardPostOutput(hawkeye, QStringLiteral("Warning: ntoskrnl.exe not found for symbol preload."));
    return false;
}

void iguardPostOutput(Hawkeye* hawkeye, const QString& text)
{
    if (hawkeye == nullptr)
    {
        return;
    }

    QMetaObject::invokeMethod(hawkeye, [hawkeye, text]() {
        hawkeye->setOutputText(text);
    }, Qt::QueuedConnection);
}

void runIguardScan(
    Hawkeye* hawkeye,
    bool scanAll,
    const QString& moduleFilter,
    bool enableSymbols,
    SymbolManager* symbolManager)
{
    if (hawkeye == nullptr)
    {
        return;
    }

    if (DriverStatusError)
    {
        iguardPostOutput(hawkeye, QStringLiteral("Error: driver is not loaded."));
        return;
    }

    const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(4);
    if (modules.empty())
    {
        iguardPostOutput(hawkeye, QStringLiteral("Error: no kernel modules enumerated."));
        return;
    }

    std::set<std::wstring> attemptedModuleKeys;
    if (enableSymbols)
    {
        if (symbolManager == nullptr)
        {
            iguardPostOutput(hawkeye, QStringLiteral("Warning: symbol manager unavailable, continuing without symbols."));
            enableSymbols = false;
        }
        else
        {
            iguardPostOutput(
                hawkeye,
                QStringLiteral("Symbol resolve: enabled (preload ntoskrnl.exe PDB)"));
            iguardPreloadNtoskrnlSymbols(symbolManager, hawkeye, modules, attemptedModuleKeys);
        }
    }

    std::vector<Process::ModuleInfo> targets;
    targets.reserve(modules.size());
    for (const Process::ModuleInfo& module : modules)
    {
        if (scanAll)
        {
            targets.push_back(module);
        }
        else if (iguardModuleFilterMatches(module.path, moduleFilter))
        {
            targets.push_back(module);
        }
    }

    if (!scanAll && targets.empty())
    {
        iguardPostOutput(hawkeye, QString("Error: kernel module '%1' not found.").arg(moduleFilter));
        return;
    }

    iguardPostOutput(hawkeye, QString("iguard scan: checking %1 kernel module(s)...").arg(targets.size()));

    quint32 modulesScanned = 0;
    quint32 modulesWithHits = 0;
    quint32 totalHits = 0;

    for (const Process::ModuleInfo& module : targets)
    {
        auto scanResult = std::make_unique<IGUARD_PIT_SCAN>();
        std::memset(scanResult.get(), 0, sizeof(IGUARD_PIT_SCAN));
        scanResult->sysBase = module.base;
        IGuardPitScan(scanResult.get());
        modulesScanned++;

        if (scanResult->errCode == 2 || scanResult->errCode == 3)
        {
            iguardPostOutput(hawkeye, QString("  [skip] %1  base=0x%2  errCode=%3")
                .arg(iguardExtractFileName(module.path))
                .arg(static_cast<qulonglong>(module.base), 16, 16, QChar('0'))
                .arg(scanResult->errCode));
            continue;
        }

        if (scanResult->hitCount == 0)
        {
            continue;
        }

        modulesWithHits++;
        totalHits += scanResult->hitCount;

        const QString truncated = (scanResult->errCode == 4)
            ? QStringLiteral("  (hit buffer full, results truncated)")
            : QString();

        iguardPostOutput(hawkeye, QString("[module] %1").arg(QString::fromStdWString(module.path)));
        iguardPostOutput(hawkeye, QString("  base=0x%1  size=0x%2  suspicious pits=%3%4")
            .arg(static_cast<qulonglong>(module.base), 16, 16, QChar('0'))
            .arg(module.size, 0, 16)
            .arg(scanResult->hitCount)
            .arg(truncated));

        if (enableSymbols)
        {
            iguardLoadModuleSymbols(symbolManager, hawkeye, module.path, attemptedModuleKeys);
        }

        for (ULONG hitIndex = 0; hitIndex < scanResult->hitCount; ++hitIndex)
        {
            const IGUARD_PIT_HIT& hit = scanResult->hits[hitIndex];
            GET_VIRTUAL_ADDRESS_PTE pteQuery = { 0 };
            pteQuery.pid = 4;
            pteQuery.va = hit.pitData;
            GetVirtualAddressPte(&pteQuery);

            const QString regionLabel = iguardFormatRegionLabel(hit.mRegion, hit.regionValue);
            const QString regionName = GetKernelMemoryRegionName(hit.pitData);
            const qulonglong pitRva = static_cast<qulonglong>(hit.pitAddr - module.base);
            const QString pteText = (pteQuery.errCode == 1)
                ? QString("0x%1 [%2]")
                    .arg(static_cast<qulonglong>(pteQuery.pteData), 16, 16, QChar('0'))
                    .arg(iguardFormatPteFlags(pteQuery.pteData))
                : QStringLiteral("unavailable");

            const QString pitSymbol = enableSymbols
                ? iguardFormatResolvedSymbol(symbolManager, hit.pitAddr)
                : QString();
            const QString targetSymbol = enableSymbols
                ? iguardFormatResolvedSymbol(symbolManager, hit.pitData)
                : QString();

            QString pitLine = QString("  [%1] pit=0x%2 (+0x%3) -> target=0x%4")
                .arg(hitIndex, 3, 10, QChar('0'))
                .arg(static_cast<qulonglong>(hit.pitAddr), 16, 16, QChar('0'))
                .arg(pitRva, 0, 16)
                .arg(static_cast<qulonglong>(hit.pitData), 16, 16, QChar('0'));
            if (!pitSymbol.isEmpty())
            {
                pitLine += QString("  pit: %1").arg(pitSymbol);
            }
            iguardPostOutput(hawkeye, pitLine);

            if (!targetSymbol.isEmpty())
            {
                iguardPostOutput(hawkeye, QString("        target: %1").arg(targetSymbol));
            }
            iguardPostOutput(hawkeye, QString("        region: %1  %2")
                .arg(regionLabel)
                .arg(regionName));
            iguardPostOutput(hawkeye, QString("        pte:    %1").arg(pteText));
        }
    }

    iguardPostOutput(hawkeye, QString("Done: scanned=%1  modules_with_hits=%2  total_suspicious_pits=%3")
        .arg(modulesScanned)
        .arg(modulesWithHits)
        .arg(totalHits));

    if (totalHits == 0)
    {
        iguardPostOutput(hawkeye, QStringLiteral("No suspicious _guard_dispatch_icall pits found."));
    }
}

void inlineHookPostColoredBatch(Hawkeye* hawkeye, QVector<ConsoleColoredLine> lines)
{
    if (hawkeye == nullptr || lines.isEmpty())
    {
        return;
    }

    QMetaObject::invokeMethod(hawkeye, [hawkeye, lines = std::move(lines)]() mutable {
        hawkeye->appendConsoleColoredBatch(std::move(lines));
    }, Qt::QueuedConnection);
}

struct InlineHookModuleGroup
{
    std::uint64_t moduleBase = 0;
    bool moduleIsPe32 = false;
    std::wstring modulePath;
    std::vector<std::size_t> hitIndices;
};

QString formatInlineHookInstruction(const InlineHookHit& hit)
{
    if (hit.memorySnippetSize == 0)
    {
        return QString("mem=0x%1 file=0x%2")
            .arg(hit.memoryByte, 2, 16, QChar('0'))
            .arg(hit.fileByte, 2, 16, QChar('0'));
    }

    INSTRUX ix;
    std::memset(&ix, 0, sizeof(ix));
    const NDSTATUS decodeStatus = hit.moduleIsPe32
        ? NdDecodeEx(&ix, hit.memorySnippet, hit.memorySnippetSize, ND_CODE_32, ND_DATA_32)
        : NdDecodeEx(&ix, hit.memorySnippet, hit.memorySnippetSize, ND_CODE_64, ND_DATA_64);

    if (!ND_SUCCESS(decodeStatus))
    {
        return QString("mem=0x%1 file=0x%2")
            .arg(hit.memoryByte, 2, 16, QChar('0'))
            .arg(hit.fileByte, 2, 16, QChar('0'));
    }

    char text[ND_MIN_BUF_SIZE] = { 0 };
    const NDSTATUS textStatus = NdToText(
        &ix,
        static_cast<UINT64>(hit.address),
        sizeof(text),
        text);
    if (ND_SUCCESS(textStatus))
    {
        return QString::fromLatin1(text).trimmed();
    }

    return QString::fromLatin1(ix.Mnemonic);
}

std::vector<InlineHookModuleGroup> groupInlineHookHits(const std::vector<InlineHookHit>& hits)
{
    std::vector<InlineHookModuleGroup> groups;
    for (std::size_t hitIndex = 0; hitIndex < hits.size(); ++hitIndex)
    {
        const InlineHookHit& hit = hits[hitIndex];
        InlineHookModuleGroup* group = nullptr;
        for (InlineHookModuleGroup& candidate : groups)
        {
            if (candidate.moduleBase == hit.moduleBase && candidate.modulePath == hit.modulePath)
            {
                group = &candidate;
                break;
            }
        }

        if (group == nullptr)
        {
            InlineHookModuleGroup created;
            created.moduleBase = hit.moduleBase;
            created.moduleIsPe32 = hit.moduleIsPe32;
            created.modulePath = hit.modulePath;
            groups.push_back(std::move(created));
            group = &groups.back();
        }

        group->hitIndices.push_back(hitIndex);
    }

    std::sort(groups.begin(), groups.end(), [](const InlineHookModuleGroup& left, const InlineHookModuleGroup& right) {
        if (left.modulePath != right.modulePath)
        {
            return left.modulePath < right.modulePath;
        }
        return left.moduleBase < right.moduleBase;
    });

    return groups;
}

void runInlineHookScan(Hawkeye* hawkeye, std::uint32_t pid)
{
    if (hawkeye == nullptr)
    {
        return;
    }

    const InlineHookScanResult result = DetectGlobalInlineHookEx(pid);
    QVector<ConsoleColoredLine> lines;
    lines.reserve(result.hits.empty() ? 4u : static_cast<int>(result.hits.size() + 64));

    auto addLine = [&lines](const QString& text, const QColor& color = QColor()) {
        ConsoleColoredLine line;
        line.text = text;
        line.color = color;
        lines.push_back(std::move(line));
    };

    if (!result.error.empty())
    {
        addLine(QString("Error: %1").arg(QString::fromStdWString(result.error)));
        inlineHookPostColoredBatch(hawkeye, std::move(lines));
        return;
    }

    addLine(
        QString("inline hook scan: pid=%1  modules=%2  skipped=%3  hits=%4")
            .arg(result.pid)
            .arg(result.modulesScanned)
            .arg(result.modulesSkipped)
            .arg(result.hits.size()));

    if (result.hits.empty())
    {
        addLine(QStringLiteral("No inline hooks detected."));
        inlineHookPostColoredBatch(hawkeye, std::move(lines));
        return;
    }

    const std::vector<InlineHookModuleGroup> groups = groupInlineHookHits(result.hits);
    addLine(QString("Found %1 module(s) with inline hook byte diffs:").arg(groups.size()));

    const QColor moduleHeaderColor("#6B8E23");
    const QColor hookLineColor("#202020");

    for (const InlineHookModuleGroup& group : groups)
    {
        const QString path = group.modulePath.empty()
            ? QStringLiteral("[path unavailable]")
            : QString::fromStdWString(group.modulePath);

        addLine(
            QString("0x%1  %2  (%3 hit%4, pe=%5)")
                .arg(static_cast<qulonglong>(group.moduleBase), 16, 16, QChar('0'))
                .arg(path)
                .arg(group.hitIndices.size())
                .arg(group.hitIndices.size() == 1 ? QString() : QStringLiteral("s"))
                .arg(group.moduleIsPe32 ? QStringLiteral("32") : QStringLiteral("64")),
            moduleHeaderColor);

        for (std::size_t groupHitIndex = 0; groupHitIndex < group.hitIndices.size(); ++groupHitIndex)
        {
            const InlineHookHit& hit = result.hits[group.hitIndices[groupHitIndex]];
            const QString addrHex = QString("0x%1")
                .arg(static_cast<qulonglong>(hit.address), 16, 16, QChar('0'));
            const bool isLastHit = groupHitIndex + 1 >= group.hitIndices.size();
            const QString treePrefix = isLastHit ? QStringLiteral("  `- ") : QStringLiteral("  |- ");

            const QString diffSizeText = hit.diffByteCount > 1
                ? QString(" (%1 bytes)").arg(hit.diffByteCount)
                : QString();

            addLine(
                QString("%1%2 <inline hook> [%3]%4~~%5")
                    .arg(treePrefix)
                    .arg(addrHex)
                    .arg(addrHex)
                    .arg(diffSizeText)
                    .arg(formatInlineHookInstruction(hit)),
                hookLineColor);
        }

        addLine(QString());
    }

    inlineHookPostColoredBatch(hawkeye, std::move(lines));
}

} // namespace

Hawkeye::Hawkeye(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    this->resize(1280, 800);
    this->setMinimumSize(800, 600);
    HawkeyeTitleBar::attach(this, HawkeyeTitleBar::MinMaxClose);
    HawkeyeStyle::applyChrome(this);
    applyDriverStatusChip();
    ui.pushButtonMemory->setCursor(Qt::PointingHandCursor);

    {
        const int cmdRowIndex = ui.horizontalLayout->indexOf(ui.lineEditCMD);
        ui.horizontalLayout->removeWidget(ui.lineEditCMD);
        ui.horizontalLayout->removeWidget(ui.pushButtonMemory);

        auto* cmdMemoryRow = new QWidget(this);
        auto* cmdMemoryLayout = new QHBoxLayout(cmdMemoryRow);
        cmdMemoryLayout->setContentsMargins(0, 0, 0, 0);
        cmdMemoryLayout->setSpacing(10);
        cmdMemoryLayout->addWidget(ui.lineEditCMD, 1);
        cmdMemoryLayout->addWidget(ui.pushButtonMemory, 0);

        ui.horizontalLayout->insertWidget(cmdRowIndex, cmdMemoryRow, 1);
    }

    QPalette consolePalette = ui.textEditConsole->palette();
    consolePalette.setColor(QPalette::Text, QColor("#222222"));
    consolePalette.setColor(QPalette::Base, QColor("#fafcfa"));
    ui.textEditConsole->setPalette(consolePalette);

    new ConsoleBorderGlow(ui.textEditConsole);
    new CmdLineScanGlow(ui.lineEditCMD);

    QFont consoleFont("Consolas");
    consoleFont.setStyleHint(QFont::Monospace);
    ui.textEditConsole->setFont(consoleFont);
    ui.textEditConsole->setReadOnly(true);
    ui.textEditConsole->document()->setUndoRedoEnabled(false);
    ui.textEditConsole->setLineWrapMode(QTextEdit::NoWrap);
    ui.textEditConsole->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    ui.textEditConsole->setOpenExternalLinks(false);
    ui.textEditConsole->setOpenLinks(false);
    connect(ui.textEditConsole, SIGNAL(anchorClicked(QUrl)), this, SLOT(onConsoleAnchorClicked(QUrl)));
    ui.textEditConsole->installEventFilter(this);
    installEventFilter(this);

    ui.checkBoxMCP->hide();

    connect(ui.pushButtonMemory, &QPushButton::clicked,
        this, &Hawkeye::onPushButtonMemoryClicked);

    ui.labelEditionStatus->installEventFilter(this);
    ui.labelDriverStatus->installEventFilter(this);
    applyEditionChip();

    QToolButton* runButton = new QToolButton(ui.lineEditCMD);
    runButton->setIcon(HawkeyeStyle::runCommandIcon());
    runButton->setIconSize(QSize(18, 18));
    runButton->setToolTip(QStringLiteral("Run command (Enter)"));
    runButton->setCursor(Qt::PointingHandCursor);
    runButton->setAutoRaise(false);
    runButton->setFixedSize(22, 22);

    QWidgetAction* runCmdAction = new QWidgetAction(ui.lineEditCMD);
    runCmdAction->setDefaultWidget(runButton);
    ui.lineEditCMD->addAction(runCmdAction, QLineEdit::TrailingPosition);

    connect(ui.lineEditCMD, &QLineEdit::returnPressed, runButton, &QToolButton::click);

    auto runCommand = [this]() {
        QString text = ui.lineEditCMD->text();
        addCommandToHistory(text);

        handleCommandLine(text);
        resetCommandHistoryNavigation();
        ui.lineEditCMD->clear();
        ui.lineEditCMD->setPlaceholderText("");
    };
    connect(runButton, &QToolButton::clicked, this, runCommand);

    ui.lineEditCMD->setPlaceholderText("!help");
    ui.lineEditCMD->installEventFilter(this);
    setupCommandCompleter(ui.lineEditCMD);

    CaptureMemoryIntegrityState();

    QTimer::singleShot(1000, this, &Hawkeye::onStartupDelayed);

    m_resizeSettleTimer = new QTimer(this);
    m_resizeSettleTimer->setSingleShot(true);
    m_resizeSettleTimer->setInterval(150);
    connect(m_resizeSettleTimer, &QTimer::timeout, this, &Hawkeye::onConsoleResizeSettled);
}

Hawkeye::~Hawkeye()
{
    if (m_memoryDialog) {
        disconnect(m_memoryDialog, nullptr, this, nullptr);
        delete m_memoryDialog;
        m_memoryDialog = nullptr;
    }

    if (m_driverSetupDialog) {
        disconnect(m_driverSetupDialog, nullptr, this, nullptr);
        delete m_driverSetupDialog;
        m_driverSetupDialog = nullptr;
    }

}

HWND Hawkeye::getWindowHandle() const
{
    WId windowId = winId();
    if (windowId == 0) {
        windowId = const_cast<Hawkeye*>(this)->winId();
    }
    return reinterpret_cast<HWND>(windowId);
}

bool Hawkeye::nativeEvent(const QByteArray& eventType, void* message, long* result)
{
    if (eventType != "windows_generic_MSG" || isMaximized()) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    const MSG* msg = static_cast<MSG*>(message);
    if (msg->message != WM_NCHITTEST) {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    RECT rc = {};
    GetWindowRect(reinterpret_cast<HWND>(winId()), &rc);
    const POINT pt = { GET_X_LPARAM(msg->lParam), GET_Y_LPARAM(msg->lParam) };
    const int border = 6;
    const bool left = pt.x < rc.left + border;
    const bool right = pt.x >= rc.right - border;
    const bool top = pt.y < rc.top + border;
    const bool bottom = pt.y >= rc.bottom - border;

    if (top && left) {
        *result = HTTOPLEFT;
        return true;
    }
    if (top && right) {
        *result = HTTOPRIGHT;
        return true;
    }
    if (bottom && left) {
        *result = HTBOTTOMLEFT;
        return true;
    }
    if (bottom && right) {
        *result = HTBOTTOMRIGHT;
        return true;
    }
    if (left) {
        *result = HTLEFT;
        return true;
    }
    if (right) {
        *result = HTRIGHT;
        return true;
    }
    if (top) {
        *result = HTTOP;
        return true;
    }
    if (bottom) {
        *result = HTBOTTOM;
        return true;
    }

    return QMainWindow::nativeEvent(eventType, message, result);
}

bool Hawkeye::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == ui.labelEditionStatus && event->type() == QEvent::MouseButtonRelease) {
        onEditionChipClicked();
        return true;
    }
    if (watched == ui.labelDriverStatus && event->type() == QEvent::MouseButtonRelease) {
        onDriverSetupClicked();
        return true;
    }

    if ((watched == ui.textEditConsole || watched == this)
        && event->type() == QEvent::Resize) {
        beginConsoleResizeFreeze();
    }

    if (watched == ui.lineEditCMD && event->type() == QEvent::KeyPress) {
        auto* keyEvent = static_cast<QKeyEvent*>(event);
        if (keyEvent->key() == Qt::Key_Up || keyEvent->key() == Qt::Key_Down) {
            if (QCompleter* completer = ui.lineEditCMD->completer()) {
                if (completer->popup()->isVisible()) {
                    return false;
                }
            }

            if (m_cmdHistory.isEmpty()) {
                return QMainWindow::eventFilter(watched, event);
            }

            if (keyEvent->key() == Qt::Key_Up) {
                if (m_historyIndex == -1) {
                    m_historyDraft = ui.lineEditCMD->text();
                    m_historyIndex = m_cmdHistory.size() - 1;
                }
                else if (m_historyIndex > 0) {
                    --m_historyIndex;
                }
            }
            else {
                if (m_historyIndex == -1) {
                    return QMainWindow::eventFilter(watched, event);
                }

                if (m_historyIndex < m_cmdHistory.size() - 1) {
                    ++m_historyIndex;
                }
                else {
                    m_historyIndex = -1;
                    ui.lineEditCMD->setText(m_historyDraft);
                    ui.lineEditCMD->setCursorPosition(m_historyDraft.length());
                    return true;
                }
            }

            ui.lineEditCMD->setText(m_cmdHistory.at(m_historyIndex));
            ui.lineEditCMD->setCursorPosition(m_cmdHistory.at(m_historyIndex).length());
            return true;
        }
    }

    return QMainWindow::eventFilter(watched, event);
}

void Hawkeye::addCommandToHistory(const QString& command)
{
    const QString trimmedCmd = command.trimmed();
    if (trimmedCmd.isEmpty()) {
        return;
    }

    if (m_cmdHistory.isEmpty() || m_cmdHistory.last() != trimmedCmd) {
        m_cmdHistory.append(trimmedCmd);
        if (m_cmdHistory.size() > kMaxCmdHistory) {
            m_cmdHistory.removeFirst();
        }
    }
}

void Hawkeye::resetCommandHistoryNavigation()
{
    m_historyIndex = -1;
    m_historyDraft.clear();
}

void Hawkeye::onStartupDelayed()
{
    performStartupTasks();
}

void Hawkeye::showStartupWelcome(bool driverReady)
{
    QString heading = QStringLiteral(HAWKEYE_PRODUCT_NAME);
    const QString version = QCoreApplication::applicationVersion();
    if (!version.isEmpty()) {
        heading += QStringLiteral("  Release ") + version;
    }
    setOutputTextHeading(heading);
    setOutputText(QString());
    if (!IsRunningAsAdmin()) {
        setOutputText(QString());
        setOutputTextColored(
            QStringLiteral("Hawkeye Community needs Administrator to load the driver."),
            QColor("#B71C1C"));
        setOutputText(QStringLiteral("Choose Restart as Administrator to continue."));

        QMessageBox box(this);
        box.setIcon(QMessageBox::Warning);
        box.setWindowTitle(QStringLiteral("Hawkeye Community"));
        box.setText(QStringLiteral("Hawkeye Community needs Administrator to load the driver."));
        box.setInformativeText(QStringLiteral("Choose Restart as Administrator to continue."));
        QPushButton* restartBtn = box.addButton(
            QStringLiteral("Restart as Administrator"), QMessageBox::AcceptRole);
        box.addButton(QStringLiteral("Not now"), QMessageBox::RejectRole);
        box.setDefaultButton(restartBtn);
        box.exec();

        if (box.clickedButton() == restartBtn) {
            if (RestartHawkeyeAsAdministrator()) {
                QCoreApplication::quit();
                return;
            }
            setOutputText(QStringLiteral(
                "Administrator restart was cancelled or failed. You can continue, or start Hawkeye again as Administrator."));
        }
    }
    if (driverReady && MemoryIntegrityIsRunning()) {
        setOutputText(QString());
        setOutputTextColored(
            QStringLiteral("Memory integrity is on. Turn it off, then restart Windows."),
            QColor("#B71C1C"));
        setOutputTextLinked(QStringLiteral("Open Memory integrity on the status bar."));
    }
    ui.lineEditCMD->setPlaceholderText(QStringLiteral("!help"));
}

void Hawkeye::printGettingStarted()
{
    const QString linkStyle = QStringLiteral("color:#1E88E5;text-decoration:underline;");
    const auto href = [&linkStyle](const QString& target, const QString& label) {
        return QStringLiteral("<a href=\"%1\" style=\"%2\">%3</a>")
            .arg(target.toHtmlEscaped(), linkStyle, label.toHtmlEscaped());
    };
    const auto title = [&](const QString& text) {
        appendConsoleHtmlLine(
            QStringLiteral("<span style=\"font-size:14pt;font-weight:700;\">%1</span>")
                .arg(text.toHtmlEscaped()));
    };
    const auto section = [&](const QString& text) {
        appendConsoleHtmlLine(
            QStringLiteral("<span style=\"font-weight:700;\">%1</span>")
                .arg(text.toHtmlEscaped()));
    };
    const auto door = [&](const QString& n, const QString& restHtml) {
        appendConsoleHtmlLine(
            QStringLiteral("<span style=\"font-weight:700;\">%1.</span>  %2")
                .arg(n, restHtml));
    };

    setOutputText(QString());
    title(QStringLiteral("Getting started"));
    setOutputText(QStringLiteral(
        "Hawkeye Community is an open console for authorized Windows research."));
    setOutputText(QStringLiteral(
        "Inspect live processes, modules, certificates, hooks, pages, and CPU samples."));
    setOutputText(QStringLiteral(
        "Use !probe for live, symbol-backed analysis on a process or the kernel."));

    setOutputText(QString());
    section(QStringLiteral("Probe and symbols"));
    setOutputText(QStringLiteral("  !probe attaches a live symbol context to a process or the kernel."));
    setOutputText(QStringLiteral("  Study runtime data with names and types, not addresses alone."));

    setOutputText(QString());
    section(QStringLiteral("Inspection"));
    setOutputText(QStringLiteral("  Processes, modules, threads, and digital signatures"));
    setOutputText(QStringLiteral("  Kernel CFG dispatch (!iguard_scan) and user-mode inline hooks"));
    setOutputText(QStringLiteral("  Page-table / PFN inspect and page dumps"));
    setOutputText(QStringLiteral("  ETW live CPU sampling"));

    setOutputText(QString());
    section(QStringLiteral("See what you get"));
    {
        appendConsoleHtmlLine(
            QStringLiteral("  Type ")
            + href(QStringLiteral("cmd:!help"), QStringLiteral("!help"))
            + QStringLiteral("."));
        setOutputText(QStringLiteral(
            "  Automated analysis and reports are Hawkeye Lab (separate product)."));
        setOutputText(QStringLiteral(
            "  Website: %1").arg(QStringLiteral(HAWKEYE_WEBSITE_URL)));
    }
    setOutputText(QString());
    section(QStringLiteral("To begin"));
    door(QStringLiteral("1"),
         href(QStringLiteral("ui://driver-setup"), QStringLiteral("Driver setup"))
         + QStringLiteral(" -- Administrator, Secure Boot, test signing, Memory integrity, and the driver"));
    door(QStringLiteral("2"),
         QStringLiteral("Type ")
         + href(QStringLiteral("cmd:!help"), QStringLiteral("!help"))
         + QStringLiteral(" -- the full command list, grouped by family"));
    door(QStringLiteral("3"),
         QStringLiteral("Type ")
         + href(QStringLiteral("cmd:!support"), QStringLiteral("!support"))
         + QStringLiteral(" -- website, email, and a machine report if something breaks"));
    if (!gettingStartedIsHidden()) {
        setOutputText(QString());
        appendConsoleHtmlLine(
            href(QStringLiteral("ui://hide-getting-started"),
                 QStringLiteral("Don't show this again")));
    }
}

bool Hawkeye::gettingStartedIsHidden() const
{
    QSettings settings(QStringLiteral("HKEY_CURRENT_USER\\Software\\Hawkeye Community"), QSettings::NativeFormat);
    return settings.value(QStringLiteral("gettingStarted/hidden"), false).toBool();
}

void Hawkeye::hideGettingStartedFromNow()
{
    QSettings settings(QStringLiteral("HKEY_CURRENT_USER\\Software\\Hawkeye Community"), QSettings::NativeFormat);
    settings.setValue(QStringLiteral("gettingStarted/hidden"), true);
    setOutputTextLinked(QStringLiteral(
        "Getting started will not show at startup. Type !getting-started to open it again."));
}

void Hawkeye::printSupportReport()
{
    setOutputText(CompatReportText(GetLastDriverCompatRef(), GetLastDriverStartError()));
}

void Hawkeye::performStartupTasks()
{
    bool driverConnected = TestDrv();
    DrvStartFailReason reason = DrvStartOk;
    if (!driverConnected)
    {
        reason = InstallHawkDrvWithReason();
        driverConnected = (reason == DrvStartOk);
    }

    if (!driverConnected)
    {
        DriverStatusError = true;
        m_driverSetupNeeded = (reason != DrvStartFailKernelLayout);
        m_driverStatusReady = true;
        applyDriverStatusChip();
        applyEditionChip();
        showStartupWelcome(false);
        if (reason == DrvStartFailSignature)
        {
            setOutputText("Driver not loaded -- signature blocked by Windows.");
            setOutputTextLinked("Open Driver setup on the status bar.");
        }
        else if (reason == DrvStartFailKernelLayout)
        {
            const char* compatRef = GetLastDriverCompatRef();
            const QString reference = compatRef != nullptr
                ? QString::fromLatin1(compatRef)
                : QStringLiteral("HAWK-COMPAT-0200");
            setOutputText(QStringLiteral(
                "Sorry -- this Windows build is not supported yet."));
            setOutputText(QStringLiteral("Reference: %1").arg(reference));
            setOutputText(QStringLiteral(
                "Email !support output to %1 so we can prioritize this build.")
                              .arg(QStringLiteral(HAWKEYE_SUPPORT_EMAIL)));
            setOutputTextLinked(QStringLiteral("Run !support"));
        }
        else
        {
            setOutputText("Driver not loaded.");
            setOutputTextLinked("Open Driver setup on the status bar.");
        }
        if (!gettingStartedIsHidden()) {
            printGettingStarted();
        }
        return;
    }

    if (!TestDrv())
    {
        DriverStatusError = true;
        m_driverSetupNeeded = false;
        m_driverStatusReady = true;
        applyDriverStatusChip();
        applyEditionChip();
        showStartupWelcome(false);
        setOutputText("Driver loaded but did not finish setup. Restart Hawkeye as Administrator.");
        setOutputTextLinked("Open Driver failed on the status bar.");
        if (!gettingStartedIsHidden()) {
            printGettingStarted();
        }
        return;
    }

    DriverStatusError = false;
    m_driverSetupNeeded = false;
    m_driverStatusReady = true;
    applyDriverStatusChip();
    applyEditionChip();
    showStartupWelcome(true);
    if (!gettingStartedIsHidden()) {
        printGettingStarted();
    }

    if (!m_symbolManager.Initialize())
    {
        setOutputText("Symbol manager initialization failed.");
    }
}

void Hawkeye::applyEditionChip()
{
    ui.labelEditionStatus->setText(QStringLiteral("Community"));
    ui.labelEditionStatus->setFrameShape(QFrame::NoFrame);
    ui.labelEditionStatus->setFrameShadow(QFrame::Plain);
    ui.labelEditionStatus->setCursor(Qt::PointingHandCursor);
    ui.labelEditionStatus->setStyleSheet(HawkeyeStyle::communityChipStyle(true));
    ui.labelEditionStatus->setToolTip(
        QStringLiteral("Hawkeye Community -- open source. Click for Hawkeye Lab."));
    setWindowTitle(QStringLiteral("Hawkeye Community"));
}

void Hawkeye::beginConsoleResizeFreeze()
{
    m_consoleResizeFreeze = true;
    ui.textEditConsole->setUpdatesEnabled(false);
    if (m_resizeSettleTimer != nullptr)
    {
        m_resizeSettleTimer->start();
    }
}

void Hawkeye::onConsoleResizeSettled()
{
    m_consoleResizeFreeze = false;
    ui.textEditConsole->setUpdatesEnabled(true);
    ui.textEditConsole->viewport()->update();
}

void Hawkeye::applyDriverStatusChip()
{
    ui.labelDriverStatus->setFrameShape(QFrame::NoFrame);
    ui.labelDriverStatus->setFrameShadow(QFrame::Plain);
    ui.labelDriverStatus->setCursor(Qt::PointingHandCursor);

    if (!m_driverStatusReady) {
        ui.labelDriverStatus->setText(QStringLiteral("Checking\u2026"));
        ui.labelDriverStatus->setToolTip(QStringLiteral("Checking driver status"));
        ui.labelDriverStatus->setStyleSheet(
            HawkeyeStyle::statusChipStyle(HawkeyeStyle::StatusChipKind::Pending, true));
        return;
    }

    if (DriverStatusError) {
        if (m_driverSetupNeeded) {
            ui.labelDriverStatus->setText(QStringLiteral("Driver setup"));
            ui.labelDriverStatus->setToolTip(QStringLiteral("Driver not loaded -- click for driver setup"));
        } else {
            ui.labelDriverStatus->setText(QStringLiteral("Driver failed"));
            ui.labelDriverStatus->setToolTip(QStringLiteral("Driver did not finish setup -- click for details"));
        }
        ui.labelDriverStatus->setStyleSheet(
            HawkeyeStyle::statusChipStyle(HawkeyeStyle::StatusChipKind::Fail, true));
        return;
    }

    if (MemoryIntegrityIsRunning()) {
        ui.labelDriverStatus->setText(QStringLiteral("Memory integrity"));
        ui.labelDriverStatus->setToolTip(QStringLiteral("Memory integrity is on -- click for driver setup"));
        ui.labelDriverStatus->setStyleSheet(
            HawkeyeStyle::statusChipStyle(HawkeyeStyle::StatusChipKind::Warn, true));
        return;
    }

    ui.labelDriverStatus->setText(QStringLiteral("Driver OK"));
    ui.labelDriverStatus->setToolTip(QStringLiteral("Driver setup -- click for details"));
    ui.labelDriverStatus->setStyleSheet(
        HawkeyeStyle::statusChipStyle(HawkeyeStyle::StatusChipKind::Ok, true));
}

void Hawkeye::startEnableTestSigning()
{
    if (m_testSigningRunning) {
        setOutputText("Error: !enable_testsigning / !disable_testsigning is already running. Please wait for it to complete.");
        return;
    }

    m_testSigningRunning = true;
    if (m_driverSetupDialog) {
        m_driverSetupDialog->setTestSigningBusy(true);
    }

    QThread* tsThread = QThread::create([this]() {
        WCHAR* logBuf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 16384 * sizeof(WCHAR));
        QString result;
        if (logBuf) {
            DWORD logLen = EnableTestSigning(logBuf, 16384);
            result = QString::fromWCharArray(logBuf, logLen);
            HeapFree(GetProcessHeap(), 0, logBuf);
        } else {
            result = QStringLiteral("[Error] Out of memory (failed to alloc log buffer).");
        }

        QMetaObject::invokeMethod(this, [this, result]() {
            m_testSigningRunning = false;
            setOutputText(result);
            if (m_driverSetupDialog) {
                m_driverSetupDialog->setTestSigningBusy(false);
                m_driverSetupDialog->refresh();
            }
        }, Qt::QueuedConnection);
    });
    connect(tsThread, &QThread::finished, tsThread, &QObject::deleteLater);
    tsThread->start();
}

void Hawkeye::onDriverSetupClicked()
{
    if (!m_driverSetupDialog) {
        m_driverSetupDialog = new DriverSetupDialog(this);
        connect(m_driverSetupDialog, &QObject::destroyed, this, [this]() {
            m_driverSetupDialog = nullptr;
        });
        connect(m_driverSetupDialog, &DriverSetupDialog::enableTestSigningRequested,
                this, &Hawkeye::startEnableTestSigning);
    }

    m_driverSetupDialog->refresh();
    m_driverSetupDialog->show();
    m_driverSetupDialog->raise();
    m_driverSetupDialog->activateWindow();
}

void Hawkeye::onEditionChipClicked()
{
    setOutputText(QStringLiteral("Hawkeye Community (open source). No subscription."));
    setOutputText(QStringLiteral("Hawkeye Lab is the commercial analyze/report edition: %1")
                      .arg(QStringLiteral(HAWKEYE_WEBSITE_URL)));
}

void Hawkeye::printMemoryIntegrityBlocked()
{
    setOutputText(QStringLiteral("Failed: Memory integrity is on."));
    setOutputTextLinked(QStringLiteral("Open Memory integrity on the status bar."));
    setOutputText(QStringLiteral("Turn it off, then restart Windows. After restart, that row should read OK."));
}

void Hawkeye::onPushButtonMemoryClicked()
{
    if (MemoryIntegrityIsRunning()) {
        printMemoryIntegrityBlocked();
        return;
    }

    if (!m_memoryDialog) {
        m_memoryDialog = new MemoryDialog(nullptr);
        m_memoryDialog->setSymbolManager(&m_symbolManager);
        connect(m_memoryDialog, &QObject::destroyed, this, [this]() {
            m_memoryDialog = nullptr;
        });
        
        connect(m_memoryDialog, &MemoryDialog::instructionStatsReady,
            this, [this](const QString& stats) {
                QColor color = stats.contains("[risk] HIGH")
                    ? QColor("#B71C1C")
                    : HawkeyeStyle::kAddr;
                setOutputTextColored(stats, color);
            });
    }
    m_memoryDialog->setSymbolManager(&m_symbolManager);
    m_memoryDialog->show();
    m_memoryDialog->raise();
    m_memoryDialog->activateWindow();
}

void Hawkeye::appendConsoleLine(const QString& text, const QColor& textColor, bool bold)
{
    
    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);

    if (cursor.position() > 0) {
        cursor.insertText("\n");
    }

    QTextCharFormat format;
    if (textColor.isValid()) {
        format.setForeground(textColor);
    }
    if (bold) {
        format.setFontWeight(QFont::Bold);
    }
    cursor.setCharFormat(format);
    cursor.insertText(text);

    ui.textEditConsole->setTextCursor(cursor);
    ui.textEditConsole->ensureCursorVisible();

    if (hScrollBar) {
        hScrollBar->setValue(savedHValue);
    }
}

void Hawkeye::echoUserCommand(const QString& text)
{
    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);

    if (cursor.position() > 0) {
        cursor.insertText(QStringLiteral("\n\n"));
    }

    QTextCharFormat format;
    format.setForeground(HawkeyeStyle::kMnemonic);
    format.setFontWeight(QFont::Bold);
    qreal pointSize = ui.textEditConsole->font().pointSizeF();
    if (pointSize <= 0) {
        pointSize = 10;
    }
    format.setFontPointSize(pointSize + 1);
    cursor.setCharFormat(format);
    cursor.insertText(text);

    ui.textEditConsole->setTextCursor(cursor);
    ui.textEditConsole->ensureCursorVisible();

    if (hScrollBar) {
        hScrollBar->setValue(savedHValue);
    }
}

void Hawkeye::setOutputText(const QString& text)
{
    appendConsoleLine(text);
}

void Hawkeye::setOutputTextHeading(const QString& text)
{
    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);

    if (cursor.position() > 0) {
        cursor.insertText(QStringLiteral("\n"));
    }

    QTextCharFormat format;
    format.setFontWeight(QFont::Bold);
    qreal pointSize = ui.textEditConsole->font().pointSizeF();
    if (pointSize <= 0) {
        pointSize = 10;
    }
    format.setFontPointSize(pointSize + 1);
    cursor.setCharFormat(format);
    cursor.insertText(text);

    ui.textEditConsole->setTextCursor(cursor);
    ui.textEditConsole->ensureCursorVisible();

    if (hScrollBar) {
        hScrollBar->setValue(savedHValue);
    }
}

void Hawkeye::setOutputTextLinked(const QString& text)
{
    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);

    if (cursor.position() > 0) {
        cursor.insertText("\n");
    }

    // Match !command names, including hyphenated commands such as !getting-started.
    static const QRegularExpression cmdRegex(R"(![a-zA-Z_][a-zA-Z0-9_-]*)");
    QString processed = text;
    QString html;
    int idx = 0;
    QRegularExpressionMatchIterator it = cmdRegex.globalMatch(processed);
    while (it.hasNext()) {
        QRegularExpressionMatch m = it.next();
        int pos = m.capturedStart();
        int len = m.capturedLength();
        QString raw = m.captured(0);
        if (pos > idx) {
            QString plain = processed.mid(idx, pos - idx);
            html += plain.toHtmlEscaped();
        }
        html += QString(
            "<a href=\"cmd:%1\" "
            "style=\"color:#1E88E5;text-decoration:underline;\" "
            "title=\"Click to fill '%1' in command line\">"
            "%1</a>").arg(raw.toHtmlEscaped());
        idx = pos + len;
    }
    if (idx < processed.size()) {
        html += processed.mid(idx).toHtmlEscaped();
    }

    cursor.insertHtml(html);
    ui.textEditConsole->setTextCursor(cursor);
    ui.textEditConsole->ensureCursorVisible();

    if (hScrollBar) {
        hScrollBar->setValue(savedHValue);
    }
}

void Hawkeye::appendConsoleHtmlLine(const QString& html)
{
    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);

    if (cursor.position() > 0) {
        cursor.insertText("\n");
    }

    cursor.insertHtml(html);
    ui.textEditConsole->setTextCursor(cursor);
    ui.textEditConsole->ensureCursorVisible();

    if (hScrollBar) {
        hScrollBar->setValue(savedHValue);
    }
}

void Hawkeye::setOutputTextColored(const QString& text, const QColor& textColor, bool bold)
{
    appendConsoleLine(text, textColor, bold);
}

void Hawkeye::onConsoleAnchorClicked(const QUrl& url)
{
    if (url.scheme() == QLatin1String("ui")) {
        const QString action = url.host();
        if (action == QLatin1String("driver-setup")) {
            onDriverSetupClicked();
        } else if (action == QLatin1String("license") || action == QLatin1String("edition")) {
            onEditionChipClicked();
        } else if (action == QLatin1String("hide-getting-started")) {
            hideGettingStartedFromNow();
        }
        return;
    }

    if (url.scheme() != "cmd") {
        return;
    }
    QString cmd = url.path();
    if (cmd.isEmpty()) {
        cmd = url.toString(QUrl::RemoveScheme);
        if (cmd.startsWith(":")) {
            cmd.remove(0, 1);
        }
    }
    cmd = QUrl::fromPercentEncoding(cmd.toUtf8());
    if (!cmd.startsWith("!")) {
        cmd = "!" + cmd;
    }
    ui.lineEditCMD->blockSignals(true);
    ui.lineEditCMD->setText(cmd);
    ui.lineEditCMD->blockSignals(false);
    ui.lineEditCMD->setFocus();
    ui.lineEditCMD->selectAll();
}

void Hawkeye::appendConsoleColoredLinesChunk(
    QTextCursor* cursor,
    const QVector<ConsoleColoredLine>& lines,
    int beginIndex,
    int endIndex)
{
    for (int i = beginIndex; i < endIndex; ++i)
    {
        const ConsoleColoredLine& line = lines[i];
        if (cursor->position() > 0)
        {
            cursor->insertText("\n");
        }

        QTextCharFormat format;
        if (line.color.isValid())
        {
            format.setForeground(line.color);
        }
        cursor->setCharFormat(format);
        cursor->insertText(line.text);
    }
}

void Hawkeye::appendConsoleColoredBatch(QVector<ConsoleColoredLine> lines)
{
    if (lines.isEmpty())
    {
        return;
    }

    QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
    const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

    QScrollBar* scrollBar = ui.textEditConsole->verticalScrollBar();
    const bool stickToBottom = scrollBar != nullptr
        && (scrollBar->maximum() - scrollBar->value() <= 4);

    const int firstChunkEnd = lines.size() <= 512 ? lines.size() : 512;

    ui.textEditConsole->setUpdatesEnabled(false);

    QTextCursor cursor(ui.textEditConsole->document());
    cursor.movePosition(QTextCursor::End);
    cursor.beginEditBlock();
    appendConsoleColoredLinesChunk(&cursor, lines, 0, firstChunkEnd);
    cursor.endEditBlock();
    ui.textEditConsole->setTextCursor(cursor);

    if (stickToBottom && scrollBar != nullptr)
    {
        scrollBar->setValue(scrollBar->maximum());
    }
    else
    {
        ui.textEditConsole->ensureCursorVisible();
    }

    if (hScrollBar)
    {
        hScrollBar->setValue(savedHValue);
    }

    ui.textEditConsole->setUpdatesEnabled(true);

    if (firstChunkEnd >= lines.size())
    {
        return;
    }

    auto pending = std::make_shared<QVector<ConsoleColoredLine>>(std::move(lines));
    auto nextIndex = std::make_shared<int>(firstChunkEnd);
    auto appendNextChunk = std::make_shared<std::function<void()>>();

    *appendNextChunk = [this, pending, nextIndex, appendNextChunk, savedHValue]() {
        if (*nextIndex >= pending->size())
        {
            return;
        }

        QScrollBar* chunkHScrollBar = ui.textEditConsole->horizontalScrollBar();
        QScrollBar* chunkVScrollBar = ui.textEditConsole->verticalScrollBar();
        const bool chunkStickToBottom = chunkVScrollBar != nullptr
            && (chunkVScrollBar->maximum() - chunkVScrollBar->value() <= 4);

        ui.textEditConsole->setUpdatesEnabled(false);

        QTextCursor chunkCursor(ui.textEditConsole->document());
        chunkCursor.movePosition(QTextCursor::End);
        chunkCursor.beginEditBlock();

        const int chunkEnd = (*nextIndex + 512 < pending->size()) ? (*nextIndex + 512) : pending->size();
        appendConsoleColoredLinesChunk(&chunkCursor, *pending, *nextIndex, chunkEnd);
        *nextIndex = chunkEnd;

        chunkCursor.endEditBlock();
        ui.textEditConsole->setTextCursor(chunkCursor);

        if (chunkStickToBottom && chunkVScrollBar != nullptr)
        {
            chunkVScrollBar->setValue(chunkVScrollBar->maximum());
        }
        else
        {
            ui.textEditConsole->ensureCursorVisible();
        }

        if (chunkHScrollBar)
        {
            chunkHScrollBar->setValue(savedHValue);
        }

        ui.textEditConsole->setUpdatesEnabled(true);

        if (*nextIndex < pending->size())
        {
            QTimer::singleShot(0, this, [appendNextChunk]() {
                (*appendNextChunk)();
            });
        }
    };

    QTimer::singleShot(0, this, [appendNextChunk]() {
        (*appendNextChunk)();
    });
}

void Hawkeye::appendProbeFindResultLines(std::vector<QString> lines)
{
    if (lines.empty()) {
        endProbeQueryOperation();
        return;
    }

    auto pending = std::make_shared<std::vector<QString>>(std::move(lines));
    auto nextIndex = std::make_shared<std::size_t>(0);
    auto appendNextChunk = std::make_shared<std::function<void()>>();

    *appendNextChunk = [this, pending, nextIndex, appendNextChunk]() {
        if (*nextIndex >= pending->size()) {
            endProbeQueryOperation();
            return;
        }

        QScrollBar* vScrollBar = ui.textEditConsole->verticalScrollBar();
        const bool stickToBottom = vScrollBar != nullptr
            && (vScrollBar->maximum() - vScrollBar->value() <= 4);

        QScrollBar* hScrollBar = ui.textEditConsole->horizontalScrollBar();
        const int savedHValue = hScrollBar ? hScrollBar->value() : 0;

        constexpr std::size_t kChunkSize = 400;
        const std::size_t chunkEnd = (*nextIndex + kChunkSize < pending->size())
            ? (*nextIndex + kChunkSize)
            : pending->size();

        ui.textEditConsole->setUpdatesEnabled(false);

        QTextCursor cursor(ui.textEditConsole->document());
        cursor.movePosition(QTextCursor::End);
        cursor.beginEditBlock();

        for (std::size_t index = *nextIndex; index < chunkEnd; ++index) {
            if (cursor.position() > 0) {
                cursor.insertText("\n");
            }
            cursor.insertText((*pending)[index]);
        }

        cursor.endEditBlock();
        ui.textEditConsole->setTextCursor(cursor);

        if (stickToBottom && vScrollBar != nullptr) {
            vScrollBar->setValue(vScrollBar->maximum());
        }

        if (hScrollBar) {
            hScrollBar->setValue(savedHValue);
        }

        ui.textEditConsole->setUpdatesEnabled(true);

        *nextIndex = chunkEnd;
        if (*nextIndex < pending->size()) {
            QTimer::singleShot(1, this, [appendNextChunk]() {
                (*appendNextChunk)();
            });
            return;
        }

        endProbeQueryOperation();
    };

    QTimer::singleShot(0, this, [appendNextChunk]() {
        (*appendNextChunk)();
    });
}

void Hawkeye::appendEtwResultChunks(std::vector<std::wstring> chunks)
{
    if (chunks.empty()) {
        return;
    }

    auto pending = std::make_shared<std::vector<std::wstring>>(std::move(chunks));
    auto nextIndex = std::make_shared<size_t>(0);
    auto appendNext = std::make_shared<std::function<void()>>();

    *appendNext = [this, pending, nextIndex, appendNext]() {
        if (*nextIndex >= pending->size()) {
            return;
        }

        appendConsoleLine(QString::fromStdWString((*pending)[*nextIndex]));
        ++(*nextIndex);

        if (*nextIndex < pending->size()) {
            QTimer::singleShot(0, this, [appendNext]() {
                (*appendNext)();
            });
        }
    };

    (*appendNext)();
}

bool Hawkeye::tryBeginSymOperation()
{
    bool expected = false;
    return m_symBusy.compare_exchange_strong(expected, true);
}

void Hawkeye::endSymOperation()
{
    m_symBusy = false;
}

void Hawkeye::endProbeQueryOperation()
{
    m_probeFindInProgress.store(false);
    endSymOperation();
}

bool Hawkeye::isProbeAttachInProgress() const
{
    return m_probeAttachInProgress.load();
}

bool Hawkeye::rejectIfProbeAttachBusy(const QString& actionHint)
{
    if (!m_probeAttachInProgress.load()) {
        return false;
    }

    setOutputText(QStringLiteral("Probe attach in progress -- please wait until you see \"Probe ready\"."));
    if (!actionHint.isEmpty()) {
        setOutputText(QStringLiteral("  Blocked: %1").arg(actionHint));
    }
    setOutputText(QStringLiteral("  Do not use !sym while attach is running. !probe -status is OK."));
    setOutputText(QStringLiteral("  To abort: !probe -stop (or !probe -detach)."));
    return true;
}

bool Hawkeye::rejectIfProbeQueryBusy(const QString& actionHint)
{
    if (!m_probeFindInProgress.load()) {
        return false;
    }

    setOutputText(QStringLiteral("Probe -sym/-find in progress -- please wait for results."));
    if (!actionHint.isEmpty()) {
        setOutputText(QStringLiteral("  Blocked: %1").arg(actionHint));
    }
    setOutputText(QStringLiteral("  !probe -status is OK. Do not use !sym or !probe -sym/-find until the query completes."));
    return true;
}

void Hawkeye::requestProbeAttachStop()
{
    if (!m_probeAttachInProgress.load()) {
        setOutputText(QStringLiteral("Probe: no attach in progress."));
        return;
    }

    const bool alreadyRequested = m_probeAttachCancelRequested.exchange(true);
    if (alreadyRequested) {
        setOutputText(QStringLiteral("Probe attach stop already requested. Please wait..."));
        return;
    }

    setOutputText(QStringLiteral("Probe attach stop requested."));
    setOutputText(QStringLiteral("  Finishing the current module, then unloading symbols..."));
    setOutputText(QStringLiteral("  !sym and other commands unlock when stop completes."));
}

QString Hawkeye::parseSymPathArg(const QStringList& parts)
{
    for (int i = 1; i < parts.size(); ++i) {
        if (parts[i].startsWith("-path:", Qt::CaseInsensitive)) {
            return parts[i].mid(6);
        }
    }
    return {};
}

bool Hawkeye::parseSymPidArg(const QStringList& parts, DWORD& outPid, QString& outError)
{
    outPid = 0;
    outError.clear();

    for (int i = 1; i < parts.size(); ++i) {
        if (!parts[i].startsWith("-pid:", Qt::CaseInsensitive)) {
            continue;
        }

        const QString pidText = parts[i].mid(5);
        if (pidText.isEmpty()) {
            outError = QStringLiteral("Invalid -pid value (empty)");
            return false;
        }

        bool ok = false;
        const qulonglong pidValue = pidText.toULongLong(&ok);
        if (!ok || pidValue == 0 || pidValue > 0xFFFFFFFFu) {
            outError = QStringLiteral("Invalid -pid value: %1").arg(pidText);
            return false;
        }

        outPid = static_cast<DWORD>(pidValue);
        return true;
    }

    return false;
}

bool Hawkeye::parseSymAddrArg(const QStringList& parts, quint64& outAddr, QString& outError)
{
    outAddr = 0;
    outError.clear();

    for (int i = 1; i < parts.size(); ++i) {
        if (!parts[i].startsWith("-addr:", Qt::CaseInsensitive)) {
            continue;
        }

        const QString addrText = parts[i].mid(6);
        if (addrText.isEmpty()) {
            outError = QStringLiteral("Invalid -addr value (empty)");
            return false;
        }
        if (!addrText.startsWith("0x", Qt::CaseInsensitive)) {
            outError = QStringLiteral("-addr value must start with 0x.");
            return false;
        }

        const QString hexPart = addrText.mid(2);
        if (hexPart.isEmpty()) {
            outError = QStringLiteral("Invalid -addr value (empty)");
            return false;
        }

        bool ok = false;
        const qulonglong addrValue = hexPart.toULongLong(&ok, 16);
        if (!ok || addrValue == 0) {
            outError = QStringLiteral("Invalid -addr value: %1").arg(addrText);
            return false;
        }

        outAddr = addrValue;
        return true;
    }

    outError = QStringLiteral("-addr parameter is required.");
    return false;
}

QString Hawkeye::formatCertResultLine(const CertVerifier::Result& r,
                                      std::uint32_t processedCount,
                                      std::uint32_t totalCount) const
{
    
    if (!r.isPe)
    {
        return QString();
    }

    QString progressPrefix;
    if (totalCount > 0)
    {
        progressPrefix = QStringLiteral("[%1/%2] ").arg(processedCount).arg(totalCount);
    }
    else
    {
        progressPrefix = QStringLiteral("[%1] ").arg(processedCount);
    }

    QString statusTag;
    if (!r.hasSignature)
    {
        statusTag = "[UNSIGNED]";
    }
    else if (r.verified)
    {
        statusTag = "[OK]";
    }
    else
    {
        if (r.failureReason.rfind("non-fatal", 0) == 0)
            statusTag = "[NON-FATAL]";
        else
            statusTag = "[BROKEN]";
    }

    const int kStatusWidth = 12;
    const int kSignerWidth = 36;
    QString signer = r.hasSignature ? QString::fromStdString(r.signer) : QStringLiteral("-");

    QString line = progressPrefix
        + statusTag.leftJustified(kStatusWidth, ' ')
        + signer.leftJustified(kSignerWidth, ' ', true)
        + "  "
        + QString::fromStdWString(r.filePath);

    if (r.hasSignature && !r.verified && !r.failureReason.empty())
    {
        const int kIndent = progressPrefix.size() + kStatusWidth + kSignerWidth + 4;
        line += "\n" + QString(kIndent, ' ') + "reason: " + QString::fromStdString(r.failureReason);
        if (r.winTrustError != 0)
        {
            line += QString(" (0x%1)").arg(QString::number(r.winTrustError, 16).toUpper());
        }
    }

    return line;
}

QColor Hawkeye::certResultColor(const CertVerifier::Result& r) const
{
    if (!r.isPe)
    {
        return QColor();
    }

    if (!r.hasSignature)
    {
        return QColor("#B71C1C");
    }

    if (!r.verified && !(r.failureReason.rfind("non-fatal", 0) == 0))
    {
        return QColor("#B71C1C");
    }

    return QColor();
}

QString Hawkeye::buildCertReport(std::uint32_t pid,
                                 const std::vector<CertVerifier::Result>& /*results*/,
                                 const CertVerifier::Summary& summary,
                                 bool byDir) const
{
    QString text;
    QTextStream ts(&text);

    ts << "==================== Digital Signature Verification Summary ====================";

    if (byDir)
    {
        ts << "\nMode       : Directory scan (recursive)";
    }
    else
    {
        ts << "\nMode       : Process modules (PID " << pid << ")";
    }

    ts << "\nTotal files scanned : " << summary.totalFiles;
    ts << "\nPE files            : " << summary.peFiles;
    ts << "\nNon-PE (skipped)    : " << (summary.totalFiles - summary.peFiles);
    ts << "\nSigned              : " << summary.signedFiles;
    ts << "\n  - Verified OK     : " << summary.verifiedFiles;
    ts << "\n  - Broken          : " << summary.brokenFiles;
    ts << "\nUnsigned PE files   : " << summary.unsignedFiles;

    const quint32 anomalyCount = summary.brokenFiles + summary.unsignedFiles;
    ts << "\n------------------------------------------------------------------------------";
    ts << "\nAnomalies: " << anomalyCount
       << " (broken=" << summary.brokenFiles
       << ", unsigned=" << summary.unsignedFiles << ")";
    ts << "\n==============================================================================";
    ts.flush();

    return text;
}

void Hawkeye::iguard_scan(const QStringList& parts)
{
    if (m_iguardScanning)
    {
        setOutputText("iguard scan is already running, please wait...");
        return;
    }

    bool scanAll = false;
    QString moduleFilter;
    bool hasModuleFlag = false;
    bool enableSymbols = false;
    bool hasSymFlag = false;
    QString symRawValue;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].compare("-all", Qt::CaseInsensitive) == 0)
        {
            scanAll = true;
        }
        else if (parts[i].startsWith("-m:", Qt::CaseInsensitive))
        {
            hasModuleFlag = true;
            moduleFilter = parts[i].mid(3).trimmed();
        }
        else if (parts[i].startsWith("-sym:", Qt::CaseInsensitive))
        {
            hasSymFlag = true;
            symRawValue = parts[i].mid(5).trimmed();
        }
    }

    if (hasSymFlag && symRawValue != QStringLiteral("0") && symRawValue != QStringLiteral("1"))
    {
        setOutputText(QString("Error: -sym value '%1' is not valid. Only 0 or 1 is allowed.").arg(symRawValue));
    }
    else if (scanAll && hasModuleFlag)
    {
        setOutputText("Error: use either -all or -m:<module>, not both.");
    }
    else if (!scanAll && !hasModuleFlag)
    {
        setOutputText("Usage: !iguard_scan -all");
        setOutputText("       !iguard_scan -m:<module.sys>");
        setOutputText("  Scan kernel modules for suspicious _guard_dispatch_icall pit slots.");
        setOutputText("  A hit means the pit points to executable system/nonpaged memory.");
        setOutputText("    -sym:0|1        symbol resolve on/off (default 0; preload ntoskrnl.exe PDB when 1)");
        setOutputText("  e.g. !iguard_scan -all");
        setOutputText("  e.g. !iguard_scan -all -sym:1");
        setOutputText("  e.g. !iguard_scan -m:ntoskrnl.exe -sym:1");
    }
    else if (hasModuleFlag && moduleFilter.isEmpty())
    {
        setOutputText("Error: -m: requires a module file name.");
    }
    else if (DriverStatusError)
    {
        setOutputText("Error: driver is not loaded.");
    }
    else
    {
        if (hasSymFlag)
        {
            enableSymbols = (symRawValue == QStringLiteral("1"));
        }

        const QString symSuffix = enableSymbols ? QStringLiteral(" -sym:1") : QString();
        setOutputText(QString("Starting iguard scan (%1)%2...")
            .arg(scanAll ? QStringLiteral("-all") : QStringLiteral("-m:") + moduleFilter)
            .arg(symSuffix));

        m_iguardScanning = true;
        QThread* iguardThread = QThread::create([this, scanAll, moduleFilter, enableSymbols]() {
            runIguardScan(this, scanAll, moduleFilter, enableSymbols, &m_symbolManager);

            QMetaObject::invokeMethod(this, [this]() {
                m_iguardScanning = false;
                setOutputText("iguard scan finished.");
            }, Qt::QueuedConnection);
        });
        connect(iguardThread, &QThread::finished, iguardThread, &QObject::deleteLater);
        iguardThread->start();
    }
}

void Hawkeye::inline_hook(const QStringList& parts)
{
    if (m_inlineHookScanning)
    {
        setOutputText("Inline hook scan is already running, please wait...");
        return;
    }

    QString pidRawValue;
    bool hasPidFlag = false;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
        {
            hasPidFlag = true;
            pidRawValue = parts[i].mid(5);
        }
    }

    if (!hasPidFlag || pidRawValue.isEmpty())
    {
        setOutputText("Usage: !inline_hook -pid:<pid>");
        setOutputText("  Scan all MEM_IMAGE modules in a user process for inline hooks.");
        setOutputText("  Supports native x64 and WoW64 processes; each module uses PE header Machine for 32/64 parsing.");
        setOutputText("  e.g. !inline_hook -pid:1234");
    }
    else
    {
        bool pidOk = false;
        const uint parsedPid = pidRawValue.toUInt(&pidOk);
        if (!pidOk || parsedPid == 0)
        {
            setOutputText(QString("Error: pid value '%1' is not valid.").arg(pidRawValue));
        }
        else if (!Process::isPlausiblePid(parsedPid) || parsedPid <= 4)
        {
            setOutputText(QString("Error: pid %1 is not a valid user process id.").arg(parsedPid));
        }
        else if (DriverStatusError)
        {
            setOutputText("Error: driver is not loaded.");
        }
        else
        {
            setOutputText(QString("Starting inline hook scan for pid %1...").arg(parsedPid));
            m_inlineHookScanning = true;
            QThread* inlineHookThread = QThread::create([this, parsedPid]() {
                runInlineHookScan(this, static_cast<std::uint32_t>(parsedPid));

                QMetaObject::invokeMethod(this, [this]() {
                    m_inlineHookScanning = false;
                    setOutputText("Inline hook scan finished.");
                }, Qt::QueuedConnection);
            });
            connect(inlineHookThread, &QThread::finished, inlineHookThread, &QObject::deleteLater);
            inlineHookThread->start();
        }
    }
}

void Hawkeye::probe(const QStringList& parts)
{
    bool detachRequested = false;
    bool stopRequested = false;
    bool statusRequested = false;
    DWORD targetPid = 0;
    QString findKeyword;
    bool findRequested = false;
    QString findKindFilter = QStringLiteral("all");
    bool symRequested = false;
    bool symTypoFromSys = false;
    QString symQuery;
    QString moduleFilter;
    QString pidParseError;

    for (int i = 1; i < parts.size(); ++i)
    {
        const QString& arg = parts[i];
        if (arg.compare(QStringLiteral("-detach"), Qt::CaseInsensitive) == 0)
        {
            detachRequested = true;
            continue;
        }
        if (arg.compare(QStringLiteral("-stop"), Qt::CaseInsensitive) == 0)
        {
            stopRequested = true;
            continue;
        }
        if (arg.compare(QStringLiteral("-status"), Qt::CaseInsensitive) == 0)
        {
            statusRequested = true;
            continue;
        }
        if (arg.compare(QStringLiteral("-find"), Qt::CaseInsensitive) == 0)
        {
            findRequested = true;
            continue;
        }
        if (arg.startsWith(QStringLiteral("-find:"), Qt::CaseInsensitive))
        {
            findRequested = true;
            findKeyword = arg.mid(6);
            continue;
        }
        if (arg.compare(QStringLiteral("-sym"), Qt::CaseInsensitive) == 0)
        {
            symRequested = true;
            continue;
        }
        if (arg.compare(QStringLiteral("-sys"), Qt::CaseInsensitive) == 0)
        {
            symRequested = true;
            symTypoFromSys = true;
            continue;
        }
        if (arg.startsWith(QStringLiteral("-sym:"), Qt::CaseInsensitive))
        {
            symRequested = true;
            symQuery = arg.mid(5);
            continue;
        }
        if (arg.startsWith(QStringLiteral("-addr:"), Qt::CaseInsensitive))
        {
            const QString addrText = arg.mid(6);
            if (addrText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                setOutputText(QStringLiteral("Usage: !probe -sym:<symbol> for name lookup."));
                setOutputText(QStringLiteral("  Reverse VA lookup: !sym -resolve -addr:%1 -pid:<pid>")
                    .arg(addrText));
                return;
            }
            symQuery = addrText;
            continue;
        }
        if (arg.startsWith(QStringLiteral("-mod:"), Qt::CaseInsensitive))
        {
            moduleFilter = arg.mid(5);
            continue;
        }
        if (arg.startsWith(QStringLiteral("-kind:"), Qt::CaseInsensitive))
        {
            findKindFilter = arg.mid(6);
            continue;
        }
        if (arg.startsWith(QStringLiteral("-pid:"), Qt::CaseInsensitive))
        {
            const QString pidText = arg.mid(5);
            bool ok = false;
            const qulonglong parsed = pidText.toULongLong(&ok);
            if (!ok || parsed == 0 || parsed > 0xFFFFFFFFULL)
            {
                pidParseError = QStringLiteral("Invalid -pid value: %1").arg(pidText);
                break;
            }
            targetPid = static_cast<DWORD>(parsed);
        }
    }

    if (!pidParseError.isEmpty())
    {
        setOutputText(pidParseError);
        return;
    }

    auto makeProbeLogFn = [this]() {
        return ProbeLogFn([this](const std::wstring& line) {
            const QString text = QString::fromStdWString(line);
            QMetaObject::invokeMethod(this, [this, text]() {
                setOutputText(text);
            }, Qt::QueuedConnection);
        });
    };

    if (stopRequested)
    {
        if (rejectIfProbeQueryBusy(QStringLiteral("!probe -stop"))) {
            return;
        }

        if (m_probeAttachInProgress.load())
        {
            requestProbeAttachStop();
            return;
        }

        if (m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe: stopping active session (unloading symbols)..."));
            m_probeSession.Detach(m_symbolManager, makeProbeLogFn());
            return;
        }

        setOutputText(QStringLiteral("Probe: no active session."));
        return;
    }

    if (detachRequested)
    {
        if (rejectIfProbeQueryBusy(QStringLiteral("!probe -detach"))) {
            return;
        }

        if (m_probeAttachInProgress.load())
        {
            requestProbeAttachStop();
            return;
        }

        if (!m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe: no active session."));
            return;
        }

        m_probeSession.Detach(m_symbolManager, makeProbeLogFn());
        return;
    }

    if (statusRequested)
    {
        if (!m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe: no active session."));
            return;
        }

        std::uint32_t pid = 0;
        std::size_t totalSymbols = 0;
        std::size_t loadedModules = 0;
        std::size_t failedModules = 0;
        std::vector<ProbeModuleRecord> modules;
        m_probeSession.GetStatus(pid, totalSymbols, loadedModules, failedModules, modules);

        setOutputText(QStringLiteral("Probe session status:"));
        setOutputText(QStringLiteral("  PID: %1").arg(pid));
        setOutputText(QStringLiteral("  Indexed symbols: %1").arg(static_cast<qulonglong>(totalSymbols)));
        setOutputText(QStringLiteral("  Modules with PDB: %1").arg(static_cast<qulonglong>(loadedModules)));
        setOutputText(QStringLiteral("  Modules without PDB / failed: %1").arg(static_cast<qulonglong>(failedModules)));
        for (const ProbeModuleRecord& module : modules)
        {
            const QString state = module.symbolsLoaded ? QStringLiteral("PDB")
                                                       : QStringLiteral("---");
            setOutputText(QStringLiteral("  [%1] %2  symbols=%3  %4")
                .arg(state)
                .arg(QString::fromStdWString(module.fileName))
                .arg(static_cast<qulonglong>(module.symbolCount))
                .arg(QString::fromStdWString(module.statusMessage)));
        }
        return;
    }

    auto printProbeSymbolHit = [this](const ProbeSymbolHit& hit) {
        setOutputText(QStringLiteral("  %1")
            .arg(QString::fromStdWString(ProbeFormatHitLine(hit, true))));
        if (!hit.friendlyName.empty()
            && hit.friendlyName != ProbePickSymbolLabel(hit))
        {
            setOutputText(QStringLiteral("    %1")
                .arg(QString::fromStdWString(hit.friendlyName)));
        }
    };

    if (symRequested)
    {
        if (symQuery.isEmpty())
        {
            if (symTypoFromSys) {
                setOutputText(QStringLiteral("Unknown option: -sys"));
                setOutputText(QStringLiteral("  Did you mean !probe -sym:<symbol> ?"));
            }
            setOutputText(QStringLiteral("Usage: !probe -sym:<symbol> [-mod:<dll>[,<dll>...|all]]"));
            setOutputText(QStringLiteral("  Run !probe for usage."));
            return;
        }

        if (rejectIfProbeAttachBusy(QStringLiteral("!probe -sym")))
        {
            return;
        }

        if (rejectIfProbeQueryBusy(QStringLiteral("!probe -sym")))
        {
            return;
        }

        if (!m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe: attach first with !probe -pid:<pid>"));
            return;
        }

        if (!tryBeginSymOperation())
        {
            setOutputText(QStringLiteral("Symbol operation already in progress, please wait..."));
            return;
        }
        m_probeFindInProgress.store(true);

        if (!moduleFilter.isEmpty())
        {
            setOutputText(QStringLiteral("Probe: resolving '%1' in '%2' (background, downloading PDBs if needed)...")
                .arg(symQuery)
                .arg(moduleFilter));

            const std::wstring symQueryW = symQuery.toStdWString();
            const std::wstring moduleFilterW = moduleFilter.toStdWString();
            auto ensureLogs = std::make_shared<std::vector<std::wstring>>();
            ProbeLogFn collectLogFn = [ensureLogs](const std::wstring& line) {
                ensureLogs->push_back(line);
            };
            auto handoffDone = std::make_shared<std::atomic<bool>>(false);

            QThread* symThread = QThread::create([this, symQueryW, moduleFilterW, symQuery, moduleFilter, collectLogFn, ensureLogs, printProbeSymbolHit, handoffDone]() {
                m_probeSession.EnsureModulesForFilter(m_symbolManager, moduleFilterW, collectLogFn);
                std::vector<ProbeSymbolHit> hits = m_probeSession.Resolve(symQueryW, moduleFilterW);
                ProbeAnnotateExecuteKind(hits, m_probeSession.TargetPid());
                auto hitsCopy = std::make_shared<std::vector<ProbeSymbolHit>>(std::move(hits));

                QMetaObject::invokeMethod(this, [this, ensureLogs, hitsCopy, symQuery, moduleFilter, printProbeSymbolHit]() {
                    for (const std::wstring& line : *ensureLogs) {
                        setOutputText(QString::fromStdWString(line));
                    }

                    if (hitsCopy->empty())
                    {
                        setOutputText(QStringLiteral("Probe: no exact symbol match for '%1'%2")
                            .arg(symQuery)
                            .arg(moduleFilter.isEmpty()
                                     ? QString()
                                     : QStringLiteral(" in module filter '%1'").arg(moduleFilter)));
                        setOutputText(QStringLiteral("  Tip: use !probe -find:%1 and copy the name in [] into -sym.")
                            .arg(symQuery));
                        endProbeQueryOperation();
                        return;
                    }

                    if (hitsCopy->size() > 1)
                    {
                        setOutputText(QStringLiteral("Probe: %1 exact matches for '%2' (use -mod: to narrow):")
                            .arg(static_cast<qulonglong>(hitsCopy->size()))
                            .arg(symQuery));
                    }
                    else
                    {
                        setOutputText(QStringLiteral("Probe symbol '%1':").arg(symQuery));
                    }

                    for (const ProbeSymbolHit& hit : *hitsCopy)
                    {
                        printProbeSymbolHit(hit);
                    }
                    endProbeQueryOperation();
                }, Qt::QueuedConnection);

                handoffDone->store(true);
            });
            connect(symThread, &QThread::finished, this, [this, handoffDone]() {
                if (!handoffDone->load()) {
                    endProbeQueryOperation();
                    setOutputText(QStringLiteral("Probe: -sym search failed before results were ready."));
                }
            });
            connect(symThread, &QThread::finished, symThread, &QObject::deleteLater);
            symThread->start();
            return;
        }

        std::vector<ProbeSymbolHit> hits = m_probeSession.Resolve(
            symQuery.toStdWString(),
            moduleFilter.toStdWString());
        ProbeAnnotateExecuteKind(hits, m_probeSession.TargetPid());

        if (hits.empty())
        {
            setOutputText(QStringLiteral("Probe: no exact symbol match for '%1'%2")
                .arg(symQuery)
                .arg(moduleFilter.isEmpty()
                         ? QString()
                         : QStringLiteral(" in module filter '%1'").arg(moduleFilter)));
            setOutputText(QStringLiteral("  Tip: use !probe -find:%1 and copy the name in [] into -sym.")
                .arg(symQuery));
            endProbeQueryOperation();
            return;
        }

        if (hits.size() > 1)
        {
            setOutputText(QStringLiteral("Probe: %1 exact matches for '%2' (use -mod: to narrow):")
                .arg(static_cast<qulonglong>(hits.size()))
                .arg(symQuery));
        }
        else
        {
            setOutputText(QStringLiteral("Probe symbol '%1':").arg(symQuery));
        }

        for (const ProbeSymbolHit& hit : hits)
        {
            printProbeSymbolHit(hit);
        }
        endProbeQueryOperation();
        return;
    }

    if (findRequested)
    {
        if (findKeyword.isEmpty())
        {
            setOutputText(QStringLiteral("Usage: !probe -find:<keyword>[,<keyword>...] [-mod:<dll>[,<dll>...|all]] [-kind:func|data|all]"));
            setOutputText(QStringLiteral("  Run !probe for usage."));
            return;
        }

        if (rejectIfProbeAttachBusy(QStringLiteral("!probe -find")))
        {
            return;
        }

        if (rejectIfProbeQueryBusy(QStringLiteral("!probe -find")))
        {
            return;
        }

        if (!m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe: attach first with !probe -pid:<pid>"));
            return;
        }

        if (!tryBeginSymOperation())
        {
            setOutputText(QStringLiteral("Symbol operation already in progress, please wait..."));
            return;
        }

        const std::size_t indexedCount = m_probeSession.IndexedSymbolCount();
        m_probeFindInProgress.store(true);
        const bool modLoadRequested = !moduleFilter.isEmpty();
        const DWORD probePid = m_probeSession.TargetPid();
        setOutputText(QStringLiteral("Probe: searching %1 indexed symbol(s) for '%2'%3%4%5")
            .arg(static_cast<qulonglong>(indexedCount))
            .arg(findKeyword)
            .arg(moduleFilter.isEmpty()
                     ? QString()
                     : QStringLiteral(" in '%1'").arg(moduleFilter))
            .arg(findKindFilter.compare(QStringLiteral("all"), Qt::CaseInsensitive) == 0
                     ? QString()
                     : QStringLiteral(" [-kind:%1]").arg(findKindFilter))
            .arg(modLoadRequested
                     ? QStringLiteral(" (downloading missing -mod PDBs first...)")
                     : QString()));

        const std::wstring keywordW = findKeyword.toStdWString();
        const std::wstring moduleFilterW = moduleFilter.toStdWString();
        const ProbeFindKind findKind = ProbeParseFindKind(findKindFilter.toStdWString());
        auto ensureLogs = std::make_shared<std::vector<std::wstring>>();
        ProbeLogFn collectLogFn = [ensureLogs](const std::wstring& line) {
            ensureLogs->push_back(line);
        };

        auto handoffDone = std::make_shared<std::atomic<bool>>(false);

        QThread* findThread = QThread::create([this, keywordW, moduleFilterW, findKind, findKeyword, moduleFilter, collectLogFn, ensureLogs, handoffDone, probePid]() {
            if (!moduleFilterW.empty()) {
                m_probeSession.EnsureModulesForFilter(m_symbolManager, moduleFilterW, collectLogFn);
            }

            std::vector<ProbeSymbolHit> hits = m_probeSession.Find(keywordW, moduleFilterW, findKind);
            ProbeAnnotateExecuteKind(hits, probePid);
            ProbeFilterHitsByExecuteKind(hits, findKind);

            auto lines = std::make_shared<std::vector<QString>>();
            lines->reserve(hits.size());
            for (const ProbeSymbolHit& hit : hits) {
                lines->push_back(QStringLiteral("  %1")
                    .arg(QString::fromStdWString(ProbeFormatHitLine(hit, true))));
            }

            QMetaObject::invokeMethod(this, [this, ensureLogs, lines, findKeyword, moduleFilter]() {
                for (const std::wstring& line : *ensureLogs) {
                    setOutputText(QString::fromStdWString(line));
                }

                if (lines->empty())
                {
                    endProbeQueryOperation();
                    setOutputText(QStringLiteral("Probe: no symbols matched '%1'%2")
                        .arg(findKeyword)
                        .arg(moduleFilter.isEmpty()
                                 ? QString()
                                 : QStringLiteral(" in module filter '%1'").arg(moduleFilter)));
                    return;
                }

                setOutputText(QStringLiteral("Probe matches for '%1': %2 result(s)")
                    .arg(findKeyword)
                    .arg(static_cast<qulonglong>(lines->size())));

                if (lines->size() > 5000) {
                    setOutputText(QStringLiteral("  Rendering %1 line(s) in batches (UI stays responsive)...")
                        .arg(static_cast<qulonglong>(lines->size())));
                    setOutputText(QStringLiteral("  Tip: next time try -mod:<dll> or -mod:dwmcore,udwm to narrow modules."));
                }

                appendProbeFindResultLines(std::move(*lines));
            }, Qt::QueuedConnection);

            handoffDone->store(true);
        });
        connect(findThread, &QThread::finished, this, [this, handoffDone]() {
            if (!handoffDone->load()) {
                endProbeQueryOperation();
                setOutputText(QStringLiteral("Probe: -find search failed before results were ready."));
            }
        });
        connect(findThread, &QThread::finished, findThread, &QObject::deleteLater);
        findThread->start();
        return;
    }

    if (targetPid != 0)
    {
        if (rejectIfProbeQueryBusy(QStringLiteral("!probe -pid"))) {
            return;
        }

        if (m_probeAttachInProgress.load())
        {
            setOutputText(QStringLiteral("Probe attach already in progress. Please wait for \"Probe ready\"."));
            setOutputText(QStringLiteral("  Tip: !probe -status shows load progress; !probe -stop to abort."));
            return;
        }

        if (m_probeSession.IsAttached())
        {
            setOutputText(QStringLiteral("Probe already attached to PID %1. Use !probe -detach first.")
                .arg(m_probeSession.TargetPid()));
            return;
        }

        if (!tryBeginSymOperation())
        {
            setOutputText(QStringLiteral("Symbol operation already in progress, please wait..."));
            return;
        }

        m_probeAttachInProgress.store(true);
        m_probeAttachCancelRequested.store(false);

        if (targetPid == 4) {
            setOutputText(QStringLiteral("Probe attach: PID 4 (kernel drivers)..."));
        } else {
            setOutputText(QStringLiteral("Probe attach: PID %1 (user-mode)...").arg(targetPid));
        }

        ProbeLogFn logFn = makeProbeLogFn();

        bool symPathBusy = false;
        m_probeCacheDirectory = m_symbolManager.GetSymbolCacheDirectory(&symPathBusy);
        m_probeCacheBaseline = ProbeMeasureDirectoryBytes(m_probeCacheDirectory);
        m_probeLastReportedBytes = 0;

        if (m_probeProgressTimer == nullptr)
        {
            m_probeProgressTimer = new QTimer(this);
            m_probeProgressTimer->setInterval(250);
            connect(m_probeProgressTimer, &QTimer::timeout, this, [this]() {
                if (!m_probeAttachInProgress.load() || m_probeCacheDirectory.empty()) {
                    return;
                }

                const std::uint64_t cacheNow = ProbeMeasureDirectoryBytes(m_probeCacheDirectory);
                const std::uint64_t delta = (cacheNow > m_probeCacheBaseline)
                    ? (cacheNow - m_probeCacheBaseline)
                    : 0;
                if (delta <= m_probeLastReportedBytes) {
                    return;
                }
                if (delta < m_probeLastReportedBytes + (512ULL * 1024ULL)
                    && m_probeLastReportedBytes != 0) {
                    return;
                }

                m_probeLastReportedBytes = delta;
                setOutputText(QStringLiteral("  PDB download: %1 (cache total %2)")
                    .arg(QString::fromStdWString(ProbeFormatBytes(delta)))
                    .arg(QString::fromStdWString(ProbeFormatBytes(cacheNow))));
            });
        }

        m_probeProgressTimer->start();

        QThread* probeThread = QThread::create([this, targetPid, logFn]() {
            ProbeCancelFn cancelFn = [this]() {
                return m_probeAttachCancelRequested.load();
            };
            const bool success = m_probeSession.Attach(targetPid, m_symbolManager, logFn, cancelFn);
            const bool cancelled = m_probeAttachCancelRequested.load();
            QMetaObject::invokeMethod(this, [this, success, cancelled]() {
                if (cancelled) {
                    setOutputText(QStringLiteral("Probe attach stopped. Symbols unloaded; you can use other commands."));
                } else if (!success && !m_probeSession.IsAttached()) {
                    setOutputText(QStringLiteral("Probe attach failed."));
                }
            }, Qt::QueuedConnection);
        });
        connect(probeThread, &QThread::finished, this, [this]() {
            if (m_probeProgressTimer != nullptr) {
                m_probeProgressTimer->stop();
            }
            m_probeAttachCancelRequested.store(false);
            m_probeAttachInProgress.store(false);
            endSymOperation();
        });
        connect(probeThread, &QThread::finished, probeThread, &QObject::deleteLater);
        probeThread->start();
        return;
    }

    setOutputText(QStringLiteral("!probe gives a live symbol context on a chosen process or the kernel, so you can run joint, symbol-backed analysis against runtime data."));
    setOutputText(QStringLiteral("Typical flow: attach a pid, -find to explore names, copy the name in [] into -sym for an exact VA."));
    setOutputText(QStringLiteral("Attach loads locally cached PDBs only (no download). -find / -sym with -mod: may download and index extra modules."));
    setOutputText(QStringLiteral("Only one session at a time; -detach (or -stop) before attaching a different pid."));
    setOutputText(QStringLiteral(""));
    setOutputText(QStringLiteral("  -pid:<pid>   attach"));
    setOutputText(QStringLiteral("               pid:4  kernel drivers (same module set as !modules -pid:4)"));
    setOutputText(QStringLiteral("               pid>4  that user process"));
    setOutputText(QStringLiteral("  -stop        abort attach in progress, or end an active session"));
    setOutputText(QStringLiteral("  -detach      end an active session; during attach, same as -stop"));
    setOutputText(QStringLiteral("  -status      attached pid, indexed symbols, and per-module PDB state"));
    setOutputText(QStringLiteral("  -find:...    fuzzy / substring search (attach first)"));
    setOutputText(QStringLiteral("  -sym:...     exact name -> VA (attach first; copy the name in [] from -find)"));
    setOutputText(QStringLiteral("  -mod:...     limit -find/-sym to module(s), or load them if not indexed"));
    setOutputText(QStringLiteral("               user: bare name implies .dll; kernel: .sys; then the raw token"));
    setOutputText(QStringLiteral("               nt and ntos map to ntoskrnl; comma list, or all"));
    setOutputText(QStringLiteral("               -mod:all can take a long time (loads every not-yet-indexed module)"));
    setOutputText(QStringLiteral("  -kind:...    -find only: all (default), func, or data"));
    setOutputText(QStringLiteral("               func = executable page; data = not executable"));
    setOutputText(QStringLiteral(""));
    setOutputText(QStringLiteral("Usage:"));
    setOutputText(QStringLiteral("  !probe -pid:<pid>"));
    setOutputText(QStringLiteral("  !probe -status"));
    setOutputText(QStringLiteral("  !probe -stop"));
    setOutputText(QStringLiteral("  !probe -detach"));
    setOutputText(QStringLiteral("  !probe -find:<keyword>[,<keyword>...] [-mod:<dll>[,<dll>...|all]] [-kind:func|data|all]"));
    setOutputText(QStringLiteral("  !probe -sym:<symbol> [-mod:<dll>[,<dll>...|all]]"));
    setOutputText(QStringLiteral("Comma in -find is AND: every fragment must match. -sym is exact; mangled names are allowed."));
    setOutputText(QStringLiteral("e.g. kernel:"));
    setOutputText(QStringLiteral("     !probe -pid:4"));
    setOutputText(QStringLiteral("     !probe -find:openprocess -mod:nt"));
    setOutputText(QStringLiteral("     !probe -find:openprocess -mod:nt -kind:func"));
    setOutputText(QStringLiteral("     !probe -find:NtUser -mod:win32k,win32kfull,win32kbase"));
    setOutputText(QStringLiteral("     !probe -find:protect,window -mod:win32k,win32kfull,win32kbase"));
    setOutputText(QStringLiteral("e.g. user process (dwm.exe):"));
    setOutputText(QStringLiteral("     !probe -pid:1234"));
    setOutputText(QStringLiteral("     !probe -find:present,mpo -kind:func"));
    setOutputText(QStringLiteral("     !probe -find:swapchain,present -mod:dwmcore,dwmredir,udwm -kind:all"));
    setOutputText(QStringLiteral("     !probe -find:vftable -kind:data"));
    setOutputText(QStringLiteral("     !probe -sym:??_7CVisual@@6B@"));
}

void Hawkeye::etw(const QStringList& parts)
{
    quint32 targetPid = 0;
    quint32 targetTid = 0;
    int profileInterval = 1;
    int duration = 1000;
    DWORD minCounter = 1;
    bool hasPidFlag = false;
    bool hasAllFlag = false;
    bool hasTidFlag = false;
    bool hasProfileFlag = false;
    bool hasIntervalFlag = false;
    bool hasMinFlag = false;
    bool hasStackFlag = false;
    bool enableStackTrace = false;
    bool hasTopFlag = false;
    DWORD stackTopN = 20;
    bool enableEtwSymbols = true;
    QString pidRawValue;
    QString tidRawValue;
    QString profileRawValue;
    QString intervalRawValue;
    QString minRawValue;
    QString topRawValue;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
        {
            hasPidFlag = true;
            pidRawValue = parts[i].mid(5);
        }
        else if (parts[i].compare("-all", Qt::CaseInsensitive) == 0)
        {
            hasAllFlag = true;
        }
        else if (parts[i].startsWith("-tid:", Qt::CaseInsensitive))
        {
            hasTidFlag = true;
            tidRawValue = parts[i].mid(5);
        }
        else if (parts[i].startsWith("-profile:", Qt::CaseInsensitive))
        {
            hasProfileFlag = true;
            profileRawValue = parts[i].mid(9);
        }
        else if (parts[i].startsWith("-interval:", Qt::CaseInsensitive))
        {
            hasIntervalFlag = true;
            intervalRawValue = parts[i].mid(10);
        }
        else if (parts[i].startsWith("-min:", Qt::CaseInsensitive))
        {
            hasMinFlag = true;
            minRawValue = parts[i].mid(5);
        }
        else if (parts[i].startsWith("-sym:", Qt::CaseInsensitive))
        {
            const QString symRawValue = parts[i].mid(5);
            if (symRawValue == QStringLiteral("0"))
            {
                enableEtwSymbols = false;
            }
            else if (symRawValue == QStringLiteral("1"))
            {
                enableEtwSymbols = true;
            }
            else
            {
                setOutputText(QString("Error: -sym value '%1' is invalid (use 0 or 1).").arg(symRawValue));
                return;
            }
        }
        else if (parts[i].startsWith("-stack:", Qt::CaseInsensitive))
        {
            hasStackFlag = true;
            const QString stackRawValue = parts[i].mid(7);
            if (stackRawValue == QStringLiteral("0"))
            {
                enableStackTrace = false;
            }
            else if (stackRawValue == QStringLiteral("1"))
            {
                enableStackTrace = true;
            }
            else
            {
                setOutputText(QString("Error: -stack value '%1' is invalid (use 0 or 1).").arg(stackRawValue));
                return;
            }
        }
        else if (parts[i].startsWith("-top:", Qt::CaseInsensitive))
        {
            hasTopFlag = true;
            topRawValue = parts[i].mid(5);
        }
    }

    if (enableStackTrace && !hasTidFlag)
    {
        setOutputText("Error: -stack:1 requires -tid:<tid>.");
        return;
    }

    if (hasTopFlag)
    {
        bool topOk = false;
        const uint topParsed = topRawValue.toUInt(&topOk);
        if (!topOk || topParsed == 0)
        {
            setOutputText(QString("Error: -top value '%1' is not a valid positive integer.").arg(topRawValue));
            return;
        }
        stackTopN = topParsed;
    }

    if (hasPidFlag && hasAllFlag)
    {
        setOutputText("Error: -pid and -all cannot be specified together.");
        return;
    }
    else if (hasAllFlag)
    {
        targetPid = 0;
    }
    else if (hasPidFlag)
    {
        if (pidRawValue.isEmpty())
        {
            setOutputText("Error: -pid value is empty.");
            return;
        }

        bool pidOk = false;
        const quint32 parsedPid = pidRawValue.toUInt(&pidOk);
        if (!pidOk)
        {
            setOutputText(QString("Error: -pid value '%1' is not a valid integer.").arg(pidRawValue));
            return;
        }
        if (parsedPid != 0 && parsedPid % 4 != 0)
        {
            setOutputText(QString("Error: -pid value '%1' is not a multiple of 4. PID must be aligned to 4.").arg(pidRawValue));
            return;
        }
        targetPid = parsedPid;
    }
    else if (!hasTidFlag)
    {
        setOutputText("Usage: !etw -pid:<pid> | -tid:<tid> | -all [options]");
        setOutputText("  Live CPU sampling: which instructions and addresses executed over a short window.");
        setOutputText("  Results are grouped by process, then by thread.");
        setOutputText("  Under each thread you see the instruction pointers sampled in that window - the sites the thread actually ran.");
        setOutputText("  With -stack:1, one thread is shown as aggregated call stacks instead of a list of instruction pointers.");
        setOutputText("  Symbol resolution is on by default. If the run seems to stall mid-way, wait a moment - names are still being resolved.");
        setOutputText("  Scope (pick one):");
        setOutputText("    -pid:<pid>   sample all threads in the process");
        setOutputText("    -tid:<tid>   sample one thread");
        setOutputText("    -all         sample all processes");
        setOutputText("  Options:");
        setOutputText("    -profile:<ms>   sample interval in ms (default 1)");
        setOutputText("    -interval:<ms>  total capture duration in ms (default 1000)");
        setOutputText("    -min:<n>        only show hits with count > n (default 1)");
        setOutputText("    -sym:0|1        symbol resolve on/off (default 1)");
        setOutputText("    -stack:0|1      aggregated call stacks (default 0; requires -tid)");
        setOutputText("    -top:<n>        top N stacks when -stack:1 (default 20)");
        setOutputText("  e.g. !etw -pid:1234");
        setOutputText("  e.g. !etw -all -interval:3000 -min:5");
        setOutputText("  e.g. !etw -tid:5678 -stack:1 -sym:1 -top:10");
        setOutputText("  e.g. !etw -pid:1234 -profile:1 -interval:2000");
        setOutputText("  e.g. !etw -all -min:0");
        return;
    }

    if (hasTidFlag)
    {
        bool tidOk = false;
        const quint32 parsedTid = tidRawValue.toUInt(&tidOk);
        if (!tidOk || parsedTid == 0)
        {
            setOutputText(QString("Error: -tid value '%1' is not a valid positive integer.").arg(tidRawValue));
            return;
        }
        targetTid = parsedTid;
    }

    if (hasProfileFlag)
    {
        bool profileOk = false;
        const int parsedProfile = profileRawValue.toInt(&profileOk);
        if (!profileOk || parsedProfile <= 0)
        {
            setOutputText(QString("Error: -profile value '%1' is not a valid positive integer (ms).").arg(profileRawValue));
            return;
        }
        profileInterval = parsedProfile;
    }

    if (hasIntervalFlag)
    {
        bool intervalOk = false;
        const int parsedInterval = intervalRawValue.toInt(&intervalOk);
        if (!intervalOk || parsedInterval <= 0)
        {
            setOutputText(QString("Error: -interval value '%1' is not a valid positive integer (ms).").arg(intervalRawValue));
            return;
        }
        duration = parsedInterval;
    }

    if (hasMinFlag)
    {
        bool minOk = false;
        const uint minParsed = minRawValue.toUInt(&minOk);
        if (!minOk)
        {
            setOutputText(QString("Error: -min value '%1' is not a valid integer.").arg(minRawValue));
            return;
        }
        minCounter = minParsed;
    }

    const QString scopeStr = (targetPid == 0 && targetTid == 0)
        ? QStringLiteral("ALL")
        : (targetPid != 0 ? QString("PID:%1").arg(targetPid) : QString())
          + (targetTid > 0 ? QString(targetPid != 0 ? " TID:%1" : "TID:%1").arg(targetTid) : QString());
    const QString symStr = enableEtwSymbols ? QStringLiteral("on") : QStringLiteral("off");
    const QString stackStr = enableStackTrace ? QStringLiteral("on") : QStringLiteral("off");

    if (m_etwRunning.load()) {
        setOutputText("Error: !etw is already running. Please wait for it to complete.");
        return;
    }

    setOutputText(QString("Starting ETW sampling for %1 (profile:%2ms, interval:%3ms, min>%4, sym:%5, stack:%6) ...")
        .arg(scopeStr).arg(profileInterval).arg(duration).arg(minCounter).arg(symStr).arg(stackStr));

    m_etwRunning.store(true);

    QThread* etwThread = QThread::create([this, targetPid, targetTid, profileInterval, duration, minCounter,
                                          enableEtwSymbols, enableStackTrace, stackTopN]() {
        EtwSampler sampler;
        EtwError initError = sampler.Initialize((DWORD)profileInterval, enableStackTrace ? TRUE : FALSE);
        if (initError.hasError())
        {
            QMetaObject::invokeMethod(this, [this, initError]() {
                setOutputText(QString::fromStdWString(L"ETW initialization failed: " + initError.toString()));
            }, Qt::QueuedConnection);
            return;
        }

        EtwFormatOptions formatOptions;
        formatOptions.symbolManager = &m_symbolManager;
        formatOptions.enableSymbols = enableEtwSymbols;
        formatOptions.logFn = [this](const std::wstring& message) {
            QMetaObject::invokeMethod(this, [this, message]() {
                setOutputText(QString::fromStdWString(message));
            }, Qt::QueuedConnection);
        };

        if (enableStackTrace)
        {
            EtwStackSampleResult stackResult;
            EtwError sampleError = sampler.GetStackSamples((DWORD)targetPid, (DWORD)targetTid,
                                                           (DWORD)duration, etwSampleModeAll, stackResult);
            EtwError cleanupError = sampler.Cleanup();

            if (sampleError.hasError())
            {
                QMetaObject::invokeMethod(this, [this, sampleError]() {
                    setOutputText(QString::fromStdWString(L"ETW stack sampling failed: " + sampleError.toString()));
                }, Qt::QueuedConnection);
            }
            else if (stackResult.totalSamples == 0)
            {
                QMetaObject::invokeMethod(this, [this, targetTid]() {
                    setOutputText(QString("No ETW stack samples collected for TID:%1 (thread may be idle/waiting).")
                        .arg(targetTid));
                }, Qt::QueuedConnection);
            }
            else
            {
                std::vector<std::wstring> formattedChunks;
                FormatEtwStackSampleResult(stackResult, minCounter, stackTopN, formattedChunks,
                                           enableEtwSymbols ? &formatOptions : nullptr);
                QMetaObject::invokeMethod(this, [this, chunks = std::move(formattedChunks)]() mutable {
                    appendEtwResultChunks(std::move(chunks));
                }, Qt::QueuedConnection);
            }

            if (cleanupError.hasError())
            {
                QMetaObject::invokeMethod(this, [this, cleanupError]() {
                    setOutputText(QString::fromStdWString(L"ETW cleanup failed: " + cleanupError.toString()));
                }, Qt::QueuedConnection);
            }
            return;
        }

        EtwSampleResult sampleResult;
        EtwError sampleError = sampler.GetRipSamples((DWORD)targetPid, (DWORD)targetTid,
                                                     (DWORD)duration, etwSampleModeAll, sampleResult);

        EtwError cleanupError = sampler.Cleanup();

        if (sampleError.hasError())
        {
            QMetaObject::invokeMethod(this, [this, sampleError]() {
                setOutputText(QString::fromStdWString(L"ETW sampling failed: " + sampleError.toString()));
            }, Qt::QueuedConnection);
        }
        else if (sampleResult.totalSamples == 0)
        {
            QMetaObject::invokeMethod(this, [this]() {
                setOutputText("No ETW RIP samples collected.");
            }, Qt::QueuedConnection);
        }
        else
        {
            std::vector<std::wstring> formattedChunks;
            FormatEtwSampleResult((DWORD)targetPid, sampleResult, minCounter, formattedChunks,
                                  enableEtwSymbols ? &formatOptions : nullptr);
            QMetaObject::invokeMethod(this, [this, chunks = std::move(formattedChunks)]() mutable {
                appendEtwResultChunks(std::move(chunks));
            }, Qt::QueuedConnection);
        }

        if (cleanupError.hasError())
        {
            QMetaObject::invokeMethod(this, [this, cleanupError]() {
                setOutputText(QString::fromStdWString(L"ETW cleanup failed: " + cleanupError.toString()));
            }, Qt::QueuedConnection);
        }
    });
    connect(etwThread, &QThread::finished, this, [this]() {
        m_etwRunning.store(false);
    });
    connect(etwThread, &QThread::finished, etwThread, &QObject::deleteLater);
    etwThread->start();
}

void Hawkeye::check_cert(const QStringList& parts)
{
    
    bool hasStopFlag = false;
    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].compare("-stop", Qt::CaseInsensitive) == 0)
        {
            hasStopFlag = true;
            break;
        }
    }
    if (hasStopFlag)
    {
        if (!m_certScanRunning)
        {
            setOutputText("!check_cert: no scan running.");
        }
        else if (m_certScanStopRequested.load())
        {
            setOutputText("!check_cert: stop already requested, please wait...");
        }
        else
        {
            m_certScanStopRequested.store(true);
            setOutputText("!check_cert: stop requested. Current iteration will finish shortly.");
        }
    }
    
    else
    {
        
        bool hasPidFlag = false;
        bool hasDirFlag = false;
        QString pidRawValue;
        QString dirRawValue;
        int dirStartIndex = -1;

        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
            {
                hasPidFlag = true;
                pidRawValue = parts[i].mid(5);
            }
            else if (parts[i].startsWith("-dir:", Qt::CaseInsensitive))
            {
                hasDirFlag = true;
                dirStartIndex = i;
                dirRawValue = parts[i].mid(5);
            }
        }

        if (hasDirFlag && dirStartIndex >= 0 && dirStartIndex + 1 < parts.size())
        {
            for (int i = dirStartIndex + 1; i < parts.size(); ++i)
            {
                dirRawValue += QStringLiteral(" ") + parts[i];
            }
        }

        if (m_certScanRunning)
        {
            setOutputText("Error: !check_cert is already running. Use '!check_cert -stop' to abort, or wait.");
        }
        else if (hasPidFlag && hasDirFlag)
        {
            setOutputText("Error: -pid and -dir cannot be specified together.");
        }
        else if (hasPidFlag)
        {
            if (pidRawValue.isEmpty())
            {
                setOutputText("Error: -pid value is empty.");
            }
            else
            {
                bool ok = false;
                quint32 parsed = pidRawValue.toUInt(&ok);
                if (!ok || parsed == 0)
                {
                    setOutputText(QString("Error: -pid value '%1' is not a valid positive integer.").arg(pidRawValue));
                }
                else
                {
                    
                    m_certScanRunning.store(true);
                    m_certScanStopRequested.store(false);

                    setOutputText(QString("Verifying digital signatures for all modules of PID:%1 (running in background)...").arg(parsed));

                    QThread* worker = QThread::create([this, parsed]() {
                        std::vector<CertVerifier::Result> results;
                        CertVerifier::Summary summary;

                        auto progressFn = [this](const CertVerifier::Result& r,
                                                 std::uint32_t proc, std::uint32_t total) {
                            QString line = formatCertResultLine(r, proc, total);
                            if (line.isEmpty()) return;
                            QColor color = certResultColor(r);
                            QMetaObject::invokeMethod(this, [this, line, color]() {
                                setOutputTextColored(line, color);
                            }, Qt::QueuedConnection);
                        };
                        
                        auto stopFn = [this]() -> bool {
                            return m_certScanStopRequested.load();
                        };

                        CertVerifier::verifyByPid(parsed, results, summary,
                                                  std::move(progressFn),
                                                  std::move(stopFn));

                        QString report = buildCertReport(parsed, results, summary, /*byDir*/ false);
                        
                        QColor reportColor;
                        if (summary.brokenFiles > 0)
                            reportColor = QColor("#B71C1C");
                        const bool stopped = m_certScanStopRequested.exchange(false);
                        QMetaObject::invokeMethod(this, [this, report, stopped, reportColor]() {
                            if (stopped) setOutputText("--- scan stopped by user ---");
                            setOutputTextColored(report, reportColor);
                            m_certScanRunning.store(false);
                        }, Qt::QueuedConnection);
                    });
                    connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                    worker->start();
                }
            }
        }
        else if (hasDirFlag)
        {
            if (dirRawValue.isEmpty())
            {
                setOutputText("Error: -dir value is empty.");
            }
            else
            {
                
                if (dirRawValue.size() >= 2 &&
                    ((dirRawValue.startsWith('"') && dirRawValue.endsWith('"')) ||
                     (dirRawValue.startsWith('\'') && dirRawValue.endsWith('\''))))
                {
                    dirRawValue = dirRawValue.mid(1, dirRawValue.size() - 2);
                }

                const std::wstring dirPath = dirRawValue.toStdWString();

                m_certScanRunning.store(true);
                m_certScanStopRequested.store(false);

                setOutputText(QString("Verifying digital signatures for all files under: %1 (running in background)...").arg(dirRawValue));

                QThread* worker = QThread::create([this, dirPath]() {
                    std::vector<CertVerifier::Result> results;
                    CertVerifier::Summary summary;

                    auto progressFn = [this](const CertVerifier::Result& r,
                                             std::uint32_t proc, std::uint32_t total) {
                        QString line = formatCertResultLine(r, proc, total);
                        if (line.isEmpty()) return;
                        QColor color = certResultColor(r);
                        QMetaObject::invokeMethod(this, [this, line, color]() {
                            setOutputTextColored(line, color);
                        }, Qt::QueuedConnection);
                    };
                    auto stopFn = [this]() -> bool {
                        return m_certScanStopRequested.load();
                    };

                    CertVerifier::verifyByDir(dirPath, results, summary,
                                              std::move(progressFn),
                                              std::move(stopFn));

                    QString report = buildCertReport(0, results, summary, /*byDir*/ true);
                    
                    QColor reportColor;
                    if (summary.brokenFiles > 0 || summary.unsignedFiles > 0)
                        reportColor = QColor("#B71C1C");
                    const bool stopped = m_certScanStopRequested.exchange(false);
                    QMetaObject::invokeMethod(this, [this, report, stopped, reportColor]() {
                        if (stopped) setOutputText("--- scan stopped by user ---");
                        setOutputTextColored(report, reportColor);
                        m_certScanRunning.store(false);
                    }, Qt::QueuedConnection);
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }
        }
        else
        {
            setOutputText("Usage: !check_cert -pid:<pid>      (e.g. !check_cert -pid:1234)");
            setOutputText("       !check_cert -dir:<path>     (e.g. !check_cert -dir:C:\\Windows\\System32)");
            setOutputText("       !check_cert -stop            (abort a running scan)");
            setOutputText("Non-PE files (no MZ header) are skipped automatically.");
        }
    }
}

void Hawkeye::list_pm(const QStringList& parts)
{
    QString pidRawValue;
    bool hasPidFlag = false;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
        {
            hasPidFlag = true;
            pidRawValue = parts[i].mid(5);
        }
    }

    if (!hasPidFlag || pidRawValue.isEmpty())
    {
        setOutputText("Usage: !modules -pid:<pid>");
        setOutputText("  pid:4  list kernel driver modules (SystemModuleInformation)");
        setOutputText("  pid>4  list user-process image modules (ZwQueryVirtualMemory + MEM_IMAGE)");
        setOutputText("  e.g. !modules -pid:4");
        setOutputText("  e.g. !modules -pid:1234");
    }
    else
    {
        bool pidOk = false;
        const uint parsedPid = pidRawValue.toUInt(&pidOk);
        if (!pidOk || parsedPid == 0)
        {
            setOutputText(QString("Error: pid value '%1' is not valid.").arg(pidRawValue));
        }
        else if (parsedPid != 4 && parsedPid <= 4)
        {
            setOutputText(QString("Error: pid %1 is reserved. Use pid:4 for kernel modules or pid>4 for a user process.")
                .arg(parsedPid));
        }
        else
        {
            const std::vector<Process::ModuleInfo> modules = Process::enumerateModules(parsedPid);
            const QString scope = (parsedPid == 4)
                ? QStringLiteral("kernel driver modules")
                : QStringLiteral("process image modules");

            setOutputText(QString("PID %1 - %2 count: %3")
                .arg(parsedPid)
                .arg(scope)
                .arg(modules.size()));

            if (modules.empty())
            {
                setOutputText("No modules found (process may be inaccessible or already exited).");
            }

            for (size_t i = 0; i < modules.size(); ++i)
            {
                const Process::ModuleInfo& module = modules[i];
                const QString path = module.path.empty()
                    ? QStringLiteral("[path unavailable]")
                    : QString::fromStdWString(module.path);

                setOutputText(QString("[%1] Base: 0x%2  Size: 0x%3")
                    .arg(i, 4)
                    .arg(static_cast<qulonglong>(module.base), 16, 16, QChar('0'))
                    .arg(module.size, 0, 16));
                setOutputText(QString("      %1").arg(path));
            }
        }
    }
}

void Hawkeye::list_pt(const QStringList& parts)
{
    QString pidRawValue;
    bool hasPidFlag = false;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
        {
            hasPidFlag = true;
            pidRawValue = parts[i].mid(5);
        }
    }

    if (!hasPidFlag || pidRawValue.isEmpty())
    {
        setOutputText("Usage: !threads -pid:<pid>");
        setOutputText("  List threads in the target process with Win32 start address (OEP).");
        setOutputText("  Pure usermode enumeration; kernel OEP uses driver region name + !pte-style RX/RWX.");
        setOutputText("  Kernel OEP: red if not [image region] (region 12) or PTE is RWX.");
        setOutputText("  User OEP uses VirtualQueryEx; RWX rows are highlighted red.");
        setOutputText("  e.g. !threads -pid:1234");
        setOutputText("  e.g. !threads -pid:4");
        return;
    }

    bool pidOk = false;
    const quint32 parsedPid = pidRawValue.toUInt(&pidOk);
    if (!pidOk || !Process::isPlausiblePid(parsedPid))
    {
        setOutputText(QString("Error: pid value '%1' is not valid.").arg(pidRawValue));
        return;
    }

    ListPtOutput output;
    output.line = [this](const QString& line) {
        setOutputText(line);
    };
    output.coloredLine = [this](const QString& line, const QColor& color) {
        setOutputTextColored(line, color);
    };

    QString error;
    if (!runListPt(parsedPid, output, &error))
    {
        setOutputText(error);
    }
}

void Hawkeye::pte(const QStringList& parts)
{
    quint32 targetPid = 0;
    quint64 targetVa = 0;
    bool hasPidFlag = false;
    bool hasVaFlag = false;
    QString pidRawValue;
    QString vaRawValue;

    for (int i = 1; i < parts.size(); ++i)
    {
        if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
        {
            hasPidFlag = true;
            pidRawValue = parts[i].mid(5);
        }
        else if (parts[i].startsWith("-va:", Qt::CaseInsensitive))
        {
            hasVaFlag = true;
            vaRawValue = parts[i].mid(4);
        }
    }

    if (!hasPidFlag || !hasVaFlag)
    {
        setOutputText("Usage: !pte -pid:<pid> -va:<0x...>");
        setOutputText("  -pid:4       system CR3, high canonical VA (> 0xFFFF000000000000)");
        setOutputText("  -pid:<n>     target process CR3, any VA (user or kernel canonical)");
        setOutputText("  Returns hardware PTE/PDE qword and decodes _HARDWARE_PTE fields.");
        setOutputText("  e.g. !pte -pid:4 -va:0xFFFF800012345000");
        setOutputText("  e.g. !pte -pid:1234 -va:0x7FF6A1001000");
        setOutputText("  e.g. !pte -pid:1234 -va:0xFFFFF80375CB3C29");
    }
    else if (pidRawValue.isEmpty())
    {
        setOutputText("Error: -pid value is empty.");
    }
    else if (vaRawValue.isEmpty())
    {
        setOutputText("Error: -va value is empty.");
    }
    else if (!vaRawValue.startsWith("0x", Qt::CaseInsensitive))
    {
        setOutputText("Error: -va value must start with '0x'.");
    }
    else
    {
        QString hexPart = vaRawValue.mid(2);
        bool hexValid = !hexPart.isEmpty();
        for (const QChar& c : hexPart)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                hexValid = false;
                break;
            }
        }

        bool pidOk = false;
        const quint32 parsedPid = pidRawValue.toUInt(&pidOk);

        if (!hexValid)
        {
            setOutputText(QString("Error: -va value '%1' is not a valid hex string.").arg(vaRawValue));
        }
        else if (!pidOk)
        {
            setOutputText(QString("Error: -pid value '%1' is not a valid integer.").arg(pidRawValue));
        }
        else if (parsedPid != 4 && parsedPid <= 4)
        {
            setOutputText(QString("Error: -pid value '%1' is invalid. Use 4 for kernel or a PID > 4 for user mode.").arg(parsedPid));
        }
        else
        {
            bool vaOk = false;
            const quint64 parsedVa = vaRawValue.toULongLong(&vaOk, 16);
            if (!vaOk || parsedVa == 0)
            {
                setOutputText(QString("Error: -va value '%1' is not a valid address.").arg(vaRawValue));
            }
            else if (parsedPid == 4 && parsedVa <= 0xFFFF000000000000ULL)
            {
                setOutputText("Error: pid 4 -va must be > 0xFFFF000000000000.");
            }
            else
            {
                GET_VIRTUAL_ADDRESS_PTE pteQuery = { 0 };
                pteQuery.pid = parsedPid;
                pteQuery.va = parsedVa;
                GetVirtualAddressPte(&pteQuery);

                if (pteQuery.errCode == 2)
                {
                    setOutputText("Error: driver PTE base unavailable.");
                }
                else if (pteQuery.errCode != 1)
                {
                    setOutputText(QString("Error: failed to read PTE for pid=%1 va=%2.")
                        .arg(parsedPid)
                        .arg(vaRawValue));
                }
                else
                {
                    const QString entryLabel = pteEntryTypeLabel(pteQuery.entryType);
                    setOutputText(QString("pid=%1  va=%2  entry=%3")
                        .arg(parsedPid)
                        .arg(vaRawValue)
                        .arg(entryLabel));
                    setOutputText(QString("pte entry: 0x%1")
                        .arg(static_cast<qulonglong>(pteQuery.entryAddress), 16, 16, QChar('0')));
                    setOutputText(QString("pte value: 0x%1")
                        .arg(static_cast<qulonglong>(pteQuery.pteData), 16, 16, QChar('0')));
                    setOutputText("_HARDWARE_PTE:");
                    setOutputText(formatHardwarePteDetails(pteQuery.pteData));
                }
            }
        }
    }
}

void Hawkeye::dm(const QStringList& parts)
{
    if (DriverStatusError)
    {
        setOutputText("Error: driver is not loaded.");
    }
    else
    {
        quint32 targetPid = 0;
        quint64 targetVa = 0;
        quint32 pageCount = 0;
        UCHAR readMethod = READ_KERNEL_METHOD_MMCOPY;
        bool hasPidFlag = false;
        bool hasVaFlag = false;
        bool hasPagesFlag = false;
        bool hasMethodFlag = false;
        QString pidRawValue;
        QString vaRawValue;
        QString pagesRawValue;
        QString methodRawValue;

        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
            {
                hasPidFlag = true;
                pidRawValue = parts[i].mid(5);
            }
            else if (parts[i].startsWith("-va:", Qt::CaseInsensitive))
            {
                hasVaFlag = true;
                vaRawValue = parts[i].mid(4);
            }
            else if (parts[i].startsWith("-pages:", Qt::CaseInsensitive))
            {
                hasPagesFlag = true;
                pagesRawValue = parts[i].mid(7);
            }
            else if (parts[i].startsWith("-method:", Qt::CaseInsensitive))
            {
                hasMethodFlag = true;
                methodRawValue = parts[i].mid(8);
            }
        }

        if (!hasPidFlag || !hasVaFlag || !hasPagesFlag || !hasMethodFlag)
        {
            setOutputText("Usage: !dump -pid:<pid> -va:<0x...> -pages:<n> -method:<0|2|name>");
            setOutputText("  Page-aligned dump via ReadProcessPage; files under .\\DumpPages\\");
            setOutputText("  -method:0|mmcopy         MmCopyMemory");
            setOutputText("  -method:2|map_io          PTE + MmMapIoSpaceEx");
            setOutputText("  Kernel read methods apply to pid 4 / kernel VA; user VA uses attach copy.");
            setOutputText("  e.g. !dump -pid:4 -va:0xFFFF800012340000 -pages:4 -method:0");
            setOutputText("  e.g. !dump -pid:1234 -va:0x7FF6A1000000 -pages:1");
        }
        else if (pidRawValue.isEmpty())
        {
            setOutputText("Error: -pid value is empty.");
        }
        else if (vaRawValue.isEmpty())
        {
            setOutputText("Error: -va value is empty.");
        }
        else if (pagesRawValue.isEmpty())
        {
            setOutputText("Error: -pages value is empty.");
        }
        else if (methodRawValue.isEmpty())
        {
            setOutputText("Error: -method value is empty.");
        }
        else if (!vaRawValue.startsWith("0x", Qt::CaseInsensitive))
        {
            setOutputText("Error: -va value must start with '0x'.");
        }
        else
        {
            QString hexPart = vaRawValue.mid(2);
            bool hexValid = !hexPart.isEmpty();
            for (const QChar& c : hexPart)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                {
                    hexValid = false;
                    break;
                }
            }

            bool pidOk = false;
            const quint32 parsedPid = pidRawValue.toUInt(&pidOk);
            bool pagesOk = false;
            const quint32 parsedPages = pagesRawValue.toUInt(&pagesOk);
            QString methodError;
            const bool methodOk = parseDmReadMethod(methodRawValue, readMethod, methodError);

            if (!hexValid)
            {
                setOutputText(QString("Error: -va value '%1' is not a valid hex string.").arg(vaRawValue));
            }
            else if (!pidOk)
            {
                setOutputText(QString("Error: -pid value '%1' is not a valid integer.").arg(pidRawValue));
            }
            else if (parsedPid != 4 && parsedPid <= 4)
            {
                setOutputText(QString("Error: -pid value '%1' is invalid. Use 4 for kernel or a PID > 4 for user mode.")
                    .arg(parsedPid));
            }
            else if (!pagesOk || parsedPages == 0)
            {
                setOutputText(QString("Error: -pages value '%1' is not a valid positive integer.")
                    .arg(pagesRawValue));
            }
            else if (parsedPages > 4096)
            {
                setOutputText("Error: -pages must be <= 4096.");
            }
            else if (!methodOk)
            {
                setOutputText(methodError);
            }
            else
            {
                bool vaOk = false;
                const quint64 parsedVa = vaRawValue.toULongLong(&vaOk, 16);
                if (!vaOk || parsedVa == 0)
                {
                    setOutputText(QString("Error: -va value '%1' is not a valid address.").arg(vaRawValue));
                }
                else if (parsedPid == 4 && parsedVa <= 0xFFFF000000000000ULL)
                {
                    setOutputText("Error: pid 4 -va must be > 0xFFFF000000000000.");
                }
                else
                {
                    targetPid = parsedPid;
                    targetVa = parsedVa & ~0xFFFull;
                    pageCount = parsedPages;

                    if (targetVa != parsedVa)
                    {
                        setOutputText(QString("Note: start VA aligned down to 0x%1.")
                            .arg(static_cast<qulonglong>(targetVa), 16, 16, QChar('0')));
                    }

                    const QDir dumpRoot(QCoreApplication::applicationDirPath() + QStringLiteral("/DumpPages"));
                    if (!dumpRoot.exists() && !dumpRoot.mkpath(QStringLiteral(".")))
                    {
                        setOutputText(QString("Error: failed to create DumpPages folder at %1.")
                            .arg(dumpRoot.absolutePath()));
                    }
                    else
                    {
                        const QString sessionName = QStringLiteral("dm_pid%1_va%2_pages%3_%4_%5")
                            .arg(targetPid)
                            .arg(static_cast<qulonglong>(targetVa), 16, 16, QChar('0'))
                            .arg(pageCount)
                            .arg(dmReadMethodLabel(readMethod))
                            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
                        const QString sessionPath = dumpRoot.filePath(sessionName);
                        if (!QDir().mkpath(sessionPath))
                        {
                            setOutputText(QString("Error: failed to create dump folder %1.").arg(sessionPath));
                        }
                        else
                        {
                            setOutputText(QString("Dumping %1 page(s) pid=%2 start=0x%3 method=%4")
                                .arg(pageCount)
                                .arg(targetPid)
                                .arg(static_cast<qulonglong>(targetVa), 16, 16, QChar('0'))
                                .arg(dmReadMethodLabel(readMethod)));
                            setOutputText(QString("Output: %1").arg(sessionPath));

                            quint32 dumpedPages = 0;
                            bool dumpFailed = false;
                            QString failMessage;

                            for (quint32 pageIndex = 0; pageIndex < pageCount; ++pageIndex)
                            {
                                const quint64 pageVa = targetVa + static_cast<quint64>(pageIndex) * PAGE_SIZE;

                                READ_MEMORY_PAGES in = { 0 };
                                READ_MEMORY_PAGES out = { 0 };
                                in.pid = targetPid;
                                in.va = static_cast<DWORD64>(pageVa);
                                in.readMethod = readMethod;
                                ReadProcessPage(&in, &out);

                                if (out.bytesRead != PAGE_SIZE)
                                {
                                    dumpFailed = true;
                                    failMessage = QString("page %1 va=0x%2: %3")
                                        .arg(pageIndex)
                                        .arg(static_cast<qulonglong>(pageVa), 16, 16, QChar('0'))
                                        .arg(formatDmReadError(out.errStep, out.status));
                                    break;
                                }

                                const QString pagePath = QDir(sessionPath).filePath(
                                    QStringLiteral("page_%1.bin").arg(pageIndex, 4, 10, QChar('0')));
                                QFile pageFile(pagePath);
                                if (!pageFile.open(QIODevice::WriteOnly))
                                {
                                    dumpFailed = true;
                                    failMessage = QString("page %1: failed to write %2")
                                        .arg(pageIndex)
                                        .arg(pagePath);
                                    break;
                                }

                                if (pageFile.write(reinterpret_cast<const char*>(out.page), PAGE_SIZE) != PAGE_SIZE)
                                {
                                    dumpFailed = true;
                                    failMessage = QString("page %1: short write to %2")
                                        .arg(pageIndex)
                                        .arg(pagePath);
                                    break;
                                }

                                ++dumpedPages;
                            }

                            QFile infoFile(QDir(sessionPath).filePath(QStringLiteral("info.txt")));
                            if (infoFile.open(QIODevice::WriteOnly | QIODevice::Text))
                            {
                                QTextStream infoStream(&infoFile);
                                infoStream << "pid=" << targetPid << "\n";
                                infoStream << "start_va=0x"
                                    << QString::number(static_cast<qulonglong>(targetVa), 16).toUpper() << "\n";
                                infoStream << "pages=" << pageCount << "\n";
                                infoStream << "method=" << dmReadMethodLabel(readMethod) << "\n";
                                infoStream << "dumped=" << dumpedPages << "\n";
                                infoStream << "page_size=" << PAGE_SIZE << "\n";
                                if (dumpFailed)
                                {
                                    infoStream << "error=" << failMessage << "\n";
                                }
                            }

                            if (dumpFailed)
                            {
                                setOutputText(QString("Dump failed after %1/%2 page(s): %3")
                                    .arg(dumpedPages)
                                    .arg(pageCount)
                                    .arg(failMessage));
                            }
                            else
                            {
                                setOutputText(QString("Dump complete: %1 page(s) saved.").arg(dumpedPages));
                            }
                        }
                    }
                }
            }
        }
    }
}

void Hawkeye::handleCommandLine(const QString& command)
{
    QString trimmedCmd = command.trimmed(); 

    if (trimmedCmd.isEmpty()) {
        return;
    }

    echoUserCommand(trimmedCmd);

    QStringList parts = trimmedCmd.split(' ', Qt::SkipEmptyParts);
    QString cmd = parts[0].toLower(); 

    if (MemoryIntegrityIsRunning())
    {
        const bool hawkeyeCommand = cmd.startsWith(QLatin1Char('!')) || cmd == QLatin1String("cls");
        if (hawkeyeCommand && !isMemoryIntegritySafeCommand(cmd))
        {
            printMemoryIntegrityBlocked();
            return;
        }
    }

    if (cmd == "!process")
    {
        const std::vector<Process::Info> processes = Process::enumerate();

        setOutputText(QString("Process count: %1").arg(processes.size()));
        for (const Process::Info& procInfo : processes)
        {
            setOutputText(QString("Pid : %1  Path: %2").arg(procInfo.pid).arg(QString::fromStdWString(procInfo.path)));
        }
    }
    else if (cmd == "!iguard_scan")
    {
        iguard_scan(parts);
    }
    else if (cmd == "!inline_hook")
    {
        inline_hook(parts);
    }
    else if (cmd == "!modules")
    {
        list_pm(parts);
    }
    else if (cmd == "!threads")
    {
        list_pt(parts);
    }
    else if (cmd == "!check_hwnd")
    {
        QString hwndRawValue;
        bool hasHwndFlag = false;

        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].startsWith("-hwnd:", Qt::CaseInsensitive))
            {
                hasHwndFlag = true;
                hwndRawValue = parts[i].mid(6);
            }
        }

        if (!hasHwndFlag || hwndRawValue.isEmpty())
        {
            setOutputText("Usage: !check_hwnd -hwnd:<0x...>");
            setOutputText("  Check whether the target window handle is valid.");
            setOutputText("  e.g. !check_hwnd -hwnd:0x123456");
        }
        else if (!hwndRawValue.startsWith("0x", Qt::CaseInsensitive))
        {
            setOutputText("Error: hwnd value must start with '0x'.");
        }
        else
        {
            bool hwndOk = false;
            const qulonglong parsedHwnd = hwndRawValue.toULongLong(&hwndOk, 16);
            if (!hwndOk || parsedHwnd == 0)
            {
                setOutputText(QString("Error: hwnd value '%1' is not a valid hex handle.").arg(hwndRawValue));
            }
            else if (parsedHwnd > 0xFFFFFFFFu)
            {
                setOutputText(QString("Error: hwnd value '%1' exceeds 32-bit handle range.").arg(hwndRawValue));
            }
            else
            {
                CHECK_VALID_HWND inout = { 0 };
                inout.hwnd = (ULONG)parsedHwnd;
                CheckValidHwnd(&inout);

                const QString hwndHex = QStringLiteral("0x") + QString::number(parsedHwnd, 16).toUpper();
                if (inout.errCode != 1)
                {
                    setOutputText(QString("HWND check failed for %1 (errCode=%2).")
                        .arg(hwndHex)
                        .arg(inout.errCode));
                }
                else if (inout.isValid == 0)
                {
                    setOutputText(QString("Hwnd %1 is invalid.").arg(hwndHex));
                }
                else
                {
                    setOutputText(QString("Hwnd %1 is valid. TAG_WND: 0x%2")
                        .arg(hwndHex)
                        .arg(inout.tagWnd, 0, 16));
                }
            }
        }
    }
    else if (cmd == "!kernel_region")
    {
        quint64 va = 0;
        bool hasVaFlag = false;
        bool listMTypes = false;
        QString vaRawValue;

        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].startsWith("-va:", Qt::CaseInsensitive))
            {
                hasVaFlag = true;
                vaRawValue = parts[i].mid(4);
            }
            else if (parts[i].compare("-list", Qt::CaseInsensitive) == 0)
            {
                listMTypes = true;
            }
        }

        if (!hasVaFlag && !listMTypes)
        {
            setOutputText("Usage: !kernel_region -va:<0x...> | !kernel_region -list");
            setOutputText("  -va:<0x...>  kernel VA only (high canonical, > 0xFFFF000000000000)");
            setOutputText("  -list         show live MiGetSystemRegionType region IDs from driver");
            setOutputText("  Identifies the kernel address-range type (section, nonpaged, paged pool, image, stack, ...).");
            setOutputText("  e.g. !kernel_region -va:0xFFFF800012345000");
            setOutputText("  e.g. !kernel_region -list");
        }

        if (listMTypes)
        {
            KERNEL_VA_REGION in = { 0 };
            KERNEL_VA_REGION out = { 0 };
            GetKernelVaRegion(&in, &out);
            setOutputText("MiGetSystemRegionType region IDs (probed at driver init, OS-specific):");
            setOutputText(QString("  pteMType                  %1").arg(out.pteMType));
            setOutputText(QString("  pfnMType                  %1").arg(out.pfnMType));
            setOutputText(QString("  imageMType                %1").arg(out.imageMType));
            setOutputText(QString("  stackMType                %1").arg(out.stackMType));
            setOutputText(QString("  sectionMType              %1").arg(out.sectionMType));
            setOutputText(QString("  unusedMType               %1").arg(out.unusedMType));
            setOutputText(QString("  nonpagedMType             %1").arg(out.nonpagedMType));
            setOutputText(QString("  pagedMType                %1").arg(out.pagedMType));
            setOutputText(QString("  systemMType               %1").arg(out.systemMType));
            setOutputText(QString("  specialPoolPagedMType     %1").arg(out.specialPoolPagedMType));
        }

        if (hasVaFlag)
        {
            if (vaRawValue.isEmpty())
            {
                setOutputText("Error: -va value is empty.");
            }
            else if (!vaRawValue.startsWith("0x", Qt::CaseInsensitive))
            {
                setOutputText("Error: -va value must start with '0x'.");
            }
            else
            {
                QString hexPart = vaRawValue.mid(2);
                bool hexValid = !hexPart.isEmpty();
                for (const QChar& c : hexPart)
                {
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                    {
                        hexValid = false;
                        break;
                    }
                }
                if (!hexValid)
                {
                    setOutputText(QString("Error: -va value '%1' is not a valid hex string.").arg(vaRawValue));
                }
                else
                {
                    bool ok = false;
                    quint64 parsed = vaRawValue.toULongLong(&ok, 16);
                    if (!ok)
                    {
                        setOutputText(QString("Error: -va value '%1' is not a valid hex address.").arg(vaRawValue));
                    }
                    else if (parsed <= 0xffff000000000000ULL)
                    {
                        setOutputText(QString("Error: -va value '0x%1' must be greater than 0xffff000000000000.")
                            .arg(parsed, 16, 16, QChar('0')));
                    }
                    else
                    {
                        va = parsed;
                        QString mtype = GetKernelMemoryRegionName(va);
                        setOutputText(QString("va: 0x%1  mtype: %2")
                            .arg(va, 16, 16, QChar('0'))
                            .arg(mtype));
                    }
                }
            }
        }
    }
    else if (cmd == "!inject_sim")
    {
        bool isStop = false;
        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].compare("-stop", Qt::CaseInsensitive) == 0)
            {
                isStop = true;
                break;
            }
        }

        if (isStop)
        {
            if (!m_injectSimState.active)
            {
                setOutputText("Error: inject simulation is not active.");
            }
            else
            {
                const InjectSimOutcome outcome = InjectSimUnload(m_injectSimState);
                if (outcome.ok)
                {
                    setOutputText(QString("Inject simulation stopped. Freed module 0x%1 in PID:%2")
                        .arg(outcome.remoteModule, 0, 16)
                        .arg(outcome.pid));
                    m_injectSimState = {};
                }
                else
                {
                    setOutputText(QString("Inject simulation stop failed: %1").arg(outcome.error));
                }
            }
        }
        else if (m_injectSimState.active)
        {
            setOutputText("Error: inject simulation is already active. Use !inject_sim -stop first.");
        }
        else
        {
            bool hasPidFlag = false;
            QString pidRawValue;
            for (int i = 1; i < parts.size(); ++i)
            {
                if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
                {
                    hasPidFlag = true;
                    pidRawValue = parts[i].mid(5);
                }
            }

            if (!hasPidFlag)
            {
                setOutputText("Usage: !inject_sim -pid:<pid> | -stop");
                setOutputText("  Load sim\\HawkUnsignedStub.dll into the target via CreateRemoteThread + LoadLibraryW.");
                setOutputText("  Stub path: <Hawkeye.exe dir>\\sim\\HawkUnsignedStub.dll (unsigned PE for !check_cert staging).");
                setOutputText("  Only one active injection at a time.");
                setOutputText("  Test flow:");
                setOutputText("    1) !inject_sim -pid:<pid>");
                setOutputText("    2) !check_cert -pid:<same>");
                setOutputText("    3) !inject_sim -stop");
                setOutputText("  e.g. !inject_sim -pid:1234");
            }
            else if (pidRawValue.isEmpty())
            {
                setOutputText("Error: -pid value is empty.");
            }
            else
            {
                bool pidOk = false;
                const quint32 parsedPid = pidRawValue.toUInt(&pidOk);
                if (!pidOk || parsedPid == 0)
                {
                    setOutputText(QString("Error: -pid value '%1' is not a valid positive integer.").arg(pidRawValue));
                }
                else if (parsedPid <= 4)
                {
                    setOutputText(QString("Error: -pid value '%1' must be a user process id (> 4).").arg(pidRawValue));
                }
                else if (parsedPid % 4 != 0)
                {
                    setOutputText(QString("Error: -pid value '%1' is not a multiple of 4. PID must be aligned to 4.").arg(pidRawValue));
                }
                else
                {
                    const QString processPath = QString::fromStdWString(Process::getPath(parsedPid));
                    if (processPath.isEmpty())
                    {
                        setOutputText(QString("The target process (pid:%1) does not exist.").arg(parsedPid));
                    }
                    else
                    {
                        const InjectSimOutcome outcome = InjectSimLoad(parsedPid);
                        if (!outcome.ok)
                        {
                            setOutputText(QString("Inject simulation failed: %1").arg(outcome.error));
                        }
                        else
                        {
                            m_injectSimState.active = true;
                            m_injectSimState.pid = outcome.pid;
                            m_injectSimState.remoteModule = outcome.remoteModule;
                            m_injectSimState.dllPath = outcome.dllPath;
                            setOutputText(QString("Inject simulation active for PID:%1  Path: %2")
                                .arg(outcome.pid)
                                .arg(processPath));
                            setOutputText(QString("  stub: %1").arg(outcome.dllPath));
                            setOutputText(QString("  remote module: 0x%1")
                                .arg(outcome.remoteModule, 0, 16));
                            setOutputText(QString("  Now run: !check_cert -pid:%1").arg(outcome.pid));
                        }
                    }
                }
            }
        }
    }
    else if (cmd == "!inline_hook_sim")
    {
        bool isStop = false;
        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].compare("-stop", Qt::CaseInsensitive) == 0)
            {
                isStop = true;
                break;
            }
        }

        if (isStop)
        {
            if (!m_inlineHookSimState.active)
            {
                setOutputText("Error: inline hook simulation is not active.");
            }
            else
            {
                const InlineHookSimOutcome outcome = InlineHookSimStop(m_inlineHookSimState);
                if (outcome.ok)
                {
                    setOutputText(QString("Inline hook simulation stopped. Restored %1 byte(s) to 0xCC in PID:%2")
                        .arg(outcome.patchedAddresses.size())
                        .arg(outcome.pid));
                    m_inlineHookSimState = {};
                }
                else
                {
                    setOutputText(QString("Inline hook simulation stop failed: %1").arg(outcome.error));
                }
            }
        }
        else if (m_inlineHookSimState.active)
        {
            setOutputText("Error: inline hook simulation is already active. Use !inline_hook_sim -stop first.");
        }
        else
        {
            bool hasPidFlag = false;
            QString pidRawValue;
            for (int i = 1; i < parts.size(); ++i)
            {
                if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
                {
                    hasPidFlag = true;
                    pidRawValue = parts[i].mid(5);
                }
            }

            if (!hasPidFlag)
            {
                setOutputText("Usage: !inline_hook_sim -pid:<pid> | -stop");
                setOutputText("  Patch HawkUnsignedStub.dll in-memory (0xCC -> 0x90 at module+0x1000).");
                setOutputText("  Requires HawkUnsignedStub.dll already loaded (e.g. !inject_sim -pid:<pid>).");
                setOutputText("  Does not inject or unload the stub; only patches/restores bytes.");
                setOutputText("  Only one active simulation at a time.");
                setOutputText("  Test flow:");
                setOutputText("    1) !inject_sim -pid:<pid>");
                setOutputText("    2) !inline_hook_sim -pid:<same>");
                setOutputText("    3) !inline_hook -pid:<same>");
                setOutputText("    4) !inline_hook_sim -stop");
                setOutputText("    5) !inject_sim -stop   (optional, unload stub)");
                setOutputText("  e.g. !inline_hook_sim -pid:1234");
            }
            else if (pidRawValue.isEmpty())
            {
                setOutputText("Error: -pid value is empty.");
            }
            else
            {
                bool pidOk = false;
                const quint32 parsedPid = pidRawValue.toUInt(&pidOk);
                if (!pidOk || parsedPid == 0)
                {
                    setOutputText(QString("Error: -pid value '%1' is not a valid positive integer.").arg(pidRawValue));
                }
                else if (parsedPid <= 4)
                {
                    setOutputText(QString("Error: -pid value '%1' must be a user process id (> 4).").arg(pidRawValue));
                }
                else if (parsedPid % 4 != 0)
                {
                    setOutputText(QString("Error: -pid value '%1' is not a multiple of 4. PID must be aligned to 4.").arg(pidRawValue));
                }
                else
                {
                    const QString processPath = QString::fromStdWString(Process::getPath(parsedPid));
                    if (processPath.isEmpty())
                    {
                        setOutputText(QString("The target process (pid:%1) does not exist.").arg(parsedPid));
                    }
                    else
                    {
                        const InlineHookSimOutcome outcome = InlineHookSimStart(parsedPid, m_inlineHookSimState);
                        if (!outcome.ok)
                        {
                            setOutputText(QString("Inline hook simulation failed: %1").arg(outcome.error));
                        }
                        else
                        {
                            m_inlineHookSimState.active = true;
                            m_inlineHookSimState.pid = outcome.pid;
                            m_inlineHookSimState.remoteModule = outcome.remoteModule;
                            m_inlineHookSimState.patchedAddresses = outcome.patchedAddresses;

                            setOutputText(QString("Inline hook simulation active for PID:%1  Path: %2")
                                .arg(outcome.pid)
                                .arg(processPath));
                            setOutputText(QString("  stub module: 0x%1").arg(outcome.remoteModule, 0, 16));
                            setOutputText(QString("  patched %1 byte(s) at module+0x1000 (0xCC -> 0x90)")
                                .arg(outcome.patchedAddresses.size()));
                            for (std::uintptr_t patchVa : outcome.patchedAddresses)
                            {
                                setOutputText(QString("    0x%1").arg(patchVa, 0, 16));
                            }
                            setOutputText(QString("  Now run: !inline_hook -pid:%1").arg(outcome.pid));
                        }
                    }
                }
            }
        }
    }
    else if (cmd == "!pte")
    {
        pte(parts);
    }
    else if (cmd == "!dump")
    {
        dm(parts);
    }
    else if (cmd == "!pfn")
    {
        bool hasPidFlag = false;
        bool hasVaFlag = false;
        QString pidRawValue;
        QString vaRawValue;

        for (int i = 1; i < parts.size(); ++i)
        {
            if (parts[i].startsWith("-pid:", Qt::CaseInsensitive))
            {
                hasPidFlag = true;
                pidRawValue = parts[i].mid(5);
            }
            else if (parts[i].startsWith("-va:", Qt::CaseInsensitive))
            {
                hasVaFlag = true;
                vaRawValue = parts[i].mid(4);
            }
        }

        if (!hasPidFlag || !hasVaFlag)
        {
            setOutputText("Usage: !pfn -pid:<pid> -va:<0x...>");
            setOutputText("  Resolve PTE/PDE via process CR3, then read 0x30-byte MMPFN from pfn database.");
            setOutputText("  Address rules same as !pte (pid 4=system; pid>n=any VA in process view).");
            setOutputText("  e.g. !pfn -pid:4 -va:0xFFFF800012345000");
            setOutputText("  e.g. !pfn -pid:1234 -va:0x7FF6A1001000");
        }
        else if (pidRawValue.isEmpty())
        {
            setOutputText("Error: -pid value is empty.");
        }
        else if (vaRawValue.isEmpty())
        {
            setOutputText("Error: -va value is empty.");
        }
        else if (!vaRawValue.startsWith("0x", Qt::CaseInsensitive))
        {
            setOutputText("Error: -va value must start with '0x'.");
        }
        else
        {
            QString hexPart = vaRawValue.mid(2);
            bool hexValid = !hexPart.isEmpty();
            for (const QChar& c : hexPart)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                {
                    hexValid = false;
                    break;
                }
            }

            bool pidOk = false;
            const quint32 parsedPid = pidRawValue.toUInt(&pidOk);

            if (!hexValid)
            {
                setOutputText(QString("Error: -va value '%1' is not a valid hex string.").arg(vaRawValue));
            }
            else if (!pidOk)
            {
                setOutputText(QString("Error: -pid value '%1' is not a valid integer.").arg(pidRawValue));
            }
            else if (parsedPid != 4 && parsedPid <= 4)
            {
                setOutputText(QString("Error: -pid value '%1' is invalid. Use 4 for kernel or a PID > 4 for user mode.").arg(parsedPid));
            }
            else
            {
                bool vaOk = false;
                const quint64 parsedVa = vaRawValue.toULongLong(&vaOk, 16);
                if (!vaOk || parsedVa == 0)
                {
                    setOutputText(QString("Error: -va value '%1' is not a valid address.").arg(vaRawValue));
                }
                else if (parsedPid == 4 && parsedVa <= 0xFFFF000000000000ULL)
                {
                    setOutputText("Error: pid 4 -va must be > 0xFFFF000000000000.");
                }
                else
                {
                    GET_VIRTUAL_ADDRESS_PFN pfnQuery = { 0 };
                    pfnQuery.pid = parsedPid;
                    pfnQuery.va = parsedVa;
                    GetVirtualAddressPfn(&pfnQuery);

                    if (pfnQuery.errCode != VA_PFN_ERR_SUCCESS)
                    {
                        setOutputText(QString("Error: failed to read PFN for pid=%1 va=%2 (%3).")
                            .arg(parsedPid)
                            .arg(vaRawValue)
                            .arg(pfnErrText(pfnQuery.errCode)));
                    }
                    else
                    {
                        setOutputText(QString("pid=%1  va=%2  entry=%3")
                            .arg(parsedPid)
                            .arg(vaRawValue)
                            .arg(pteEntryTypeLabel(pfnQuery.entryType)));
                        setOutputText(QString("pfn=0x%1 (%2)  (Page Frame Number from PTE bits 12:51; physical base = pfn * 0x1000)")
                            .arg(static_cast<qulonglong>(pfnQuery.pfnNumber), 0, 16)
                            .arg(static_cast<qulonglong>(pfnQuery.pfnNumber)));
                        setOutputText(QString("pte entry: 0x%1")
                            .arg(static_cast<qulonglong>(pfnQuery.entryAddress), 16, 16, QChar('0')));
                        setOutputText(QString("pfn entry: 0x%1")
                            .arg(static_cast<qulonglong>(pfnQuery.pfnEntryAddress), 16, 16, QChar('0')));
                        setOutputText(QString("pte value: 0x%1")
                            .arg(static_cast<qulonglong>(pfnQuery.pteData), 16, 16, QChar('0')));
                        setOutputText("MMPFN (0x30 bytes):");
                        setOutputText(formatMmpfnDetails(pfnQuery.pfnData));
                    }
                }
            }
        }
    }
    else if (cmd == "!etw")
    {
        etw(parts);
    }
    else if (cmd == "!sym")
    {
        bool downloadRequested = false;
        bool loadRequested = false;
        bool unloadRequested = false;
        bool resolveRequested = false;
        bool listRequested = false;

        for (int i = 1; i < parts.size(); ++i)
        {
            const QString& arg = parts[i];
            if (arg.compare(QStringLiteral("-download"), Qt::CaseInsensitive) == 0)
            {
                downloadRequested = true;
                continue;
            }
            if (arg.compare(QStringLiteral("-load"), Qt::CaseInsensitive) == 0)
            {
                loadRequested = true;
                continue;
            }
            if (arg.compare(QStringLiteral("-unload"), Qt::CaseInsensitive) == 0)
            {
                unloadRequested = true;
                continue;
            }
            if (arg.compare(QStringLiteral("-resolve"), Qt::CaseInsensitive) == 0)
            {
                resolveRequested = true;
                continue;
            }
            if (arg.compare(QStringLiteral("-list"), Qt::CaseInsensitive) == 0)
            {
                listRequested = true;
                continue;
            }
        }

        const int actionCount = (downloadRequested ? 1 : 0)
            + (loadRequested ? 1 : 0)
            + (unloadRequested ? 1 : 0)
            + (resolveRequested ? 1 : 0)
            + (listRequested ? 1 : 0);

        if (actionCount > 1)
        {
            setOutputText(QStringLiteral("Error: pick one of -download, -load, -unload, -resolve, -list."));
            setOutputText(QStringLiteral("  Run !sym for usage."));
            return;
        }

        if (actionCount == 0)
        {
            setOutputText(QStringLiteral("!sym manages symbol files for a module: download, load, unload, resolve, and list."));
            setOutputText(QStringLiteral("Pick one action."));
            setOutputText(QStringLiteral(""));
            setOutputText(QStringLiteral("  -download    fetch the PDB for -path:<file> into the local symbols cache"));
            setOutputText(QStringLiteral("               does not keep the module loaded"));
            setOutputText(QStringLiteral("  -load        load symbols for -path:<file> (downloads if missing)"));
            setOutputText(QStringLiteral("               user module: -pid:<pid>; kernel: omit -pid or use -pid:4"));
            setOutputText(QStringLiteral("  -unload      unload from this session; the cache entry is kept"));
            setOutputText(QStringLiteral("  -resolve     look up a VA; kernel finds the module, user VA needs -pid if not loaded"));
            setOutputText(QStringLiteral("  -list        tracked symbols ([cached] or [loaded])"));
            setOutputText(QStringLiteral(""));
            setOutputText(QStringLiteral("Usage:"));
            setOutputText(QStringLiteral("  !sym -download -path:<file>"));
            setOutputText(QStringLiteral("  !sym -load -path:<file> [-pid:<pid>]"));
            setOutputText(QStringLiteral("  !sym -unload -path:<file>"));
            setOutputText(QStringLiteral("  !sym -resolve -addr:<0x...> [-pid:<pid>]"));
            setOutputText(QStringLiteral("  !sym -list"));
            setOutputText(QStringLiteral("e.g."));
            setOutputText(QStringLiteral("  !sym -download -path:C:\\Windows\\System32\\ntoskrnl.exe"));
            setOutputText(QStringLiteral("  !sym -load -path:C:\\Windows\\System32\\ntoskrnl.exe"));
            setOutputText(QStringLiteral("  !sym -load -path:C:\\Windows\\System32\\dwmcore.dll -pid:1234"));
            setOutputText(QStringLiteral("  !sym -resolve -addr:0xFFFFF80012345678"));
            setOutputText(QStringLiteral("  !sym -list"));
            return;
        }

        if (downloadRequested)
        {
        if (rejectIfProbeAttachBusy(QStringLiteral("!sym -download"))) {
            return;
        }
        if (rejectIfProbeQueryBusy(QStringLiteral("!sym -download"))) {
            return;
        }

        const QString targetPath = parseSymPathArg(parts);
        if (targetPath.isEmpty())
        {
            setOutputText("Usage: !sym -download -path:<file>");
            setOutputText("  e.g. !sym -download -path:C:\\Windows\\System32\\ntoskrnl.exe");
            setOutputText("  Run !sym for usage.");
            return;
        }

        if (!tryBeginSymOperation())
        {
            setOutputText("Symbol operation already in progress, please wait...");
            return;
        }

        const std::wstring filePath = targetPath.toStdWString();
        setOutputText(QString("Downloading symbol for: %1").arg(targetPath));

        QThread* downloadThread = QThread::create([this, filePath]() {
            std::wstring pdbPath;
            std::wstring errorMsg;
            const bool success = m_symbolManager.DownloadSymbol(filePath, pdbPath, errorMsg);

            QMetaObject::invokeMethod(this, [this, success, pdbPath, filePath, errorMsg]() {
                if (success)
                {
                    setOutputText(QString("Symbol cached successfully: %1").arg(QString::fromStdWString(pdbPath)));
                }
                else
                {
                    setOutputText(QString("Failed to download symbol for: %1").arg(QString::fromStdWString(filePath)));
                    setOutputText(QString("  Error: %1").arg(QString::fromStdWString(errorMsg)));
                }
            }, Qt::QueuedConnection);
        });
        connect(downloadThread, &QThread::finished, this, [this]() { endSymOperation(); });
        connect(downloadThread, &QThread::finished, downloadThread, &QObject::deleteLater);
        downloadThread->start();
        }
        else if (loadRequested)
        {
        if (rejectIfProbeAttachBusy(QStringLiteral("!sym -load"))) {
            return;
        }
        if (rejectIfProbeQueryBusy(QStringLiteral("!sym -load"))) {
            return;
        }

        const QString targetPath = parseSymPathArg(parts);
        if (targetPath.isEmpty())
        {
            setOutputText("Usage: !sym -load -path:<file> [-pid:<pid>]");
            setOutputText("  e.g. !sym -load -path:C:\\Windows\\System32\\ntoskrnl.exe");
            setOutputText("  e.g. !sym -load -path:C:\\Windows\\System32\\dwmcore.dll -pid:1234");
            setOutputText("  Run !sym for usage.");
            return;
        }

        DWORD targetPid = 0;
        QString pidParseError;
        const bool hasTargetPid = parseSymPidArg(parts, targetPid, pidParseError);
        if (!pidParseError.isEmpty())
        {
            setOutputText(pidParseError);
            return;
        }

        if (!tryBeginSymOperation())
        {
            setOutputText("Symbol operation already in progress, please wait...");
            return;
        }

        const std::wstring filePath = targetPath.toStdWString();
        const DWORD loadPid = (hasTargetPid && targetPid == 4) ? 0u : targetPid;
        if (hasTargetPid)
        {
            if (targetPid == 4) {
                setOutputText(QString("Loading symbol for: %1 (kernel)").arg(targetPath));
            } else {
                setOutputText(QString("Loading symbol for: %1 (PID %2)").arg(targetPath).arg(targetPid));
            }
        }
        else
        {
            setOutputText(QString("Loading symbol for: %1").arg(targetPath));
        }

        QThread* loadThread = QThread::create([this, filePath, loadPid]() {
            std::wstring loadError;
            const bool success = m_symbolManager.LoadSymbol(filePath, loadError, loadPid);

            QMetaObject::invokeMethod(this, [this, success, filePath, loadPid, loadError]() {
                if (success)
                {
                    if (loadPid != 0)
                    {
                        setOutputText(QString("Symbol loaded successfully: %1 (PID %2)")
                            .arg(QString::fromStdWString(filePath))
                            .arg(loadPid));
                    }
                    else
                    {
                        setOutputText(QString("Symbol loaded successfully: %1").arg(QString::fromStdWString(filePath)));
                    }
                }
                else
                {
                    setOutputText(QString("Failed to load symbol for: %1").arg(QString::fromStdWString(filePath)));
                    setOutputText(QString("  Error: %1").arg(QString::fromStdWString(loadError)));
                }
            }, Qt::QueuedConnection);
        });
        connect(loadThread, &QThread::finished, this, [this]() { endSymOperation(); });
        connect(loadThread, &QThread::finished, loadThread, &QObject::deleteLater);
        loadThread->start();
        }
        else if (unloadRequested)
        {
        if (rejectIfProbeAttachBusy(QStringLiteral("!sym -unload"))) {
            return;
        }
        if (rejectIfProbeQueryBusy(QStringLiteral("!sym -unload"))) {
            return;
        }

        const QString targetPath = parseSymPathArg(parts);
        if (targetPath.isEmpty())
        {
            setOutputText("Usage: !sym -unload -path:<file>");
            setOutputText("  Run !sym for usage.");
            return;
        }

        const std::wstring filePath = targetPath.toStdWString();
        bool symBusy = false;
        if (m_symbolManager.UnloadSymbol(filePath, &symBusy))
        {
            setOutputText(QString("Symbol unloaded (cache entry kept): %1").arg(targetPath));
        }
        else if (symBusy)
        {
            setOutputText("Symbol operation in progress (PDB download/load). Please try !sym -unload again shortly.");
        }
        else
        {
            setOutputText(QString("Failed to unload symbol for: %1 (not loaded?)").arg(targetPath));
        }
        }
        else if (resolveRequested)
        {
        if (rejectIfProbeAttachBusy(QStringLiteral("!sym -resolve"))) {
            return;
        }
        if (rejectIfProbeQueryBusy(QStringLiteral("!sym -resolve"))) {
            return;
        }

        quint64 address = 0;
        QString addrError;
        if (!parseSymAddrArg(parts, address, addrError))
        {
            setOutputText("Usage: !sym -resolve -addr:<0x...> [-pid:<pid>]");
            setOutputText("  Kernel VA: auto lookup module via driver (PID 4)");
            setOutputText("  User VA: pass -pid when symbols are not loaded yet");
            setOutputText("  Run !sym for usage.");
            if (!addrError.isEmpty() && addrError != QStringLiteral("-addr parameter is required."))
            {
                setOutputText(addrError);
            }
            return;
        }

        DWORD targetPid = 0;
        QString pidParseError;
        if (!parseSymPidArg(parts, targetPid, pidParseError) && !pidParseError.isEmpty())
        {
            setOutputText(pidParseError);
            return;
        }

        constexpr quint64 kKernelAddressThreshold = 0xFFFF000000000000ULL;
        const bool isKernelAddress = address >= kKernelAddressThreshold;

        std::wstring symbolName;
        DWORD64 displacement = 0;
        std::wstring moduleName;
        DWORD64 moduleBase = 0;
        bool symBusy = false;
        if (m_symbolManager.ResolveAddress(address, symbolName, displacement, moduleName, moduleBase, &symBusy))
        {
            const QString formattedSymbol = moduleName.empty()
                ? QString("%1+0x%2").arg(QString::fromStdWString(symbolName)).arg(displacement, 0, 16)
                : QString("%1!%2+0x%3")
                      .arg(QString::fromStdWString(moduleName))
                      .arg(QString::fromStdWString(symbolName))
                      .arg(displacement, 0, 16);
            setOutputText(QString("0x%1 -> %2")
                .arg(address, 16, 16, QChar('0'))
                .arg(formattedSymbol));
            const std::wstring friendlyName = SymbolManager::DemangleSymbolName(symbolName);
            if (!friendlyName.empty())
            {
                setOutputText(QString("  Friendly: %1").arg(QString::fromStdWString(friendlyName)));
            }
            setOutputText(QString("  Module: %1  Base: 0x%2  RVA: 0x%3")
                .arg(QString::fromStdWString(moduleName))
                .arg(moduleBase, 16, 16, QChar('0'))
                .arg(address - moduleBase, 0, 16));
            return;
        }

        if (symBusy)
        {
            setOutputText("Symbol operation in progress (PDB download/load). Please try !sym -resolve again shortly.");
            return;
        }

        if (moduleBase != 0)
        {
            const QString formattedOffset = moduleName.empty()
                ? QString("+0x%1").arg(address - moduleBase, 0, 16)
                : QString("%1+0x%2")
                      .arg(QString::fromStdWString(moduleName))
                      .arg(address - moduleBase, 0, 16);
            setOutputText(QString("0x%1 -> %2 (no symbol)")
                .arg(address, 16, 16, QChar('0'))
                .arg(formattedOffset));
            return;
        }

        DWORD lookupPid = 0;
        if (isKernelAddress)
        {
            lookupPid = 4;
        }
        else if (targetPid != 0)
        {
            lookupPid = targetPid;
        }
        else
        {
            setOutputText(QString("0x%1 -> symbols not loaded for this address").arg(address, 16, 16, QChar('0')));
            setOutputText("Pass -pid:<pid> to locate the module file, then load symbols with !sym -load.");
            return;
        }

        GET_MODULE_PATH inout = {};
        inout.pid = lookupPid;
        inout.va = address;
        GetModulePathByPid(&inout);

        if (!inout.path[0])
        {
            setOutputText(QString("0x%1 -> Module not found").arg(address, 16, 16, QChar('0')));
            return;
        }

        const std::wstring modulePath = convertSystemRootPathW(inout.path);
        setOutputText(QString("0x%1 -> symbols not loaded").arg(address, 16, 16, QChar('0')));
        setOutputText(QString("  Module: %1").arg(QString::fromStdWString(modulePath)));
        if (isKernelAddress)
        {
            setOutputText(QString("  Try: !sym -load -path:%1").arg(QString::fromStdWString(modulePath)));
        }
        else
        {
            setOutputText(QString("  Try: !sym -load -path:%1 -pid:%2")
                .arg(QString::fromStdWString(modulePath))
                .arg(lookupPid));
        }
        }
        else if (listRequested)
        {
        if (rejectIfProbeAttachBusy(QStringLiteral("!sym -list"))) {
            return;
        }
        if (rejectIfProbeQueryBusy(QStringLiteral("!sym -list"))) {
            return;
        }

        std::vector<SYMBOL_FILE_INFO> symbolEntries;
        bool symBusy = false;
        if (!m_symbolManager.GetSymbolEntries(symbolEntries, &symBusy) && symBusy)
        {
            setOutputText("Symbol operation in progress (PDB download/load). Please try !sym -list again shortly.");
            return;
        }

        if (symbolEntries.empty())
        {
            setOutputText("No symbol entries tracked.");
            return;
        }

        setOutputText(QString("Symbol entries (%1):").arg(symbolEntries.size()));
        for (const SYMBOL_FILE_INFO& info : symbolEntries)
        {
            const QString state = info.loadedInDbgHelp ? QStringLiteral("loaded")
                                                       : QStringLiteral("cached");
            setOutputText(QString("  [%1] %2").arg(state, QString::fromStdWString(info.pdbName)));
            setOutputText(QString("    File: %1").arg(QString::fromStdWString(info.filePath)));
            if (info.targetPid != 0) {
                setOutputText(QString("    PID: %1").arg(info.targetPid));
            }
            setOutputText(QString("    PDB: %1").arg(QString::fromStdWString(info.localPdbPath)));
            setOutputText(QString("    Timestamp: 0x%1, Checksum: 0x%2")
                .arg(info.timestamp, 8, 16, QChar('0'))
                .arg(info.checksum, 8, 16, QChar('0')));
            if (info.loadedInDbgHelp && info.baseAddr != 0) {
                setOutputText(QString("    Base: 0x%1")
                    .arg(static_cast<qulonglong>(info.baseAddr), 16, 16, QChar('0')));
            }
        }
        }
    }
    else if (cmd == "!probe")
    {
        probe(parts);
    }
    else if (cmd == "!enable_testsigning")
    {
        startEnableTestSigning();
    }
    else if (cmd == "!disable_testsigning")
    {
        if (m_testSigningRunning)
        {
            setOutputText("Error: !enable_testsigning / !disable_testsigning is already running. Please wait for it to complete.");
        }
        else
        {
            m_testSigningRunning = true;
            QThread* tsThread = QThread::create([this]() {
                WCHAR* logBuf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 16384 * sizeof(WCHAR));
                QString result;
                if (logBuf)
                {
                    DWORD logLen = DisableTestSigning(logBuf, 16384);
                    result = QString::fromWCharArray(logBuf, logLen);
                    HeapFree(GetProcessHeap(), 0, logBuf);
                }
                else
                {
                    result = "[Error] Out of memory (failed to alloc log buffer).";
                }

                QMetaObject::invokeMethod(this, [this, result]() {
                    m_testSigningRunning = false;
                    setOutputText(result);
                    if (m_driverSetupDialog) {
                        m_driverSetupDialog->refresh();
                    }
                }, Qt::QueuedConnection);
            });
            connect(tsThread, &QThread::finished, tsThread, &QObject::deleteLater);
            tsThread->start();
        }
    }
    else if (cmd == "!check_cert")
    {
        check_cert(parts);
    }
    else if (cmd == "!support" || cmd == "!compat-report")
    {
        printSupportReport();
    }
    else if (cmd == "!getting-started")
    {
        printGettingStarted();
    }
    else if (cmd == "!license" || cmd == "!about")
    {
        setOutputText(QStringLiteral("Hawkeye Community %1 (open source). No subscription.")
                          .arg(QStringLiteral(HAWKEYE_VERSION_STRING)));
        setOutputText(QStringLiteral("Website: %1").arg(QStringLiteral(HAWKEYE_WEBSITE_URL)));
        setOutputText(QStringLiteral("Hawkeye Lab is the commercial analyze/report edition."));
    }
    else if (cmd == "!help")
    {
        setOutputText("Hawkeye Community command reference. Run a command without arguments for detailed usage.");
        if (MemoryIntegrityIsRunning()) {
            setOutputText("");
            setOutputTextColored(
                QStringLiteral("Memory integrity is on. Open Memory integrity on the status bar."),
                QColor("#B71C1C"));
        }
        setOutputText("");

        setOutputTextHeading("[Environment]");
        setOutputText("!enable_testsigning - Turn on Windows test signing and trust the Hawkeye test certificate");
        setOutputText("!disable_testsigning - Turn off test signing and remove the Hawkeye test certificate");
        setOutputText("!getting-started - Show the Getting started map");
        setOutputText("!support - Website, email, and a system report to send if something breaks");
        setOutputText("!license - Edition and website");
        setOutputText("");

        setOutputTextHeading("[Processes]");
        setOutputText("!process - Scan all system processes");
        setOutputText("!modules - Enumerate kernel or user-mode modules (run !modules for usage)");
        setOutputText("!threads - List threads and Win32 start addresses (OEP) for a process (run !threads for usage)");
        setOutputText("!check_cert - Verify digital signatures of all modules in a process, or all PE files in a directory (run !check_cert for usage)");
        setOutputText("!inject_sim - Inject unsigned stub DLL for !check_cert staging (run !inject_sim for usage)");
        setOutputText("");

        setOutputTextHeading("[Hooks]");
        setOutputText("!iguard_scan - Scan kernel modules for CFG dispatch tampering (run !iguard_scan for usage)");
        setOutputText("!inline_hook - Scan user process modules for inline hooks (run !inline_hook for usage)");
        setOutputText("!inline_hook_sim - Patch HawkUnsignedStub in-memory to stage !inline_hook test (run !inline_hook_sim for usage)");
        setOutputText("");

        setOutputTextHeading("[Windows]");
        setOutputText("!check_hwnd - Check whether a window handle is valid (run !check_hwnd for usage)");
        setOutputText("");

        setOutputTextHeading("[Memory]");
        setOutputText("!pte - Inspect page-table entry for an address (run !pte for usage)");
        setOutputText("!pfn - Inspect physical-frame info for an address (run !pfn for usage)");
        setOutputText("!dump - Memory page dump to .\\DumpPages (MmCopyMemory or MmMapIoSpace; run !dump for usage)");
        setOutputText("!kernel_region - Identify kernel address range type (-va: or -list)");
        setOutputText("");

        setOutputTextHeading("[Analysis]");
        setOutputText("!probe - Live symbol context on a chosen process or the kernel, for joint analysis against runtime data (run !probe for usage)");
        setOutputText("!etw - Live CPU sampling on a process, a thread, or the whole system (run !etw for usage)");
        setOutputText("");

        setOutputTextHeading("[Symbols]");
        setOutputText("!sym - Download, load, unload, resolve, and list symbol files (run !sym for usage)");
        setOutputText("");

        setOutputTextHeading("[Console]");
        setOutputText("!search [<keyword>] - Highlight matching console lines; omit the keyword to restore default color");
        setOutputText(" cls - Clear console");
    }

    else if (cmd == "!search")
    {
        if (parts.size() < 2)
        {
            
            QTextCursor cursor(ui.textEditConsole->document());
            cursor.select(QTextCursor::Document);
            QTextCharFormat fmt;
            fmt.setForeground(QColor("#222222"));
            cursor.mergeCharFormat(fmt);
            setOutputText("All highlighted lines restored to default color.");
        }
        else
        {
            
            QString keyword = parts.mid(1).join(' ');
            QTextDocument* doc = ui.textEditConsole->document();
            QTextCharFormat redFmt;
            redFmt.setForeground(QColor("#B71C1C"));

            int matchCount = 0;
            QTextBlock block = doc->begin();
            while (block.isValid())
            {
                if (block.text().contains(keyword, Qt::CaseInsensitive))
                {
                    QTextCursor lineCursor(block);
                    lineCursor.select(QTextCursor::LineUnderCursor);
                    lineCursor.mergeCharFormat(redFmt);
                    ++matchCount;
                }
                block = block.next();
            }
            setOutputText(QString("Found %1 matching lines for '%2'.").arg(matchCount).arg(keyword));
        }
    }
    else if (cmd == "cls")
    {
        ui.textEditConsole->clear();
    }
    else if (cmd.startsWith(QStringLiteral("!sym_"), Qt::CaseInsensitive))
    {
        setOutputText(QString("Unknown command: %1").arg(cmd));
        setOutputText("  Symbol commands are now !sym -<action>. Run !sym for usage.");
    }
    else
    {
        setOutputText(QString("Unknown command: %1").arg(cmd));
        setOutputText("  Run !help for the Community command list.");
    }
}

void Hawkeye::closeEvent(QCloseEvent* closeEv)
{
    if (m_resizeSettleTimer) {
        m_resizeSettleTimer->stop();
    }

    if (m_inlineHookSimState.active) {
        InlineHookSimStop(m_inlineHookSimState);
        m_inlineHookSimState = {};
    }

    if (m_memoryDialog) {
        disconnect(m_memoryDialog, nullptr, this, nullptr);
        delete m_memoryDialog;
        m_memoryDialog = nullptr;
    }

    if (m_probeSession.IsAttached()) {
        m_probeSession.Detach(m_symbolManager, ProbeLogFn{});
    }

    UninstallHawkDrv();

    closeEv->accept();
    QApplication::quit();
}
