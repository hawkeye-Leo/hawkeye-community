#pragma once

#include <QDialog>
#include <QtGlobal>
#include <QHash>
#include "ui_memory.h"
#include "disasm/memory_view_build.h"

#include <set>
#include <vector>
#include "qhex.h"

class SymbolManager;

class MemoryDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MemoryDialog(QWidget* parent = nullptr);
    ~MemoryDialog() override;

    void setSymbolManager(SymbolManager* symbolManager);

    void displayHexDump(quint64 baseAddr, const unsigned char* data, int size);

protected:
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onDisasmContextMenuRequested(const QPoint& pos);
    void onPushButtonReadClicked();
    void onDisasmScrollBarChanged(int value);

signals:
    
    void instructionStatsReady(const QString& stats);

private:
    void applyReadStatus(bool ok, const QString& text);

    Ui::MemoryDialog ui;
    QHexMonitor* m_hexMonitor;

    void syncHexFromDisasm();
    void resetSymbolSession();
    void requestModuleSymbolsAsync(quint64 va);
    void refreshDisasmWithSymbols();
    void rebuildDisasmView(bool emitStats);
    void applyMemoryViewBuildResult(const MemoryViewBuildResult& result, quint64 jobId);
    void appendRawHexData(quint64 baseAddr, const unsigned char* data, int size);
    void prefetchDisasmSymbols();
    bool currentModuleSymbolsReady() const;
    QString symbolAnnotationForAddress(quint64 address);
    QString symbolAnnotationForBranchTarget(quint64 address);
    QString cachedSymbolAnnotation(quint64 address) const;
    QString cachedBranchTargetSymbol(quint64 address) const;

    void rememberSuccessfulInput(const QString& pid, const QString& address);
    bool navigateInputHistory(QLineEdit* edit, QStringList& history, int& index, QString& draft, bool up);

    static const int kMaxInputHistory = 50;

    QStringList m_pidHistory;
    QStringList m_addressHistory;
    int m_pidHistoryIndex = -1;
    int m_addressHistoryIndex = -1;
    QString m_pidHistoryDraft;
    QString m_addressHistoryDraft;

    SymbolManager* m_symbolManager = nullptr;
    QHash<quint64, QString> m_symbolAnnotationCache;
    QHash<quint64, QString> m_branchTargetSymbolCache;
    std::set<std::wstring> m_symbolLoadInProgress;
    std::set<std::wstring> m_symbolLoadFailures;
    quint64 m_readSessionId = 0;
    quint64 m_disasmJobId = 0;
    int m_pendingDisasmScrollRestore = -1;
    bool m_syncHexAfterDisasm = false;

    quint64 m_baseAddr;
    std::vector<unsigned char> m_rawData;

    quint32 m_currentPid;
    quint64 m_currentVa;
    quint8 m_currentReadMethod = 0;
    bool m_isLoading;

    std::vector<unsigned char> m_allData;
    quint64 m_allDataBaseAddr;
    int m_disasmStartOffset = 0;
    int m_statsFromOffset = 0;
    int m_lastCompleteInstrEnd;
    bool m_disasmB64;
};
