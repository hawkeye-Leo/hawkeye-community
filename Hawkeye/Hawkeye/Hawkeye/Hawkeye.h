#pragma once

#include <QtWidgets/QMainWindow>
#include <QColor>
#include <QStringList>
#include <QTextEdit>
#include <QUrl>
#include <QVector>
#include <QVBoxLayout>
#include <QWidget>
#include "ui_Hawkeye.h"
#include "symmanager.h"
#include "probe.h"
#include "inject_sim.h"
#include "inline_hook_sim.h"

#include <Windows.h>
#include <windowsx.h>

#include <string>
#include <vector>
#include <atomic>
#include "CertVerifier.h"

struct ConsoleColoredLine
{
    QString text;
    QColor color;
};

extern bool DriverStatusError;
class QTimer;
class MemoryDialog;
class DriverSetupDialog;

class Hawkeye : public QMainWindow
{
    Q_OBJECT

public:
    Hawkeye(QWidget *parent = nullptr);
    ~Hawkeye();

    void setOutputText(const QString& text);
    void setOutputTextHeading(const QString& text);
    void setOutputTextLinked(const QString& text);
    void setOutputTextColored(const QString& text, const QColor& textColor, bool bold = false);
    void appendConsoleColoredBatch(QVector<ConsoleColoredLine> lines);
    void appendConsoleColoredLinesChunk(
        QTextCursor* cursor,
        const QVector<ConsoleColoredLine>& lines,
        int beginIndex,
        int endIndex);
    void handleCommandLine(const QString& command);
    void closeEvent(QCloseEvent* closeEv);
    HWND getWindowHandle() const;

private slots:
    void onStartupDelayed();
    void onConsoleResizeSettled();
    void onPushButtonMemoryClicked();
    void onEditionChipClicked();
    void onDriverSetupClicked();
    void onConsoleAnchorClicked(const QUrl& url);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
    bool nativeEvent(const QByteArray& eventType, void* message, long* result) override;

private:
    void appendConsoleLine(const QString& text, const QColor& textColor = QColor(), bool bold = false);
    void echoUserCommand(const QString& text);
    void appendEtwResultChunks(std::vector<std::wstring> chunks);
    void appendProbeFindResultLines(std::vector<QString> lines);
    void addCommandToHistory(const QString& command);
    void iguard_scan(const QStringList& parts);
    void inline_hook(const QStringList& parts);
    void probe(const QStringList& parts);
    void etw(const QStringList& parts);
    void check_cert(const QStringList& parts);
    void list_pm(const QStringList& parts);
    void pte(const QStringList& parts);
    void dm(const QStringList& parts);
    void list_pt(const QStringList& parts);
    void resetCommandHistoryNavigation();
    void performStartupTasks();
    void showStartupWelcome(bool driverReady);
    void printGettingStarted();
    void printSupportReport();
    void appendConsoleHtmlLine(const QString& html);
    bool gettingStartedIsHidden() const;
    void hideGettingStartedFromNow();
    void applyDriverStatusChip();
    void startEnableTestSigning();
    void printMemoryIntegrityBlocked();
    void applyEditionChip();
    void beginConsoleResizeFreeze();
    QString buildCertReport(std::uint32_t pid,
                            const std::vector<CertVerifier::Result>& results,
                            const CertVerifier::Summary& summary,
                            bool byDir) const;

    QString formatCertResultLine(const CertVerifier::Result& result,
                                 std::uint32_t processedCount,
                                 std::uint32_t totalCount) const;

    QColor certResultColor(const CertVerifier::Result& result) const;

    Ui::HawkeyeClass ui;
    QStringList m_cmdHistory;
    int m_historyIndex = -1;
    QString m_historyDraft;
    static const int kMaxCmdHistory = 100;

    bool m_consoleResizeFreeze = false;
    bool m_iguardScanning = false;
    bool m_inlineHookScanning = false;
    bool m_testSigningRunning = false;
    std::atomic<bool> m_certScanRunning{ false };
    std::atomic<bool> m_certScanStopRequested{ false };
    std::atomic<bool> m_etwRunning{ false };
    InjectSimState m_injectSimState;
    InlineHookSimState m_inlineHookSimState;
    QTimer* m_resizeSettleTimer = nullptr;
    MemoryDialog* m_memoryDialog = nullptr;
    DriverSetupDialog* m_driverSetupDialog = nullptr;
    bool m_driverStatusReady = false;
    bool m_driverSetupNeeded = false;
    SymbolManager m_symbolManager;
    ProbeSession m_probeSession;
    std::atomic<bool> m_probeAttachInProgress{ false };
    std::atomic<bool> m_probeAttachCancelRequested{ false };
    std::atomic<bool> m_probeFindInProgress{ false };
    std::atomic<bool> m_symBusy{ false };
    QTimer* m_probeProgressTimer = nullptr;
    std::uint64_t m_probeCacheBaseline = 0;
    std::uint64_t m_probeLastReportedBytes = 0;
    std::wstring m_probeCacheDirectory;

    bool tryBeginSymOperation();
    void endSymOperation();
    void endProbeQueryOperation();
    bool isProbeAttachInProgress() const;
    bool rejectIfProbeAttachBusy(const QString& actionHint);
    bool rejectIfProbeQueryBusy(const QString& actionHint);
    void requestProbeAttachStop();
    static QString parseSymPathArg(const QStringList& parts);
    static bool parseSymPidArg(const QStringList& parts, DWORD& outPid, QString& outError);
    static bool parseSymAddrArg(const QStringList& parts, quint64& outAddr, QString& outError);
};
