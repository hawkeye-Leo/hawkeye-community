#include "driversetupdialog.h"

#include "CompatReport.h"
#include "Driver.h"
#include "HawkeyeStyle.h"
#include "HawkeyeTitleBar.h"

#include <QCoreApplication>
#include <QEvent>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStringList>
#include <QVBoxLayout>

#include <Windows.h>
#include <shellapi.h>

extern bool DriverStatusError;

namespace {

constexpr int kNameColWidth = 140;
constexpr int kChipWidth = 120;
constexpr int kChipHeight = 22;

const char kLinkStyle[] =
    "color:#1B5E20; text-decoration:none; font-weight:600;";

bool enableShutdownPrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES privileges = {};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL lookedUp = LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
    BOOL adjusted = FALSE;
    if (lookedUp) {
        adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
    }
    CloseHandle(token);
    return lookedUp && adjusted && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

} // namespace

DriverSetupDialog::DriverSetupDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setWindowTitle(QStringLiteral("Driver setup"));
    setMinimumWidth(520);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    m_intro = new QLabel(this);
    m_intro->setWordWrap(true);
    m_intro->setText(QStringLiteral(
        "Hawkeye Community needs a test-signed driver. Work top to bottom. Restart Windows when a row asks for it."));
    layout->addWidget(m_intro);

    auto* grid = new QGridLayout();
    grid->setHorizontalSpacing(16);
    grid->setVerticalSpacing(10);
    grid->setColumnMinimumWidth(0, kNameColWidth);
    grid->setColumnMinimumWidth(1, kChipWidth);
    grid->setColumnStretch(2, 1);

    auto addRow = [&](int row, const QString& name, QLabel** status, QLabel** action) {
        auto* nameLabel = new QLabel(name, this);
        nameLabel->setMinimumWidth(kNameColWidth);
        *status = new QLabel(this);
        (*status)->setAlignment(Qt::AlignCenter);
        (*status)->setFixedSize(kChipWidth, kChipHeight);
        grid->addWidget(nameLabel, row, 0, Qt::AlignLeft | Qt::AlignVCenter);
        grid->addWidget(*status, row, 1, Qt::AlignLeft | Qt::AlignVCenter);
        *action = new QLabel(this);
        (*action)->setTextFormat(Qt::RichText);
        (*action)->setTextInteractionFlags(Qt::LinksAccessibleByMouse);
        (*action)->setOpenExternalLinks(false);
        connect(*action, &QLabel::linkActivated, this, &DriverSetupDialog::onActionLink);
        grid->addWidget(*action, row, 2, Qt::AlignLeft | Qt::AlignVCenter);
    };

    addRow(0, QStringLiteral("Administrator"), &m_adminStatus, &m_adminAction);
    addRow(1, QStringLiteral("Secure Boot"), &m_secureBootStatus, &m_secureBootAction);
    addRow(2, QStringLiteral("Test signing"), &m_testSigningStatus, &m_testSigningAction);
    addRow(3, QStringLiteral("Memory integrity"), &m_memoryIntegrityStatus, &m_memoryIntegrityAction);
    addRow(4, QStringLiteral("Driver"), &m_driverStatus, &m_driverAction);
    layout->addLayout(grid);

    m_note = new QLabel(this);
    m_note->setWordWrap(true);
    m_note->setStyleSheet(QStringLiteral("color: #5A5A5A; font-size: 11px;"));
    layout->addWidget(m_note);

    auto* buttons = new QHBoxLayout();
    m_restartWindows = new QPushButton(QStringLiteral("Restart Windows"), this);
    m_restartWindows->setCursor(Qt::PointingHandCursor);
    auto* closeButton = new QPushButton(QStringLiteral("Close"), this);
    closeButton->setCursor(Qt::PointingHandCursor);
    buttons->addWidget(m_restartWindows);
    buttons->addStretch(1);
    buttons->addWidget(closeButton);
    layout->addLayout(buttons);

    HawkeyeTitleBar::attach(this, HawkeyeTitleBar::CloseOnly);
    HawkeyeStyle::applyChrome(this);

    connect(m_restartWindows, &QPushButton::clicked, this, &DriverSetupDialog::onRestartWindows);
    connect(closeButton, &QPushButton::clicked, this, &QWidget::hide);

    refresh();
}

DriverSetupDialog::~DriverSetupDialog() = default;

void DriverSetupDialog::showEvent(QShowEvent* event)
{
    QDialog::showEvent(event);
    refresh();
}

void DriverSetupDialog::changeEvent(QEvent* event)
{
    QDialog::changeEvent(event);
    if (event->type() == QEvent::ActivationChange && isActiveWindow()) {
        refresh();
    }
}

void DriverSetupDialog::setChip(QLabel* status, HawkeyeStyle::StatusChipKind kind, const QString& text)
{
    if (status == nullptr) {
        return;
    }
    status->setText(text);
    status->setStyleSheet(HawkeyeStyle::statusChipStyle(kind, false));
}

void DriverSetupDialog::setActionLink(QLabel* action, const QString& href, const QString& text, bool visible)
{
    if (action == nullptr) {
        return;
    }
    if (!visible || text.isEmpty()) {
        action->clear();
        action->setStyleSheet(QString());
        action->setCursor(Qt::ArrowCursor);
        return;
    }
    action->setStyleSheet(QString());
    action->setTextFormat(Qt::RichText);
    action->setTextInteractionFlags(Qt::LinksAccessibleByMouse);
    action->setCursor(Qt::PointingHandCursor);
    action->setText(QStringLiteral("<a href=\"%1\" style=\"%2\">%3</a>")
                        .arg(href, QString::fromLatin1(kLinkStyle), text.toHtmlEscaped()));
}

void DriverSetupDialog::setHint(QLabel* action, const QString& text)
{
    if (action == nullptr) {
        return;
    }
    if (text.isEmpty()) {
        action->clear();
        action->setStyleSheet(QString());
        action->setCursor(Qt::ArrowCursor);
        return;
    }
    action->setTextFormat(Qt::PlainText);
    action->setTextInteractionFlags(Qt::NoTextInteraction);
    action->setCursor(Qt::ArrowCursor);
    action->setStyleSheet(QStringLiteral("color: #5A5A5A; font-size: 11px;"));
    action->setText(text);
}

void DriverSetupDialog::refresh()
{
    const bool admin = IsRunningAsAdmin();
    const bool secureBoot = IsSecureBootEnabled();
    const bool testSigningLive = TestSigningIsEnabled();
    const bool testSigningBcd = TestSigningBcdEnabled();
    const bool testSigningRestart = testSigningBcd && !testSigningLive;
    const bool memoryIntegrityLive = MemoryIntegrityIsRunningNow();
    const bool memoryIntegrityRestart = MemoryIntegrityRestartNeeded();
    const bool driverOk = !DriverStatusError;

    setChip(m_adminStatus,
            admin ? HawkeyeStyle::StatusChipKind::Ok : HawkeyeStyle::StatusChipKind::Fail,
            admin ? QStringLiteral("OK") : QStringLiteral("Not admin"));
    setChip(m_secureBootStatus,
            secureBoot ? HawkeyeStyle::StatusChipKind::Fail : HawkeyeStyle::StatusChipKind::Ok,
            secureBoot ? QStringLiteral("Turn off") : QStringLiteral("OK"));
    if (testSigningLive) {
        setChip(m_testSigningStatus, HawkeyeStyle::StatusChipKind::Ok, QStringLiteral("OK"));
    } else if (testSigningRestart) {
        setChip(m_testSigningStatus, HawkeyeStyle::StatusChipKind::Warn, QStringLiteral("Restart needed"));
    } else {
        setChip(m_testSigningStatus, HawkeyeStyle::StatusChipKind::Fail, QStringLiteral("Turn on"));
    }
    if (memoryIntegrityRestart) {
        setChip(m_memoryIntegrityStatus, HawkeyeStyle::StatusChipKind::Warn, QStringLiteral("Restart needed"));
    } else if (memoryIntegrityLive) {
        setChip(m_memoryIntegrityStatus, HawkeyeStyle::StatusChipKind::Fail, QStringLiteral("Turn off"));
    } else {
        setChip(m_memoryIntegrityStatus, HawkeyeStyle::StatusChipKind::Ok, QStringLiteral("OK"));
    }
    setChip(m_driverStatus,
            driverOk ? HawkeyeStyle::StatusChipKind::Ok : HawkeyeStyle::StatusChipKind::Fail,
            driverOk ? QStringLiteral("Loaded") : QStringLiteral("Not loaded"));

    setActionLink(m_adminAction, QStringLiteral("admin"), QStringLiteral("Restart as Administrator"), !admin);
    if (secureBoot) {
        setHint(m_secureBootAction, QStringLiteral("Firmware or VM settings \u2014 then restart."));
    } else {
        setHint(m_secureBootAction, QString());
    }
    if (m_testSigningBusy) {
        setHint(m_testSigningAction, QStringLiteral("Working\u2026"));
    } else {
        setActionLink(m_testSigningAction, QStringLiteral("testsigning"), QStringLiteral("Enable test signing"),
                      !testSigningLive && !testSigningRestart && !secureBoot);
    }
    setActionLink(m_memoryIntegrityAction, QStringLiteral("memory"), QStringLiteral("Open Windows Security"),
                  memoryIntegrityLive && !memoryIntegrityRestart);

    const bool envReady = admin && !secureBoot && testSigningLive && !memoryIntegrityLive;
    if (driverOk) {
        setHint(m_driverAction, QString());
    } else if (!envReady) {
        setHint(m_driverAction, QString());
    } else if (GetLastDriverStartFailReason() == DrvStartFailSignature) {
        const DWORD err = GetLastDriverStartError();
        setHint(m_driverAction,
                err != 0 ? QStringLiteral("Windows blocked the signature (%1).").arg(err)
                         : QStringLiteral("Windows blocked the signature."));
    } else if (GetLastDriverStartFailReason() == DrvStartFailKernelLayout) {
        const char* compatRef = GetLastDriverCompatRef();
        setHint(m_driverAction,
                compatRef != nullptr
                    ? QStringLiteral("This Windows build is not supported (%1).")
                          .arg(QString::fromLatin1(compatRef))
                    : QStringLiteral("This Windows build is not supported."));
    } else if (GetLastDriverStartError() != 0) {
        setHint(m_driverAction, QStringLiteral("Start failed (%1).").arg(GetLastDriverStartError()));
    } else {
        setHint(m_driverAction, QStringLiteral("Start failed. See the console."));
    }

    QStringList notes;
    if (!admin) {
        notes << QStringLiteral("Restart as Administrator. No Windows restart required.");
    }
    if (secureBoot) {
        notes << QStringLiteral(
            "Turn Secure Boot off in firmware or in the VM settings, then restart Windows. "
            "Test signing cannot be enabled while Secure Boot is on.");
    }
    if (memoryIntegrityRestart) {
        notes << QStringLiteral("Memory integrity is off. Restart Windows, then start Hawkeye again.");
    } else if (memoryIntegrityLive) {
        notes << QStringLiteral(
            "Turn Memory integrity off: Windows Security \u2192 Device security \u2192 Core isolation \u2192 "
            "Memory integrity \u2192 Off, then restart Windows.");
    }
    if (testSigningRestart) {
        notes << QStringLiteral("Test signing is set. Restart Windows, then start Hawkeye again.");
    } else if (!testSigningLive && !secureBoot) {
        notes << QStringLiteral("Turn on test signing, then restart Windows.");
    }

    if (envReady && driverOk) {
        m_note->setText(QStringLiteral("Ready."));
    } else if (envReady && !driverOk) {
        m_note->setText(QStringLiteral(
            "Windows is configured. Restart Hawkeye if the driver still does not load. "
            "If it still fails, see the console for details."));
    } else {
        m_note->setText(notes.join(QStringLiteral("\n\n")));
    }
}

void DriverSetupDialog::setTestSigningBusy(bool busy)
{
    m_testSigningBusy = busy;
    refresh();
}

void DriverSetupDialog::onActionLink(const QString& href)
{
    if (href == QStringLiteral("admin")) {
        if (RestartHawkeyeAsAdministrator()) {
            QCoreApplication::quit();
            return;
        }
        QMessageBox::warning(
            this,
            QStringLiteral("Hawkeye Community"),
            QStringLiteral(
                "Administrator restart was cancelled or failed. You can continue, or start Hawkeye again as Administrator."));
        return;
    }
    if (href == QStringLiteral("testsigning")) {
        if (!m_testSigningBusy) {
            emit enableTestSigningRequested();
        }
        return;
    }
    if (href == QStringLiteral("memory")) {
        const HINSTANCE result = ShellExecuteW(
            nullptr, L"open", L"windowsdefender://coreisolation", nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(result) <= 32) {
            ShellExecuteW(nullptr, L"open", L"ms-settings:windowsdefender", nullptr, nullptr, SW_SHOWNORMAL);
        }
    }
}

void DriverSetupDialog::onRestartWindows()
{
    const auto answer = QMessageBox::question(
        this,
        QStringLiteral("Hawkeye Community"),
        QStringLiteral(
            "Restart Windows now so pending settings take effect?"));
    if (answer != QMessageBox::Yes) {
        return;
    }
    if (!enableShutdownPrivilege() || !ExitWindowsEx(EWX_REBOOT | EWX_FORCEIFHUNG,
                                                     SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIG)) {
        QMessageBox::warning(
            this,
            QStringLiteral("Hawkeye Community"),
            QStringLiteral("Could not restart Windows. Restart from the Start menu, then start Hawkeye again."));
    }
}
