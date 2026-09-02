#include "Hawkeye.h"
#include "HawkeyeTitleBar.h"
#include "IntroSplash.h"
#include "HawkeyeVersion.h"
#include "resource.h"
#include"Driver.h"
#include"process.h"
#include <QtWidgets/QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QIcon>
#include <QRect>
#include <QScreen>
#include <Shobjidl.h>

namespace {

void applyNativeWindowIcon(QWidget* widget)
{
    if (widget == nullptr) {
        return;
    }

    const HWND hwnd = reinterpret_cast<HWND>(widget->winId());
    if (hwnd == nullptr) {
        return;
    }

    const HINSTANCE instance = GetModuleHandleW(nullptr);
    const HICON bigIcon = static_cast<HICON>(LoadImageW(
        instance,
        MAKEINTRESOURCEW(IDI_ICON1),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),
        GetSystemMetrics(SM_CYICON),
        LR_DEFAULTCOLOR | LR_SHARED));
    const HICON smallIcon = static_cast<HICON>(LoadImageW(
        instance,
        MAKEINTRESOURCEW(IDI_ICON1),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR | LR_SHARED));

    if (bigIcon != nullptr) {
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));
    }
    if (smallIcon != nullptr) {
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
    }
}

} // namespace

int main(int argc, char *argv[])
{
    SetCurrentProcessExplicitAppUserModelID(L"HawkeyeCommunity.Hawkeye");

    HANDLE  mutex = CreateMutexA(NULL, FALSE, "Hawkeye-community");
    SetHawkeyeInstanceMutex(mutex);
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        MessageBoxA(NULL, "Hawkeye Community is already running.", "Hawkeye Community", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    enableDebugPrivilege();

    InstallHawkDrv();

    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
    QApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral(HAWKEYE_PRODUCT_NAME));
    QCoreApplication::setApplicationVersion(QStringLiteral(HAWKEYE_VERSION_STRING));
    QCoreApplication::setOrganizationName(QStringLiteral(HAWKEYE_COMPANY_NAME));
    QFont appFont(QStringLiteral("Segoe UI"), 9);
    app.setFont(appFont);

    QIcon icon(QCoreApplication::applicationFilePath());
    if (icon.isNull()) {
        icon = QIcon(QStringLiteral(":/Hawkeye/AppIcon.png"));
    }
    app.setWindowIcon(icon);

    Hawkeye window;
    IntroSplash splash;

    window.setWindowIcon(icon);
    window.setWindowOpacity(0.0);
    window.show();
    applyNativeWindowIcon(&window);
    app.processEvents();

    QRect titleRect;
    QScreen* screen = window.screen();
    if (screen == nullptr) {
        screen = QGuiApplication::primaryScreen();
    }
    if (screen != nullptr) {
        const QRect avail = screen->availableGeometry();
        QRect frame = window.frameGeometry();
        QPoint pos(
            avail.x() + qMax(0, (avail.width() - frame.width()) / 2),
            avail.y() + qMax(0, (avail.height() - frame.height()) / 2));
        window.move(pos);
        app.processEvents();
    }
    if (auto* bar = qobject_cast<HawkeyeTitleBar*>(window.menuWidget())) {
        titleRect = bar->titleTextScreenRect();
    }

    QObject::connect(&splash, &IntroSplash::finished, &window, [&window, icon]() {
        window.setWindowOpacity(1.0);
        window.setWindowIcon(icon);
        applyNativeWindowIcon(&window);
        window.raise();
        window.activateWindow();
    });

    splash.start(&window, titleRect);
    return app.exec();
}
