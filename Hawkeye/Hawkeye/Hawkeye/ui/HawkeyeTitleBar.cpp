#include "HawkeyeTitleBar.h"

#include "HawkeyeStyle.h"

#include <QColor>
#include <QDialog>
#include <QEvent>
#include <QFont>
#include <QHBoxLayout>
#include <QFontMetrics>
#include <QLabel>
#include <QLayout>
#include <QMainWindow>
#include <QMargins>
#include <QMouseEvent>
#include <QPushButton>
#include <QSizePolicy>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

HawkeyeTitleBar::HawkeyeTitleBar(QWidget* host, Mode mode, QWidget* parent)
    : QWidget(parent)
    , m_host(host)
    , m_mode(mode)
{
    setObjectName(QStringLiteral("hawkeyeTitleBar"));
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedHeight(36);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setCursor(Qt::ArrowCursor);

    auto* layout = new QHBoxLayout(this);
    layout->setContentsMargins(10, 0, 0, 0);
    layout->setSpacing(8);

    m_icon = new QLabel(this);
    m_icon->setFixedSize(16, 16);
    m_icon->setScaledContents(true);
    m_icon->setAttribute(Qt::WA_TransparentForMouseEvents, true);

    m_title = new QLabel(this);
    m_title->setObjectName(QStringLiteral("hawkeyeTitleLabel"));
    m_title->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    m_title->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    QFont titleFont(QStringLiteral("Segoe UI"), 9);
    titleFont.setPixelSize(12);
    titleFont.setWeight(QFont::DemiBold);
    m_title->setFont(titleFont);

    layout->addWidget(m_icon, 0, Qt::AlignVCenter);
    layout->addWidget(m_title, 1, Qt::AlignVCenter);

    m_pin = new QPushButton(this);
    m_pin->setObjectName(QStringLiteral("titleBarPin"));
    m_pin->setFocusPolicy(Qt::NoFocus);
    m_pin->setCursor(Qt::ArrowCursor);
    m_pin->setCheckable(true);
    m_pin->setFlat(true);
    m_pin->setIconSize(QSize(14, 14));
    m_pin->setToolTip(QStringLiteral("Pin on top"));
    connect(m_pin, &QPushButton::clicked, this, &HawkeyeTitleBar::onPinClicked);
    layout->addWidget(m_pin);

    if (m_mode == MinMaxClose) {
        m_min = new QPushButton(QStringLiteral("\u2013"), this);
        m_min->setObjectName(QStringLiteral("titleBarMin"));
        m_min->setFocusPolicy(Qt::NoFocus);
        m_min->setCursor(Qt::ArrowCursor);
        connect(m_min, &QPushButton::clicked, this, &HawkeyeTitleBar::onMinClicked);
        layout->addWidget(m_min);

        m_max = new QPushButton(this);
        m_max->setObjectName(QStringLiteral("titleBarMax"));
        m_max->setFocusPolicy(Qt::NoFocus);
        m_max->setCursor(Qt::ArrowCursor);
        m_max->setIconSize(QSize(14, 14));
        connect(m_max, &QPushButton::clicked, this, &HawkeyeTitleBar::onMaxClicked);
        layout->addWidget(m_max);
    }

    m_close = new QPushButton(QStringLiteral("\u00D7"), this);
    m_close->setObjectName(QStringLiteral("titleBarClose"));
    m_close->setFocusPolicy(Qt::NoFocus);
    m_close->setCursor(Qt::ArrowCursor);
    connect(m_close, &QPushButton::clicked, this, &HawkeyeTitleBar::onCloseClicked);
    layout->addWidget(m_close);

    applyStyle();
    if (m_host) {
        setTitle(m_host->windowTitle());
        connect(m_host, &QWidget::windowTitleChanged, this, &HawkeyeTitleBar::setTitle);
        m_host->installEventFilter(this);
        refreshPinButton();
        refreshMaxButton();
    }
}

void HawkeyeTitleBar::attach(QWidget* host, Mode mode)
{
    if (!host) {
        return;
    }

    auto* bar = new HawkeyeTitleBar(host, mode, host);
    const auto restyle = [bar]() {
        bar->applyStyle();
        bar->refreshPinButton();
        bar->refreshMaxButton();
    };
    if (auto* mainWindow = qobject_cast<QMainWindow*>(host)) {
        host->setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
        mainWindow->setMenuWidget(bar);
        QTimer::singleShot(0, bar, restyle);
        return;
    }

    auto* dialog = qobject_cast<QDialog*>(host);
    if (!dialog) {
        return;
    }

    dialog->setWindowFlags(Qt::Window | Qt::FramelessWindowHint);

    constexpr int kTitleBarHeight = 36;
    if (QLayout* inner = dialog->layout()) {
        QWidget holder;
        holder.setLayout(inner);

        auto* outer = new QVBoxLayout(dialog);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->setSpacing(0);

        auto* body = new QWidget(dialog);
        body->setLayout(holder.layout());

        bar->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        outer->addWidget(bar, 0);
        outer->addWidget(body, 1);
        bar->m_overlay = false;
    } else {
        bar->m_overlay = true;
        bar->setGeometry(0, 0, dialog->width(), kTitleBarHeight);
        bar->raise();
    }

    const int minH = dialog->minimumHeight();
    const int maxH = dialog->maximumHeight();
    if (minH > 0 && minH < QWIDGETSIZE_MAX) {
        dialog->setMinimumHeight(minH + kTitleBarHeight);
    }
    if (maxH > 0 && maxH < QWIDGETSIZE_MAX) {
        dialog->setMaximumHeight(maxH + kTitleBarHeight);
    }
    dialog->resize(dialog->width(), dialog->height() + kTitleBarHeight);
    QTimer::singleShot(0, bar, restyle);
}

void HawkeyeTitleBar::setTitle(const QString& title)
{
    if (m_title) {
        m_title->setText(title);
    }
}

QRect HawkeyeTitleBar::titleTextScreenRect() const
{
    if (m_title == nullptr || m_title->text().isEmpty()) {
        return {};
    }

    const QRect contents = m_title->contentsRect();
    const QRect text = QFontMetrics(m_title->font()).boundingRect(
        contents, Qt::AlignVCenter | Qt::AlignLeft, m_title->text());
    if (!text.isValid()) {
        return {};
    }
    return QRect(m_title->mapToGlobal(text.topLeft()), text.size());
}

void HawkeyeTitleBar::applyStyle()
{
    const QColor bg = HawkeyeStyle::systemAccentColor();
    const QColor fg = HawkeyeStyle::contrastingFg(bg);
    const QColor hover = HawkeyeStyle::mixRgb(bg, fg, 0.14);
    const QColor pinned = HawkeyeStyle::mixRgb(bg, QColor(QStringLiteral("#000000")), 0.22);
    setStyleSheet(QStringLiteral(
        "QWidget#hawkeyeTitleBar {"
        "  background-color: %1;"
        "  border: none;"
        "}"
        "QLabel#hawkeyeTitleLabel {"
        "  color: %2;"
        "  font-family: 'Segoe UI', sans-serif;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "  background: transparent;"
        "}"
        "QPushButton#titleBarPin, QPushButton#titleBarMin, QPushButton#titleBarMax, QPushButton#titleBarClose {"
        "  min-width: 46px;"
        "  max-width: 46px;"
        "  min-height: 36px;"
        "  max-height: 36px;"
        "  padding: 0;"
        "  margin: 0;"
        "  border: none;"
        "  border-radius: 0;"
        "  background-color: %1;"
        "  color: %2;"
        "  font-family: 'Segoe UI', sans-serif;"
        "  font-size: 14px;"
        "  font-weight: 400;"
        "}"
        "QPushButton#titleBarPin:hover, QPushButton#titleBarMin:hover, QPushButton#titleBarMax:hover {"
        "  background-color: %3;"
        "}"
        "QPushButton#titleBarPin:checked {"
        "  background-color: %4;"
        "}"
        "QPushButton#titleBarClose:hover {"
        "  background-color: #c42b1c;"
        "  color: #ffffff;"
        "}"
    ).arg(bg.name(QColor::HexRgb),
          fg.name(QColor::HexRgb),
          hover.name(QColor::HexRgb),
          pinned.name(QColor::HexRgb)));
    if (m_icon) {
        m_icon->setPixmap(HawkeyeStyle::titleBarAppMark(fg));
        m_icon->show();
    }
}

void HawkeyeTitleBar::onPinClicked()
{
    if (!m_host || !m_pin) {
        return;
    }

    const bool pinned = m_pin->isChecked();
    const bool wasMaximized = m_host->isMaximized();
    Qt::WindowFlags flags = m_host->windowFlags();
    flags.setFlag(Qt::WindowStaysOnTopHint, pinned);
    m_host->setWindowFlags(flags);
    if (wasMaximized) {
        m_host->showMaximized();
    } else {
        m_host->show();
    }
    refreshPinButton();
}

void HawkeyeTitleBar::onMinClicked()
{
    if (m_host) {
        m_host->showMinimized();
    }
}

void HawkeyeTitleBar::onMaxClicked()
{
    if (!m_host) {
        return;
    }
    if (m_host->isMaximized()) {
        m_host->showNormal();
    } else {
        m_host->showMaximized();
    }
    refreshMaxButton();
}

void HawkeyeTitleBar::onCloseClicked()
{
    if (m_host) {
        m_host->close();
    }
}

void HawkeyeTitleBar::refreshMaxButton()
{
    if (!m_max || !m_host) {
        return;
    }
    m_max->setText(QString());
    m_max->setIcon(HawkeyeStyle::titleBarWindowIcon(
        m_host->isMaximized(), HawkeyeStyle::contrastingFg(HawkeyeStyle::systemAccentColor())));
}

void HawkeyeTitleBar::refreshPinButton()
{
    if (!m_pin || !m_host) {
        return;
    }

    const bool pinned = m_host->windowFlags() & Qt::WindowStaysOnTopHint;
    m_pin->blockSignals(true);
    m_pin->setChecked(pinned);
    m_pin->blockSignals(false);
    m_pin->setIcon(HawkeyeStyle::titleBarPinIcon(
        pinned, HawkeyeStyle::contrastingFg(HawkeyeStyle::systemAccentColor())));
    m_pin->setToolTip(pinned
        ? QStringLiteral("Unpin from top")
        : QStringLiteral("Pin on top"));
}

void HawkeyeTitleBar::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && m_host && !m_host->isMaximized()) {
        QWidget* hit = childAt(event->pos());
        while (hit && hit != this) {
            if (hit == m_pin || hit == m_min || hit == m_max || hit == m_close) {
                QWidget::mousePressEvent(event);
                return;
            }
            hit = hit->parentWidget();
        }
        m_dragging = true;
        m_dragOffset = event->globalPos() - m_host->frameGeometry().topLeft();
        grabMouse();
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void HawkeyeTitleBar::mouseMoveEvent(QMouseEvent* event)
{
    if (m_dragging && m_host && (event->buttons() & Qt::LeftButton)) {
        m_host->move(event->globalPos() - m_dragOffset);
        event->accept();
        return;
    }
    QWidget::mouseMoveEvent(event);
}

void HawkeyeTitleBar::mouseReleaseEvent(QMouseEvent* event)
{
    if (m_dragging) {
        m_dragging = false;
        releaseMouse();
        event->accept();
        return;
    }
    QWidget::mouseReleaseEvent(event);
}

void HawkeyeTitleBar::mouseDoubleClickEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && m_mode == MinMaxClose) {
        onMaxClicked();
        event->accept();
        return;
    }
    QWidget::mouseDoubleClickEvent(event);
}

bool HawkeyeTitleBar::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_host) {
        if (event->type() == QEvent::WindowStateChange) {
            refreshMaxButton();
        } else if (m_overlay && event->type() == QEvent::Resize) {
            setGeometry(0, 0, m_host->width(), 36);
            raise();
        }
    }
    return QWidget::eventFilter(watched, event);
}
