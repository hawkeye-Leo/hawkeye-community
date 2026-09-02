#include "IntroSplash.h"

#include <QFontMetrics>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPaintEvent>
#include <QScreen>

namespace {

float clamp01(float value)
{
    if (value < 0.0f) {
        return 0.0f;
    }
    if (value > 1.0f) {
        return 1.0f;
    }
    return value;
}

} // namespace

IntroSplash::IntroSplash(QWidget* parent)
    : QWidget(parent)
{
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_DeleteOnClose, false);
    setFocusPolicy(Qt::StrongFocus);

    m_timer.setTimerType(Qt::PreciseTimer);
    connect(&m_timer, &QTimer::timeout, this, &IntroSplash::onTick);
}

void IntroSplash::start(QWidget* host, const QRect& titleScreenRect)
{
    m_host = host;
    m_titleRect = titleScreenRect;
    m_finished = false;
    m_textOpacity = 0.0f;
    m_glow = 0.0f;

    if (m_host == nullptr || !m_titleRect.isValid() || m_titleRect.isEmpty()) {
        complete();
        return;
    }

    if (QScreen* screen = QGuiApplication::primaryScreen()) {
        setGeometry(screen->geometry());
    } else {
        resize(1280, 720);
    }

    beginPhase(Phase::Flash);
    m_timer.start(kTickMs);
    show();
    raise();
    activateWindow();
}

void IntroSplash::beginPhase(Phase phase)
{
    m_phase = phase;
    m_phaseClock.restart();
}

void IntroSplash::onTick()
{
    advanceAnimation();
    update();
    if (m_phase == Phase::Done) {
        m_timer.stop();
        complete();
    }
}

void IntroSplash::advanceAnimation()
{
    const float elapsed = float(m_phaseClock.elapsed());

    switch (m_phase) {
    case Phase::Flash: {
        const float t = clamp01(elapsed / float(kFlashMs));
        m_textOpacity = t;
        m_glow = t * 1.15f;
        if (elapsed >= kFlashMs) {
            beginPhase(Phase::Hold);
        }
        break;
    }
    case Phase::Hold: {
        m_textOpacity = 1.0f;
        m_glow = 0.85f;
        if (elapsed >= kHoldMs) {
            beginPhase(Phase::Fade);
        }
        break;
    }
    case Phase::Fade: {
        const float t = clamp01(elapsed / float(kFadeMs));
        m_textOpacity = 1.0f - t;
        m_glow = 0.85f * (1.0f - t);
        if (m_host != nullptr) {
            m_host->setWindowOpacity(t);
        }
        if (elapsed >= kFadeMs) {
            beginPhase(Phase::Done);
        }
        break;
    }
    case Phase::Done:
        break;
    }
}

void IntroSplash::complete()
{
    if (m_finished) {
        return;
    }
    m_finished = true;
    m_timer.stop();
    if (m_host != nullptr) {
        m_host->setWindowOpacity(1.0);
    }
    hide();
    emit finished();
}

void IntroSplash::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);
    if (m_textOpacity <= 0.01f || !m_titleRect.isValid()) {
        return;
    }

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    QFont font(QStringLiteral("Segoe UI"), 9);
    font.setPixelSize(18);
    font.setWeight(QFont::DemiBold);
    painter.setFont(font);

    const QString title = QStringLiteral("Hawkeye Community");
    const QRect titleLocal(mapFromGlobal(m_titleRect.topLeft()), m_titleRect.size());
    const QRect textBounds = QFontMetrics(font).boundingRect(title);
    const QRect localRect(
        titleLocal.left(),
        titleLocal.center().y() - textBounds.height() / 2,
        textBounds.width() + 8,
        textBounds.height());

    if (m_glow > 0.02f) {
        const int glowAlpha = int(70.0f * m_glow * m_textOpacity);
        painter.setPen(QColor(186, 104, 255, glowAlpha));
        const int radii[] = { 5, 3, 2, 1 };
        for (int radius : radii) {
            for (int dx = -radius; dx <= radius; ++dx) {
                for (int dy = -radius; dy <= radius; ++dy) {
                    if (dx == 0 && dy == 0) {
                        continue;
                    }
                    painter.drawText(localRect.translated(dx, dy), Qt::AlignLeft | Qt::AlignVCenter, title);
                }
            }
        }
    }

    const int textAlpha = int(245.0f * m_textOpacity);
    painter.setPen(QColor(236, 224, 255, textAlpha));
    painter.drawText(localRect, Qt::AlignLeft | Qt::AlignVCenter, title);
}

void IntroSplash::mousePressEvent(QMouseEvent* event)
{
    Q_UNUSED(event);
    complete();
}

void IntroSplash::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Escape || event->key() == Qt::Key_Return || event->key() == Qt::Key_Space) {
        complete();
        return;
    }
    QWidget::keyPressEvent(event);
}
