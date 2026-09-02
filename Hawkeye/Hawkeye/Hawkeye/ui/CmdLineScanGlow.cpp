#include "CmdLineScanGlow.h"

#include <QLineEdit>
#include <QPainter>
#include <QPaintEvent>
#include <QtMath>

CmdLineScanGlow::CmdLineScanGlow(QLineEdit* targetLineEdit)
    : QWidget(targetLineEdit)
    , m_lineEdit(targetLineEdit)
{
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setAttribute(Qt::WA_NoSystemBackground);
    setFocusPolicy(Qt::NoFocus);

    if (m_lineEdit) {
        setGeometry(m_lineEdit->rect());
        m_lineEdit->installEventFilter(this);
        connect(m_lineEdit, &QLineEdit::textChanged, this, &CmdLineScanGlow::onTextChanged);
    }

    connect(&m_timer, &QTimer::timeout, this, &CmdLineScanGlow::onTick);
    raise();
}

bool CmdLineScanGlow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == m_lineEdit
        && (event->type() == QEvent::Resize || event->type() == QEvent::Show)) {
        setGeometry(m_lineEdit->rect());
        raise();
    }

    return QWidget::eventFilter(watched, event);
}

void CmdLineScanGlow::onTextChanged(const QString& text)
{
    if (text.length() > m_lastTextLength) {
        startScan();
    }
    m_lastTextLength = text.length();
}

void CmdLineScanGlow::startScan()
{
    m_scanning = true;
    m_scanClock.restart();
    if (!m_timer.isActive()) {
        m_timer.start(kTickMs);
    }
    update();
}

void CmdLineScanGlow::onTick()
{
    if (!m_scanning) {
        m_timer.stop();
        return;
    }

    if (m_scanClock.elapsed() >= kScanDurationMs) {
        m_scanning = false;
        m_timer.stop();
        update();
        return;
    }

    update();
}

void CmdLineScanGlow::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

    if (!m_scanning) {
        return;
    }

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF area = rect().adjusted(1.0, 1.0, -1.0, -1.0);
    if (area.width() <= 0.0 || area.height() <= 0.0) {
        return;
    }

    const float progress = qBound(
        0.0f,
        float(m_scanClock.elapsed()) / float(kScanDurationMs),
        1.0f);
    const float eased = 1.0f - qPow(1.0f - progress, 3.0f);
    const float beamX = area.left() + eased * area.width();

    const float beamWidth = qMax(28.0f, float(area.height()) * 1.6f);
    QLinearGradient beamGradient(beamX - beamWidth, 0.0, beamX + beamWidth, 0.0);
    beamGradient.setColorAt(0.0, QColor(0, 230, 118, 0));
    beamGradient.setColorAt(0.45, QColor(0, 230, 118, 55));
    beamGradient.setColorAt(0.5, QColor(120, 255, 190, 130));
    beamGradient.setColorAt(0.55, QColor(0, 230, 118, 55));
    beamGradient.setColorAt(1.0, QColor(0, 230, 118, 0));

    painter.fillRect(
        QRectF(beamX - beamWidth, area.top(), beamWidth * 2.0f, area.height()),
        beamGradient);

    QPen corePen(QColor(180, 255, 220, int(160 * (1.0f - progress * 0.35f))), 1.6);
    corePen.setCapStyle(Qt::RoundCap);
    painter.setPen(corePen);
    painter.drawLine(QPointF(beamX, area.top() + 2.0), QPointF(beamX, area.bottom() - 2.0));

    QPen trailPen(QColor(0, 230, 118, 90), 1.0, Qt::SolidLine, Qt::RoundCap);
    painter.setPen(trailPen);
    const float trailLength = qMin(36.0f, float(area.width()) * 0.18f);
    const qreal trailStartX = qMax(area.left(), qreal(beamX - trailLength));
    painter.drawLine(
        QPointF(trailStartX, area.center().y()),
        QPointF(beamX, area.center().y()));
}
