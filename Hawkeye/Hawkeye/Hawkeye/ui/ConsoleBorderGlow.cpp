#include "ConsoleBorderGlow.h"

#include "Hawkeye.h"
#include <QPainter>
#include <QPaintEvent>

ConsoleBorderGlow::ConsoleBorderGlow(QWidget* targetWidget)
    : QWidget(targetWidget)
{
    setAttribute(Qt::WA_TransparentForMouseEvents);
    setAttribute(Qt::WA_NoSystemBackground);
    setFocusPolicy(Qt::NoFocus);

    m_resizeTimer.setSingleShot(true);
    m_resizeTimer.setInterval(120);
    connect(&m_resizeTimer, &QTimer::timeout, this, &ConsoleBorderGlow::onResizeSettled);

    if (targetWidget) {
        setGeometry(targetWidget->rect());
        targetWidget->installEventFilter(this);
    }

    raise();
}

bool ConsoleBorderGlow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == parentWidget()
        && (event->type() == QEvent::Resize || event->type() == QEvent::Show)) {
        setGeometry(parentWidget()->rect());
        raise();
        m_resizeTimer.start();
    }

    return QWidget::eventFilter(watched, event);
}

void ConsoleBorderGlow::onResizeSettled()
{
    update();
}

void ConsoleBorderGlow::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

    QPainter painter(this);

    const QRectF border = rect().adjusted(2.0, 2.0, -2.0, -2.0);
    if (border.width() <= 0.0 || border.height() <= 0.0) {
        return;
    }

    const QColor borderColor = DriverStatusError
        ? QColor(183, 28, 28, 180)
        : QColor(27, 94, 32, 180);

    QPen pen(borderColor, 1.0);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);
    painter.drawRect(border);
}
