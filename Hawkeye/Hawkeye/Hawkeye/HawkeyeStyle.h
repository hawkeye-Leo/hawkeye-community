#pragma once

#include <QColor>
#include <QIcon>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QString>
#include <QtGlobal>
#include <QWidget>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

namespace HawkeyeStyle
{

const QColor kAddr("#1B5E20");
const QColor kBytes("#5A5A5A");
const QColor kMnemonic("#8E2452");
const QColor kComment("#2E7D32");
const QColor kCallTarget("#1B5E20");
const QColor kHexBg("#FFFFFF");
const QColor kHexText("#222222");
const QColor kHexHeader("#1B5E20");
const QColor kHexHeaderBg("#E4EEE4");
const QColor kHexSelect("#C8E6C9");

inline QColor mixRgb(const QColor& a, const QColor& b, qreal t)
{
    return QColor(
        qRound(a.red() + (b.red() - a.red()) * t),
        qRound(a.green() + (b.green() - a.green()) * t),
        qRound(a.blue() + (b.blue() - a.blue()) * t));
}

inline QColor contrastingFg(const QColor& bg)
{
    const int y = (bg.red() * 299 + bg.green() * 587 + bg.blue() * 114) / 1000;
    return y > 160 ? QColor(QStringLiteral("#202020")) : QColor(QStringLiteral("#ffffff"));
}

inline QColor systemAccentColor()
{
    DWORD accent = 0;
    DWORD size = sizeof(accent);
    if (RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\DWM",
            L"AccentColor",
            RRF_RT_REG_DWORD,
            nullptr,
            &accent,
            &size) == ERROR_SUCCESS) {
        const QColor color(int(accent & 0xFF), int((accent >> 8) & 0xFF), int((accent >> 16) & 0xFF));
        if (color.isValid() && color.rgb() != 0) {
            return color;
        }
    }

    DWORD colorization = 0;
    BOOL opaque = FALSE;
    if (SUCCEEDED(DwmGetColorizationColor(&colorization, &opaque))) {
        return QColor(
            int((colorization >> 16) & 0xFF),
            int((colorization >> 8) & 0xFF),
            int(colorization & 0xFF));
    }
    return QColor(QStringLiteral("#323232"));
}

inline QString chrome()
{
    const QColor bg = systemAccentColor();
    const QColor fg = contrastingFg(bg);
    const QColor hover = mixRgb(bg, fg, 0.14);
    const QColor pressed = mixRgb(bg, QColor(QStringLiteral("#000000")), 0.22);
    const QColor border = mixRgb(bg, fg, 0.20);
    return QStringLiteral(
        "QMainWindow, QDialog, QWidget#centralWidget { background-color: #f3f3f3; }"
        "QMainWindow, QDialog { border: 1px solid #6a6a6a; }"
        "QLabel { color: #222; font-size: 12px; }"
        "QCheckBox {"
        "  color: #222;"
        "  font-family: 'Segoe UI', sans-serif;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "  spacing: 6px;"
        "}"
        "QLineEdit {"
        "  font-family: Consolas, 'Courier New', monospace;"
        "  font-size: 13px;"
        "  padding: 5px 8px;"
        "  border: 1px solid #b0b0b0;"
        "  border-radius: 3px;"
        "  background: #ffffff;"
        "  selection-background-color: #003300;"
        "  selection-color: #00FF00;"
        "}"
        "QLineEdit:focus { border: 1px solid #008800; }"
        "QLineEdit:disabled { background: #ececec; color: #777; }"
        "QLineEdit#lineEditCMD {"
        "  color: #1B5E20;"
        "  font-size: 12pt;"
        "  font-weight: bold;"
        "  padding-right: 28px;"
        "}"
        "QLineEdit#lineEditCMD QToolButton {"
        "  background-color: %1;"
        "  border: none;"
        "  border-radius: 11px;"
        "  padding: 0;"
        "  margin: 0;"
        "  min-width: 22px;"
        "  max-width: 22px;"
        "  min-height: 22px;"
        "  max-height: 22px;"
        "}"
        "QLineEdit#lineEditCMD QToolButton:hover { background-color: %3; }"
        "QLineEdit#lineEditCMD QToolButton:pressed { background-color: %4; }"
        "QComboBox {"
        "  font-family: Consolas, 'Courier New', monospace;"
        "  font-size: 12px;"
        "  padding: 4px 8px;"
        "  min-height: 26px;"
        "  border: 1px solid #b0b0b0;"
        "  border-radius: 3px;"
        "  background: #ffffff;"
        "}"
        "QComboBox:hover { border: 1px solid #888; }"
        "QComboBox:focus { border: 1px solid #008800; }"
        "QComboBox::drop-down {"
        "  subcontrol-origin: padding;"
        "  subcontrol-position: top right;"
        "  width: 18px;"
        "  border: none;"
        "}"
        "QComboBox QAbstractItemView {"
        "  background: #ffffff;"
        "  selection-background-color: #003300;"
        "  selection-color: #00FF00;"
        "  border: 1px solid #b0b0b0;"
        "}"
        "QPushButton {"
        "  font-family: 'Segoe UI', sans-serif;"
        "  font-size: 12px;"
        "  font-weight: 600;"
        "  min-width: 88px;"
        "  min-height: 30px;"
        "  padding: 5px 14px;"
        "  border-radius: 3px;"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %5;"
        "}"
        "QPushButton:hover { background-color: %3; border: 1px solid %5; }"
        "QPushButton:pressed { background-color: %4; }"
        "QPushButton:disabled {"
        "  background-color: #d8d8d8;"
        "  color: #8a8a8a;"
        "  border: 1px solid #c0c0c0;"
        "}"
        "QTextBrowser#textEditConsole, QTextEdit#textEditDisasm {"
        "  background: #fafcfa;"
        "  border: none;"
        "  padding: 6px 8px;"
        "  selection-background-color: #c8e6c9;"
        "  selection-color: #1b5e20;"
        "}"
        "QTextEdit#textEditDisasm {"
        "  border-right: 1px solid #d4dcd4;"
        "}"
        "QWidget#hawkeyeTitleBar {"
        "  min-height: 36px;"
        "  max-height: 36px;"
        "}"
        "QWidget#hawkeyeTitleBar QPushButton {"
        "  min-width: 46px;"
        "  max-width: 46px;"
        "  min-height: 36px;"
        "  max-height: 36px;"
        "  padding: 0;"
        "  margin: 0;"
        "  border: none;"
        "  border-radius: 0;"
        "  font-family: 'Segoe UI', sans-serif;"
        "  font-size: 14px;"
        "  font-weight: 400;"
        "}"
    ).arg(bg.name(QColor::HexRgb),
          fg.name(QColor::HexRgb),
          hover.name(QColor::HexRgb),
          pressed.name(QColor::HexRgb),
          border.name(QColor::HexRgb));
}

inline QString coloredChipStyle(const QColor& fill, const QColor& ink, bool compact, const QColor& edge = QColor())
{
    const QColor border = edge.isValid() ? edge : ink;
    QString style =
        "border-radius: 2px;"
        "font-family: \"Courier New\", monospace;"
        "font-weight: bold;";
    style += compact ? "padding: 2px;" : "padding: 2px 8px;";
    style += QStringLiteral("background-color: %1; color: %2; border: 1px solid %3;")
        .arg(fill.name(QColor::HexRgb), ink.name(QColor::HexRgb), border.name(QColor::HexRgb));
    return style;
}

inline QString accentChipStyle(bool compact)
{
    const QColor accent = systemAccentColor();
    const QColor fill = mixRgb(accent, QColor(QStringLiteral("#ffffff")), 0.86);
    const QColor ink = mixRgb(accent, QColor(QStringLiteral("#1a1a1a")), 0.42);
    const QColor text = contrastingFg(fill);
    const int inkY = (ink.red() * 299 + ink.green() * 587 + ink.blue() * 114) / 1000;
    const int fillY = (fill.red() * 299 + fill.green() * 587 + fill.blue() * 114) / 1000;
    const QColor fg = qAbs(inkY - fillY) >= 90 ? ink : text;
    return coloredChipStyle(fill, fg, compact, accent);
}

inline QString communityChipStyle(bool compact = false)
{
    return accentChipStyle(compact);
}

inline QString resultChipStyle(bool ok)
{
    if (ok) {
        return accentChipStyle(false);
    }
    return coloredChipStyle(QColor(QStringLiteral("#330000")), QColor(QStringLiteral("#FF0000")), false);
}

enum class StatusChipKind { Ok, Fail, Warn, Pending };

inline QString statusChipStyle(StatusChipKind kind, bool compact = true)
{
    if (kind == StatusChipKind::Ok) {
        return accentChipStyle(compact);
    }
    if (kind == StatusChipKind::Warn) {
        return coloredChipStyle(QColor(QStringLiteral("#332600")), QColor(QStringLiteral("#FFB000")), compact);
    }
    if (kind == StatusChipKind::Pending) {
        return coloredChipStyle(QColor(QStringLiteral("#2b2b2b")), QColor(QStringLiteral("#c0c0c0")), compact);
    }
    return coloredChipStyle(QColor(QStringLiteral("#330000")), QColor(QStringLiteral("#FF0000")), compact);
}

inline QPixmap titleBarAppMark(const QColor& fg)
{
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(fg);

    QPainterPath mark;
    mark.moveTo(5.5, 16.0);
    mark.lineTo(13.0, 7.0);
    mark.lineTo(27.0, 16.0);
    mark.lineTo(13.0, 25.0);
    mark.closeSubpath();
    painter.drawPath(mark);

    painter.setCompositionMode(QPainter::CompositionMode_DestinationOut);
    QPainterPath slit;
    slit.moveTo(11.5, 16.0);
    slit.lineTo(14.8, 12.8);
    slit.lineTo(20.0, 16.0);
    slit.lineTo(14.8, 19.2);
    slit.closeSubpath();
    painter.drawPath(slit);
    painter.end();
    return pixmap;
}

inline QIcon titleBarPinIcon(bool pinned, const QColor& fg = QColor("#e8e8e8"))
{
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QColor stroke = fg;
    const QColor fill = pinned ? fg : QColor(Qt::transparent);

    QPen pen(stroke, 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    painter.setPen(pen);
    painter.setBrush(fill);
    painter.drawEllipse(QPointF(16.0, 9.5), 5.0, 5.0);

    painter.setBrush(Qt::NoBrush);
    painter.drawLine(QPointF(16.0, 14.5), QPointF(16.0, 22.0));

    QPainterPath legs;
    legs.moveTo(16.0, 22.0);
    legs.lineTo(11.5, 26.5);
    legs.moveTo(16.0, 22.0);
    legs.lineTo(20.5, 26.5);
    painter.drawPath(legs);
    painter.end();

    QIcon icon;
    icon.addPixmap(pixmap);
    return icon;
}

inline QIcon titleBarWindowIcon(bool maximized, const QColor& fg = QColor("#e8e8e8"))
{
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);

    QPen pen(fg, 2.0, Qt::SolidLine, Qt::SquareCap, Qt::MiterJoin);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);

    if (!maximized) {
        painter.drawRect(QRectF(9.0, 9.0, 14.0, 14.0));
    } else {
        painter.drawRect(QRectF(12.0, 7.0, 13.0, 13.0));
        painter.drawRect(QRectF(7.0, 12.0, 13.0, 13.0));
    }

    painter.end();

    QIcon icon;
    icon.addPixmap(pixmap);
    return icon;
}

inline QIcon runCommandIcon()
{
    QPixmap pixmap(32, 32);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);

    QPen pen(contrastingFg(systemAccentColor()), 2.6, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    painter.setPen(pen);
    painter.setBrush(Qt::NoBrush);

    // Up arrow — larger, centered in icon canvas
    painter.drawLine(QPointF(16.0, 23.0), QPointF(16.0, 9.0));

    QPainterPath head;
    head.moveTo(9.5, 14.0);
    head.lineTo(16.0, 7.0);
    head.lineTo(22.5, 14.0);
    painter.drawPath(head);
    painter.end();

    QIcon icon;
    icon.addPixmap(pixmap);
    return icon;
}

inline void applyChrome(QWidget* widget)
{
    if (widget) {
        widget->setStyleSheet(chrome());
    }
}

inline void applyResultChip(QLabel* label, bool ok)
{
    if (label) {
        label->setStyleSheet(resultChipStyle(ok));
    }
}

} // namespace HawkeyeStyle
