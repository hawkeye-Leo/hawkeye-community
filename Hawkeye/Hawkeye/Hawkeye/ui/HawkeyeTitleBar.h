#pragma once

#include <QRect>
#include <QWidget>

class QLabel;
class QPushButton;

class HawkeyeTitleBar : public QWidget
{
    Q_OBJECT

public:
    enum Mode
    {
        CloseOnly,
        MinMaxClose
    };

    static void attach(QWidget* host, Mode mode);

    explicit HawkeyeTitleBar(QWidget* host, Mode mode, QWidget* parent = nullptr);

    void setTitle(const QString& title);
    QRect titleTextScreenRect() const;

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void onPinClicked();
    void onMinClicked();
    void onMaxClicked();
    void onCloseClicked();
    void refreshMaxButton();
    void refreshPinButton();

private:
    void applyStyle();

    QWidget* m_host = nullptr;
    Mode m_mode = CloseOnly;
    QLabel* m_icon = nullptr;
    QLabel* m_title = nullptr;
    QPushButton* m_pin = nullptr;
    QPushButton* m_min = nullptr;
    QPushButton* m_max = nullptr;
    QPushButton* m_close = nullptr;
    QPoint m_dragOffset;
    bool m_dragging = false;
    bool m_overlay = false;
};
