#pragma once

#include <QWidget>
#include <QTimer>

class ConsoleBorderGlow : public QWidget
{
    Q_OBJECT

public:
    explicit ConsoleBorderGlow(QWidget* targetWidget);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private slots:
    void onResizeSettled();

private:
    QTimer m_resizeTimer;
};
