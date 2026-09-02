#pragma once

#include <QElapsedTimer>
#include <QRect>
#include <QTimer>
#include <QWidget>

class IntroSplash : public QWidget
{
    Q_OBJECT

public:
    explicit IntroSplash(QWidget* parent = nullptr);
    void start(QWidget* host, const QRect& titleScreenRect);

signals:
    void finished();

protected:
    void paintEvent(QPaintEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;

private slots:
    void onTick();

private:
    enum class Phase
    {
        Flash,
        Hold,
        Fade,
        Done
    };

    void beginPhase(Phase phase);
    void advanceAnimation();
    void complete();

    QWidget* m_host = nullptr;
    QRect m_titleRect;
    QTimer m_timer;
    QElapsedTimer m_phaseClock;
    Phase m_phase = Phase::Flash;
    float m_textOpacity = 0.0f;
    float m_glow = 0.0f;
    bool m_finished = false;

    static const int kFlashMs = 110;
    static const int kHoldMs = 380;
    static const int kFadeMs = 420;
    static const int kTickMs = 16;
};
