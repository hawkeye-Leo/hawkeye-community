#pragma once

#include "HawkeyeStyle.h"

#include <QDialog>

class QEvent;
class QLabel;
class QPushButton;

class DriverSetupDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DriverSetupDialog(QWidget* parent = nullptr);
    ~DriverSetupDialog() override;

    void refresh();
    void setTestSigningBusy(bool busy);

signals:
    void enableTestSigningRequested();

protected:
    void showEvent(QShowEvent* event) override;
    void changeEvent(QEvent* event) override;

private slots:
    void onActionLink(const QString& href);
    void onRestartWindows();

private:
    void setChip(QLabel* status, HawkeyeStyle::StatusChipKind kind, const QString& text);
    void setActionLink(QLabel* action, const QString& href, const QString& text, bool visible);
    void setHint(QLabel* action, const QString& text);

    QLabel* m_intro = nullptr;
    QLabel* m_adminStatus = nullptr;
    QLabel* m_secureBootStatus = nullptr;
    QLabel* m_testSigningStatus = nullptr;
    QLabel* m_memoryIntegrityStatus = nullptr;
    QLabel* m_driverStatus = nullptr;
    QLabel* m_adminAction = nullptr;
    QLabel* m_secureBootAction = nullptr;
    QLabel* m_testSigningAction = nullptr;
    QLabel* m_memoryIntegrityAction = nullptr;
    QLabel* m_driverAction = nullptr;
    QLabel* m_note = nullptr;
    QPushButton* m_restartWindows = nullptr;
    bool m_testSigningBusy = false;
};
