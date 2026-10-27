#pragma once

#include <QThread>
#include <QString>

class EtwTiWorker : public QThread
{
	Q_OBJECT

public:
	explicit EtwTiWorker(QObject* parent = nullptr);
	~EtwTiWorker() override;

	void requestStop();

signals:
	void eventLineReady(const QString& line);
	void traceFailed(const QString& message);
	void traceStopped();

protected:
	void run() override;

private:
	volatile long m_stop;
};
