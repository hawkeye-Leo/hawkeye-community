#ifndef QHEXMONITOR_H
#define QHEXMONITOR_H

#include <QAbstractScrollArea>
#include <QPen>
#include <QBrush>
#include <qpainter.h>
#include <QPaintEvent>
#include <QStringList>
#include <QMenu>
#include <QAction>
#include <QtGlobal>
#define MIN_COL_COUNT 2
#define MAX_COL_COUNT 64

class QHexMonitor : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit QHexMonitor(QWidget *parent = 0);
    void setColumn(int count);
    QByteArray getData() const { return _data; }
    int getDataSize() const { return _data.size(); }
    void setBaseAddr(quint64 addr) { _baseAddr = addr; viewport()->update(); }
    quint64 getBaseAddr() const { return _baseAddr; }
    int getColumn() const { return _colCount; }

public slots:
    void append(QByteArray ba);
    void setData(const QByteArray &ba);
    void setFont(const QFont &font);
    void setLightStyle();
    void setDarkStyle();

    void setTextColor(QColor color){_textColor=color;}
    void setBgColor(QColor color){_bgColor=color;}
    void setHeaderColor(QColor color){_headerColor=color;}
    void setHeaderBgColor(QColor color){_headerBgColor=color;}
    void setSelectColor(QColor color){_selectColor=color;}

    void copyAddr();
    void copyHex();
    void copyStr();
    void selectAll(){_baseCursor=0;_endCursor=_data.size();viewport()->update();}
    void clearAll(){_data.clear();_baseCursor=-1;viewport()->update();}
    void setAutoScroll(bool ok){_autoScroll=ok;}
    void setColumn();
    void setFont();


private:
    QByteArray _data;
    quint64 _baseAddr = 0;
    uint16_t _pxCharWidth,_pxCharHeight;
    uint16_t _colCount=16;
    uint16_t _showCount;
    QPoint _topLeft;
    QPoint _markTopLeft;
    bool _autoScroll=false;
    int _baseCursor=-1;
    int _endCursor;
    QFont _currentFont;

    QColor _textColor;
    QColor _bgColor;
    QColor _headerColor;
    QColor _headerBgColor;
    QColor _selectColor;
    QColor _addrColor;

    QMenu   *pop_menu;
    QAction *actionCopyHex;
    QAction *actionCopyAddr;
    QAction *actionCopyStr;
    QAction *actionSelectAll;
    QAction *actionClear;
    QAction *actionAutoScroll;
    QAction *actionSetColumn;

    void adjustColumn();

    QString getHexStr(QByteArray dat,char c=' ');
    QString getAsciiStr(QByteArray dat,char c='.');
    int getCursorIndex(QPointF pos);
    void paintSelectMark(QPainter *painter);
    QByteArray getSelectData();
    QString formatAddrValue(const QByteArray &dat);

    void createActions();
protected:
    void paintEvent(QPaintEvent *event);
    void resizeEvent(QResizeEvent *e);
    void mouseMoveEvent(QMouseEvent *e);
    void mousePressEvent(QMouseEvent *e);
    void mouseDoubleClickEvent(QMouseEvent *e);
    void keyPressEvent(QKeyEvent *e);
    void contextMenuEvent(QContextMenuEvent *event);
};

#endif // QHEXMONITOR_H
