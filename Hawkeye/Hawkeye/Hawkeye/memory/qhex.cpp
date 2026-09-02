#include "qhex.h"
#include "HawkeyeStyle.h"
#include <QDebug>
#include <QClipboard>
#include <QKeyEvent>
#include <QPainter>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QInputDialog>
#include <QFontDialog>
#include <QMouseEvent>

QHexMonitor::QHexMonitor(QWidget *parent) : QAbstractScrollArea(parent)
{
    setFont(QFont("Consolas", 10));
    setAcceptDrops(true);
    setFocusPolicy(Qt::StrongFocus);
    setLightStyle();
    createActions();
}

void QHexMonitor::setColumn(int count)
{
    if(count<MIN_COL_COUNT)_colCount=MIN_COL_COUNT;
    else if(count>MAX_COL_COUNT)_colCount=MAX_COL_COUNT;
    else _colCount=count;
    adjustColumn();
    viewport()->update();
}

void QHexMonitor::createActions()
{
    pop_menu = new QMenu(this);

    actionCopyAddr = pop_menu->addAction("Copy Value (Little-Endian)");
    actionCopyHex  = pop_menu->addAction("Copy Hex");
    actionCopyStr  = pop_menu->addAction("Copy ASCII");
    pop_menu->addSeparator();
    actionSelectAll= pop_menu->addAction("Select All");

    connect(actionCopyAddr, SIGNAL(triggered(bool)), this, SLOT(copyAddr()));
    connect(actionCopyHex,  SIGNAL(triggered(bool)), this, SLOT(copyHex()));
    connect(actionCopyStr,  SIGNAL(triggered(bool)), this, SLOT(copyStr()));
    connect(actionSelectAll,SIGNAL(triggered(bool)), this, SLOT(selectAll()));
}

void QHexMonitor::append(QByteArray ba)
{
    _data.append(ba);
    viewport()->update();
}

void QHexMonitor::setData(const QByteArray &ba)
{
    _data = ba;
    _baseCursor = -1;
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

void QHexMonitor::setFont(const QFont &font)
{
    QFont theFont(font);
    theFont.setStyleHint(QFont::Monospace);
    QWidget::setFont(theFont);
    QFontMetrics metrics = fontMetrics();
#if QT_VERSION >= QT_VERSION_CHECK(5, 11, 0)
    _pxCharWidth = metrics.horizontalAdvance(QLatin1Char('2'));
#else
    _pxCharWidth = metrics.width(QLatin1Char('2'));
#endif
    _pxCharHeight = metrics.height();
    _markTopLeft.setX(_pxCharWidth*10);
    _markTopLeft.setY(_pxCharHeight);
    _topLeft=_markTopLeft-QPoint(0,4);
    viewport()->update();
    _currentFont=theFont;
}

void QHexMonitor::setLightStyle()
{
    setTextColor(HawkeyeStyle::kHexText);
    setBgColor(HawkeyeStyle::kHexBg);
    setHeaderColor(HawkeyeStyle::kHexHeader);
    setSelectColor(HawkeyeStyle::kHexSelect);
    setHeaderBgColor(HawkeyeStyle::kHexHeaderBg);
    _addrColor = HawkeyeStyle::kAddr;
}

void QHexMonitor::setDarkStyle()
{
    setTextColor(QColor(212,212,212));
    setBgColor(QColor(30,30,30));
    setHeaderColor(QColor(86,156,214));
    setSelectColor(QColor(14,99,156));
    setHeaderBgColor(QColor(45,45,45));
    _addrColor = QColor(86,156,214);
}

QString QHexMonitor::formatAddrValue(const QByteArray &dat)
{
    if (dat.isEmpty()) return QString();

    int byteCount = dat.size();
    if (byteCount > 8) byteCount = 8;

    quint64 value = 0;
    for (int i = 0; i < byteCount; ++i) {
        value |= static_cast<quint64>(static_cast<uchar>(dat.at(i))) << (i * 8);
    }

    if (byteCount <= 1) {
        return QString("0x%1").arg(QString("%1").arg(static_cast<quint8>(value), 2, 16, QChar('0')).toUpper());
    } else if (byteCount <= 2) {
        return QString("0x%1").arg(QString("%1").arg(static_cast<quint16>(value), 4, 16, QChar('0')).toUpper());
    } else if (byteCount <= 4) {
        return QString("0x%1").arg(QString("%1").arg(static_cast<quint32>(value), 8, 16, QChar('0')).toUpper());
    } else {
        return QString("0x%1").arg(QString("%1").arg(value, byteCount * 2, 16, QChar('0')).toUpper());
    }
}

void QHexMonitor::copyAddr()
{
    QByteArray sel = getSelectData();
    if (sel.isEmpty()) return;
    QString valueStr = formatAddrValue(sel);
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(valueStr);
}

void QHexMonitor::copyHex()
{
    QString str=getHexStr(getSelectData());
    str = str.trimmed();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(str);
}

void QHexMonitor::copyStr()
{
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(getAsciiStr(getSelectData()));
}

void QHexMonitor::setColumn()
{
    bool ok;
    int newCol=QInputDialog::getInt(this,"Input width","width",_colCount,2,64,1,&ok);
    if(ok)setColumn(newCol);
}

void QHexMonitor::setFont()
{
   bool ok;
   QFont font= QFontDialog::getFont(&ok,_currentFont,this,"Get Font");
   if(ok)setFont(font);
}

void QHexMonitor::adjustColumn()
{
   int width=viewport()->width();
   int textWidth=_pxCharWidth*(4*(_colCount+1)+10);
   if(width>=textWidth)horizontalScrollBar()->setMaximum(0);
   else
   {
       int less=(textWidth-width)/_pxCharWidth;
       horizontalScrollBar()->setMaximum(less);
   }
}

QByteArray QHexMonitor::getSelectData()
{
    int start=0;
    int size=0;
    if(_baseCursor>=0)
    {
        if(_baseCursor!=_endCursor)
        {
            int bia=_endCursor-_baseCursor;
            if(bia>0)
            {
                start=_baseCursor;
                size=bia+1;
            }
            else
            {
                start=_endCursor;
                size=-bia+1;
            }
        }
        else
        {
            start=_baseCursor;
            size=1;
        }
        if(start>=_data.size())
        {
            start=0;
            size=0;
        }
    }
    return _data.mid(start,size);
}

QString QHexMonitor::getHexStr(QByteArray dat, char c)
{
    int size=dat.size();
    QByteArray hex(size * 3,c);
    char *hexData = hex.data();
    char *data = dat.data();
    for (int i = 0; i <size; ++i) {
        hexData[i*3] = "0123456789ABCDEF"[(data[i] >> 4) & 0xF];
        hexData[i*3+1] = "0123456789ABCDEF"[data[i]  & 0xF];
    }
    return hex;
}

QString QHexMonitor::getAsciiStr(QByteArray dat, char c)
{
    int size=dat.size();
    QByteArray str(size,c);

    uchar ch;
    for (int i = 0; i <size; ++i)
    {
        ch=(uchar)dat.at(i);
        if ( ch >= ' ' && ch <= '~' )
        {
            str[i]=ch;
        }

    }
    return str;
}

int QHexMonitor::getCursorIndex(QPointF pos)
{
    int res=-1;
    int base=verticalScrollBar()->value();
    int showBegin=base*_colCount;
    QPointF temp=pos-_topLeft;
    int width3=_pxCharWidth*3;

    int basey=horizontalScrollBar()->value();
    int leftSize=basey*_pxCharWidth;
    temp.rx()+=leftSize;


    int x=temp.x();
    int y=temp.y()/_pxCharHeight;
    int right=(_colCount*4+3)*_pxCharWidth;
    if(x<0 || x>right)x=0;
    else
    {
        if(x<_colCount*width3)x=x/width3;
        else x=(x-(_colCount+1)*width3)/_pxCharWidth;
        if(x<0)x=0;
    }
    res=showBegin + y*_colCount + x;
    if(res>_data.size())res=_data.size();
    return res;
}

void QHexMonitor::paintSelectMark(QPainter *painter)
{
    if(_baseCursor>=0)
    {
        int base=verticalScrollBar()->value();
        int showBegin=base*_colCount;
        int showSize=_data.size()-showBegin-1;
        int start,stop;
        if(_baseCursor<_endCursor)
        {
            start=_baseCursor-showBegin;
            stop=_endCursor-showBegin;
        }
        else
        {
            start=_endCursor-showBegin;
            stop=_baseCursor-showBegin;
        }

        if(stop<0 || start>showSize)return;
        if(start<0)start=0;
        if(stop>showSize)stop=showSize;

       uint16_t startRow=start/_colCount;
       uint16_t stopRow=stop/_colCount;
       uint16_t rowCnt=stopRow-startRow;
       uint16_t strWidth3=3*_pxCharWidth;
       uint16_t hexStrWidth=strWidth3*(_colCount+1);
        int basey=horizontalScrollBar()->value();
        int leftSize=basey*_pxCharWidth;
        QPoint realStartPoint=_markTopLeft-QPoint(leftSize,0);
       QPointF startPoint=realStartPoint+QPointF((start%_colCount)*strWidth3,startRow*_pxCharHeight);
       QPointF stoptPoint=realStartPoint+QPointF(0,stopRow*_pxCharHeight);
       QPointF strStartPoint=realStartPoint+QPointF(hexStrWidth+(start%_colCount)*_pxCharWidth,startRow*_pxCharHeight);
       QPointF strStopPoint=realStartPoint+QPointF(hexStrWidth,stopRow*_pxCharHeight);

       if(rowCnt==0)
       {
           painter->fillRect(QRectF(startPoint,QSize((stop-start+1)*strWidth3,_pxCharHeight)),_selectColor);
           painter->fillRect(QRectF(strStartPoint,QSize((stop-start+1)*_pxCharWidth,_pxCharHeight)),_selectColor);
       }
       else if(rowCnt==1)
       {
            painter->fillRect(QRectF(startPoint,QSize((_colCount-(start%_colCount))*strWidth3,_pxCharHeight)),_selectColor);
            painter->fillRect(QRectF(stoptPoint,QSize((stop%_colCount+1)*strWidth3,_pxCharHeight)),_selectColor);

            painter->fillRect(QRectF(strStartPoint,QSize((_colCount-(start%_colCount))*_pxCharWidth,_pxCharHeight)),_selectColor);
            painter->fillRect(QRectF(strStopPoint,QSize((stop%_colCount+1)*_pxCharWidth,_pxCharHeight)),_selectColor);
       }
       else
       {
           QPointF firstPoint=realStartPoint+QPointF(0,(startRow+1)*_pxCharHeight);
           QPointF firstStrPoint=firstPoint+QPointF(hexStrWidth,0);
           painter->fillRect(QRectF(startPoint,QSize((_colCount-(start%_colCount))*strWidth3,_pxCharHeight)),_selectColor);
           painter->fillRect(QRectF(firstPoint,QSize(_colCount*strWidth3,_pxCharHeight*(rowCnt-1))),_selectColor);
           painter->fillRect(QRectF(stoptPoint,QSize((stop%_colCount+1)*strWidth3,_pxCharHeight)),_selectColor);

           painter->fillRect(QRectF(strStartPoint,QSize((_colCount-(start%_colCount))*_pxCharWidth,_pxCharHeight)),_selectColor);
           painter->fillRect(QRectF(firstStrPoint,QSize(_colCount*_pxCharWidth,_pxCharHeight*(rowCnt-1))),_selectColor);
           painter->fillRect(QRectF(strStopPoint,QSize((stop%_colCount+1)*_pxCharWidth,_pxCharHeight)),_selectColor);
       }
    }
}


void QHexMonitor::paintEvent(QPaintEvent *event)
{
     int basey=horizontalScrollBar()->value();
     int leftSize=basey*_pxCharWidth;
     int base=verticalScrollBar()->value();
     int showBegin=base*_colCount;
     int showSize=_showCount*_colCount;
     QByteArray showDate=_data.mid(showBegin,showSize);
     QPainter painter(viewport());
     int w=viewport()->width();
     int h=viewport()->height();

     int rowCount=_data.size()/_colCount;
     int maxSize=rowCount-_showCount+5;
     if(maxSize>0)verticalScrollBar()->setMaximum(maxSize);
     else verticalScrollBar()->setMaximum(0);

     if(_autoScroll)
     {
         int maxRow=verticalScrollBar()->maximum();
         verticalScrollBar()->setValue(maxRow);
     }

     painter.fillRect(event->rect(),_bgColor);
     if(leftSize<_markTopLeft.x())
     {
         painter.fillRect(QRect(0,0,_markTopLeft.x()-leftSize,viewport()->height()),_headerBgColor);
     }
     painter.fillRect(QRect(0,0,viewport()->width(),_pxCharHeight),_headerBgColor);
     QString header,offsetText;
     painter.setPen(QPen(_headerColor));
     paintSelectMark(&painter);

     QPoint leftConer=_markTopLeft;
     leftConer.rx()-=leftSize;
     painter.setPen(QPen(QColor(_headerColor.red(), _headerColor.green(), _headerColor.blue(), 80)));
     painter.drawRect(QRect(leftConer,QSize(w+leftSize,h)));
     painter.setPen(QPen(_headerColor));

     for(int i=0;i<_showCount;i++)
     {
         int offset = (base+i)*_colCount;
         offsetText = QString("%1").arg(offset, 8, 16, QChar('0')).toUpper();
         painter.setPen(QPen(_addrColor));
         painter.drawText(QPoint(_pxCharWidth-leftSize,(i+2)*_pxCharHeight),offsetText);
     }
     QPoint startPoint=_topLeft-QPoint(leftSize,0);

     painter.setPen(QPen(_headerColor));
     for(int i=0;i<_colCount;i++)
     {
         header.append(QString(" %1").arg(i, 2,16, QChar('0')));
     }
     painter.drawText(startPoint,header.toUpper());

     painter.setPen(QPen(_textColor));
     for(int i=0;i<_showCount;i++)
     {
         painter.drawText(QPoint(startPoint.x()+_pxCharWidth,(i+2)*_pxCharHeight),getHexStr(showDate.mid(i*_colCount,_colCount)));
         painter.drawText(QPoint(startPoint.x()+_pxCharWidth*3*(_colCount+1),(i+2)*_pxCharHeight),getAsciiStr(showDate.mid(i*_colCount,_colCount)));
     }
}

void QHexMonitor::resizeEvent(QResizeEvent *e)
{
    Q_UNUSED(e);
    _showCount=viewport()->height()/_pxCharHeight;
    adjustColumn();
    viewport()->update();

}

void QHexMonitor::mouseMoveEvent(QMouseEvent *e)
{
    _endCursor=getCursorIndex(e->localPos());

    if(e->localPos().y()>viewport()->height())
    {
        verticalScrollBar()->setValue(verticalScrollBar()->value()+1);
    }
    else if(e->localPos().y()<0)
    {
        verticalScrollBar()->setValue(verticalScrollBar()->value()-1);
    }
    if(e->localPos().x()>viewport()->width())
    {
        horizontalScrollBar()->setValue(horizontalScrollBar()->value()+1);
    }
    else if(e->localPos().x()<0)
    {
        horizontalScrollBar()->setValue(horizontalScrollBar()->value()-1);
    }
    viewport()->update();
}

void QHexMonitor::mousePressEvent(QMouseEvent *e)
{
    if(e->button()==Qt::LeftButton)
    {
        _baseCursor=getCursorIndex(e->localPos());
        _endCursor=_baseCursor;
        viewport()->update();
    }
}

void QHexMonitor::mouseDoubleClickEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton)
    {
        _baseCursor = getCursorIndex(e->localPos());
        _endCursor = _baseCursor;
        viewport()->update();
    }
}

void QHexMonitor::keyPressEvent(QKeyEvent *e)
{
    QAbstractScrollArea::keyPressEvent(e);
}

void QHexMonitor::contextMenuEvent(QContextMenuEvent *event)
{
    pop_menu->exec(QCursor::pos());
    event->accept();
}
