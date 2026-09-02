#pragma once

#include <QColor>
#include <QString>

#include <vector>

#include <cstdint>
#include <functional>

struct ListPtOutput
{
    std::function<void(const QString&)> line;
    std::function<void(const QString&, const QColor&)> coloredLine;
};

struct ListPtThreadFinding
{
    std::uint32_t tid = 0;
    std::uint64_t oep = 0;
    std::uint32_t kernelRegion = 0;
    QString regionLabel;
    QString protectLabel;
    bool isRwx = false;
};

struct ListPtTriageResult
{
    bool ok = false;
    QString error;
    std::uint32_t pid = 0;
    int threadCount = 0;
    int highRiskCount = 0;
    std::vector<ListPtThreadFinding> findings;
};

bool runListPt(std::uint32_t pid, const ListPtOutput& output, QString* outError = nullptr);
bool runListPtTriage(std::uint32_t pid, ListPtTriageResult* out);
