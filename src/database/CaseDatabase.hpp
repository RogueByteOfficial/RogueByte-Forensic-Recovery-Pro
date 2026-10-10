#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include "rfrp/Types.hpp"

namespace rfrp::database {

class CaseDatabase {
public:
    CaseDatabase();
    ~CaseDatabase();

    bool open(const std::filesystem::path& dbPath);
    void close();
    bool logAudit(const AuditRecord& record);

private:
    void* m_sqliteHandle{nullptr};
    std::filesystem::path m_dbPath;
};

} // namespace rfrp::database
