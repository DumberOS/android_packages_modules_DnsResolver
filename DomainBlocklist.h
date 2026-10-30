#pragma once

#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/stat.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dumberos {

constexpr const char* kDomainBlocklist = "/data/misc/dumberos/blocked_domains";

// File replacement is atomic. Read only when its inode, size, or timestamp changes.
class DomainBlocklist {
  public:
    explicit DomainBlocklist(std::string path = kDomainBlocklist) : mPath(std::move(path)) {}

    bool blocks(std::string name) {
        std::lock_guard guard(mMutex);
        reload();
        if (mInvalid) return true;  // An unreadable/corrupt installed list must not fail open.
        for (char& c : name) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (!name.empty() && name.back() == '.') name.pop_back();
        for (const auto& domain : mDomains) {
            if (name == domain || (name.size() > domain.size() &&
                name.ends_with(domain) &&
                name[name.size() - domain.size() - 1] == '.')) return true;
        }
        return false;
    }

  private:
    void reload() {
        struct stat current {};
        if (stat(mPath.c_str(), &current) != 0) {
            mInvalid = errno != ENOENT;
            mLoaded = false;
            mDomains.clear();
            return;
        }
        if (mLoaded && current.st_ino == mStat.st_ino && current.st_size == mStat.st_size &&
            current.st_mtim.tv_sec == mStat.st_mtim.tv_sec &&
            current.st_mtim.tv_nsec == mStat.st_mtim.tv_nsec) return;
        mStat = current;
        mLoaded = true;
        mInvalid = true;
        mDomains.clear();
        if (!S_ISREG(current.st_mode) || current.st_size > 65536) return;
        std::ifstream input(mPath);
        if (!input.is_open()) return;
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty()) continue;
            if (!validDomain(line) || mDomains.size() == 256) return;
            mDomains.push_back(line);
        }
        if (input.bad()) return;
        mInvalid = false;
    }

    static bool validDomain(std::string_view value) {
        if (value.size() < 3 || value.size() > 253 || value.find('.') == value.npos ||
            value.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-") != value.npos)
            return false;
        for (;;) {
            const size_t dot = value.find('.');
            const auto label = value.substr(0, dot);
            if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
                return false;
            if (dot == value.npos) return true;
            value.remove_prefix(dot + 1);
        }
    }

    std::string mPath;
    std::mutex mMutex;
    struct stat mStat {};
    bool mLoaded = false;
    bool mInvalid = false;
    std::vector<std::string> mDomains;
};

// Return zero for allowed queries, a local NXDOMAIN response length, or a negative error.
// Run before the resolver cache so adding a rule also covers previously cached answers.
inline int blockedDomainResponse(DomainBlocklist& list, const uint8_t* query, size_t querySize,
                                 uint8_t* answer, size_t answerSize) {
    ns_msg parsed;
    if (querySize > 65535 || ns_initparse(query, querySize, &parsed) < 0 ||
        ns_msg_getflag(parsed, ns_f_qr) || ns_msg_getflag(parsed, ns_f_opcode) != ns_o_query)
        return 0;
    const int count = ns_msg_count(parsed, ns_s_qd);
    for (int i = 0; i < count; ++i) {
        ns_rr question;
        if (ns_parserr(&parsed, ns_s_qd, i, &question) < 0) return -EINVAL;
        if (!list.blocks(ns_rr_name(question))) continue;
        // The resolver's normal API emits one question. Never forward a multi-question bypass.
        if (count != 1) return -EACCES;
        if (answerSize < NS_HFIXEDSZ + NS_QFIXEDSZ + 1) return -EMSGSIZE;
        std::memset(answer, 0, NS_HFIXEDSZ);
        answer[0] = query[0];
        answer[1] = query[1];
        answer[2] = 0x80 | (query[2] & 0x01);  // QR, preserve RD; clear AD/TC/AA.
        answer[3] = 0x80 | ns_r_nxdomain;      // RA, NXDOMAIN; no DNSSEC claim.
        answer[5] = 1;
        const int encoded = dn_comp(ns_rr_name(question), answer + NS_HFIXEDSZ,
                                    answerSize - NS_HFIXEDSZ - NS_QFIXEDSZ, nullptr, nullptr);
        if (encoded < 0) return -EMSGSIZE;
        uint8_t* fields = answer + NS_HFIXEDSZ + encoded;
        ns_put16(ns_rr_type(question), fields);
        ns_put16(ns_rr_class(question), fields + NS_INT16SZ);
        return NS_HFIXEDSZ + encoded + NS_QFIXEDSZ;
    }
    return 0;
}

}  // namespace dumberos
