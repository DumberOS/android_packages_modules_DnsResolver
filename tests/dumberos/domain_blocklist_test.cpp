#include "DomainBlocklist.h"
#include <cassert>
#include <filesystem>
#include <iostream>
#include <unistd.h>

int main() {
    const auto path = "/tmp/dumberos-domain-test-" + std::to_string(getpid());
    dumberos::DomainBlocklist list(path);
    auto write = [&](const std::string& text) {
        { std::ofstream file(path + ".new"); file << text; }
        std::filesystem::rename(path + ".new", path);
    };
    assert(!list.blocks("example.com"));
    write("example.com\nexample.org");
    assert(list.blocks("example.com"));
    assert(list.blocks("www.example.com"));
    assert(list.blocks("A.B.EXAMPLE.COM."));
    assert(!list.blocks("badexample.com"));
    assert(!list.blocks("example.com.evil.org"));
    uint8_t query[512] {}, answer[512] {};
    auto send = [&](const char* name, int type) {
        const int length = res_mkquery(ns_o_query, name, ns_c_in, type, nullptr, 0, nullptr,
                                      query, sizeof(query));
        assert(length > 0);
        return dumberos::blockedDomainResponse(list, query, length, answer, sizeof(answer));
    };
    for (int type : {int(ns_t_a), int(ns_t_aaaa), 65, int(ns_t_mx), 0x1234}) {
        const int length = send("www.example.com", type);
        assert(length > NS_HFIXEDSZ);
        ns_msg parsed;
        assert(ns_initparse(answer, length, &parsed) == 0);
        assert(ns_msg_getflag(parsed, ns_f_rcode) == ns_r_nxdomain);
        assert(ns_msg_getflag(parsed, ns_f_qr));
        assert(!ns_msg_getflag(parsed, ns_f_ad));
        assert(answer[0] == query[0] && answer[1] == query[1]);
        ns_rr question;
        assert(ns_parserr(&parsed, ns_s_qd, 0, &question) == 0);
        assert(ns_rr_type(question) == type);
        assert(ns_rr_class(question) == ns_c_in);
    }
    // Refuse to forward a blocked question even if a client combines it with another.
    const int singleLength = res_mkquery(ns_o_query, "example.com", ns_c_in, ns_t_a,
                                         nullptr, 0, nullptr, query, sizeof(query));
    std::memcpy(query + singleLength, query + NS_HFIXEDSZ, singleLength - NS_HFIXEDSZ);
    query[5] = 2;
    assert(dumberos::blockedDomainResponse(list, query, singleLength * 2 - NS_HFIXEDSZ,
                                          answer, sizeof(answer)) == -EACCES);
    const int queryLength = res_mkquery(ns_o_query, "example.com", ns_c_in, ns_t_a,
                                       nullptr, 0, nullptr, query, sizeof(query));
    assert(dumberos::blockedDomainResponse(list, query, queryLength, answer, 12) == -EMSGSIZE);
    assert(send("allowed.example.net", ns_t_a) == 0);
    // Edits replace the inode: newly added and removed rules take effect without restarting.
    write("example.net");
    assert(!list.blocks("example.com"));
    assert(list.blocks("www.example.net"));
    const auto label63 = std::string(63, 'a');
    const auto longest = label63 + "." + label63 + "." + label63 + "." + std::string(61, 'b');
    for (const auto& domain : {std::string("a.b"), std::string("a-b.0c"),
                              std::string("example.xn--p1ai"), label63 + ".example", longest}) {
        write(domain);
        assert(list.blocks(domain));
        assert(!list.blocks("anything.example"));
    }
    for (const std::string domain : {"ab", ".example.com", "example.com.", "a..b", "-a.b",
                                     "a-.b", "a.-b", "a.b-", "EXAMPLE.com", "a_b.example",
                                     "https://invalid.example", "a b.c", "example.com\r"}) {
        write(domain);
        assert(list.blocks("anything.example"));
    }
    for (const auto& domain : {label63 + "a.example", longest + "b", std::string("a\0.b", 4)}) {
        write(domain);
        assert(list.blocks("anything.example"));
    }
    std::string full;
    for (int i = 0; i < 256; ++i) full += std::to_string(i) + ".example\n";
    write(full);
    assert(list.blocks("255.example"));
    assert(!list.blocks("anything.example"));
    write(full + "overflow.example");
    assert(list.blocks("anything.example"));
    write(std::string(65537, 'a'));
    assert(list.blocks("anything.example"));
    write("");
    assert(!list.blocks("anything.example"));
    std::filesystem::remove(path);
    assert(!list.blocks("anything.example"));
    assert(dumberos::blockedDomainResponse(list, query, 3, answer, sizeof(answer)) == 0);
    std::cout << "Domain matching, DNS response, edit/reload and failure tests passed\n";
}
