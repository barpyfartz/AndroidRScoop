#include "extract.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <zlib.h>

#define GRY "\033[90m"
#define RST "\033[0m"

static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    size_t sz = f.tellg();
    f.seekg(0);
    out.resize(sz);
    f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good();
}

static bool extract_file_from_apk(const std::vector<uint8_t>& apk,
                                  const std::string& target_name,
                                  std::vector<uint8_t>& out) {
    if (apk.size() < 22) return false;

    size_t eocd = 0;
    for (size_t i = apk.size() - 22; i > 0; --i) {
        if (apk[i] == 0x50 && apk[i+1] == 0x4B && apk[i+2] == 0x05 && apk[i+3] == 0x06) {
            eocd = i;
            break;
        }
    }
    if (!eocd) return false;

    uint32_t cd_offset = *(uint32_t*)&apk[eocd + 16];
    uint16_t cd_entries = *(uint16_t*)&apk[eocd + 8];

    size_t pos = cd_offset;
    for (size_t i = 0; i < cd_entries; ++i) {
        if (pos + 46 > apk.size()) break;
        if (apk[pos] != 0x50 || apk[pos+1] != 0x4B || apk[pos+2] != 0x01 || apk[pos+3] != 0x02)
            break;

        uint16_t fn_len    = *(uint16_t*)&apk[pos + 28];
        uint16_t extra_len = *(uint16_t*)&apk[pos + 30];
        uint16_t cmnt_len  = *(uint16_t*)&apk[pos + 32];
        uint32_t l_offset  = *(uint32_t*)&apk[pos + 42];
        uint32_t comp_size = *(uint32_t*)&apk[pos + 20];
        uint32_t uncomp    = *(uint32_t*)&apk[pos + 24];
        uint16_t method    = *(uint16_t*)&apk[pos + 10];

        std::string name((char*)&apk[pos + 46], fn_len);

        if (name == target_name) {
            uint16_t lfn = *(uint16_t*)&apk[l_offset + 26];
            uint16_t lex = *(uint16_t*)&apk[l_offset + 28];
            size_t dp = l_offset + 30 + lfn + lex;

            if (method == 0) {
                out.assign(apk.begin() + dp, apk.begin() + dp + comp_size);
                return true;
            }
            if (method == 8) {
                out.resize(uncomp);
                z_stream zs = {};
                zs.next_in  = const_cast<uint8_t*>(&apk[dp]);
                zs.avail_in = comp_size;
                zs.next_out = out.data();
                zs.avail_out = uncomp;
                inflateInit2(&zs, -15);
                int r = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);
                if (r == Z_STREAM_END || r == Z_OK) {
                    out.resize(zs.total_out);
                    return true;
                }
            }
        }

        pos += 46 + fn_len + extra_len + cmnt_len;
    }
    return false;
}

std::string extract_so_from_apk(const std::string& apk_path, const std::string& arch) {
    std::vector<uint8_t> apk, so_data;
    if (!read_file(apk_path, apk)) {
        std::cerr << GRY "failed to read APK: " << apk_path << RST "\n";
        return "";
    }

    std::string lib_path = "lib/" + arch + "/libroblox.so";
    
    if (!extract_file_from_apk(apk, lib_path, so_data)) {
        std::cerr << GRY "libroblox.so not found in APK for " << arch << RST "\n";
        return "";
    }

    std::string out_path = "libroblox_" + arch + ".so";
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << GRY "failed to write " << out_path << RST "\n";
        return "";
    }
    out.write((char*)so_data.data(), so_data.size());
    out.close();

    std::cout << GRY "extracted: " << out_path << " (" << so_data.size() << " bytes)" << RST "\n";
    return out_path;
}
