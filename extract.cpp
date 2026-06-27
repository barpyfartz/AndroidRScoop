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
        std::cerr << "\n" << GRY << "failed to read APK: " << apk_path << RST "\n";
        return "";
    }
    std::string lib_path = "lib/" + arch + "/libroblox.so";

    if (!extract_file_from_apk(apk, lib_path, so_data)) {
        std::cerr << "\n" << GRY << "libroblox.so not found in APK for " << arch << RST "\n";
        return "";
    }
    std::string out_path = "libroblox.so";
    std::ofstream out(out_path, std::ios::binary);
    if (!out) {
        std::cerr << "\n" << GRY << "failed to write " << out_path << RST "\n";
        return "";
    }
    out.write((char*)so_data.data(), so_data.size());
    out.close();
    return out_path;
}

static std::vector<std::string> axml_read_strings(const std::vector<uint8_t>& d, size_t chunk) {
    std::vector<std::string> strings;
    if (chunk + 28 > d.size()) return strings;

    uint32_t string_count = *(uint32_t*)&d[chunk + 8];
    uint32_t flags        = *(uint32_t*)&d[chunk + 16];
    uint32_t strings_start = *(uint32_t*)&d[chunk + 20];
    bool utf8 = (flags & (1u << 8)) != 0;

    size_t offsets_base = chunk + 28;
    size_t strs_base    = chunk + strings_start;

    strings.reserve(string_count);
    for (uint32_t i = 0; i < string_count; i++) {
        if (offsets_base + i * 4 + 4 > d.size()) break;
        uint32_t off = *(uint32_t*)&d[offsets_base + i * 4];
        size_t p = strs_base + off;
        if (p >= d.size()) { strings.emplace_back(); continue; }

        std::string s;
        if (utf8) {

            uint8_t c0 = d[p++];
            if (c0 & 0x80) p++;

            if (p >= d.size()) { strings.emplace_back(); continue; }
            uint8_t b0 = d[p++];
            size_t byte_len = b0;
            if (b0 & 0x80) {
                if (p >= d.size()) { strings.emplace_back(); continue; }
                byte_len = ((b0 & 0x7f) << 8) | d[p++];
            }
            for (size_t j = 0; j < byte_len && p + j < d.size(); j++)
                s += (char)d[p + j];
        } else {
            if (p + 2 > d.size()) { strings.emplace_back(); continue; }
            uint16_t char_len = *(uint16_t*)&d[p]; p += 2;
            for (uint16_t j = 0; j < char_len && p + j * 2 + 1 < d.size(); j++) {
                uint16_t c = *(uint16_t*)&d[p + j * 2];
                s += (c < 128) ? (char)c : '?';
            }
        }
        strings.push_back(std::move(s));
    }
    return strings;
}

static std::string parse_axml_version(const std::vector<uint8_t>& d) {
    if (d.size() < 8) return "";
    if (*(uint32_t*)&d[0] != 0x00080003) return "";

    std::vector<std::string> strings;
    size_t pos = 8;

    while (pos + 8 <= d.size()) {
        uint32_t type = *(uint32_t*)&d[pos];
        uint32_t size = *(uint32_t*)&d[pos + 4];
        if (size < 8 || pos + size > d.size()) break;
        if ((type & 0xFFFF) == 0x0001) {
            strings = axml_read_strings(d, pos);
            break;
        }
        pos += size;
    }
    if (strings.empty()) return "";

    pos = 8;
    while (pos + 8 <= d.size()) {
        uint32_t type = *(uint32_t*)&d[pos];
        uint32_t size = *(uint32_t*)&d[pos + 4];
        if (size < 8 || pos + size > d.size()) break;

        if ((type & 0xFFFF) == 0x0102 && pos + 36 <= d.size()) {
            uint16_t attr_count = *(uint16_t*)&d[pos + 28];
            size_t attr_pos = pos + 36;
            for (uint16_t i = 0; i < attr_count; i++) {
                if (attr_pos + 20 > d.size()) break;
                uint32_t name_idx = *(uint32_t*)&d[attr_pos + 4];
                uint32_t raw_idx  = *(uint32_t*)&d[attr_pos + 8];
                if (name_idx < strings.size() && strings[name_idx] == "versionName") {
                    if (raw_idx != 0xFFFFFFFFu && raw_idx < strings.size())
                        return strings[raw_idx];
                }
                attr_pos += 20;
            }
        }
        pos += size;
    }
    return "";
}

static std::string version_from_apk(const std::string& apk_path) {
    std::vector<uint8_t> apk;
    if (!read_file(apk_path, apk)) return "";
    std::vector<uint8_t> manifest;
    if (!extract_file_from_apk(apk, "AndroidManifest.xml", manifest)) return "";
    return parse_axml_version(manifest);
}

static std::string dir_of(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return (p == std::string::npos) ? "." : path.substr(0, p);
}

std::string get_roblox_version(const std::string& apk_path) {

    std::string ver = version_from_apk(apk_path);
    if (!ver.empty()) return ver;

    std::string base = dir_of(apk_path) + "/base.apk";
    return version_from_apk(base);
}
