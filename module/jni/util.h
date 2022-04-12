//
// Created by Don Johnny on 2022/4/11.
//

#ifndef ZYGISK_MODULE_MIPUSHFAKE_UTIL_H
#define ZYGISK_MODULE_MIPUSHFAKE_UTIL_H

// trim from start (in place)
static inline void l_trim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void r_trim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(),
            s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    l_trim(s);
    r_trim(s);
}

#endif //ZYGISK_MODULE_MIPUSHFAKE_UTIL_H
