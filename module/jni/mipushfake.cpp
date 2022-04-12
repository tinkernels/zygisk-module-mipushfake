#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <sys/inotify.h>
#include <thread>
#include <sys/stat.h>
#include <vector>
#include <sys/un.h>
#include <shared_mutex>
#include <sstream>
#include <fstream>
#include <map>
#include <sys/system_properties.h>

#include "zygisk.hpp"
#include "util.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOG_DEBUG_MPF(...) __android_log_print(ANDROID_LOG_DEBUG, "MiPushFake", __VA_ARGS__)
#define LOG_INFO_MPF(...) __android_log_print(ANDROID_LOG_INFO, "MiPushFake", __VA_ARGS__)
#define LOG_WARN_MPF(...) __android_log_print(ANDROID_LOG_WARN, "MiPushFake", __VA_ARGS__)
#define LOG_ERROR_MPF(...) __android_log_print(ANDROID_LOG_ERROR, "MiPushFake", __VA_ARGS__)
#define INOTIFY_EVENT_BUF_LEN (10 * (sizeof(struct inotify_event) + PATH_MAX + 1))

static std::vector<std::string> packages_2_work;
static std::shared_mutex packages_2_work_rw_mutex;
static bool watcher_initialized = false;
const static std::string conf_file_dir = "/data/adb/mi-push-fake";
const static std::string conf_file_path = "/data/adb/mi-push-fake/packages.txt";
// properties to hack.
const static char *brand_hack = "Xiaomi";
const static char *internal_storage_hack = "/sdcard/";
const static char *fingerprint_hack = "Xiaomi/missi/missi:12/SP1A.210812.016/V12.0.9.0.SLKCNXM:user/release-keys";
const static char *version_name_hack = "V12";
const static char *version_code_hack = "10";
const static char *version_code_time_hack = "1592409600";
const static char *notch_hack = "1";
const static std::map<std::string, std::string> props_4_hack{
        {"ro.product.manufacturer",        brand_hack},
        {"ro.product.system.manufacturer", brand_hack},
        {"ro.product.vendor.manufacturer", brand_hack},
        {"ro.product.brand",               brand_hack},
        {"ro.product.system.brand",        brand_hack},
        {"ro.product.vendor.brand",        brand_hack},
        {"ro.fota.oem",                    brand_hack},
        {"ro.system.build.fingerprint",    fingerprint_hack},
        {"ro.miui.internal.storage",       internal_storage_hack},
        {"ro.miui.ui.version.name",        version_name_hack},
        {"ro.miui.ui.version.code",        version_code_hack},
        {"ro.miui.version.code_time",      version_code_time_hack},
        {"ro.miui.notch",                  notch_hack}
};

// callback func for __system_property_read_callback
using sys_prop_read_callback_param_callback_func =
void(void *cookie,
     const char *name,
     const char *value,
     uint32_t serial);
// __system_property_read_callback
using sys_prop_read_callback_func =
void(const prop_info *pi,
     sys_prop_read_callback_param_callback_func *callback,
     void *cookie);
// __system_property_find
using sys_prop_find_func = prop_info *(const char *name);
// __system_property_get
using sys_prop_get_func = int(const char *key, char *value);

// callback parameter for __system_property_read_callback
thread_local sys_prop_read_callback_param_callback_func *cb_param_4_sys_prop_read_cb_orig = nullptr;

static void cb_param_4_sys_prop_read_cb_new(void *cookie, const char *name, const char *value,
                                            uint32_t serial) {
    if (!cb_param_4_sys_prop_read_cb_orig){
        LOG_WARN_MPF("not found original __system_property_read_callback");
        return;
    }

//    auto search_ = props_4_hack.find(name);
//    if (search_ != props_4_hack.end()) {
//        LOG_INFO_MPF("hack __system_property_read_callback: [%s]=[%s] -> [%s]", name, value,
//                     search_->second.c_str());
//        cb_param_4_sys_prop_read_cb_orig(cookie, name, search_->second.c_str(), serial);
//    } else {
        LOG_INFO_MPF("skip hack __system_property_read_callback: [%s]=[%s]", name, value);
        cb_param_4_sys_prop_read_cb_orig(cookie, name, value, serial);
//        return;
//    }
}

static sys_prop_read_callback_func *f_sys_prop_read_callback_orig = nullptr;

static void f_sys_prop_read_callback_new(const prop_info *pi,
                                         sys_prop_read_callback_param_callback_func *callback,
                                         void *cookie) {
    cb_param_4_sys_prop_read_cb_orig = callback;
    if (f_sys_prop_read_callback_orig) {
        f_sys_prop_read_callback_orig(pi, cb_param_4_sys_prop_read_cb_new, cookie);
    }
}

static sys_prop_find_func *f_sys_prop_find_orig = nullptr;

static prop_info *f_sys_prop_find_new(const char *name) {
//    auto search_ = props_4_hack.find(name);
//    if (search_ != props_4_hack.end()) {
//        LOG_INFO_MPF("hack __system_property_find");
//        return reinterpret_cast<prop_info *>((void *) name);
//    } else if (f_sys_prop_find_orig) {
    LOG_INFO_MPF("skip hack __system_property_find");
    return f_sys_prop_find_orig(name);
//    } else {
//        LOG_INFO_MPF("skip hack __system_property_find and orig func because of nullptr");
//        return nullptr;
//    }
}

static sys_prop_get_func *f_sys_prop_get_orig = nullptr;

static int f_sys_prop_get_new(const char *name, char *value) {
    if (f_sys_prop_get_orig == nullptr) {
        LOG_WARN_MPF("not found original __system_property_get");
        return 0;
    }
//    auto search_ = props_4_hack.find(name);
//    if (search_ != props_4_hack.end()) {
//        memset(value, 0, strlen(value));
//        strcpy(value, search_->second.c_str());
//        LOG_INFO_MPF("hack __system_property_get: [%s] -> [%s]", name, search_->second.c_str());
//        return (int) strlen(value);
//    } else {
    int ret_ = f_sys_prop_get_orig(name, value);
    LOG_INFO_MPF("skip hack __system_property_get: [%s] -> [%s]", name, value);
    return ret_;
//    }
}

static void display_inotify_event(struct inotify_event *event) {
    char buf_[4096] = {};

    sprintf(buf_, "wd=%d;", event->wd);

    if (event->cookie > 0) {
        sprintf(buf_, "%s cookie=%d; mask=", std::string(buf_).c_str(), event->cookie);
    }

    auto event_mask_text_ = "";
    if (event->mask & IN_ACCESS) {
        event_mask_text_ = "IN_ACCESS";
    } else if (event->mask & IN_ATTRIB) {
        event_mask_text_ = "IN_ATTRIB";
    } else if (event->mask & IN_CLOSE_NOWRITE) {
        event_mask_text_ = "IN_CLOSE_NOWRITE";
    } else if (event->mask & IN_CLOSE_WRITE) {
        event_mask_text_ = "IN_CLOSE_WRITE ";
    } else if (event->mask & IN_CREATE) {
        event_mask_text_ = "IN_CREATE";
    } else if (event->mask & IN_DELETE) {
        event_mask_text_ = "IN_DELETE";
    } else if (event->mask & IN_DELETE_SELF) {
        event_mask_text_ = "IN_DELETE_SELF";
    } else if (event->mask & IN_IGNORED) {
        event_mask_text_ = "IN_IGNORED";
    } else if (event->mask & IN_ISDIR) {
        event_mask_text_ = "IN_ISDIR";
    } else if (event->mask & IN_MODIFY) {
        event_mask_text_ = "IN_MODIFY";
    } else if (event->mask & IN_MOVE_SELF) {
        event_mask_text_ = "IN_MOVE_SELF";
    } else if (event->mask & IN_MOVED_FROM) {
        event_mask_text_ = "IN_MOVED_FROM";
    } else if (event->mask & IN_MOVED_TO) {
        event_mask_text_ = "IN_MOVED_TO";
    } else if (event->mask & IN_OPEN) {
        event_mask_text_ = "IN_OPEN";
    } else if (event->mask & IN_Q_OVERFLOW) {
        event_mask_text_ = "IN_Q_OVERFLOW";
    } else if (event->mask & IN_UNMOUNT) {
        event_mask_text_ = "IN_UNMOUNT";
    }
    LOG_INFO_MPF("file notify event %s%s\n", std::string(buf_).c_str(), event_mask_text_);
}

static void read_packages_2_work(const std::string &file) {
    packages_2_work_rw_mutex.lock();
    packages_2_work.clear();
    std::ifstream i_file_(file);
    std::string line_;
    while (std::getline(i_file_, line_)) {
        trim(line_);
        if (line_.empty()) {
            continue;
        }
        packages_2_work.push_back(line_);
    }
    for (const auto &p: packages_2_work) {
        LOG_INFO_MPF("mi push work package: [%s]\n", p.c_str());
    }
    packages_2_work_rw_mutex.unlock();
}

static void watch_conf_file(const std::string &file) {
    auto ntf_fd_ = inotify_init();
    if (ntf_fd_ < 0) {
        LOG_ERROR_MPF("file watcher init error\n");
        goto end;
    } else {
        char buf_[INOTIFY_EVENT_BUF_LEN];
        ssize_t num_read_;
        struct inotify_event *event_;
        auto watcher_fd_ = inotify_add_watch(ntf_fd_, file.c_str(), IN_ALL_EVENTS);
        if (watcher_fd_ < 0) {
            LOG_ERROR_MPF("file watcher add error\n");
            goto end;
        }
#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
        for (;;) {
            num_read_ = read(ntf_fd_, buf_, INOTIFY_EVENT_BUF_LEN);
            if (num_read_ == 0) {
                LOG_ERROR_MPF("read() from inotify fd returned 0!\n");
                continue;
            }

            if (num_read_ == -1) {
                continue;
            }
            for (char *p = buf_; p < buf_ + num_read_;) {
                event_ = (struct inotify_event *) p;
                display_inotify_event(event_);
                if (event_->mask & IN_MODIFY) {
                    // Reread packages config.
                    read_packages_2_work(file);
                }
                p += sizeof(struct inotify_event) + event_->len;
            }
        }
#pragma clang diagnostic pop
    }
    end:
    LOG_ERROR_MPF("file watcher end\n");
}

class MiPushFakeModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *pApi, JNIEnv *pEnv) override {
        this->api = pApi;
        this->env = pEnv;
//        // Ensure conf file exists.
//        std::filesystem::create_directory(conf_file_dir);
//        // Create file if not exist.
//        if (access(conf_file_path.c_str(), F_OK) == 0) {
//            LOG_INFO_MPF("%s file exist\n", conf_file_path.c_str());
//        } else {
//            LOG_WARN_MPF("%s no such file, will create\n", conf_file_path.c_str());
//            std::ofstream{conf_file_path};
//            chmod(conf_file_path.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
//        }
//        if (access(conf_file_path.c_str(), F_OK) != 0) {
//            return;
//        }
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (access(conf_file_path.c_str(), F_OK) != 0) {
            return;
        }
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        preSpecialize(process);
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        if (access(conf_file_path.c_str(), F_OK) != 0) {
            return;
        }
        preSpecialize("system_server");
    }

    void postAppSpecialize([[maybe_unused]] const AppSpecializeArgs *args) override {
//        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
//        LOG_INFO_MPF("inject android.os.Build for %s ", process);
//
//        jclass build_class = this->env->FindClass("android/os/Build");
//        if (build_class == nullptr) {
//            LOG_WARN_MPF("failed to inject android.os.Build for %s due to build is null", process);
//            this->env->ReleaseStringUTFChars(args->nice_name, process);
//            return;
//        }
//
//        jstring new_str = this->env->NewStringUTF(brand_hack);
//
//        jfieldID brand_id = this->env->GetStaticFieldID(build_class,
//                                                        "BRAND",
//                                                        "Ljava/lang/String;");
//        if (brand_id != nullptr) {
//            this->env->SetStaticObjectField(build_class, brand_id, new_str);
//        }
//
//        jfieldID manufacturer_id = this->env->GetStaticFieldID(build_class,
//                                                               "MANUFACTURER",
//                                                               "Ljava/lang/String;");
//        if (manufacturer_id != nullptr) {
//            this->env->SetStaticObjectField(build_class, manufacturer_id, new_str);
//        }
//
//        jfieldID product_id = this->env->GetStaticFieldID(build_class,
//                                                          "PRODUCT",
//                                                          "Ljava/lang/String;");
//        if (product_id != nullptr) {
//            this->env->SetStaticObjectField(build_class, product_id, new_str);
//        }
//
//        if (this->env->ExceptionCheck()) {
//            this->env->ExceptionClear();
//        }
//        this->env->DeleteLocalRef(new_str);
//        this->env->ReleaseStringUTFChars(args->nice_name, process);
    }

private:
    Api *api{};
    JNIEnv *env{};

    void preSpecialize(const char *process) {
//        int match_ = 0;
//        LOG_DEBUG_MPF("process=[%s]\n", process);
//        int fd = api->connectCompanion();
//        if (write(fd, process, strlen(process) + 1) <= 0) {
//            LOG_WARN_MPF("write socket failed\n");
//        }
//        if (read(fd, &match_, sizeof(match_)) <= 0) {
//            LOG_WARN_MPF("read socket failed\n");
//        }
//        close(fd);
//        if (match_ < 0) {
//            LOG_DEBUG_MPF("skip hook for [%s]\n", process);
//            return;
//        }
        LOG_INFO_MPF("Zygisk preSpecialize within [%s]", process);
        api->pltHookRegister(".*", "__system_property_get",
                             (void *) f_sys_prop_get_new,
                             (void **) &f_sys_prop_get_orig);
        api->pltHookRegister(".*", "__system_property_read_callback",
                             (void *) f_sys_prop_read_callback_new,
                             (void **) &f_sys_prop_read_callback_orig);
        api->pltHookRegister(".*", "__system_property_find",
                             (void *) f_sys_prop_find_new,
                             (void **) &f_sys_prop_find_orig);
        api->pltHookCommit();
    }
};


static void companion_handler(int fd) {
    // Run file watcher at last.
    packages_2_work_rw_mutex.lock();
    if (!watcher_initialized) {
        LOG_DEBUG_MPF("read packages_2_work");
        read_packages_2_work(conf_file_path);
        watcher_initialized = true;
        packages_2_work_rw_mutex.unlock();
        std::thread conf_watch_th_(watch_conf_file, conf_file_path);
    } else {
        packages_2_work_rw_mutex.unlock();
    }
    char buff_[BUFSIZ];
    memset(buff_, 0, BUFSIZ);
    if (read(fd, buff_, BUFSIZ) <= 0) {
        return;
    }
    auto package_ = std::string(buff_);
    int match_ = 0;
    packages_2_work_rw_mutex.lock_shared();
    for (const auto &p: packages_2_work) {
        if (strncmp(p.c_str(), package_.c_str(), strlen(p.c_str())) == 0) {
            match_ = 1;
        }
    }
    packages_2_work_rw_mutex.unlock_shared();
    LOG_DEBUG_MPF("package [%s] matching: %d", package_.c_str(), match_);
    if (write(fd, &match_, sizeof(match_)) < sizeof(match_)) {
        LOG_ERROR_MPF("partial/failed write");
    }
}

REGISTER_ZYGISK_MODULE(MiPushFakeModule)
//REGISTER_ZYGISK_COMPANION(companion_handler)
