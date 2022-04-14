LOCAL_PATH := $(call my-dir)/bhook/bytehook/src/main/cpp

# libcxx defines
bhook_export_includes := $(LOCAL_PATH)/include
bhook_includes := $(bhook_export_includes) $(LOCAL_PATH) $(LOCAL_PATH)/third_party/bsd $(LOCAL_PATH)/third_party/lss

bhook_cxxflags := -Oz -flto -faddrsig -ffunction-sections -fdata-sections
bhook_export_cxxflags := $(bhook_cxxflags)
bhook_export_ldflags := -Oz -flto

include $(CLEAR_VARS)

LOCAL_MODULE := libbhook

bhook_c_files  := $(wildcard $(LOCAL_PATH)/*.c)
bhook_c_files  := $(bhook_c_files:$(LOCAL_PATH)/%=%)

LOCAL_SRC_FILES := $(bhook_c_files)
LOCAL_C_INCLUDES := $(bhook_includes)
LOCAL_CPPFLAGS := $(bhook_cxxflags)
LOCAL_EXPORT_C_INCLUDES := $(bhook_export_includes)
LOCAL_EXPORT_CPPFLAGS := $(bhook_export_cxxflags)
LOCAL_EXPORT_LDFLAGS := $(bhook_export_ldflags)
LOCAL_ARM_NEON := false

include $(BUILD_STATIC_LIBRARY)
