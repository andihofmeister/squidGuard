#ifndef SG_SETTING_H
#define SG_SETTING_H 1

typedef void (*SettingCB)(const char *value);

void registerSetting(const char *name, const char *defaultValue, SettingCB cb);

void setSetting(const char *key, const char *value);
const char *getSetting(const char *key);

int booleanSetting(const char *value);

void freeAllSettings(void);

#endif
