/* SPDX-License-Identifier: Apache-2.0 */
#ifndef FICC_VBOX_PROVIDER_H
#define FICC_VBOX_PROVIDER_H
#include "VBoxCAPIGlue.h"
#include "ficc_module.h"
#include <stdlib.h>
#include <string.h>
#define JGET(o,k) cJSON_GetObjectItemCaseSensitive((o),(k))
#define JSTR(o,k) jstr(JGET((o),(k)))
#define SAME(a,b) (!strcmp((a),(b)))
extern IVirtualBox *provider;
extern IVirtualBoxClient *client;
const char *jstr(const cJSON *value);
int hex(const char *value, size_t size);
int sha(const cJSON *value, char result[65]);
char *utf8(PRUnichar *value);
PRUnichar *utf16(const char *value);
char *extra(IMachine *machine, const char *key);
char *vrde_property(IVRDEServer *server, const char *key);
cJSON *machine_row(IMachine *machine);
IMachine *find_machine(const char *key);
cJSON *inventory(const cJSON *binding);
cJSON *refusal(const char *code, const char *message);
cJSON *power(const cJSON *request, const cJSON *binding);
cJSON *observe(const cJSON *request, const cJSON *binding);
cJSON *display(const cJSON *binding);
int matches(const cJSON *row, const cJSON *resource, int revision);
int shutdown_ready(IMachine *machine);
int connect_provider(void);
int connect_account(void);
int prepare_account(const char *identifier, const char *socket_path);
void close_provider(void);
#endif
