/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "provider.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

IVirtualBox *provider;
IVirtualBoxClient *client;
const char *jstr(const cJSON *value) { return cJSON_IsString(value) ? value->valuestring : ""; }
int hex(const char *value, size_t size) {
    if (strlen(value) != size) return 0;
    return strspn(value, "0123456789abcdef") == size;
}
int sha(const cJSON *value, char result[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char *encoded = cJSON_PrintUnformatted(value);
    if (!encoded) return 0;
    SHA256((unsigned char *)encoded, strlen(encoded), digest); free(encoded);
    for (size_t i = 0; i < sizeof(digest); i++) snprintf(result + i * 2, 3, "%02x", digest[i]);
    return 1;
}
PRUnichar *utf16(const char *value) {
    PRUnichar *result = NULL;
    if (FAILED(g_pVBoxFuncs->pfnUtf8ToUtf16(value, &result))) return NULL;
    return result;
}
char *utf8(PRUnichar *value) {
    char *converted = NULL, *result = NULL;
    if (value && SUCCEEDED(g_pVBoxFuncs->pfnUtf16ToUtf8(value, &converted)) && converted) {
        result = strdup(converted); g_pVBoxFuncs->pfnUtf8Free(converted);
    }
    if (value) g_pVBoxFuncs->pfnComUnallocString(value);
    return result;
}
char *extra(IMachine *machine, const char *key) {
    PRUnichar *name = utf16(key), *value = NULL;
    HRESULT rc = name ? IMachine_GetExtraData(machine, name, &value) : E_FAIL;
    if (name) g_pVBoxFuncs->pfnUtf16Free(name);
    return SUCCEEDED(rc) ? utf8(value) : NULL;
}
char *vrde_property(IVRDEServer *server, const char *key) {
    PRUnichar *name = utf16(key), *value = NULL;
    HRESULT rc = name ? IVRDEServer_GetVRDEProperty(server, name, &value) : E_FAIL;
    if (name) g_pVBoxFuncs->pfnUtf16Free(name);
    return SUCCEEDED(rc) ? utf8(value) : NULL;
}
int connect_provider(void) {
    if (mkdir("/tmp/.vbox-ficc-ipc", 0700) || mkdir("/tmp/vbox-home", 0700) ||
        symlink("/provider/socket", "/tmp/.vbox-ficc-ipc/ipcd") ||
        setenv("VBOX_IPC_SOCKETID", "ficc", 1) || setenv("VBOX_USER_HOME", "/tmp/vbox-home", 1)) return 0;
    return connect_account();
}
int connect_account(void) {
    if (VBoxCGlueInit() || g_pVBoxFuncs->pfnGetAPIVersion() != 7002) return 0;
    if (FAILED(g_pVBoxFuncs->pfnClientInitialize(NULL, &client)) || !client ||
        FAILED(IVirtualBoxClient_get_VirtualBox(client, &provider)) || !provider) return 0;
    PRUnichar *wide = NULL; PRUint32 revision = 0;
    if (FAILED(IVirtualBox_get_Version(provider, &wide))) return 0;
    char *version = utf8(wide);
    int supported = version && SAME(version, "7.2.20") &&
        SUCCEEDED(IVirtualBox_get_Revision(provider, &revision)) && revision == 175154;
    free(version); return supported;
}
void close_provider(void) {
    if (provider) IVirtualBox_Release(provider);
    if (client) IVirtualBoxClient_Release(client);
    if (g_pVBoxFuncs) { g_pVBoxFuncs->pfnClientUninitialize(); VBoxCGlueTerm(); }
}
static const char *state(PRUint32 value) {
    switch (value) {
        case MachineState_PoweredOff: return "off";
        case MachineState_Saved: return "suspended";
        case MachineState_Aborted: return "crashed";
        case MachineState_Running: return "running";
        case MachineState_Paused: return "paused";
        case MachineState_Stuck: return "blocked";
        case MachineState_Stopping: return "shutting-down";
        default: return "unknown";
    }
}
cJSON *machine_row(IMachine *machine) {
    PRUnichar *raw = NULL;
    char *key = NULL, *name = NULL, *birth = NULL, *pack = NULL, *address = NULL, *port = NULL;
    PRUint32 memory = 0, cpus = 0, status = 0, session_state = 0, pid = 0;
    PRInt64 changed = 0;
    PRBool enabled = 0, accessible = 0;
    IVRDEServer *server = NULL;
    cJSON *row = NULL, *resource = NULL, *revision = NULL;
    char id[65], hash[65];
    if (FAILED(IMachine_get_Accessible(machine, &accessible)) || !accessible ||
        FAILED(IMachine_get_Id(machine, &raw)) || !(key = utf8(raw))) goto done;
    raw = NULL;
    if (strlen(key) != 36 || FAILED(IMachine_get_Name(machine, &raw)) || !(name = utf8(raw))) goto done;
    raw = NULL;
    if (!*name || strlen(name) > 1024) goto done;
    for (const unsigned char *p = (unsigned char *)name; *p; p++) if (*p < 32) goto done;
    if (FAILED(IMachine_get_MemorySize(machine, &memory)) || FAILED(IMachine_get_CPUCount(machine, &cpus)) ||
        FAILED(IMachine_get_State(machine, &status)) || FAILED(IMachine_get_LastStateChange(machine, &changed)) ||
        FAILED(IMachine_get_SessionState(machine, &session_state)) || FAILED(IMachine_get_SessionPID(machine, &pid))) goto done;
    birth = extra(machine, "FICC/Birth");
    if (!birth || !hex(birth, 64)) { free(birth); birth = strdup("0000000000000000000000000000000000000000000000000000000000000000"); }
    if (!birth) goto done;
    if (SUCCEEDED(IMachine_get_VRDEServer(machine, &server)) && server) {
        IVRDEServer_get_Enabled(server, &enabled);
        if (SUCCEEDED(IVRDEServer_get_VRDEExtPack(server, &raw))) pack = utf8(raw);
        raw = NULL; address = vrde_property(server, "VNCUnixSocket"); port = vrde_property(server, "TCP/Ports");
    }
    /* The operation revision names the lifecycle and display fields used here. */
    revision = cJSON_CreateArray();
    cJSON_AddItemToArray(revision, cJSON_CreateString(key));
    cJSON_AddItemToArray(revision, cJSON_CreateString(birth));
    cJSON_AddItemToArray(revision, cJSON_CreateString(name));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber(memory));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber(cpus));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber(status));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber((double)changed));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber(session_state));
    cJSON_AddItemToArray(revision, cJSON_CreateNumber(pid));
    cJSON_AddItemToArray(revision, cJSON_CreateBool(enabled));
    cJSON_AddItemToArray(revision, cJSON_CreateString(pack ? pack : ""));
    cJSON_AddItemToArray(revision, cJSON_CreateString(address ? address : ""));
    cJSON_AddItemToArray(revision, cJSON_CreateString(port ? port : ""));
    if (!sha(revision, hash)) goto done;
    resource = cJSON_CreateObject();
    /* Stable identity uses the host's canonical birth,key field order. */
    cJSON_AddStringToObject(resource, "birth", birth); cJSON_AddStringToObject(resource, "key", key);
    if (!sha(resource, id)) goto done;
    id[32] = 0; cJSON_AddStringToObject(resource, "id", id);
    cJSON_AddStringToObject(resource, "revision", hash); cJSON_AddStringToObject(resource, "state", state(status));
    row = cJSON_CreateObject(); cJSON_AddItemToObject(row, "resource", resource); resource = NULL;
    cJSON_AddStringToObject(row, "name", name); cJSON_AddNumberToObject(row, "memory_kib", (double)memory * 1024);
    cJSON_AddNumberToObject(row, "vcpus", cpus);
    cJSON_AddBoolToObject(row, "console", enabled && pack && SAME(pack, "FICC VNC") && address && address[0] == '/' && status == MachineState_Running);
done:
    if (server) IVRDEServer_Release(server);
    free(key); free(name); free(birth); free(pack); free(address); free(port);
    cJSON_Delete(resource); cJSON_Delete(revision);
    return row;
}
IMachine *find_machine(const char *key) {
    IMachine *machine = NULL; PRUnichar *wide = utf16(key);
    HRESULT rc = wide ? IVirtualBox_FindMachine(provider, wide, &machine) : E_FAIL;
    if (wide) g_pVBoxFuncs->pfnUtf16Free(wide);
    return SUCCEEDED(rc) ? machine : NULL;
}
int matches(const cJSON *row, const cJSON *resource, int revision) {
    const cJSON *now = JGET(row, "resource");
    return now && SAME(JSTR(now, "id"), JSTR(resource, "id")) && SAME(JSTR(now, "key"), JSTR(resource, "key")) &&
        SAME(JSTR(now, "birth"), JSTR(resource, "birth")) && (!revision ||
        (SAME(JSTR(now, "revision"), JSTR(resource, "revision")) && SAME(JSTR(now, "state"), JSTR(resource, "state"))));
}
static int compare(const void *a, const void *b) {
    return strcmp(JSTR(JGET(*(cJSON *const *)a, "resource"), "key"), JSTR(JGET(*(cJSON *const *)b, "resource"), "key"));
}
cJSON *inventory(const cJSON *binding) {
    SAFEARRAY *array = g_pVBoxFuncs->pfnSafeArrayOutParamAlloc();
    IMachine **machines = NULL; ULONG count = 0;
    cJSON *rows[4096] = {0}, *result = NULL, *list = NULL;
    if (!array) return NULL;
    HRESULT rc = IVirtualBox_get_Machines(provider, ComSafeArrayAsOutIfaceParam(array, IMachine *));
    if (SUCCEEDED(rc)) rc = g_pVBoxFuncs->pfnSafeArrayCopyOutIfaceParamHelper((IUnknown ***)&machines, &count, array);
    g_pVBoxFuncs->pfnSafeArrayDestroy(array);
    if (FAILED(rc) || count > 4096) goto done;
    for (ULONG i = 0; i < count; i++) if (!(rows[i] = machine_row(machines[i]))) goto done;
    qsort(rows, count, sizeof(*rows), compare);
    const cJSON *params = JGET(binding, "parameters"), *offset = JGET(params, "offset"), *limit = JGET(params, "limit");
    int start = offset ? offset->valueint : 0, maximum = limit ? limit->valueint : 64;
    if (start < 0 || start > 4096 || maximum < 1 || maximum > 256) goto done;
    result = cJSON_CreateObject(); list = cJSON_CreateArray(); cJSON_AddItemToObject(result, "resources", list);
    ULONG end = (ULONG)start;
    for (; end < count && end < (ULONG)(start + maximum); end++) { cJSON_AddItemToArray(list, rows[end]); rows[end] = NULL; }
    if (end < count) cJSON_AddNumberToObject(result, "next_offset", end); else cJSON_AddNullToObject(result, "next_offset");
    cJSON_AddBoolToObject(result, "truncated", end < count);
done:
    for (ULONG i = 0; i < count; i++) { if (i < 4096) cJSON_Delete(rows[i]); if (machines && machines[i]) IMachine_Release(machines[i]); }
    if (machines) g_pVBoxFuncs->pfnArrayOutFree(machines);
    return result;
}
cJSON *refusal(const char *code, const char *message) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "code", code); cJSON_AddStringToObject(value, "message", message); return value;
}
