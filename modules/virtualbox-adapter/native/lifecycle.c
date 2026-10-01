/* SPDX-License-Identifier: Apache-2.0 */
#include "provider.h"

int shutdown_ready(IMachine *machine) {
    ISession *session = NULL; IConsole *console = NULL;
    PRBool acpi = 0; int locked = 0;
    if (!machine || FAILED(IVirtualBoxClient_get_Session(client, &session)) || !session ||
        FAILED(IMachine_LockMachine(machine, session, LockType_Shared))) goto done;
    locked = 1;
    if (FAILED(ISession_get_Console(session, &console)) || !console ||
        FAILED(IConsole_GetGuestEnteredACPIMode(console, &acpi))) acpi = 0;
done:
    if (console) IConsole_Release(console);
    if (session) { if (locked) ISession_UnlockMachine(session); ISession_Release(session); }
    return acpi != 0;
}

static cJSON *proof(const char *state, cJSON *token, const char *task, int complete) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "state", state); cJSON_AddItemToObject(value, "token", token ? token : cJSON_CreateObject());
    cJSON_AddBoolToObject(value, "completed", complete);
    cJSON_AddStringToObject(value, "result", SAME(state, "observed") ? "success" :
                           (SAME(state, "failed") || SAME(state, "refused")) ? "failure" : "unknown");
    cJSON_AddStringToObject(value, "task_state", task); return value;
}
static cJSON *token_for(const cJSON *resource, const char *action, HRESULT rc) {
    cJSON *value = cJSON_CreateObject();
    cJSON_AddStringToObject(value, "key", JSTR(resource, "key"));
    cJSON_AddStringToObject(value, "birth", JSTR(resource, "birth"));
    cJSON_AddStringToObject(value, "action", action);
    cJSON_AddNumberToObject(value, "return_code", (double)(PRUint32)rc);
    cJSON_AddNullToObject(value, "progress");
    cJSON_AddBoolToObject(value, "acknowledged", 0); return value;
}
static const cJSON *intent_for(const cJSON *binding, const cJSON *resource, const char *action) {
    const cJSON *targets = JGET(JGET(binding, "intent"), "targets");
    for (const cJSON *target = targets ? targets->child : NULL; target; target = target->next) {
        const cJSON *intent = JGET(target, "intent");
        if (SAME(JSTR(target, "id"), JSTR(resource, "id")) && cJSON_GetArraySize(intent) == 3 &&
            cJSON_Compare(JGET(intent, "resource"), resource, 1) && SAME(JSTR(intent, "action"), action) &&
            SAME(JSTR(intent, "method"), SAME(action, "start") ? "LaunchVMProcess" : "PowerButton")) return intent;
    }
    return NULL;
}
static cJSON *change(const cJSON *resource, const char *action, int wait_ms) {
    IMachine *machine = find_machine(JSTR(resource, "key"));
    ISession *session = NULL; IConsole *console = NULL; IProgress *progress = NULL;
    cJSON *row = machine ? machine_row(machine) : NULL, *result = NULL;
    int locked = 0;
    if (!matches(row, resource, 1) || !strcmp(JSTR(resource, "birth"), "0000000000000000000000000000000000000000000000000000000000000000") ||
        !SAME(JSTR(resource, "state"), SAME(action, "start") ? "off" : "running") ||
        FAILED(IVirtualBoxClient_get_Session(client, &session)) || !session) goto done;
    HRESULT rc;
    if (SAME(action, "start")) {
        PRUnichar *frontend = utf16("headless");
        SAFEARRAY *env = g_pVBoxFuncs->pfnSafeArrayCreateVector(VT_BSTR, 0, 0);
        if (!frontend || !env) { if (frontend) g_pVBoxFuncs->pfnUtf16Free(frontend); if (env) g_pVBoxFuncs->pfnSafeArrayDestroy(env); goto done; }
        /* The provider requires an unlocked session for this operation. */
        rc = IMachine_LaunchVMProcess(machine, session, frontend, ComSafeArrayAsInParam(env), &progress);
        g_pVBoxFuncs->pfnSafeArrayDestroy(env); g_pVBoxFuncs->pfnUtf16Free(frontend);
        cJSON *token = token_for(resource, action, rc);
        if (SUCCEEDED(rc) && progress) {
            locked = 1;
            PRUnichar *wide = NULL; PRBool complete = 0; PRInt32 code = 0;
            if (SUCCEEDED(IProgress_get_Id(progress, &wide))) {
                char *id = utf8(wide);
                if (id) { cJSON_ReplaceItemInObjectCaseSensitive(token, "progress", cJSON_CreateString(id)); free(id); }
            }
            IProgress_WaitForCompletion(progress, wait_ms);
            if (SUCCEEDED(IProgress_get_Completed(progress, &complete)) && complete &&
                SUCCEEDED(IProgress_get_ResultCode(progress, &code))) {
                cJSON_ReplaceItemInObjectCaseSensitive(token, "acknowledged", cJSON_CreateBool(code == 0));
                cJSON_AddNumberToObject(token, "completion_code", (double)(PRUint32)code);
                result = proof(code ? "failed" : "accepted", token, code ? "finished" : "none", code != 0);
            } else result = proof("accepted", token, "active", 0);
        } else {
            /* A failed call does not prove that no external side effect occurred. */
            result = proof("unknown", token, "unknown", 0);
        }
    } else {
        if (FAILED(IMachine_LockMachine(machine, session, LockType_Shared))) goto done;
        locked = 1;
        cJSON_Delete(row); row = machine_row(machine);
        PRBool acpi = 0;
        if (!matches(row, resource, 1) || FAILED(ISession_get_Console(session, &console)) || !console ||
            FAILED(IConsole_GetGuestEnteredACPIMode(console, &acpi)) || !acpi) goto done;
        rc = IConsole_PowerButton(console);
        cJSON *token = token_for(resource, action, rc);
        cJSON_ReplaceItemInObjectCaseSensitive(token, "acknowledged", cJSON_CreateBool(SUCCEEDED(rc)));
        result = proof(SUCCEEDED(rc) ? "accepted" : "unknown", token, "none", 0);
    }
done:
    if (progress) IProgress_Release(progress);
    if (console) IConsole_Release(console);
    if (session) { if (locked) ISession_UnlockMachine(session); ISession_Release(session); }
    if (machine) IMachine_Release(machine);
    cJSON_Delete(row); return result ? result : proof("refused", NULL, "none", 1);
}
cJSON *power(const cJSON *request, const cJSON *binding) {
    const char *action = JSTR(request, "action");
    const cJSON *resources = JGET(binding, "resources");
    /* Validate every frozen intent before the first external dispatch. */
    for (const cJSON *resource = resources->child; resource; resource = resource->next)
        if (!intent_for(binding, resource, action)) return NULL;
    cJSON *output = cJSON_CreateObject(), *rows = cJSON_CreateArray(); cJSON_AddItemToObject(output, "results", rows);
    for (const cJSON *resource = resources->child; resource; resource = resource->next) {
        cJSON *row = cJSON_CreateObject(); cJSON_AddStringToObject(row, "id", JSTR(resource, "id"));
        cJSON_AddItemToObject(row, "receipt", change(resource, action, 5000 / cJSON_GetArraySize(resources)));
        cJSON_AddItemToArray(rows, row);
    }
    return output;
}
static cJSON *observed(const cJSON *resource, const cJSON *previous, const char *action, const cJSON *row) {
    const cJSON *saved = JGET(previous, "receipt"), *token = JGET(saved, "token");
    if (!saved || !cJSON_GetArraySize(token)) return proof("unknown", NULL, "none", 0);
    if (!SAME(JSTR(token, "key"), JSTR(resource, "key")) || !SAME(JSTR(token, "birth"), JSTR(resource, "birth")) ||
        !SAME(JSTR(token, "action"), action)) return NULL;
    if (cJSON_IsTrue(JGET(saved, "completed"))) return cJSON_Duplicate(saved, 1);
    cJSON *copy = cJSON_Duplicate(token, 1);
    int acknowledged = cJSON_IsTrue(JGET(token, "acknowledged"));
    const char *id = JSTR(token, "progress");
    if (!acknowledged && *id) {
        if (strlen(id) != 36) { cJSON_Delete(copy); return NULL; }
        for (size_t i = 0; i < 36; i++) {
            int valid = (i == 8 || i == 13 || i == 18 || i == 23) ? id[i] == '-' : strchr("0123456789abcdef", id[i]) != NULL;
            if (!valid) { cJSON_Delete(copy); return NULL; }
        }
        IProgress *progress = NULL; PRUnichar *wide = utf16(id);
        HRESULT rc = wide ? IVirtualBox_FindProgressById(provider, wide, &progress) : E_FAIL;
        if (wide) g_pVBoxFuncs->pfnUtf16Free(wide);
        if (rc == E_INVALIDARG) {
            /* Completed provider tasks disappear. Absence cannot prove success. */
            return proof("unknown", copy, "finished", 1);
        }
        if (FAILED(rc) || !progress) return proof("unknown", copy, "unknown", 0);
        PRBool complete = 0; PRInt32 code = 0;
        HRESULT completed = IProgress_get_Completed(progress, &complete);
        if (SUCCEEDED(completed) && complete) completed = IProgress_get_ResultCode(progress, &code);
        IProgress_Release(progress);
        if (FAILED(completed)) return proof("unknown", copy, "unknown", 0);
        if (!complete) return proof("accepted", copy, "active", 0);
        if (code) return proof("failed", copy, "finished", 1);
        /* The retained task token is immutable across observations. */
        acknowledged = 1;
    }
    if (acknowledged && matches(row, resource, 0) &&
        SAME(JSTR(JGET(row, "resource"), "state"), SAME(action, "start") ? "running" : "off"))
        return proof("observed", copy, "finished", 1);
    return proof(acknowledged ? "accepted" : "unknown", copy, "none", 0);
}
cJSON *observe(const cJSON *request, const cJSON *binding) {
    const char *action = JSTR(request, "action");
    const cJSON *resources = JGET(binding, "resources"), *previous = JGET(JGET(binding, "receipt"), "targets");
    if (!cJSON_IsArray(previous) || cJSON_GetArraySize(previous) != cJSON_GetArraySize(resources)) return NULL;
    cJSON *output = cJSON_CreateObject(), *items = cJSON_CreateArray(); cJSON_AddItemToObject(output, "results", items);
    const cJSON *prior = previous->child;
    for (const cJSON *resource = resources->child; resource; resource = resource->next, prior = prior->next) {
        if (!intent_for(binding, resource, action) || !SAME(JSTR(resource, "id"), JSTR(prior, "id"))) { cJSON_Delete(output); return NULL; }
        IMachine *machine = find_machine(JSTR(resource, "key")); cJSON *now = machine ? machine_row(machine) : NULL;
        if (machine) IMachine_Release(machine);
        cJSON *receipt = observed(resource, prior, action, now);
        if (!receipt) { cJSON_Delete(now); cJSON_Delete(output); return NULL; }
        cJSON *item = cJSON_CreateObject(); cJSON_AddStringToObject(item, "id", JSTR(resource, "id"));
        cJSON_AddItemToObject(item, "receipt", receipt);
        if (matches(now, resource, 0)) cJSON_AddStringToObject(item, "observed_state", JSTR(JGET(now, "resource"), "state"));
        cJSON_AddItemToArray(items, item); cJSON_Delete(now);
    }
    return output;
}
cJSON *display(const cJSON *binding) {
    const cJSON *resources = JGET(binding, "resources"), *resource = resources->child;
    if (cJSON_GetArraySize(resources) != 1) return NULL;
    IMachine *machine = find_machine(JSTR(resource, "key"));
    ISession *session = NULL; IConsole *console = NULL; IVRDEServer *server = NULL;
    cJSON *row = machine ? machine_row(machine) : NULL, *result = NULL;
    int locked = 0; PRUint32 pid = 0; char *password = NULL, *socket_path = NULL;
    if (!matches(row, resource, 1) || !cJSON_IsTrue(JGET(row, "console")) ||
        FAILED(IMachine_get_SessionPID(machine, &pid)) || !pid ||
        FAILED(IVirtualBoxClient_get_Session(client, &session)) || !session ||
        FAILED(IMachine_LockMachine(machine, session, LockType_Shared))) goto done;
    locked = 1;
    if (FAILED(ISession_get_Console(session, &console)) || !console) goto done;
    if (FAILED(IMachine_get_VRDEServer(machine, &server)) || !server) goto done;
    password = vrde_property(server, "VNCPassword");
    socket_path = vrde_property(server, "VNCUnixSocket");
    if (!socket_path || socket_path[0] != '/' || strlen(socket_path) > 107 || !password || strlen(password) != 8 ||
        strspn(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != 8) goto done;
    result = cJSON_CreateObject(); cJSON_AddItemToObject(result, "resource", cJSON_Duplicate(resource, 1));
    cJSON_AddStringToObject(result, "kind", "vnc");
    cJSON_AddStringToObject(result, "binding_id", JSTR(binding, "transport_binding_id"));
    cJSON *params = cJSON_AddObjectToObject(result, "parameters");
    cJSON_AddNumberToObject(params, "pid", pid); cJSON_AddStringToObject(params, "socket_path", socket_path);
    cJSON_AddStringToObject(params, "password", password);
done:
    free(password); free(socket_path);
    if (server) IVRDEServer_Release(server);
    if (console) IConsole_Release(console);
    if (session) { if (locked) ISession_UnlockMachine(session); ISession_Release(session); }
    if (machine) IMachine_Release(machine);
    cJSON_Delete(row); return result;
}
