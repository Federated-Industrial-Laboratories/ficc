/* SPDX-License-Identifier: Apache-2.0 */
#include "provider.h"

static cJSON *selected(const cJSON *request, const cJSON *binding) {
    const char *phase = JSTR(request, "phase"), *action = JSTR(request, "action");
    cJSON *output = cJSON_CreateObject(), *items = cJSON_CreateArray(); cJSON_AddItemToObject(output, "results", items);
    for (const cJSON *resource = JGET(binding, "resources")->child; resource; resource = resource->next) {
        IMachine *machine = find_machine(JSTR(resource, "key")); cJSON *now = machine ? machine_row(machine) : NULL;
        cJSON *item = cJSON_CreateObject(); cJSON_AddStringToObject(item, "id", JSTR(resource, "id"));
        if (!matches(now, resource, SAME(phase, "prepare")))
            cJSON_AddItemToObject(item, "error", refusal("changed", "The VM identity or operation revision changed."));
        else if (SAME(phase, "status")) { cJSON_AddItemToObject(item, "data", now); now = NULL; }
        else if (!SAME(JSTR(resource, "state"), SAME(action, "start") ? "off" : "running") ||
                 SAME(JSTR(resource, "birth"), "0000000000000000000000000000000000000000000000000000000000000000"))
            cJSON_AddItemToObject(item, "error", refusal("state", "The VM state or birth identity does not permit this action."));
        else if (SAME(action, "shutdown") && !shutdown_ready(machine))
            cJSON_AddItemToObject(item, "error", refusal("guest_not_ready", "The guest has not entered ACPI mode for graceful shutdown."));
        else {
            cJSON *intent = cJSON_AddObjectToObject(item, "intent");
            cJSON_AddItemToObject(intent, "resource", cJSON_Duplicate(resource, 1));
            cJSON_AddStringToObject(intent, "action", action);
            cJSON_AddStringToObject(intent, "method", SAME(action, "start") ? "LaunchVMProcess" : "PowerButton");
            cJSON_AddStringToObject(item, "desired_state", SAME(action, "start") ? "running" : "off");
        }
        if (machine) IMachine_Release(machine);
        cJSON_Delete(now); cJSON_AddItemToArray(items, item);
    }
    return output;
}
static cJSON *phase(const cJSON *request, const cJSON *binding) {
    const char *name = JSTR(request, "phase");
    if (!SAME(JSTR(binding, "consistency"), "checked-before-dispatch")) return NULL;
    if (SAME(name, "inventory")) return inventory(binding);
    if (SAME(name, "apply")) return power(request, binding);
    if (SAME(name, "observe")) return observe(request, binding);
    if (SAME(name, "console")) return display(binding);
    if (SAME(name, "probe")) {
        PRUnichar *wide = NULL; char *version = NULL, hash[65];
        if (FAILED(IVirtualBox_get_Version(provider, &wide)) || !(version = utf8(wide))) return NULL;
        cJSON *result = cJSON_CreateObject(), *info = cJSON_AddObjectToObject(result, "provider");
        cJSON_AddStringToObject(info, "name", "Oracle VirtualBox"); cJSON_AddStringToObject(info, "version", version);
        free(version); if (!sha(info, hash)) { cJSON_Delete(result); return NULL; }
        cJSON_AddStringToObject(info, "fingerprint", hash); return result;
    }
    return selected(request, binding);
}
static cJSON *handle(const cJSON *request, ficc_adapter *adapter) {
    (void)adapter;
    cJSON *results = cJSON_CreateArray(); int available = connect_provider();
    for (const cJSON *binding = JGET(request, "bindings")->child; binding; binding = binding->next) {
        cJSON *item = cJSON_CreateObject(), *data = available ? phase(request, binding) : NULL;
        cJSON_AddStringToObject(item, "profile_id", JSTR(binding, "id"));
        cJSON_AddItemToObject(item, data ? "data" : "error", data ? data :
            refusal("provider", "The VirtualBox request or result was refused."));
        cJSON_AddItemToArray(results, item);
    }
    close_provider(); return results;
}
int main(int count, char **args) {
    if (count == 5 && SAME(args[1], "--prepare-vm") && SAME(args[4], "--confirm"))
        return prepare_account(args[2], args[3]);
    return count == 1 ? ficc_serve_adapter(handle) : 2;
}
