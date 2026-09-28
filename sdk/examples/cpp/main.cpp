// SPDX-License-Identifier: Apache-2.0
#include "ficc_module.h"
#include <cstring>
#include <memory>

using Json = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;

static cJSON *echo_batch(const cJSON *request) {
    const auto *targets = cJSON_GetObjectItemCaseSensitive(request, "targets");
    const auto *action = cJSON_GetObjectItemCaseSensitive(request, "action");
    const auto *params = cJSON_GetObjectItemCaseSensitive(request, "parameters");
    const auto *message = cJSON_GetObjectItemCaseSensitive(params, "message");
    const bool supported = !std::strcmp(action->valuestring, "echo") && cJSON_IsString(message);
    Json results(cJSON_CreateArray(), cJSON_Delete);
    if (!results) return nullptr;
    int index = 0;
    for (const auto *target = targets->child; target; target = target->next, ++index) {
        Json item(cJSON_CreateObject(), cJSON_Delete), value(cJSON_CreateObject(), cJSON_Delete);
        if (!item || !value || !cJSON_AddStringToObject(item.get(), "target", target->valuestring))
            return nullptr;
        if (supported) {
            if (!cJSON_AddStringToObject(value.get(), "message", message->valuestring) ||
                !cJSON_AddNumberToObject(value.get(), "index", index)) return nullptr;
        } else if (!cJSON_AddStringToObject(value.get(), "code", "unsupported_action") ||
                   !cJSON_AddStringToObject(value.get(), "message",
                       "Select the echo action and supply a message.")) return nullptr;
        if (!cJSON_AddItemToObject(item.get(), supported ? "data" : "error", value.get()))
            return nullptr;
        value.release();
        if (!cJSON_AddItemToArray(results.get(), item.get())) return nullptr;
        item.release();
    }
    return results.release();
}

int main() { return ficc_serve(echo_batch); }
