/* SPDX-License-Identifier: Apache-2.0 */
/* Check public batch observation with independent provider task identities. */
#include <stdio.h>
#include "lifecycle.c"

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "check failed: %s at line %d\n", #value, __LINE__); exit(1); \
} } while (0)

enum outcome { ACTIVE, SUCCESS, FAILED_TASK, MISSING_TASK, LOOKUP_ERROR,
    COMPLETION_ERROR, RESULT_ERROR, TERMINAL, ACK_PENDING, REPLACED, STATE_PENDING, OUTCOMES };
struct expected {
    const char *state, *task, *result, *machine_state;
    int completed, lookup_calls, completion_calls, result_calls, releases;
};
static const struct expected expected[OUTCOMES] = {
    {"accepted", "active", "unknown", "running", 0, 1, 1, 0, 1},
    {"observed", "finished", "success", "running", 1, 1, 1, 1, 1},
    {"failed", "finished", "failure", "running", 1, 1, 1, 1, 1},
    {"unknown", "finished", "unknown", "running", 1, 1, 0, 0, 0},
    {"unknown", "unknown", "unknown", "running", 0, 1, 0, 0, 0},
    {"unknown", "unknown", "unknown", "running", 0, 1, 1, 0, 1},
    {"unknown", "unknown", "unknown", "running", 0, 1, 1, 1, 1},
    {"failed", "finished", "failure", "running", 1, 0, 0, 0, 0},
    {"accepted", "none", "unknown", "off", 0, 0, 0, 0, 0},
    {"accepted", "none", "unknown", NULL, 0, 1, 1, 1, 1},
    {"accepted", "none", "unknown", "off", 0, 1, 1, 1, 1},
};
struct fixture {
    IProgress progress;
    IMachine machine;
    cJSON *resource, *row, *previous;
    char progress_id[37];
    enum outcome outcome;
    int lookups, completions, results, progress_releases, machine_lookups, machine_releases;
};
static struct fixture fixtures[64];
static int fixture_count;

static struct fixture *progress_fixture(IProgress *progress) {
    for (int i = 0; i < fixture_count; i++) if (&fixtures[i].progress == progress) return &fixtures[i];
    CHECK(0); return NULL;
}
static struct fixture *machine_fixture(IMachine *machine) {
    for (int i = 0; i < fixture_count; i++) if (&fixtures[i].machine == machine) return &fixtures[i];
    CHECK(0); return NULL;
}
static nsrefcnt release_progress(IProgress *progress) {
    progress_fixture(progress)->progress_releases++; return 1;
}
static nsrefcnt release_machine(IMachine *machine) {
    machine_fixture(machine)->machine_releases++; return 1;
}
static nsresult get_complete(IProgress *progress, PRBool *value) {
    struct fixture *f = progress_fixture(progress); f->completions++;
    *value = f->outcome != ACTIVE;
    return f->outcome == COMPLETION_ERROR ? E_FAIL : S_OK;
}
static nsresult get_code(IProgress *progress, PRInt32 *value) {
    struct fixture *f = progress_fixture(progress); f->results++;
    *value = f->outcome == FAILED_TASK ? (PRInt32)E_FAIL : 0;
    return f->outcome == RESULT_ERROR ? E_FAIL : S_OK;
}
static const struct IProgressVtbl progress_methods = {
    .Release=release_progress, .GetCompleted=get_complete, .GetResultCode=get_code,
};
static const struct IMachineVtbl machine_methods = {.Release=release_machine};
static nsresult find_progress(IVirtualBox *provider, PRUnichar *id, IProgress **value) {
    (void)provider;
    char text[37]; CHECK(id);
    for (int i = 0; i < 37; i++) { CHECK(id[i] < 128); text[i] = (char)id[i]; }
    CHECK(text[36] == '\0');
    for (int i = 0; i < fixture_count; i++) {
        struct fixture *f = &fixtures[i];
        if (!SAME(text, f->progress_id)) continue;
        f->lookups++; *value = NULL;
        if (f->outcome == MISSING_TASK) return E_INVALIDARG;
        if (f->outcome == LOOKUP_ERROR) return E_FAIL;
        *value = &f->progress; return S_OK;
    }
    CHECK(0); return E_FAIL;
}
static const struct IVirtualBoxVtbl provider_methods = {.FindProgressById=find_progress};
static IVirtualBox fake_provider = {.lpVtbl=&provider_methods};
static void free_wide(PRUnichar *value) { free(value); }
static const VBOXCAPI api = {.pfnUtf16Free=free_wide};
PCVBOXCAPI g_pVBoxFuncs = &api;
IVirtualBox *provider = &fake_provider;
IVirtualBoxClient *client;
const char *jstr(const cJSON *value) { return cJSON_IsString(value) ? value->valuestring : ""; }
PRUnichar *utf16(const char *value) {
    size_t size = strlen(value) + 1;
    PRUnichar *wide = calloc(size, sizeof(*wide)); CHECK(wide);
    for (size_t i = 0; i < size; i++) wide[i] = (unsigned char)value[i];
    return wide;
}
IMachine *find_machine(const char *key) {
    for (int i = 0; i < fixture_count; i++) if (SAME(key, JSTR(fixtures[i].resource, "key"))) {
        fixtures[i].machine_lookups++; return &fixtures[i].machine;
    }
    CHECK(0); return NULL;
}
cJSON *machine_row(IMachine *machine) { return cJSON_Duplicate(machine_fixture(machine)->row, 1); }
int matches(const cJSON *row, const cJSON *resource, int revision) {
    const cJSON *now = JGET(row, "resource");
    return now && SAME(JSTR(now, "id"), JSTR(resource, "id")) &&
        SAME(JSTR(now, "key"), JSTR(resource, "key")) && SAME(JSTR(now, "birth"), JSTR(resource, "birth")) &&
        (!revision || (SAME(JSTR(now, "revision"), JSTR(resource, "revision")) &&
                       SAME(JSTR(now, "state"), JSTR(resource, "state"))));
}

static void make_fixture(int index, int round) {
    struct fixture *f = &fixtures[index]; memset(f, 0, sizeof(*f));
    f->progress.lpVtbl = &progress_methods; f->machine.lpVtbl = &machine_methods;
    f->outcome = (index + round) % OUTCOMES;
    unsigned int number = (unsigned int)(1 + index + 64 * round);
    char id[33], key[37], birth[65], revision[65];
    snprintf(id, sizeof(id), "%032x", number);
    snprintf(key, sizeof(key), "10000000-0000-4000-8000-%012x", number);
    snprintf(birth, sizeof(birth), "%064x", number + 1024);
    snprintf(revision, sizeof(revision), "%064x", number + 2048);
    snprintf(f->progress_id, sizeof(f->progress_id), "20000000-0000-4000-8000-%012x", number);
    f->resource = cJSON_CreateObject();
    cJSON_AddStringToObject(f->resource, "id", id); cJSON_AddStringToObject(f->resource, "key", key);
    cJSON_AddStringToObject(f->resource, "birth", birth); cJSON_AddStringToObject(f->resource, "revision", revision);
    cJSON_AddStringToObject(f->resource, "state", "off");
    f->row = cJSON_CreateObject();
    cJSON *now = cJSON_Duplicate(f->resource, 1); cJSON_AddItemToObject(f->row, "resource", now);
    cJSON_ReplaceItemInObjectCaseSensitive(now, "state", cJSON_CreateString(
        f->outcome == ACK_PENDING || f->outcome == STATE_PENDING ? "off" : "running"));
    cJSON_ReplaceItemInObjectCaseSensitive(now, "revision", cJSON_CreateString("changed-revision"));
    if (f->outcome == REPLACED) {
        snprintf(birth, sizeof(birth), "%064x", number + 4096);
        cJSON_ReplaceItemInObjectCaseSensitive(now, "birth", cJSON_CreateString(birth));
    }
    cJSON *token = cJSON_CreateObject();
    cJSON_AddStringToObject(token, "key", key); cJSON_AddStringToObject(token, "birth", JSTR(f->resource, "birth"));
    cJSON_AddStringToObject(token, "action", "start"); cJSON_AddNumberToObject(token, "return_code", 0);
    cJSON_AddStringToObject(token, "progress", f->progress_id);
    cJSON_AddBoolToObject(token, "acknowledged", f->outcome == ACK_PENDING);
    f->previous = cJSON_CreateObject(); cJSON_AddStringToObject(f->previous, "id", id);
    cJSON *receipt = cJSON_AddObjectToObject(f->previous, "receipt");
    cJSON_AddItemToObject(receipt, "token", token);
    cJSON_AddStringToObject(receipt, "state", f->outcome == TERMINAL ? "failed" : "accepted");
    cJSON_AddStringToObject(receipt, "result", f->outcome == TERMINAL ? "failure" : "unknown");
    cJSON_AddStringToObject(receipt, "task_state", f->outcome == TERMINAL ? "finished" : "active");
    cJSON_AddBoolToObject(receipt, "completed", f->outcome == TERMINAL);
}
static void check_result(const cJSON *item, const struct fixture *f) {
    const struct expected *e = &expected[f->outcome];
    const cJSON *receipt = JGET(item, "receipt"), *saved = JGET(f->previous, "receipt");
    const cJSON *saved_token = JGET(saved, "token");
    CHECK(SAME(JSTR(item, "id"), JSTR(f->resource, "id")));
    CHECK(cJSON_Compare(JGET(receipt, "token"), saved_token, 1));
    CHECK(SAME(JSTR(receipt, "state"), e->state)); CHECK(SAME(JSTR(receipt, "task_state"), e->task));
    CHECK(SAME(JSTR(receipt, "result"), e->result));
    CHECK(cJSON_IsBool(JGET(receipt, "completed")) && cJSON_IsTrue(JGET(receipt, "completed")) == e->completed);
    if (e->machine_state) CHECK(SAME(JSTR(item, "observed_state"), e->machine_state));
    else CHECK(!JGET(item, "observed_state"));
    if (f->outcome == TERMINAL) CHECK(cJSON_Compare(receipt, saved, 1));
    CHECK(f->lookups == e->lookup_calls && f->completions == e->completion_calls);
    CHECK(f->results == e->result_calls && f->progress_releases == e->releases);
    CHECK(f->machine_lookups == 1 && f->machine_releases == 1);
}
static void check_refusal(const cJSON *request, const cJSON *binding, const char *field) {
    cJSON *changed = cJSON_Duplicate(binding, 1);
    cJSON *targets = JGET(JGET(changed, "receipt"), "targets"), *prior = cJSON_GetArrayItem(targets, 0);
    cJSON *token = JGET(JGET(prior, "receipt"), "token");
    if (SAME(field, "id")) cJSON_ReplaceItemInObjectCaseSensitive(prior, "id", cJSON_CreateString("wrong-id"));
    else cJSON_ReplaceItemInObjectCaseSensitive(token, field, cJSON_CreateString("wrong-value"));
    CHECK(observe(request, changed) == NULL); cJSON_Delete(changed);
}
static void run(int count, int round) {
    fixture_count = count;
    for (int i = 0; i < count; i++) make_fixture(i, round);
    cJSON *request = cJSON_CreateObject(); cJSON_AddStringToObject(request, "action", "start");
    cJSON *binding = cJSON_CreateObject(), *resources = cJSON_AddArrayToObject(binding, "resources");
    cJSON *targets = cJSON_AddArrayToObject(cJSON_AddObjectToObject(binding, "intent"), "targets");
    cJSON *previous = cJSON_AddArrayToObject(cJSON_AddObjectToObject(binding, "receipt"), "targets");
    for (int position = 0; position < count; position++) {
        /* Provider order, request order, and intent order are different. */
        int index = (position * 17 + round) % count;
        cJSON_AddItemToArray(resources, cJSON_Duplicate(fixtures[index].resource, 1));
        cJSON_AddItemToArray(previous, cJSON_Duplicate(fixtures[index].previous, 1));
        struct fixture *f = &fixtures[count - position - 1];
        cJSON *target = cJSON_CreateObject(); cJSON_AddStringToObject(target, "id", JSTR(f->resource, "id"));
        cJSON *intent = cJSON_AddObjectToObject(target, "intent");
        cJSON_AddItemToObject(intent, "resource", cJSON_Duplicate(f->resource, 1));
        cJSON_AddStringToObject(intent, "action", "start"); cJSON_AddStringToObject(intent, "method", "LaunchVMProcess");
        cJSON_AddItemToArray(targets, target);
    }
    cJSON *before = cJSON_Duplicate(binding, 1), *request_before = cJSON_Duplicate(request, 1);
    cJSON *output = observe(request, binding);
    CHECK(cJSON_IsObject(output));
    const cJSON *items = JGET(output, "results");
    CHECK(cJSON_IsArray(items) && cJSON_GetArraySize(items) == count);
    CHECK(cJSON_Compare(binding, before, 1) && cJSON_Compare(request, request_before, 1));
    for (int position = 0; position < count; position++)
        check_result(cJSON_GetArrayItem(items, position), &fixtures[(position * 17 + round) % count]);
    cJSON_Delete(output);
    /* A repeated observation must not change input receipts or returned tokens. */
    for (int i = 0; i < count; i++) {
        fixtures[i].lookups = fixtures[i].completions = fixtures[i].results = 0;
        fixtures[i].progress_releases = fixtures[i].machine_lookups = fixtures[i].machine_releases = 0;
    }
    output = observe(request, binding); CHECK(cJSON_IsObject(output));
    CHECK(cJSON_Compare(binding, before, 1)); items = JGET(output, "results");
    CHECK(cJSON_GetArraySize(items) == count);
    for (int position = 0; position < count; position++)
        check_result(cJSON_GetArrayItem(items, position), &fixtures[(position * 17 + round) % count]);
    cJSON_Delete(output);
    for (int i = 0; i < 4; i++) check_refusal(request, binding, (const char *[]) {"id", "key", "birth", "action"}[i]);
    cJSON_Delete(before); cJSON_Delete(request_before); cJSON_Delete(request); cJSON_Delete(binding);
    for (int i = 0; i < count; i++) {
        cJSON_Delete(fixtures[i].resource); cJSON_Delete(fixtures[i].row); cJSON_Delete(fixtures[i].previous);
    }
}
int main(int argc, char **argv) {
    CHECK(argc == 2 && (SAME(argv[1], "1") || SAME(argv[1], "64")));
    int count = atoi(argv[1]);
    for (int round = 0; round < OUTCOMES; round++) run(count, round);
    printf("{\"count\":%d,\"outcomes\":%d,\"observations\":%d,\"refusals\":%d}\n",
           count, OUTCOMES, count * OUTCOMES * 2, OUTCOMES * 4);
    return 0;
}
