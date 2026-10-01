/* SPDX-License-Identifier: Apache-2.0 */
/* Operator-only setup keeps the generated display credential out of arguments. */
#include "provider.h"
#include <errno.h>
#include <sys/random.h>

static int random_bytes(unsigned char *value, size_t count) {
    size_t offset = 0;
    while (offset < count) {
        ssize_t done = getrandom(value + offset, count - offset, 0);
        if (done < 0 && errno == EINTR) continue;
        if (done <= 0) return 0;
        offset += (size_t)done;
    }
    return 1;
}
static HRESULT property(IVRDEServer *server, const char *name, const char *value) {
    PRUnichar *key = utf16(name), *wide = utf16(value);
    HRESULT rc = key && wide ? IVRDEServer_SetVRDEProperty(server, key, wide) : E_FAIL;
    if (key) g_pVBoxFuncs->pfnUtf16Free(key);
    if (wide) g_pVBoxFuncs->pfnUtf16Free(wide);
    return rc;
}
int prepare_account(const char *identifier, const char *socket_path) {
    if (strlen(identifier) != 36 || socket_path[0] != '/' || strlen(socket_path) > 107) return 2;
    if (!connect_account()) { close_provider(); return 1; }
    IMachine *machine = find_machine(identifier), *mutable = NULL;
    ISession *session = NULL; IVRDEServer *server = NULL;
    PRUint32 state = 0; int locked = 0, result = 1;
    char password[9] = {0}, marker[65] = {0}, *previous = NULL;
    unsigned char random[32]; PRUnichar *pack = NULL, *key = NULL, *value = NULL;
    if (!machine || FAILED(IMachine_get_State(machine, &state)) || state != MachineState_PoweredOff ||
        FAILED(IVirtualBoxClient_get_Session(client, &session)) || !session ||
        FAILED(IMachine_LockMachine(machine, session, LockType_Write))) goto done;
    locked = 1;
    if (FAILED(ISession_get_Machine(session, &mutable)) || !mutable ||
        FAILED(IMachine_get_State(mutable, &state)) || state != MachineState_PoweredOff ||
        FAILED(IMachine_get_VRDEServer(mutable, &server)) || !server || !random_bytes(random, sizeof(random))) goto done;
    for (size_t i = 0; i < sizeof(random); i++) {
        marker[2*i] = "0123456789abcdef"[random[i] >> 4];
        marker[2*i+1] = "0123456789abcdef"[random[i] & 15];
    }
    for (size_t i = 0; i < 8;) {
        unsigned char next;
        if (!random_bytes(&next, 1)) goto done;
        if (next < 248) password[i++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[next % 62];
    }
    previous = extra(mutable, "FICC/Birth");
    if (!previous || !hex(previous, 64) || strspn(previous, "0") == 64) {
        key = utf16("FICC/Birth"); value = utf16(marker);
        if (!key || !value || FAILED(IMachine_SetExtraData(mutable, key, value))) goto done;
    }
    pack = utf16("FICC VNC");
    if (!pack || FAILED(IVRDEServer_put_VRDEExtPack(server, pack)) ||
        FAILED(IVRDEServer_put_Enabled(server, 1)) ||
        FAILED(property(server, "VNCUnixSocket", socket_path)) ||
        FAILED(property(server, "VNCPassword", password)) || FAILED(IMachine_SaveSettings(mutable))) goto done;
    result = 0;
done:
    if (result && mutable) IMachine_DiscardSettings(mutable);
    memset(password, 0, sizeof(password)); memset(random, 0, sizeof(random));
    free(previous);
    if (pack) g_pVBoxFuncs->pfnUtf16Free(pack);
    if (key) g_pVBoxFuncs->pfnUtf16Free(key);
    if (value) g_pVBoxFuncs->pfnUtf16Free(value);
    if (server) IVRDEServer_Release(server);
    if (mutable) IMachine_Release(mutable);
    if (session) { if (locked) ISession_UnlockMachine(session); ISession_Release(session); }
    if (machine) IMachine_Release(machine);
    close_provider(); return result;
}
