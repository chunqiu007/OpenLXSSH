#include "AuthenticationMaterialProbe.h"
// These are the already-built pinned libssh2 1.11.1 headers. The script checks their
// version and links the existing Files archives, without compiling native dependencies.
#include "libssh2_priv.h"
#include <stdint.h>

static void store_u32(unsigned char *out, uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

int olxs_probe_authentication_material(const char *private_bytes, size_t private_length,
                                       const char *passphrase, const char *algorithm,
                                       const unsigned char *expected_public, size_t expected_length) {
    if(libssh2_init(0) != 0) return 10;
    LIBSSH2_SESSION *session = libssh2_session_init();
    if(!session) { libssh2_exit(); return 11; }
    unsigned char *method = NULL, *public_bytes = NULL, *signature = NULL, *wire = NULL;
    size_t method_length = 0, public_length = 0, signature_length = 0;
    const LIBSSH2_HOSTKEY_METHOD *implementation = NULL;
    void *private_context = NULL, *public_context = NULL;
    int result = 12;
    // Exactly the parser used by userauth_publickey_frommemory when publicKey == nil.
    if(_libssh2_pub_priv_keyfilememory(session, &method, &method_length,
                                      &public_bytes, &public_length,
                                      private_bytes, private_length, passphrase) != 0) goto done;
    if(strlen(algorithm) != method_length || memcmp(algorithm, method, method_length) != 0 ||
       public_length != expected_length || memcmp(public_bytes, expected_public, public_length) != 0) {
        result = 13; goto done;
    }
    const char *signing_method = strcmp(algorithm, "ssh-rsa") == 0 ? "rsa-sha2-256" : algorithm;
    const LIBSSH2_HOSTKEY_METHOD **available = libssh2_hostkey_methods();
    for(; *available; ++available) {
        if(strcmp((*available)->name, signing_method) == 0) { implementation = *available; break; }
    }
    result = 14;
    if(!implementation || !implementation->initPEMFromMemory || !implementation->init ||
       !implementation->signv || !implementation->sig_verify || !implementation->dtor) goto done;
    // Same private-key initializer and signing callback used by sign_frommemory.
    if(implementation->initPEMFromMemory(session, private_bytes, private_length,
                                        (const unsigned char *)passphrase, &private_context) != 0) goto done;
    result = 15;
    if(implementation->init(session, public_bytes, public_length, &public_context) != 0) goto done;
    static const char challenge[] = "OpenLXSSH offline authentication material verification";
    struct iovec vector = {(void *)challenge, sizeof(challenge) - 1};
    result = 16;
    if(implementation->signv(session, &signature, &signature_length, 1, &vector, &private_context) != 0) goto done;
    size_t signing_length = strlen(signing_method);
    if(signature_length > UINT32_MAX || signing_length > UINT32_MAX || signature_length > SIZE_MAX - signing_length - 8) goto done;
    size_t wire_length = 8 + signing_length + signature_length;
    wire = LIBSSH2_ALLOC(session, wire_length);
    result = 17;
    if(!wire) goto done;
    store_u32(wire, (uint32_t)signing_length);
    memcpy(wire + 4, signing_method, signing_length);
    store_u32(wire + 4 + signing_length, (uint32_t)signature_length);
    memcpy(wire + 8 + signing_length, signature, signature_length);
    result = 18;
    if(implementation->sig_verify(session, wire, wire_length,
                                  (const unsigned char *)challenge, sizeof(challenge) - 1, &public_context) != 0) goto done;
    result = 0;
done:
    if(implementation) {
        if(private_context) implementation->dtor(session, &private_context);
        if(public_context) implementation->dtor(session, &public_context);
    }
    if(wire) libssh2_free(session, wire);
    if(signature) libssh2_free(session, signature);
    if(public_bytes) libssh2_free(session, public_bytes);
    if(method) libssh2_free(session, method);
    if(libssh2_session_free(session) != 0 && result == 0) result = 19;
    libssh2_exit();
    return result;
}
