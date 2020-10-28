#include "py/mpconfig.h"

// #define MICROPY_PY_UECC 1

#if MICROPY_PY_UECC

// Include required definitions first.
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>

#define CURVE MBEDTLS_ECP_DP_SECP256K1
#define KEY_SIZE  65 // support only MBEDTLS_ECP_DP_SECP256K1 curve
#define HASH_SIZE 32 // support only sha256

typedef struct _mp_obj_ecdsa_t {
    mp_obj_base_t base;
    mbedtls_ecdsa_context ecdsa;
    const mbedtls_ecp_curve_info *curve_info;
    uint8_t key[KEY_SIZE]; 
} mp_obj_ecdsa_t;

STATIC mp_obj_t uecc_ecdsa_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_ecdsa_t *o = m_new_obj(mp_obj_ecdsa_t);
    o->base.type = type;
    
    mbedtls_ecdsa_init(&o->ecdsa);
    o->curve_info = mbedtls_ecp_curve_info_from_grp_id(CURVE);

    mbedtls_ecp_group_load(&o->ecdsa.grp, o->curve_info->grp_id);

    mp_buffer_info_t pubkey_info;

    mp_get_buffer_raise(args[0], &pubkey_info, MP_BUFFER_READ);

    if (pubkey_info.len != KEY_SIZE) mp_raise_ValueError(MP_ERROR_TEXT("pubkey invalid len"));
    
    if( mbedtls_ecp_point_read_binary( &o->ecdsa.grp, &o->ecdsa.Q, pubkey_info.buf, pubkey_info.len) != 0 )
    {
        mp_raise_ValueError(MP_ERROR_TEXT("cant import pubkey"));
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t ucryptolib_ecdsa_verify(size_t n_args, const mp_obj_t *args) 
{
    bool ret = false;
    mp_obj_ecdsa_t *self = MP_OBJ_TO_PTR(args[0]);
    unsigned char hash[HASH_SIZE];

    mp_buffer_info_t message_info;
    mp_get_buffer_raise(args[1], &message_info, MP_BUFFER_READ);

    mp_buffer_info_t signature_info;
    mp_get_buffer_raise(args[2], &signature_info, MP_BUFFER_READ);

    if( mbedtls_sha256_ret( message_info.buf, message_info.len, hash, 0 ) != 0 )
    {
        mp_raise_ValueError(MP_ERROR_TEXT("cant make sha256"));
    }

    if( !mbedtls_ecdsa_read_signature( &self->ecdsa, hash, sizeof( hash ), signature_info.buf, signature_info.len ) )
    {
        ret = true;
    }
    
    return mp_obj_new_bool(ret);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(ucryptolib_ecdsa_verify_obj, 3, 3, ucryptolib_ecdsa_verify);

STATIC const mp_rom_map_elem_t uecc_ecdsa_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&ucryptolib_ecdsa_verify_obj) },
};
STATIC MP_DEFINE_CONST_DICT(uecc_ecdsa_locals_dict, uecc_ecdsa_locals_dict_table);

STATIC const mp_obj_type_t uecc_ecdsa_type = {
    { &mp_type_type },
    .name = MP_QSTR_ecdsa,
    .make_new = uecc_ecdsa_make_new,
    .locals_dict = (void *)&uecc_ecdsa_locals_dict,
};

STATIC const mp_rom_map_elem_t mp_module_uecc_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_uecc) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa), MP_ROM_PTR(&uecc_ecdsa_type) },
};
STATIC MP_DEFINE_CONST_DICT(mp_module_uecc_globals, mp_module_uecc_globals_table);

const mp_obj_module_t mp_module_uecc = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_uecc_globals,
};
#endif // MICROPY_PY_UECC

