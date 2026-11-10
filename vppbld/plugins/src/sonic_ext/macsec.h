/*
 * Copyright (c) 2026 SONiC-VPP contributors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_sonic_ext_macsec_h__
#define __included_sonic_ext_macsec_h__

#include <sonic_ext/sonic_ext.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/hash.h>

#define SONIC_EXT_MACSEC_AN_MAX 4
#define SONIC_EXT_MACSEC_ICV_LEN 16
#define SONIC_EXT_MACSEC_SECTAG_NO_SCI 8
#define SONIC_EXT_MACSEC_SECTAG_SCI 16
#define SONIC_EXT_MACSEC_MTU_OVERHEAD 32
#define SONIC_EXT_MACSEC_IV_LEN 12
#define SONIC_EXT_MACSEC_SALT_LEN 12
#define SONIC_EXT_MACSEC_SAK_MAX 32

#define SONIC_EXT_MACSEC_TCI_SC 0x20
#define SONIC_EXT_MACSEC_TCI_E 0x08
#define SONIC_EXT_MACSEC_TCI_C 0x04
#define SONIC_EXT_MACSEC_TCI_AN 0x03

enum
{
  SONIC_EXT_MACSEC_EGRESS = 0,
  SONIC_EXT_MACSEC_INGRESS = 1,
  SONIC_EXT_MACSEC_N_DIR,
};

enum
{
  SONIC_EXT_MACSEC_CS_GCM_AES_128 = 0,
  SONIC_EXT_MACSEC_CS_GCM_AES_256,
  SONIC_EXT_MACSEC_CS_GCM_AES_XPN_128,
  SONIC_EXT_MACSEC_CS_GCM_AES_XPN_256,
};

/* SONiC reuses one chassis SCI on every protected port.  VPP must key
 * SCs by (sw_if_index, sci, direction) so two ports can share an SCI. */
typedef struct
{
  u64 sci;
  u32 sw_if_index;
  u8 direction;
  u8 pad[3];
} sonic_ext_macsec_sc_key_t;

typedef struct
{
  u32 sw_if_index;
  u8 enabled, direction, encrypt, send_sci;
  u8 replay_protect, feature_enabled;
  u32 replay_window, saved_mtu, sc_index; /* sc_index ~0 if none */
  u64 in_pkts_not_using_sa;
  u64 in_pkts_no_sci;
  u64 in_pkts_unchecked;
} sonic_ext_macsec_port_t;

typedef struct
{
  sonic_ext_macsec_sc_key_t key;
  u64 sci;
  u32 port_index;
  u8 direction, cipher, encoding_an;
  u32 sa_index[SONIC_EXT_MACSEC_AN_MAX]; /* ~0 absent */
  u64 highest_xpn_seen;
} sonic_ext_macsec_sc_t;

typedef struct
{
  u32 sc_index;
  u8 an, xpn_en, sak_len, salt[SONIC_EXT_MACSEC_SALT_LEN];
  u32 ssci;
  vnet_crypto_ctx_t *crypto_ctx;
  u64 next_xpn, lowest_acceptable_xpn;
  u64 out_pkts_encrypted, out_pkts_protected;
  u64 octets_encrypted, octets_protected;
  u64 in_pkts_ok, in_pkts_not_valid, in_pkts_invalid;
  u64 in_pkts_late, in_pkts_delayed, in_pkts_unchecked;
  u64 in_pkts_not_using_sa, in_pkts_no_sa, in_pkts_unused_sa;
  u64 in_octets_decrypted, in_octets_validated;
} sonic_ext_macsec_sa_t;

typedef struct
{
  sonic_ext_macsec_port_t *ports[SONIC_EXT_MACSEC_N_DIR];
  sonic_ext_macsec_sc_t *scs;
  sonic_ext_macsec_sa_t *sas;
  uword *sc_by_key;
  u8 *mtu_refcount;
  u32 *saved_mtu;
  u8 *mtu_is_hw;
  u8 no_handler_logged;
} sonic_ext_macsec_main_t;

extern sonic_ext_macsec_main_t sonic_ext_macsec_main;
extern vlib_node_registration_t sonic_ext_macsec_encrypt_node;
extern vlib_node_registration_t sonic_ext_macsec_decrypt_node;

int sonic_ext_macsec_port_add_del (u32 sw_if_index, u8 direction, u8 encrypt,
				   u8 send_sci, u8 replay_protect,
				   u32 replay_window, int is_add);
int sonic_ext_macsec_sc_add_del (u32 sw_if_index, u8 direction, u64 sci,
				 u8 cipher, u8 explicit_sci, u8 conf_offset,
				 int is_add);
int sonic_ext_macsec_sc_set_encoding_an (u32 sw_if_index, u64 sci, u8 an);
int sonic_ext_macsec_sa_add_del (u32 sw_if_index, u8 direction, u64 sci, u8 an,
				 const u8 *sak, u8 sak_len, const u8 *salt,
				 u32 ssci, u8 xpn_en, u64 init_xpn,
				 int is_add);
int sonic_ext_macsec_sa_set_xpn (u32 sw_if_index, u8 direction, u64 sci, u8 an,
				 u64 xpn);

static_always_inline sonic_ext_macsec_port_t *
sonic_ext_macsec_port_get (u32 sw_if_index, u8 direction)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;

  if (direction >= SONIC_EXT_MACSEC_N_DIR)
    return 0;
  if (sw_if_index >= vec_len (mm->ports[direction]))
    return 0;
  return vec_elt_at_index (mm->ports[direction], sw_if_index);
}

static_always_inline sonic_ext_macsec_sc_t *
sonic_ext_macsec_sc_get (u32 sc_index)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;

  if (sc_index == ~0 || pool_is_free_index (mm->scs, sc_index))
    return 0;
  return pool_elt_at_index (mm->scs, sc_index);
}

static_always_inline sonic_ext_macsec_sa_t *
sonic_ext_macsec_sa_get (u32 sa_index)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;

  if (sa_index == ~0 || pool_is_free_index (mm->sas, sa_index))
    return 0;
  return pool_elt_at_index (mm->sas, sa_index);
}

static_always_inline sonic_ext_macsec_sc_t *
sonic_ext_macsec_sc_by_sci (u32 sw_if_index, u64 sci, u8 direction)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_port_t *port;
  sonic_ext_macsec_sc_t *sc;
  sonic_ext_macsec_sc_key_t k;
  uword *p;

  /*
   * Phase 1 is one SC per (port, direction).  Look up by the stable
   * pool index on the port, not the SCI hash: hash_set_mem() stores a
   * pointer to the key, and pool_get() on mm->scs can move that
   * memory (VNET_API_ERROR_NO_SUCH_ENTRY / -6 on a later SA add).
   */
  port = sonic_ext_macsec_port_get (sw_if_index, direction);
  sc = port ? sonic_ext_macsec_sc_get (port->sc_index) : 0;
  if (sc && sc->sci == sci)
    return sc;

  if (PREDICT_FALSE (mm->sc_by_key == 0))
    return 0;
  clib_memset (&k, 0, sizeof (k));
  k.sci = sci;
  k.sw_if_index = sw_if_index;
  k.direction = direction;
  p = hash_get_mem (mm->sc_by_key, &k);
  if (!p)
    return 0;
  return sonic_ext_macsec_sc_get (p[0]);
}

static_always_inline u8
sonic_ext_macsec_tci (u8 send_sci, u8 an)
{
  return (u8) ((send_sci ? SONIC_EXT_MACSEC_TCI_SC : 0) |
	       SONIC_EXT_MACSEC_TCI_E | SONIC_EXT_MACSEC_TCI_C |
	       (an & SONIC_EXT_MACSEC_TCI_AN));
}

static_always_inline u8
sonic_ext_macsec_sectag_len (u8 send_sci)
{
  return send_sci ? SONIC_EXT_MACSEC_SECTAG_SCI :
			  SONIC_EXT_MACSEC_SECTAG_NO_SCI;
}

static_always_inline void
sonic_ext_macsec_sci_store (u8 *dst, u64 sci)
{
  u64 n = clib_host_to_net_u64 (sci);
  clib_memcpy (dst, &n, sizeof (n));
}

static_always_inline u64
sonic_ext_macsec_sci_load (const u8 *src)
{
  u64 n;
  clib_memcpy (&n, src, sizeof (n));
  return clib_net_to_host_u64 (n);
}

static_always_inline void
sonic_ext_macsec_build_iv (u8 *iv, u64 sci, u32 pn)
{
  sonic_ext_macsec_sci_store (iv, sci);
  u32 npn = clib_host_to_net_u32 (pn);
  clib_memcpy (iv + 8, &npn, sizeof (npn));
}

#endif /* __included_sonic_ext_macsec_h__ */
