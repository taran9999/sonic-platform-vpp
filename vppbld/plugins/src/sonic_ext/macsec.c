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
/**
 * @file
 * @brief SONiC-VPP MACsec SecY control plane.
 *
 * Port/SC/SA pools, vnet_crypto key install, per-port feature latch and
 * MTU +32.  SAK/salt are never logged.
 */

#include <sonic_ext/macsec.h>

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/interface.h>
#include <vnet/error.h>
#include <vppinfra/mem.h>

sonic_ext_macsec_main_t sonic_ext_macsec_main;

static const char *
sonic_ext_macsec_node_name (u8 direction)
{
  return direction == SONIC_EXT_MACSEC_INGRESS ? "sonic-ext-macsec-decrypt" :
						       "sonic-ext-macsec-encrypt";
}

static const char *
sonic_ext_macsec_arc_name (u8 direction)
{
  return direction == SONIC_EXT_MACSEC_INGRESS ? "device-input" :
						       "interface-output";
}

static sonic_ext_macsec_port_t *
sonic_ext_macsec_port_get_or_create (u32 sw_if_index, u8 direction)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  u32 old_len, i;

  if (direction >= SONIC_EXT_MACSEC_N_DIR)
    return 0;

  old_len = vec_len (mm->ports[direction]);
  vec_validate (mm->ports[direction], sw_if_index);
  for (i = old_len; i <= sw_if_index; i++)
    mm->ports[direction][i].sc_index = ~0;

  return vec_elt_at_index (mm->ports[direction], sw_if_index);
}

static void
sonic_ext_macsec_ensure_hash (void)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;

  if (mm->sc_by_key == 0)
    mm->sc_by_key = hash_create_mem (0, sizeof (sonic_ext_macsec_sc_key_t),
				     sizeof (uword));
}

/*
 * hash_set_mem() stores the key POINTER, not a copy.  The SC lives in a
 * clib pool, so the next pool_get() may realloc and invalidate every
 * previously inserted key (SA add then returns VNET_API_ERROR_NO_SUCH_ENTRY).
 * Keep a heap copy of the key so the hash outlives pool movement.
 */
static void
sonic_ext_macsec_sc_hash_set (sonic_ext_macsec_sc_t *sc, u32 sc_index)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_sc_key_t *kcopy;

  sonic_ext_macsec_ensure_hash ();
  kcopy = clib_mem_alloc (sizeof (*kcopy));
  clib_memcpy (kcopy, &sc->key, sizeof (*kcopy));
  hash_set_mem (mm->sc_by_key, kcopy, sc_index);
}

static void
sonic_ext_macsec_sc_hash_unset (sonic_ext_macsec_sc_t *sc)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;

  if (mm->sc_by_key)
    hash_unset_mem_free (&mm->sc_by_key, &sc->key);
}

static int
sonic_ext_macsec_mtu_adjust (u32 sw_if_index, int enable)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  vnet_sw_interface_t *si;
  clib_error_t *err;
  u8 ref;

  vec_validate (mm->mtu_refcount, sw_if_index);
  vec_validate (mm->saved_mtu, sw_if_index);
  vec_validate (mm->mtu_is_hw, sw_if_index);

  if (enable)
    {
      if (mm->mtu_refcount[sw_if_index]++)
	return 0;

      hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
      si = vnet_get_sw_interface (vnm, sw_if_index);
      err = vnet_hw_interface_set_max_frame_size (
	vnm, hw->hw_if_index, hw->max_frame_size + SONIC_EXT_MACSEC_MTU_OVERHEAD);
      if (err)
	{
	  clib_error_free (err);
	  mm->saved_mtu[sw_if_index] = si->mtu[VNET_MTU_L3];
	  mm->mtu_is_hw[sw_if_index] = 0;
	  vnet_sw_interface_set_mtu (
	    vnm, sw_if_index,
	    mm->saved_mtu[sw_if_index] + SONIC_EXT_MACSEC_MTU_OVERHEAD);
	}
      else
	{
	  mm->saved_mtu[sw_if_index] = hw->max_frame_size - SONIC_EXT_MACSEC_MTU_OVERHEAD;
	  mm->mtu_is_hw[sw_if_index] = 1;
	}
      return 0;
    }

  ref = mm->mtu_refcount[sw_if_index];
  if (ref == 0)
    return 0;
  mm->mtu_refcount[sw_if_index] = ref - 1;
  if (ref > 1)
    return 0;

  if (mm->mtu_is_hw[sw_if_index])
    {
      hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
      err = vnet_hw_interface_set_max_frame_size (vnm, hw->hw_if_index,
						  mm->saved_mtu[sw_if_index]);
      if (err)
	clib_error_free (err);
    }
  else
    vnet_sw_interface_set_mtu (vnm, sw_if_index, mm->saved_mtu[sw_if_index]);

  return 0;
}

static int
sonic_ext_macsec_feature_latch (sonic_ext_macsec_port_t *port, int enable)
{
  int rv;

  if ((u8) (enable ? 1 : 0) == port->feature_enabled)
    return 0;

  rv = vnet_feature_enable_disable (sonic_ext_macsec_arc_name (port->direction),
				    sonic_ext_macsec_node_name (port->direction),
				    port->sw_if_index, enable, 0, 0);
  if (rv == 0)
    port->feature_enabled = enable ? 1 : 0;
  else
    clib_warning ("sonic-ext macsec: feature %s on sw_if_index %u dir %u failed (rv=%d)",
		  enable ? "enable" : "disable", port->sw_if_index, port->direction,
		  rv);
  return rv;
}

static int
sonic_ext_macsec_sa_destroy (u32 sa_index)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_sa_t *sa;
  sonic_ext_macsec_sc_t *sc;
  vlib_main_t *vm = vlib_get_main ();

  sa = sonic_ext_macsec_sa_get (sa_index);
  if (!sa)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  sc = sonic_ext_macsec_sc_get (sa->sc_index);
  vlib_worker_thread_barrier_sync (vm);
  if (sc && sa->an < SONIC_EXT_MACSEC_AN_MAX)
    clib_atomic_store_rel_n (&sc->sa_index[sa->an], ~0);
  if (sa->crypto_ctx)
    {
      /* ctx_destroy defers free until this barrier is released. */
      vnet_crypto_ctx_destroy (vm, sa->crypto_ctx);
      sa->crypto_ctx = 0;
    }
  pool_put (mm->sas, sa);
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

static int
sonic_ext_macsec_sc_destroy (u32 sc_index)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_sc_t *sc;
  sonic_ext_macsec_port_t *port;
  u32 an;

  sc = sonic_ext_macsec_sc_get (sc_index);
  if (!sc)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  for (an = 0; an < SONIC_EXT_MACSEC_AN_MAX; an++)
    if (sc->sa_index[an] != ~0)
      sonic_ext_macsec_sa_destroy (sc->sa_index[an]);

  port = sonic_ext_macsec_port_get (sc->port_index, sc->direction);
  if (port && port->sc_index == sc_index)
    port->sc_index = ~0;

  sonic_ext_macsec_sc_hash_unset (sc);
  pool_put (mm->scs, sc);
  return 0;
}

int
sonic_ext_macsec_port_add_del (u32 sw_if_index, u8 direction, u8 encrypt,
			       u8 send_sci, u8 replay_protect, u32 replay_window,
			       int is_add)
{
  sonic_ext_macsec_port_t *port;
  int rv;

  if (direction >= SONIC_EXT_MACSEC_N_DIR)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      port = sonic_ext_macsec_port_get_or_create (sw_if_index, direction);
      port->sw_if_index = sw_if_index;
      port->direction = direction;
      port->encrypt = encrypt ? 1 : 0;
      port->send_sci = send_sci ? 1 : 0;
      port->replay_protect = replay_protect ? 1 : 0;
      port->replay_window = replay_window;
      port->enabled = 1;
      rv = sonic_ext_macsec_feature_latch (port, 1);
      if (rv)
	{
	  port->enabled = 0;
	  return rv;
	}
      sonic_ext_macsec_mtu_adjust (sw_if_index, 1);
      return 0;
    }

  port = sonic_ext_macsec_port_get (sw_if_index, direction);
  if (!port || !port->enabled)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (port->sc_index != ~0)
    sonic_ext_macsec_sc_destroy (port->sc_index);

  rv = sonic_ext_macsec_feature_latch (port, 0);
  port->enabled = 0;
  sonic_ext_macsec_mtu_adjust (sw_if_index, 0);
  return rv;
}

int
sonic_ext_macsec_sc_add_del (u32 sw_if_index, u8 direction, u64 sci, u8 cipher,
			     u8 explicit_sci, u8 conf_offset, int is_add)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_port_t *port;
  sonic_ext_macsec_sc_t *sc, *existing;
  u32 sc_index, an;

  (void) explicit_sci;

  if (direction >= SONIC_EXT_MACSEC_N_DIR)
    return VNET_API_ERROR_INVALID_VALUE;
  if (is_add && cipher != SONIC_EXT_MACSEC_CS_GCM_AES_128)
    return VNET_API_ERROR_INVALID_VALUE;
  if (is_add && conf_offset != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (!is_add)
    {
      existing = sonic_ext_macsec_sc_by_sci (sw_if_index, sci, direction);
      if (!existing)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      return sonic_ext_macsec_sc_destroy (existing - mm->scs);
    }

  port = sonic_ext_macsec_port_get (sw_if_index, direction);
  if (!port || !port->enabled)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (port->sc_index != ~0)
    {
      existing = sonic_ext_macsec_sc_get (port->sc_index);
      /* Same SCI: idempotent retry. Different SCI: the port is taken. */
      if (existing && existing->sci == sci)
	return VNET_API_ERROR_VALUE_EXIST;
      return VNET_API_ERROR_RSRC_IN_USE;
    }
  if (sonic_ext_macsec_sc_by_sci (sw_if_index, sci, direction))
    return VNET_API_ERROR_VALUE_EXIST;

  pool_get_zero (mm->scs, sc);
  sc_index = sc - mm->scs;
  clib_memset (&sc->key, 0, sizeof (sc->key));
  sc->key.sci = sci;
  sc->key.sw_if_index = sw_if_index;
  sc->key.direction = direction;
  sc->sci = sci;
  sc->port_index = sw_if_index;
  sc->direction = direction;
  sc->cipher = cipher;
  sc->encoding_an = 0;
  for (an = 0; an < SONIC_EXT_MACSEC_AN_MAX; an++)
    sc->sa_index[an] = ~0;
  sonic_ext_macsec_sc_hash_set (sc, sc_index);
  port->sc_index = sc_index;
  return 0;
}

int
sonic_ext_macsec_sc_set_encoding_an (u32 sw_if_index, u64 sci, u8 an)
{
  sonic_ext_macsec_sc_t *sc;

  if (an >= SONIC_EXT_MACSEC_AN_MAX)
    return VNET_API_ERROR_INVALID_VALUE;

  sc = sonic_ext_macsec_sc_by_sci (sw_if_index, sci, SONIC_EXT_MACSEC_EGRESS);
  if (!sc)
    sc = sonic_ext_macsec_sc_by_sci (sw_if_index, sci, SONIC_EXT_MACSEC_INGRESS);
  if (!sc)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  clib_atomic_store_rel_n (&sc->encoding_an, an);
  return 0;
}

int
sonic_ext_macsec_sa_add_del (u32 sw_if_index, u8 direction, u64 sci, u8 an,
			     const u8 *sak, u8 sak_len, const u8 *salt, u32 ssci,
			     u8 xpn_en, u64 init_xpn, int is_add)
{
  sonic_ext_macsec_main_t *mm = &sonic_ext_macsec_main;
  sonic_ext_macsec_sc_t *sc;
  sonic_ext_macsec_sa_t *sa;
  vnet_crypto_ctx_t *ctx;
  u32 sa_index;

  if (direction >= SONIC_EXT_MACSEC_N_DIR || an >= SONIC_EXT_MACSEC_AN_MAX)
    return VNET_API_ERROR_INVALID_VALUE;

  sc = sonic_ext_macsec_sc_by_sci (sw_if_index, sci, direction);
  if (!sc)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_add)
    {
      if (sc->sa_index[an] == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      return sonic_ext_macsec_sa_destroy (sc->sa_index[an]);
    }

  if (xpn_en || sak_len != 16 || sak == 0)
    return VNET_API_ERROR_INVALID_VALUE;
  if (sc->sa_index[an] != ~0)
    return VNET_API_ERROR_VALUE_EXIST;

  ctx = vnet_crypto_ctx_create (VNET_CRYPTO_ALG_AES_128_GCM);
  if (!ctx || !vnet_crypto_ctx_set_cipher_key (ctx, sak, sak_len) ||
      vnet_crypto_ctx_get_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_SIMPLE) ==
	VNET_CRYPTO_ENGINE_ID_NONE)
    {
      if (ctx)
	vnet_crypto_ctx_destroy (vlib_get_main (), ctx);
      if (!mm->no_handler_logged)
	{
	  clib_warning (
	    "sonic-ext macsec: no aes-128-gcm handler bound "
	    "(install vpp-crypto-engines; native/openssl auto-load "
	    "from vpp_crypto_engines/)");
	  mm->no_handler_logged = 1;
	}
      return VNET_API_ERROR_UNSPECIFIED;
    }

  pool_get_zero (mm->sas, sa);
  sa_index = sa - mm->sas;
  sa->sc_index = sc - mm->scs;
  sa->an = an;
  sa->xpn_en = 0;
  sa->sak_len = sak_len;
  if (salt)
    clib_memcpy (sa->salt, salt, SONIC_EXT_MACSEC_SALT_LEN);
  sa->ssci = ssci;
  sa->crypto_ctx = ctx;
  sa->next_xpn = init_xpn ? init_xpn : 1;
  sa->lowest_acceptable_xpn = sa->next_xpn;
  clib_atomic_store_rel_n (&sc->sa_index[an], sa_index);
  return 0;
}

int
sonic_ext_macsec_sa_set_xpn (u32 sw_if_index, u8 direction, u64 sci, u8 an,
			     u64 xpn)
{
  sonic_ext_macsec_sc_t *sc;
  sonic_ext_macsec_sa_t *sa;

  if (direction >= SONIC_EXT_MACSEC_N_DIR || an >= SONIC_EXT_MACSEC_AN_MAX)
    return VNET_API_ERROR_INVALID_VALUE;

  sc = sonic_ext_macsec_sc_by_sci (sw_if_index, sci, direction);
  if (!sc)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  sa = sonic_ext_macsec_sa_get (sc->sa_index[an]);
  if (!sa)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  clib_atomic_store_rel_n (&sa->next_xpn, xpn);
  clib_atomic_store_rel_n (&sa->lowest_acceptable_xpn, xpn);
  return 0;
}

static clib_error_t *
sonic_ext_macsec_sw_if_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  u8 dir;
  (void) vnm;

  if (is_add)
    return 0;

  for (dir = 0; dir < SONIC_EXT_MACSEC_N_DIR; dir++)
    {
      sonic_ext_macsec_port_t *port =
	sonic_ext_macsec_port_get (sw_if_index, dir);
      if (port && port->enabled)
	sonic_ext_macsec_port_add_del (sw_if_index, dir, 0, 0, 0, 0, 0);
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (sonic_ext_macsec_sw_if_add_del);

static clib_error_t *
sonic_ext_macsec_init (vlib_main_t *vm)
{
  (void) vm;
  clib_memset (&sonic_ext_macsec_main, 0, sizeof (sonic_ext_macsec_main));
  sonic_ext_macsec_ensure_hash ();
  return 0;
}

VLIB_INIT_FUNCTION (sonic_ext_macsec_init);
