
OPENSSL_GIT_COMMIT_HASH :="902f3f50d051dfd6ebf009d352aaf581195caabf"

OPENSSL_PATH :=$(EXTERNAL_SOURCE_ROOT_DIR)/openssl
ifeq ("$(wildcard $(OPENSSL_PATH))","")
    $(info   )
    $(info --- OpenSSL path $(OPENSSL_PATH) dont exists )
    $(info --- get repo from andew zamansky or from https://github.com/openssl/openssl  )
    $(info --- make sure that .git directory is located in $(OPENSSL_PATH)/  after unpacking   )
    $(error )
endif

# test if current commit and branch of openssl git is
# the same as required by application
CURR_GIT_REPO_DIR :=$(OPENSSL_PATH)
CURR_GIT_COMMIT_HASH_VARIABLE :=OPENSSL_GIT_COMMIT_HASH
#CURR_GIT_BUNDLE :=$(CURR_OPENSSL_COMPONENT_LOCATION)/openssl.bundle
include $(MAKEFILES_ROOT_DIR)/_include_functions/git_prebuild_repo_check.mk


ifneq ($(strip $(CONFIG_OPENSSL_RSA)),y)
    DUMMY := $(call ADD_TO_GLOBAL_DEFINES , OPENSSL_NO_RSA )
endif
ifneq ($(strip $(CONFIG_OPENSSL_DSA)),y)
    DUMMY := $(call ADD_TO_GLOBAL_DEFINES , OPENSSL_NO_DSA )
endif

DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_MD4 )
#DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_SHA )



   # DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_SOCK) #  No socket code.
DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_SSL2 )     #    No SSLv2.
DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_SSL3 )     #    No SSLv3.
DUMMY := $(call ADD_TO_GLOBAL_DEFINES ,OPENSSL_NO_ENGINE) #NoDynamicEngines.


# a lot of includes are in form <openssl/file.h>
# but there is folder named "openssl" in source tree that include these
# files, they are distributed over all source tree.
# this version of open ssl is expecting to find these files
# in systmem path (e.g. in linux /usr/include/openssl/file.h) so these
# files were just dublicatred in $(CURR_COMPONENT_DIR)/openssl_git/include

# CURR_COMPONENT_DIR is pointing to parent directory
INCLUDE_DIR += $(CURR_COMPONENT_DIR)/openssl_git/include


INCLUDE_DIR += $(CURR_COMPONENT_DIR)/openssl_git/include/openssl
INCLUDE_DIR += $(OPENSSL_PATH)/include
INCLUDE_DIR += $(OPENSSL_PATH)/crypto
INCLUDE_DIR += $(OPENSSL_PATH)/crypto/asn1
INCLUDE_DIR += $(OPENSSL_PATH)/crypto/evp
INCLUDE_DIR += $(OPENSSL_PATH)/crypto/modes
INCLUDE_DIR += $(OPENSSL_PATH) #for e_os.h



ifeq ($(strip $(CONFIG_USE_INTERNAL_SOCKETS_IMPLEMENTATION)),y)
    DEFINES += USE_CUSTOM_SOCKET_IN_COMPILED_MODULE
endif


ifneq ($(strip $(CONFIG_OPENSSL_MD5)),y)
    DEFINES += OPENSSL_NO_MD5
endif

ifneq ($(strip $(CONFIG_OPENSSL_DES)),y)
    DEFINES += OPENSSL_NO_DES
endif

ifneq ($(strip $(CONFIG_OPENSSL_DH)),y)
    DEFINES += OPENSSL_NO_DH
endif

ifneq ($(strip $(CONFIG_OPENSSL_SOCKET)),y)
    DEFINES += OPENSSL_NO_SOCK
endif

DEFINES += OPENSSL_NO_IDEA
#DEFINES += OPENSSL_NO_AES
DEFINES += OPENSSL_NO_CAMELLIA
DEFINES += OPENSSL_NO_SEED
DEFINES += OPENSSL_NO_BF
DEFINES += OPENSSL_NO_CAST
DEFINES += OPENSSL_NO_RC2
DEFINES += OPENSSL_NO_RC4
DEFINES += OPENSSL_NO_RC5

DEFINES += OPENSSL_NO_MD2

DEFINES += OPENSSL_NO_MDC2
DEFINES += OPENSSL_NO_MULTIBLOCK

#DEFINES += OPENSSL_NO_ECDSA
#DEFINES += OPENSSL_NO_ECDH
DEFINES += OPENSSL_NO_TLS1_3

DEFINES += OPENSSL_NO_ERR    #    No error strings.
DEFINES += OPENSSL_NO_KRB5   #    No Kerberos v5.

DEFINES += OPENSSL_NO_HW     #     No support for external hardware.

DEFINES += OPENSSL_NO_JPAKE
DEFINES += OPENSSL_NO_CAPIENG

DEFINES += OPENSSL_NO_WHRLPOOL
DEFINES += OPENSSL_NO_STORE
#DEFINES += OPENSSL_NO_SHA0
DEFINES += OPENSSL_NO_RFC3779
DEFINES += OPENSSL_NO_GMP
DEFINES += OPENSSL_NO_FIPS
DEFINES += OPENSSL_NO_ASM


DEFINES += OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
DEFINES += OPENSSL_NO_CRYPTO_MDEBUG

ifeq ($(CONFIG_HOST),y)
    DEFINES += COMPILING_FOR_HOST
    ifeq ($(findstring WINDOWS,$(COMPILER_HOST_OS)),WINDOWS)
        ifdef CONFIG_MICROSOFT_COMPILER
            DEFINES += _WINSOCKAPI_
            DEFINES += NO_WINDOWS_BRAINDEATH
        endif
        DEFINES += COMPILING_FOR_WINDOWS_HOST
    else
        DEFINES += COMPILING_FOR_LINUX_HOST
    endif
endif



#ASMFLAGS =


SRC += crypto/cversion.c
SRC += crypto/mem.c
SRC += crypto/o_init.c
SRC += crypto/uid.c
SRC += crypto/o_str.c
SRC += crypto/o_time.c
SRC += crypto/mem_clr.c
SRC += crypto/cryptlib.c
SRC += crypto/ex_data.c

SRC += crypto/mem_dbg.c
ifeq ($(findstring WINDOWS,$(COMPILER_HOST_OS)),WINDOWS)
    SRC += crypto/threads_win.c
endif
SRC += crypto/o_fips.c
SRC += crypto/o_dir.c

ifeq ($(findstring WINDOWS,$(COMPILER_HOST_OS)),WINDOWS)
    SRC += crypto/async/arch/async_win.c
endif

SRC += crypto/stack/stack.c

SRC += crypto/modes/cbc128.c
SRC += crypto/modes/ctr128.c
SRC += crypto/modes/ofb128.c
SRC += crypto/modes/cfb128.c
SRC += crypto/modes/gcm128.c
SRC += crypto/modes/ccm128.c
SRC += crypto/modes/xts128.c
SRC += crypto/modes/wrap128.c

SRC += crypto/dso/dso_lib.c
SRC += crypto/dso/dso_null.c
SRC += crypto/dso/dso_openssl.c


SRC += crypto/bio/bio_lib.c
SRC += crypto/bio/bss_mem.c
SRC += crypto/bio/b_print.c
SRC += crypto/bio/b_dump.c
SRC += crypto/bio/bss_file.c
SRC += crypto/bio/b_sock.c
SRC += crypto/bio/bss_conn.c
SRC += crypto/bio/bf_buff.c
SRC += crypto/bio/bss_file.c
SRC += crypto/bio/bss_sock.c
SRC += crypto/bio/bss_null.c

SRC += crypto/bn/bn_print.c
SRC += crypto/bn/bn_mont.c
SRC += crypto/bn/bn_shift.c
SRC += crypto/bn/bn_asm.c
SRC += crypto/bn/bn_ctx.c
SRC += crypto/bn/bn_mul.c
SRC += crypto/bn/bn_sqr.c
SRC += crypto/bn/bn_div.c
SRC += crypto/bn/bn_gcd.c
SRC += crypto/bn/bn_add.c
SRC += crypto/bn/bn_mod.c
SRC += crypto/bn/bn_rand.c
SRC += crypto/bn/bn_exp.c
SRC += crypto/bn/bn_recp.c
SRC += crypto/bn/bn_prime.c
SRC += crypto/bn/bn_exp2.c
SRC += crypto/bn/bn_blind.c
SRC += crypto/bn/bn_nist.c
SRC += crypto/bn/bn_lib.c
SRC += crypto/bn/bn_word.c
SRC += crypto/bn/bn_const.c
SRC += crypto/bn/bn_gf2m.c
SRC += crypto/bn/bn_kron.c
SRC += crypto/bn/bn_sqrt.c

SRC += crypto/txt_db/txt_db.c

SRC += crypto/buffer/buffer.c
SRC += crypto/buffer/buf_str.c

ifeq ($(strip $(CONFIG_OPENSSL_CMS)),y)
    SRC += crypto/cms/cms_io.c
    SRC += crypto/cms/cms_pwri.c
    SRC += crypto/cms/cms_enc.c
    SRC += crypto/cms/cms_lib.c
    SRC += crypto/cms/cms_dd.c
    SRC += crypto/cms/cms_kari.c
    SRC += crypto/cms/cms_asn1.c
    SRC += crypto/cms/cms_ess.c
    SRC += crypto/cms/cms_att.c
    SRC += crypto/cms/cms_env.c
    SRC += crypto/cms/cms_sd.c
else
    DEFINES += OPENSSL_NO_CMS
endif

SRC += crypto/asn1/bio_asn1.c
SRC += crypto/asn1/a_bool.c
SRC += crypto/asn1/a_set.c
SRC += crypto/asn1/bio_ndef.c
SRC += crypto/asn1/asn_mime.c
SRC += crypto/asn1/a_bytes.c
SRC += crypto/asn1/t_x509a.c
SRC += crypto/asn1/t_x509.c
SRC += crypto/asn1/asn1_gen.c
SRC += crypto/asn1/a_enum.c
SRC += crypto/asn1/asn1_lib.c
SRC += crypto/asn1/a_object.c
SRC += crypto/asn1/a_strex.c
SRC += crypto/asn1/a_time.c
SRC += crypto/asn1/a_print.c
SRC += crypto/asn1/a_utf8.c
SRC += crypto/asn1/asn1_par.c
SRC += crypto/asn1/a_mbstr.c
SRC += crypto/asn1/tasn_typ.c
SRC += crypto/asn1/tasn_new.c
SRC += crypto/asn1/tasn_fre.c
SRC += crypto/asn1/a_utctm.c
SRC += crypto/asn1/tasn_dec.c
SRC += crypto/asn1/a_bitstr.c
SRC += crypto/asn1/a_gentm.c
SRC += crypto/asn1/tasn_enc.c
SRC += crypto/asn1/asn_moid.c
SRC += crypto/asn1/a_strnid.c
SRC += crypto/asn1/x_bignum.c
SRC += crypto/asn1/x_long.c
SRC += crypto/asn1/a_dup.c
SRC += crypto/asn1/a_type.c
SRC += crypto/asn1/asn_pack.c
SRC += crypto/asn1/evp_asn1.c
SRC += crypto/asn1/a_octet.c
SRC += crypto/asn1/ameth_lib.c
SRC += crypto/asn1/x_attrib.c
SRC += crypto/rsa/rsa_asn1.c
SRC += crypto/asn1/a_int.c
SRC += crypto/asn1/t_pkey.c
SRC += crypto/asn1/x_algor.c
SRC += crypto/asn1/p8_pkey.c
SRC += crypto/asn1/p5_pbe.c
SRC += crypto/asn1/p5_pbev2.c
SRC += crypto/asn1/a_d2i_fp.c
SRC += crypto/asn1/nsseq.c
SRC += crypto/asn1/x_sig.c
SRC += crypto/asn1/a_i2d_fp.c
SRC += crypto/asn1/d2i_pr.c
SRC += crypto/asn1/x_pkey.c
SRC += crypto/asn1/i2d_pr.c
SRC += crypto/asn1/tasn_prn.c
SRC += crypto/asn1/f_int.c
SRC += crypto/asn1/a_sign.c
SRC += crypto/asn1/tasn_utl.c
SRC += crypto/asn1/f_string.c
SRC += crypto/asn1/x_spki.c
SRC += crypto/asn1/a_digest.c
SRC += crypto/asn1/a_verify.c
SRC += crypto/asn1/x_val.c
SRC += crypto/asn1/t_x509.c
SRC += crypto/asn1/x_x509.c
SRC += crypto/asn1/x_pubkey.c
SRC += crypto/asn1/x_name.c
SRC += crypto/asn1/x_crl.c
SRC += crypto/asn1/x_info.c
SRC += crypto/asn1/x_req.c
SRC += crypto/asn1/x_x509a.c
SRC += crypto/asn1/x_exten.c

SRC += crypto/srp/srp_vfy.c
SRC += crypto/srp/srp_lib.c

SRC += crypto/cmac/cm_ameth.c
SRC += crypto/cmac/cm_pmeth.c

SRC += crypto/pkcs7/pk7_lib.c
SRC += crypto/pkcs7/pk7_doit.c
SRC += crypto/pkcs7/pk7_asn1.c
SRC += crypto/pkcs7/pk7_attr.c

SRC += crypto/ecdh/ech_ossl.c
SRC += crypto/ecdh/ech_kdf.c
SRC += crypto/ecdh/ech_key.c
SRC += crypto/ecdh/ech_lib.c

SRC += crypto/ecdsa/ecs_asn1.c
SRC += crypto/ecdsa/ecs_ossl.c
SRC += crypto/ecdsa/ecs_lib.c
SRC += crypto/ecdsa/ecs_sign.c
SRC += crypto/ecdsa/ecs_vrf.c

SRC += crypto/evp/c_all.c
SRC += crypto/evp/m_dss1.c
SRC += crypto/evp/m_dss.c
SRC += crypto/evp/m_sha.c
SRC += crypto/evp/m_ecdsa.c
SRC += crypto/evp/bio_md.c
SRC += crypto/evp/bio_b64.c
SRC += crypto/evp/p_lib.c
SRC += crypto/evp/evp_cnf.c
SRC += crypto/evp/c_allc.c
SRC += crypto/evp/c_alld.c
SRC += crypto/evp/names.c
SRC += crypto/evp/e_des.c
SRC += crypto/evp/e_des3.c
SRC += crypto/evp/e_aes.c
SRC += crypto/evp/e_xcbc_d.c
SRC += crypto/evp/e_aes_cbc_hmac_sha1.c
SRC += crypto/evp/m_sha1.c
SRC += crypto/evp/m_md5.c
SRC += crypto/evp/evp_lib.c
SRC += crypto/evp/e_aes_cbc_hmac_sha256.c
SRC += crypto/evp/m_wp.c
SRC += crypto/evp/evp_enc.c
SRC += crypto/evp/evp_pbe.c
SRC += crypto/evp/p5_crpt.c
SRC += crypto/evp/p5_crpt2.c
SRC += crypto/evp/digest.c
SRC += crypto/evp/pmeth_lib.c
SRC += crypto/evp/evp_pkey.c
SRC += crypto/evp/encode.c
SRC += crypto/evp/evp_key.c
SRC += crypto/evp/pmeth_gn.c
SRC += crypto/evp/p_sign.c
SRC += crypto/evp/p_verify.c
SRC += crypto/evp/m_sigver.c
SRC += crypto/evp/bio_enc.c
SRC += crypto/evp/pmeth_fn.c
SRC += crypto/evp/e_null.c

SRC += crypto/cmac/cmac.c

SRC += crypto/pkcs12/p12_mutl.c
SRC += crypto/pkcs12/p12_attr.c
SRC += crypto/pkcs12/p12_kiss.c
SRC += crypto/pkcs12/p12_add.c
SRC += crypto/pkcs12/p12_crpt.c
SRC += crypto/pkcs12/p12_key.c
SRC += crypto/pkcs12/p12_utl.c
SRC += crypto/pkcs12/p12_asn.c
SRC += crypto/pkcs12/p12_p8d.c
SRC += crypto/pkcs12/p12_decr.c
SRC += crypto/pkcs12/p12_p8e.c

SRC += crypto/aes/aes_wrap.c
SRC += crypto/aes/aes_x86core.c
SRC += crypto/aes/aes_cbc.c



SRC += crypto/hmac/hm_ameth.c
SRC += crypto/hmac/hmac.c
SRC += crypto/hmac/hm_pmeth.c

SRC += crypto/whrlpool/wp_dgst.c
SRC += crypto/whrlpool/wp_block.c

SRC += crypto/lhash/lhash.c

SRC += crypto/objects/obj_lib.c
SRC += crypto/objects/obj_dat.c
SRC += crypto/objects/o_names.c
SRC += crypto/objects/obj_xref.c

SRC += crypto/sha/sha256.c
SRC += crypto/sha/sha_dgst.c
SRC += crypto/sha/sha512.c
SRC += crypto/sha/sha1_one.c
SRC += crypto/sha/sha1dgst.c

SRC += crypto/x509/x509_lu.c
SRC += crypto/x509/by_file.c
SRC += crypto/x509/x509_txt.c
SRC += crypto/x509/x509_set.c
SRC += crypto/x509/x509_cmp.c
SRC += crypto/x509/x509name.c
SRC += crypto/x509/x509_ext.c
SRC += crypto/x509/x509_v3.c
SRC += crypto/x509/x_all.c
SRC += crypto/x509/x509_def.c
SRC += crypto/x509/x509_att.c
SRC += crypto/x509/x509cset.c
SRC += crypto/x509/x509_vfy.c
SRC += crypto/x509/x509_vpm.c
SRC += crypto/x509/by_dir.c
SRC += crypto/x509/x509_d2.c
SRC += crypto/x509/x509type.c
SRC += crypto/x509/x509_req.c
SRC += crypto/x509/x509_obj.c
SRC += crypto/x509/x509rset.c


SRC += crypto/x509v3/v3_scts.c
SRC += crypto/x509v3/v3_prn.c
SRC += crypto/x509v3/v3_genn.c
SRC += crypto/x509v3/v3_purp.c
SRC += crypto/x509v3/v3_conf.c
SRC += crypto/x509v3/v3_utl.c
SRC += crypto/x509v3/v3_info.c
SRC += crypto/x509v3/v3_lib.c
SRC += crypto/x509v3/v3_alt.c
SRC += crypto/x509v3/v3_bcons.c
SRC += crypto/x509v3/v3_bitst.c
SRC += crypto/x509v3/v3_sxnet.c
SRC += crypto/x509v3/v3_pku.c
SRC += crypto/x509v3/v3_extku.c
SRC += crypto/x509v3/v3_ia5.c
SRC += crypto/x509v3/v3_skey.c
SRC += crypto/x509v3/v3_akey.c
SRC += crypto/x509v3/v3_int.c
SRC += crypto/x509v3/v3_enum.c
SRC += crypto/x509v3/v3_cpols.c
SRC += crypto/x509v3/v3_crld.c
SRC += crypto/x509v3/v3_akeya.c
SRC += crypto/x509v3/v3_pci.c
SRC += crypto/x509v3/v3_pmaps.c
SRC += crypto/x509v3/v3_pcons.c
SRC += crypto/x509v3/v3_ncons.c
SRC += crypto/x509v3/v3_pcia.c
SRC += crypto/x509v3/pcy_tree.c
SRC += crypto/x509/x509_trs.c
SRC += crypto/x509v3/pcy_cache.c
SRC += crypto/x509v3/pcy_data.c
SRC += crypto/x509v3/pcy_map.c
SRC += crypto/x509v3/pcy_lib.c
SRC += crypto/x509v3/pcy_node.c

SRC += crypto/err/err.c
SRC += crypto/err/err_prn.c

SRC += crypto/pem/pem_x509.c
SRC += crypto/pem/pem_info.c
SRC += crypto/pem/pem_xaux.c
SRC += crypto/pem/pem_all.c
SRC += crypto/pem/pem_lib.c
SRC += crypto/pem/pem_pkey.c
SRC += crypto/pem/pem_oth.c
SRC += crypto/pem/pem_pk8.c

SRC += ssl/ssl_err2.c
SRC += ssl/ssl_algs.c
SRC += ssl/s23_meth.c
SRC += ssl/s23_pkt.c
SRC += ssl/t1_meth.c
SRC += ssl/t1_clnt.c
SRC += ssl/t1_srvr.c
SRC += ssl/s23_lib.c
SRC += ssl/d1_meth.c
SRC += ssl/d1_clnt.c
SRC += ssl/d1_srvr.c
SRC += ssl/s3_srvr.c
SRC += ssl/s23_clnt.c
SRC += ssl/s23_srvr.c
SRC += ssl/s3_clnt.c
SRC += ssl/ssl_lib.c
SRC += ssl/ssl_rsa.c
SRC += ssl/bio_ssl.c
SRC += ssl/ssl_sess.c
SRC += ssl/s3_lib.c
SRC += ssl/s3_pkt.c
SRC += ssl/s3_both.c
SRC += ssl/t1_reneg.c
SRC += ssl/t1_lib.c
SRC += ssl/d1_lib.c
SRC += ssl/d1_pkt.c
SRC += ssl/d1_both.c
SRC += ssl/t1_enc.c
SRC += ssl/ssl_ciph.c
SRC += ssl/s3_enc.c
SRC += ssl/tls_srp.c
SRC += ssl/ssl_cert.c
SRC += ssl/s3_cbc.c
SRC += ssl/t1_ext.c
SRC += ssl/ssl_asn1.c
SRC += ssl/ssl_conf.c
SRC += ssl/d1_srtp.c

SRC += crypto/pqueue/pqueue.c

SRC += crypto/ec/ecp_nistp521.c
SRC += crypto/ec/ecp_nistp256.c
SRC += crypto/ec/ecp_nistp224.c
SRC += crypto/ec/ecp_nistputil.c
SRC += crypto/ec/ec_ameth.c
SRC += crypto/ec/ec_key.c
SRC += crypto/ec/ec_lib.c
SRC += crypto/ec/eck_prn.c
SRC += crypto/ec/ec_asn1.c
SRC += crypto/ec/ec_curve.c
SRC += crypto/ec/ec_cvt.c
SRC += crypto/ec/ec_oct.c
SRC += crypto/ec/ec_mult.c
SRC += crypto/ec/ec_print.c
SRC += crypto/ec/ecp_mont.c
SRC += crypto/ec/ecp_nist.c
SRC += crypto/ec/ec2_smpl.c
SRC += crypto/ec/ecp_oct.c
SRC += crypto/ec/ec2_oct.c
SRC += crypto/ec/ec_pmeth.c
SRC += crypto/ec/ecp_smpl.c
SRC += crypto/ec/ec2_mult.c

SRC += crypto/ui/ui_lib.c
SRC += crypto/ui/ui_openssl.c

SRC += crypto/ocsp/ocsp_vfy.c
SRC += crypto/ocsp/ocsp_prn.c
SRC += crypto/ocsp/ocsp_asn.c
SRC += crypto/ocsp/ocsp_cl.c
SRC += crypto/ocsp/ocsp_ext.c
SRC += crypto/ocsp/ocsp_lib.c
SRC += crypto/x509v3/v3_ocsp.c
SRC += crypto/ocsp/ocsp_ht.c

SRC += crypto/rand/rand_lib.c
SRC += crypto/rand/rand_egd.c
SRC += crypto/rand/randfile.c
SRC += crypto/rand/md_rand.c
ifeq ($(findstring WINDOWS,$(COMPILER_HOST_OS)),WINDOWS)
    SRC += crypto/rand/rand_win.c
else ifeq ($(findstring LINUX,$(COMPILER_HOST_OS)),LINUX)
    SRC += crypto/rand/rand_unix.c
endif

SRC += crypto/comp/c_zlib.c
SRC += crypto/comp/comp_lib.c


SRC += crypto/conf/conf_mod.c
SRC += crypto/conf/conf_mall.c
SRC += crypto/conf/conf_lib.c
SRC += crypto/conf/conf_def.c
SRC += crypto/conf/conf_api.c
SRC += crypto/conf/conf_sap.c


ifeq ($(strip $(CONFIG_OPENSSL_RSA)),y)
    SRC += crypto/rsa/rsa_eay.c
    SRC += crypto/rsa/rsa_lib.c
    SRC += crypto/rsa/rsa_ameth.c
    SRC += crypto/rsa/rsa_pmeth.c
    SRC += crypto/rsa/rsa_crpt.c
    SRC += crypto/rsa/rsa_crpt.c
    SRC += crypto/rsa/rsa_gen.c
    SRC += crypto/rsa/rsa_sign.c
    SRC += crypto/rsa/rsa_saos.c
    SRC += crypto/rsa/rsa_oaep.c
    SRC += crypto/rsa/rsa_x931.c
    SRC += crypto/rsa/rsa_pss.c
    SRC += crypto/rsa/rsa_pk1.c
    SRC += crypto/rsa/rsa_ssl.c
    SRC += crypto/rsa/rsa_none.c
endif

ifeq ($(strip $(CONFIG_OPENSSL_DSA)),y)
    SRC += crypto/dsa/dsa_lib.c
    SRC += crypto/dsa/dsa_ossl.c
    SRC += crypto/dso/dso_dl.c
    SRC += crypto/dsa/dsa_lib.c
    SRC += crypto/dsa/dsa_asn1.c
    SRC += crypto/dso/dso_dlfcn.c
    SRC += crypto/dsa/dsa_sign.c
    SRC += crypto/dsa/dsa_vrf.c
    SRC += crypto/dsa/dsa_ameth.c
    SRC += crypto/dsa/dsa_pmeth.c
    SRC += crypto/dsa/dsa_gen.c
    SRC += crypto/dsa/dsa_key.c
endif

ifeq ($(strip $(CONFIG_OPENSSL_DH)),y)
    SRC += crypto/dh/dh_kdf.c
    SRC += crypto/dh/dh_lib.c
    SRC += crypto/dh/dh_key.c
    SRC += crypto/dh/dh_check.c
    SRC += crypto/dh/dh_ameth.c
    SRC += crypto/dh/dh_asn1.c
    SRC += crypto/dh/dh_pmeth.c
    SRC += crypto/dh/dh_gen.c
    SRC += crypto/dh/dh_rfc5114.c
endif

ifeq ($(strip $(CONFIG_OPENSSL_MD5)),y)
    SRC += crypto/md5/md5_dgst.c
endif

ifeq ($(strip $(CONFIG_OPENSSL_RIPEMD)),y)
    SRC += crypto/ripemd/rmd_dgst.c
    SRC += crypto/evp/m_ripemd.c
else
    DEFINES += OPENSSL_NO_RIPEMD
endif

ifeq ($(strip $(CONFIG_OPENSSL_DES)),y)
    SRC += crypto/des/set_key.c
    SRC += crypto/des/ecb_enc.c
    SRC += crypto/des/des_enc.c
    SRC += crypto/des/cfb_enc.c
    SRC += crypto/des/cfb64enc.c
    SRC += crypto/des/ofb64enc.c
    SRC += crypto/des/ecb3_enc.c
    SRC += crypto/des/cfb64ede.c
    SRC += crypto/des/ofb64ede.c
    SRC += crypto/des/xcbc_enc.c
endif

VPATH += | $(OPENSSL_PATH)

DISABLE_GLOBAL_INCLUDES_PATH := y

include $(COMMON_CC)
