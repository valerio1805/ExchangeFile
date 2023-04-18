#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include "x509_custom.h"

/*
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
*/


static const unsigned char sanctum_eca_key_pub[] = {
  0x0f, 0xaa, 0xd4, 0xff, 0x01, 0x17, 0x85, 0x83, 0xba, 0xa5, 0x88, 0x96,
  0x6f, 0x7c, 0x1f, 0xf3, 0x25, 0x64, 0xdd, 0x17, 0xd7, 0xdc, 0x2b, 0x46,
  0xcb, 0x50, 0xa8, 0x4a, 0x69, 0x27, 0x0b, 0x4c
};

static const unsigned char sanctum_dev_secret_key[] = {
  0x40, 0xa0, 0x99, 0x47, 0x8c, 0xce, 0xfa, 0x3a, 0x06, 0x63, 0xab, 0xc9,
  0x5e, 0x7a, 0x1e, 0xc9, 0x54, 0xb4, 0xf5, 0xf6, 0x45, 0xba, 0xd8, 0x04,
  0xdb, 0x13, 0xe7, 0xd7, 0x82, 0x6c, 0x70, 0x73, 0x57, 0x6a, 0x9a, 0xb6,
  0x21, 0x60, 0xd9, 0xd1, 0xc6, 0xae, 0xdc, 0x29, 0x85, 0x2f, 0xb9, 0x60,
  0xee, 0x51, 0x32, 0x83, 0x5a, 0x16, 0x89, 0xec, 0x06, 0xa8, 0x72, 0x34,
  0x51, 0xaa, 0x0e, 0x4a
};

int main(){
  
 unsigned char key1_priv[64];
 unsigned char key1_pub[32];
  /*
  ed25519_create_keypair(key1_pub,key1_priv,0);
  for(int i = 0; i < 32; i ++){
    printf("%02X", key1_pub[i]);
  }*/

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);
  
  int ret;
  char error_buf[100];

  /*
  ret = mbedtls_x509write_crt_set_subject_name(&cert, "CN=test.com,O=Test Organization,L=Italy,C=IT");
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore1: %s\n", error_buf );
  }
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, "CN=example.com,O=Example Organization,L=San Francisco,C=US");
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore2: %s\n", error_buf );
        return 0;

} 
*/
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&cert, "CN=example.com,O=Example Organization,L=San Francisco,C=US");
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore3: %s\n", error_buf );
        return 0;

} 
ret = mbedtls_x509write_crt_set_subject_name_mod(&cert, "CN=test.com,O=Test Organization,L=Italy,C=IT");
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore3: %s\n", error_buf );
        return 0;

} 
/*
for(int i = 0; i < cert.ne_issue_arr;i++){
  printf("Caratteristica letta:\n");
  for(int j = 0; j<cert.issuer_arr[i].val.len; j++)
    printf("%c", cert.issuer_arr[i].val.p_arr[j]);
  printf("\n");
}
*/
  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);

  mbedtls_x509_crt uff_cert;
  mbedtls_x509_crt_init(&uff_cert);

  
  ret = mbedtls_pk_parse_public_key(&subj_key, sanctum_eca_key_pub, 32, 0);
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore lettura chiave pubblica" );
    return 0;
  }
  ret = mbedtls_pk_parse_public_key(&issu_key, sanctum_dev_secret_key, 64, 1);
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore lettura chiave privata" );
    return 0;
  }

  unsigned char serial_test[] = {"0xa, 0xa, 0xA"} ;
  mbedtls_x509write_crt_set_subject_key(&cert, &subj_key);
  mbedtls_x509write_crt_set_issuer_key(&cert, &issu_key);
  mbedtls_x509write_crt_set_serial_raw(&cert, serial_test, 3);
  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA512);
  ret = mbedtls_x509write_crt_set_validity(&cert, "20220101000000", "20230101000000");
  if( ret != 0 )
  {
    //mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore: %s\n", error_buf );
    return 0;
  }
  unsigned char cert_der[4096];
  size_t len_cert_der_tot = 4096;
  size_t effe_len_cert_der;

  unsigned char oid_ext[] = {0xff, 0x20, 0xff};

  unsigned char ext_val[] = {0xff, 0x20, 0xff,0xff, 0x20, 0xff,0xff, 0x20, 0xff, 0xAB};

  mbedtls_x509write_crt_set_extension(&cert, oid_ext, 3, 0, ext_val, 11);

  ret = mbedtls_x509write_crt_der(&cert,cert_der,len_cert_der_tot,NULL,NULL);
  if (ret !=0){
    effe_len_cert_der = ret;

  }

  unsigned char *cert_real = cert_der;
  int dif = 4096-effe_len_cert_der;
  cert_real += dif;

  if ((ret = mbedtls_x509_crt_parse_der(&uff_cert, cert_real, effe_len_cert_der)) == 0){
        printf("Parsing corretto\n");

  }
  
  printf("Stampa dopo lettura pubblica\n");
    for(int i =0; i <32; i ++){
        printf("%02x",uff_cert.pk.pk_ctx.pub_key[i]);//   pk_ctx->pub_key[i]);
    }
  printf("\n");

  printf("\nStampa hash inserito come extension\n");
    for(int i =0; i <10; i ++){
        printf("%02x",uff_cert.hash.p[i]);//   pk_ctx->pub_key[i]);
    }
  printf("\n");

  
  
  /*
  unsigned char* sig_oid;
  int sig_oid_len;
  mbedtls_oid_get_oid_by_sig_alg(MBEDTLS_PK_RSA, MBEDTLS_MD_MD5, &sig_oid, &sig_oid_len);
  printf("STAMPA\n");
  for(int i =0; i <sig_oid_len; i ++){
        printf("%02x\n",sig_oid[i]);
  }
  printf("FINE STAMPA\n");
  unsigned char* sig_oid2;
  int sig_oid_len2;
  mbedtls_oid_get_oid_by_sig_alg(MBEDTLS_PK_ED25519, MBEDTLS_MD_SHA512, &sig_oid2, &sig_oid_len2);
  printf("STAMPA\n");
  for(int i =0; i <sig_oid_len2; i ++){
        printf("%02x\n",sig_oid2[i]);
  }
  printf("FINE STAMPA\n");
  printf("Lunghezza: %d\n", sig_oid_len2);
  */
  /*
  30
78
32
42
00
78
36
35
00
78
37
30*/

  //mbedtls_x509write_crt_der
  /*
  //unsigned char output_buf[4096];
  //int output_len = 0;
  //mbedtls_ctr_drbg_context ctr_drbg;
  //mbedtls_ctr_drbg_init(&ctr_drbg);
  //ret = mbedtls_x509write_crt_pem(&cert, output_buf, sizeof(output_buf), NULL, NULL); //mbedtls_ctr_drbg_random, &ctr_drbg);
 //if( ret != 0 )
  //{
    char error_buf[100];
    mbedtls_strerror( ret, error_buf, 100 );
    printf( "Errore: %s\n", error_buf );
    return 0;
  }
  output_len = strlen((char*)output_buf); // determina la lunghezza del certificato generato
  printf("Certificato:\n %s\n", (output_buf)); 
  */
}



/////////////////////////////////////////////////////////////////////////////////////////////////
// PER CREARE PK
/*
 mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "key_generation";

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed the random number generator: %d\n", ret);
        return 1;
    }

    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        printf("Failed to set up the key: %d\n", ret);
        return 1;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (ret != 0) {
        printf("Failed to generate the key: %d\n", ret);
        return 1;
    }

    unsigned char pub_key_buf[2048];
    size_t pub_key_len;
    ret = mbedtls_pk_write_pubkey_der(&pk, pub_key_buf, sizeof(pub_key_buf));
    if (ret < 0) {
        printf("Failed to write the public key: %d\n", ret);
        return 1;
    }
    pub_key_len = ret;

    printf("Public key:\n");
    for (size_t i = 0; i < pub_key_len; i++) {
        printf("%02X", pub_key_buf[i]);
    }
    printf("\n");





*/

