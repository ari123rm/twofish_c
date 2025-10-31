#include "./std_defs.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define Q_TABLES
#define M_TABLE
#define MK_TABLE
#define ONE_STEP

static char *alg_name[] = { "twofish", "twofish.c", "twofish" };
char **cipher_name(void) { return alg_name; }

u4byte k_len;
u4byte l_key[40];
u4byte s_key[4];

/* GF(2^8) arithmetic */
#define G_M 0x0169
u1byte tab_5b[4] = {0, G_M >> 2, G_M >> 1, (G_M >> 1) ^ (G_M >> 2)};
u1byte tab_ef[4] = {0, (G_M >> 1) ^ (G_M >> 2), G_M >> 1, G_M >> 2};

#define ffm_01(x) (x)
#define ffm_5b(x) ((x) ^ ((x) >> 2) ^ tab_5b[(x) & 3])
#define ffm_ef(x) ((x) ^ ((x) >> 1) ^ ((x) >> 2) ^ tab_ef[(x) & 3])

u1byte ror4[16] = {0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15};
u1byte ashx[16] = {0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7};

u1byte qt0[2][16] = {
    {8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4},
    {2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5}
};
u1byte qt1[2][16] = {
    {14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13},
    {1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8}
};
u1byte qt2[2][16] = {
    {11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1},
    {4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15}
};
u1byte qt3[2][16] = {
    {13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10},
    {11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10}
};

u1byte qp(const u4byte n, const u1byte x)
{
    u1byte a0, a1, a2, a3, a4, b0, b1, b2, b3, b4;
    a0 = x >> 4; b0 = x & 15;
    a1 = a0 ^ b0; b1 = ror4[b0] ^ ashx[a0];
    a2 = qt0[n][a1]; b2 = qt1[n][b1];
    a3 = a2 ^ b2; b3 = ror4[b2] ^ ashx[a2];
    a4 = qt2[n][a3]; b4 = qt3[n][b3];
    return (b4 << 4) | a4;
}

#ifdef Q_TABLES
u4byte qt_gen = 0;
u1byte q_tab[2][256];
#define q(n, x) q_tab[n][x]
void gen_qtab(void)
{
    u4byte i;
    for (i = 0; i < 256; ++i) {
        q(0, i) = qp(0, (u1byte)i);
        q(1, i) = qp(1, (u1byte)i);
    }
}
#else
#define q(n,x) qp(n,x)
#endif

#ifdef M_TABLE
u4byte mt_gen = 0;
u4byte m_tab[4][256];
void gen_mtab(void)
{
    u4byte i,f01,f5b,fef;
    for(i=0;i<256;++i)
    {
        f01 = q(1,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[0][i] = f01 + (f5b<<8) + (fef<<16) + (fef<<24);
        m_tab[2][i] = f5b + (fef<<8) + (f01<<16) + (fef<<24);

        f01 = q(0,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[1][i] = fef + (fef<<8) + (f5b<<16) + (f01<<24);
        m_tab[3][i] = f5b + (f01<<8) + (fef<<16) + (f5b<<24);
    }
}
#define mds(n,x) m_tab[n][x]
#endif

/* h_fun */
u4byte h_fun(const u4byte x, const u4byte key[])
{
    u4byte b0 = byte(x,0), b1 = byte(x,1), b2 = byte(x,2), b3 = byte(x,3);

    switch(k_len) {
        case 4:
            b0 = q(1,b0) ^ byte(key[3],0);
            b1 = q(0,b1) ^ byte(key[3],1);
            b2 = q(0,b2) ^ byte(key[3],2);
            b3 = q(1,b3) ^ byte(key[3],3);
            /* fallthrough */
        case 3:
            b0 = q(1,b0) ^ byte(key[2],0);
            b1 = q(1,b1) ^ byte(key[2],1);
            b2 = q(0,b2) ^ byte(key[2],2);
            b3 = q(0,b3) ^ byte(key[2],3);
            /* fallthrough */
        case 2:
            b0 = q(0,q(0,b0) ^ byte(key[1],0)) ^ byte(key[0],0);
            b1 = q(0,q(1,b1) ^ byte(key[1],1)) ^ byte(key[0],1);
            b2 = q(1,q(0,b2) ^ byte(key[1],2)) ^ byte(key[0],2);
            b3 = q(1,q(1,b3) ^ byte(key[1],3)) ^ byte(key[0],3);
            break;
    }
    return mds(0,b0) ^ mds(1,b1) ^ mds(2,b2) ^ mds(3,b3);
}

/* prototype for mds_rem */
u4byte mds_rem(u4byte p0, u4byte p1);

/* MK_TABLE */
#ifdef MK_TABLE
#ifdef ONE_STEP
u4byte mk_tab[4][256];
#else
u1byte sb[4][256];
#endif

#define q20(x) (q(0,q(0,(x)) ^ byte(key[1],0)) ^ byte(key[0],0))
#define q21(x) (q(0,q(1,(x)) ^ byte(key[1],1)) ^ byte(key[0],1))
#define q22(x) (q(1,q(0,(x)) ^ byte(key[1],2)) ^ byte(key[0],2))
#define q23(x) (q(1,q(1,(x)) ^ byte(key[1],3)) ^ byte(key[0],3))

#define q30(x) (q(0,q(0,q(1,(x)) ^ byte(key[2],0)) ^ byte(key[1],0)) ^ byte(key[0],0))
#define q31(x) (q(0,q(1,q(1,(x)) ^ byte(key[2],1)) ^ byte(key[1],1)) ^ byte(key[0],1))
#define q32(x) (q(1,q(0,q(0,(x)) ^ byte(key[2],2)) ^ byte(key[1],2)) ^ byte(key[0],2))
#define q33(x) (q(1,q(1,q(0,(x)) ^ byte(key[2],3)) ^ byte(key[1],3)) ^ byte(key[0],3))

#define q40(x) (q(0,q(0,q(1,q(1,(x)) ^ byte(key[3],0)) ^ byte(key[2],0)) ^ byte(key[1],0)) ^ byte(key[0],0))
#define q41(x) (q(0,q(1,q(1,q(0,(x)) ^ byte(key[3],1)) ^ byte(key[2],1)) ^ byte(key[1],1)) ^ byte(key[0],1))
#define q42(x) (q(1,q(0,q(0,q(0,(x)) ^ byte(key[3],2)) ^ byte(key[2],2)) ^ byte(key[1],2)) ^ byte(key[0],2))
#define q43(x) (q(1,q(1,q(0,q(1,(x)) ^ byte(key[3],3)) ^ byte(key[2],3)) ^ byte(key[1],3)) ^ byte(key[0],3))
#endif

void gen_mk_tab(u4byte key[])
{
    u4byte i; u1byte by;

    switch(k_len) {
        case 2:
            for(i=0;i<256;++i) {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0][i]=mds(0,q20(by)); mk_tab[1][i]=mds(1,q21(by));
                mk_tab[2][i]=mds(2,q22(by)); mk_tab[3][i]=mds(3,q23(by));
#else
                sb[0][i]=q20(by); sb[1][i]=q21(by);
                sb[2][i]=q22(by); sb[3][i]=q23(by);
#endif
            }
            break;
        case 3:
            for(i=0;i<256;++i) {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0][i]=mds(0,q30(by)); mk_tab[1][i]=mds(1,q31(by));
                mk_tab[2][i]=mds(2,q32(by)); mk_tab[3][i]=mds(3,q33(by));
#else
                sb[0][i]=q30(by); sb[1][i]=q31(by);
                sb[2][i]=q32(by); sb[3][i]=q33(by);
#endif
            }
            break;
        case 4:
            for(i=0;i<256;++i) {
                by = (u1byte)i;
#ifdef ONE_STEP
                mk_tab[0][i]=mds(0,q40(by)); mk_tab[1][i]=mds(1,q41(by));
                mk_tab[2][i]=mds(2,q42(by)); mk_tab[3][i]=mds(3,q43(by));
#else
                sb[0][i]=q40(by); sb[1][i]=q41(by);
                sb[2][i]=q42(by); sb[3][i]=q43(by);
#endif
            }
            break;
    }
}

/* G functions */
#ifdef ONE_STEP
#define g0_fun(x) (mk_tab[0][byte(x,0)] ^ mk_tab[1][byte(x,1)] \
                   ^ mk_tab[2][byte(x,2)] ^ mk_tab[3][byte(x,3)])
#define g1_fun(x) (mk_tab[0][byte(x,3)] ^ mk_tab[1][byte(x,0)] \
                   ^ mk_tab[2][byte(x,1)] ^ mk_tab[3][byte(x,2)])
#else
#define g0_fun(x) (mds(0,sb[0][byte(x,0)]) ^ mds(1,sb[1][byte(x,1)]) \
                   ^ mds(2,sb[2][byte(x,2)]) ^ mds(3,sb[3][byte(x,3)]))
#define g1_fun(x) (mds(0,sb[0][byte(x,3)]) ^ mds(1,sb[1][byte(x,0)]) \
                   ^ mds(2,sb[2][byte(x,1)]) ^ mds(3,sb[3][byte(x,2)]))
#endif

/* mds_rem */
u4byte mds_rem(u4byte p0,u4byte p1)
{
    u4byte i,t,u;
    for(i=0;i<8;++i) {
        t=p1>>24;
        p1=(p1<<8)|(p0>>24); p0<<=8;
        u=(t<<1);
        if(t&0x80) u^=0x14d;
        p1^=t|(u<<16);
        u^=(t>>1);
        if(t&0x01) u^=(0x14d>>1);
        p1^=(u<<24)|(u<<8);
    }
    return p1;
}

/* set_key, encrypt, decrypt */
u4byte* set_key(const u4byte key[], const u4byte len)
{
    k_len = len;
    for(u4byte i=0;i<len;++i)
        l_key[i]=key[i];
    gen_qtab();
    gen_mtab();
    gen_mk_tab((u4byte*)key);
    return l_key;
}

void decrypt(const u4byte ct[4], u4byte pt[4])
{
    u4byte t0, t1;
    u4byte r0 = ct[2];
    u4byte r1 = ct[3];
    u4byte F0, F1;
    u4byte r2, r3;

    /* Reconstrói t0 e t1 a partir de r0,r1 */
    t0 = g0_fun(r0);
    t1 = g1_fun(r1);

    /* Recalculamos F0 e F1 (PHT) */
    F0 = (t0 + t1) & 0xFFFFFFFF;
    F1 = (t0 + (t1 << 1)) & 0xFFFFFFFF; /* (t0 + 2*t1) mod 2^32 */

    /* Recupera r2 e r3 usando os ct[0],ct[1] */
    r2 = F0 ^ ct[0] ^ l_key[4];
    r3 = F1 ^ ct[1] ^ l_key[5];

    /* Finalmente, reconstrói as palavras de plaintext (removendo whitening) */
    pt[0] = r0 ^ l_key[0];
    pt[1] = r1 ^ l_key[1];
    pt[2] = r2 ^ l_key[2];
    pt[3] = r3 ^ l_key[3];
}

uint32_t inverter_u4byte(uint32_t valor){
    return ((valor >> 24) & 0x000000FF) |
            ((valor >> 8) & 0x0000FF00) |
            ((valor << 8) & 0x00FF0000) |
            ((valor << 24) & 0xFF000000);
}

void completar_16bytes(char *str){
    size_t len = strlen(str);
    if(len<16){
        int espacos_necessarios = 16- (int)len;
        int i;
        //memset(str +len,' ',espacos_necessarios);
    }    
}
/*
int main() {
    // 🔹 Chave de exemplo (128 bits)
    u4byte key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    set_key(key, 4);

    // 🔹 Texto de 8 KB (8192 bytes)
		char conteudo[8193];
	

    // 🔹 Buffers estáticos (sem malloc)
    unsigned char decriptografado[8192];

		FILE *arquivo;
		arquivo=fopen("cifra.txt","r");
		fread(conteudo, 1, 8192, arquivo);
    fclose(arquivo);



//    printf("Texto original (primeiros 64 chars): %.1000s\n\n", frase);


   printf("Texto decifrado (primeiros 64 chars): %.8195s\n",conteudo);

    return 0;
}

*/


int main() {
    u4byte key[4] = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
    set_key(key, 4);

    char conteudo[8192];
    char plano[8192];
    unsigned char decriptografado[8192];

    FILE *arquivo = fopen("cifra.txt", "rb"); // ler como binário
    fread(conteudo, 1, 8192, arquivo);
    fclose(arquivo);

    const size_t blocos = 8192 / 16;

    for (size_t i = 0; i < blocos; i++) {
        u4byte ct[4] = {0};
        u4byte pt[4] = {0};

        // Copia 16 bytes do conteúdo para o bloco ct
        memcpy(ct, conteudo + (i * 16), 16);

        // Descriptografa
        decrypt(ct, pt);

        // Copia o bloco descriptografado para o buffer final
        memcpy(decriptografado + (i * 16), pt, 16);
    }

    // Agora decriptografado[] tem todo o texto original
    // Agora decriptografado[] tem todo o texto original
    printf("Texto decifrado (primeiros 128 chars): %.8192s\n", conteudo);
    printf("Texto decifrado (primeiros 128 chars): %.8192s\n", decriptografado);

    FILE *entrada = fopen("entrada.txt", "rb"); // ler como binário
    fread(plano, 1, 8192, entrada);
    fclose(entrada);

    printf("Texto plano (primeiros 128 chars): %.8192s\n", plano);

if (memcmp(plano, decriptografado,8192) == 0)
    printf("sao iguais\n");
else
    printf("sao diferentes\n");

    return 0;
}

