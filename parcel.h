#ifndef MILS_PARCEL_H
#define MILS_PARCEL_H


#define MAXPARAM 1024
#define MAXBUFFER_IN_HDR sizeof(parcel_reqhdr)
#define MAXBUFFER_OUT_HDR sizeof(parcel_reshdr)

/* 操作命令 */
#define CMD_LOGIN   0x01
#define CMD_PWD     0x02
#define CMD_PUT     0x03
#define CMD_DEL     0x04
#define CMD_GET     0x05
#define CMD_LS      0x06
#define CMD_MKDIR   0x07
#define CMD_RMDIR   0x08
#define CMD_CD      0x09


#include "session.h"

/* 返回状态 */
#define STATUS_OK 0xFF
#define STATUS_FILE 0xFE
#define STATUS_FAIL_INTERNAL 0xFD
#define STATUS_FAIL_PRIV 0xFC
#define STATUS_FAIL_AUTH 0xFB
#define STATUS_REQUEST_AUTH 0xFA
#define STATUS_SUCCESS_AUTH 0xF9
#define STATUS_OP_OK 0xF8
#define STATUS_OP_FAIL 0xf7

typedef struct{
    u_int8_t cmd;
    char param[MAXPARAM];
    u_int16_t size;
}   parcel_reqhdr;

typedef struct{
    u_int8_t status_code;
    char param[MAXPARAM];
    u_int16_t size;
}   parcel_reshdr;

int         parcel_start(Session *s);
int         parcel_recv(Session *s);
int         parcel_send(Session *s);
int         parcel_handle(Session *s);
void        parcel_loop(Session *s);
int         parcel_stop(Session *s);


#endif