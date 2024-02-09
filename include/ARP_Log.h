#ifndef ARP_LOG_H
#define ARP_LOG_H

#include "ARP_Headers.h"

#define TOSTRING(X)             #X
#define COLOR_TXT(colr)         "\e["TOSTRING(colr)"m"

#define DRED                    COLOR_TXT(31)
#define DGRN                    COLOR_TXT(32)
#define DYEL                    COLOR_TXT(33)
#define DBLU                    COLOR_TXT(34)
#define DMGN                    COLOR_TXT(35)
#define DCYN                    COLOR_TXT(36)

#define NORM                    "\e[m"
#define BOLD                    "\e[1m"


#define errExit(...)                                                        \
            {   fprintf(stderr, DRED);                                      \
                fprintf(stderr, __VA_ARGS__);                               \
                fprintf(stderr, NORM);                                      \
                exit(EXIT_FAILURE); }


#define __CheckErr(cond, ...)                                               \
        if((cond))                                                          \
        {                                                                   \
            errExit(__VA_ARGS__);                                           \
        }

#define __CheckNull(var)              __CheckErr(var==0, DRED"[ERROR][%s:%s:%d] variable %s is NULL\n"NORM, __FILE__,__FUNCTION__,__LINE__,#var);

#define LOG(...)                                                              \
           do { printf(__VA_ARGS__); } while(0);                     

#endif // ARP_LOG_H