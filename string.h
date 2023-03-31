#ifndef __STRING_H__
#define __STRING_H__

#include <stdint.h>
#include <stddef.h>
unsigned int strlen(const char *s);
int strncmp( const char * s1, const char * s2, size_t n );
char* strncpy(char* destination, const char* source, size_t num);
void * memmove(void* dest, const void* src, unsigned int n);
int memcmp (const void *str1, const void *str2, size_t count);
void* memset(void* dest, int byte, size_t len);
void* memcpy(void* dest, const void* src, size_t len);


/*
size_t
strlen(str)
	const char *str;
{
	register const char *s;

	for (s = str; *s; ++s);
	return(s - str);
}

char* strchr(const char* str, int c)     {
    const char* position = NULL;
    size_t i = 0;
    for(i = 0; ;i++) {
        if((unsigned char) str[i] == c) {
            position = &str[i];
            break;
        }
        if (str[i]=='\0') break;
    }
    return (char *) position;
}

int compare(const char *X, const char *Y)
{
    while (*X && *Y)
    {
        if (*X != *Y) {
            return 0;
        }
 
        X++;
        Y++;
    }
 
    return (*Y == '\0');
}
 
const char* strstr(const char* X, const char* Y)
{
    while (*X != '\0')
    {
        if ((*X == *Y) && compare(X, Y)) {
            return X;
        }
        X++;
    }
 
    return NULL;
}*/

#endif