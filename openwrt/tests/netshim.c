#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <curl/curl.h>

int setsockopt(int fd,int level,int option,const void *value,socklen_t length) {
    int (*real)(int,int,int,const void *,socklen_t)=dlsym(RTLD_NEXT,"setsockopt");
    if(level==SOL_SOCKET&&option==SO_MARK&&getenv("FIXTURE_MARK")) {
        if(length!=sizeof(int)||*(const int *)value!=0x20000||!strcmp(getenv("FIXTURE_MARK"),"fail")){errno=EPERM;return -1;}
        return 0;
    }
    return real(fd,level,option,value,length);
}

/* Trust only the local fixture CA during API roundtrips. */
CURLcode curl_easy_perform(CURL *handle) {
    CURLcode (*setopt)(CURL *,CURLoption,...)=dlsym(RTLD_NEXT,"curl_easy_setopt");
    CURLcode (*perform)(CURL *)=dlsym(RTLD_NEXT,"curl_easy_perform");
    const char *ca=getenv("SSL_CERT_FILE");
    if(ca)setopt(handle,CURLOPT_CAINFO,ca);
    return perform(handle);
}

/* TEST ONLY. Routes public fixtures to local test servers. Never linked into
 * the installed probe; production does not accept fixture environment vars. */
int getaddrinfo(const char *name,const char *service,const struct addrinfo *hints,struct addrinfo **out) {
    int (*real)(const char *,const char *,const struct addrinfo *,struct addrinfo **)=dlsym(RTLD_NEXT,"getaddrinfo");
    const char *answers=getenv("FIXTURE_DNS");if(!answers||!name||(!strstr(name,"example")&&!strstr(name,"xn--")&&!strstr(name,"roskompozor.ru")))return real(name,service,hints,out);
    if(!strcmp(answers,"FAIL"))return EAI_NONAME;
    char *list=strdup(answers),*cursor=NULL;struct addrinfo *head=NULL,*tail=NULL;
    for(char *ip=strtok_r(list,",",&cursor);ip;ip=strtok_r(NULL,",",&cursor)) {
        struct addrinfo local={0};if(hints)local=*hints;local.ai_flags=AI_NUMERICHOST;local.ai_family=strchr(ip,':')?AF_INET6:AF_INET;
        struct addrinfo *item=NULL;int rc=real(ip,service,&local,&item);if(rc){free(list);return rc;}
        if(tail)tail->ai_next=item;else head=item;tail=item;while(tail->ai_next)tail=tail->ai_next;
    }free(list);*out=head;return 0;
}
int connect(int fd,const struct sockaddr *address,socklen_t length) {
    int (*real)(int,const struct sockaddr *,socklen_t)=dlsym(RTLD_NEXT,"connect");
    const char *mapping=getenv("FIXTURE_PORTS");if(!mapping)return real(fd,address,length);
    int port=address->sa_family==AF_INET?ntohs(((const struct sockaddr_in *)address)->sin_port):address->sa_family==AF_INET6?ntohs(((const struct sockaddr_in6 *)address)->sin6_port):0;
    char *list=strdup(mapping),*cursor=NULL;int target=0;for(char *p=strtok_r(list,",",&cursor);p;p=strtok_r(NULL,",",&cursor)){int from,to;if(sscanf(p,"%d:%d",&from,&to)==2&&from==port)target=to;}free(list);
    /* Any missing mapping is refused, ensuring tests never contact the Internet. */
    if(!target){errno=ECONNREFUSED;return -1;}
    if(target<0){errno=target==-1?ETIMEDOUT:ECONNRESET;return -1;}
    if(address->sa_family==AF_INET){struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(target);inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);return real(fd,(void *)&a,sizeof(a));}
    errno=ECONNREFUSED;return -1;
}
