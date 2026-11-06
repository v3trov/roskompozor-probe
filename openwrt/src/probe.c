#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <idna.h>
#include <json-c/json.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

/* Measurement contract: upstream 422141a. No shell executes target input. */
#define UA "RoskompozorProbe/1.0.1"
#define HEADER_LIMIT 65536
#define API_LIMIT 1048576
#define URL_LIMIT 8192
#define MAX_ADDR 4
#define MAX_PORTS 10
typedef struct json_object J;
typedef struct { char type[32], message[256]; } Error;
typedef struct { char ip[MAX_ADDR][INET6_ADDRSTRLEN]; int count; } Addresses;
typedef struct { int tls, port; char host[254], path[URL_LIMIT]; } Url;
static SSL_CTX *tls_context;
static volatile sig_atomic_t stopping;

static double now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000.0+t.tv_nsec/1000000.0; }
static int elapsed(double start) { return (int)nearbyint(now_ms()-start); }
static void put(J *o,const char *k,J *v) { json_object_object_add(o,k,v); }
static void str(J *o,const char *k,const char *v) { put(o,k,v?json_object_new_string(v):NULL); }
static void num(J *o,const char *k,int64_t v) { put(o,k,json_object_new_int64(v)); }
static void boolean(J *o,const char *k,bool v) { put(o,k,json_object_new_boolean(v)); }
static J *get(J *o,const char *k) { J *v=NULL; if(o) json_object_object_get_ex(o,k,&v); return v; }
static const char *textval(J *o,const char *k) { J *v=get(o,k); return v&&json_object_is_type(v,json_type_string)?json_object_get_string(v):""; }
static bool truth(J *o) { return json_object_get_boolean(get(o,"ok")); }
static void copyfield(J *to,J *from,const char *key) { J *v=get(from,key); put(to,key,v?json_object_get(v):NULL); }
static void error_set(Error *e,const char *type,const char *message) { snprintf(e->type,sizeof(e->type),"%s",type); snprintf(e->message,sizeof(e->message),"%.240s",message); }
static void os_error(Error *e,int code) {
    const char *type=code==ETIMEDOUT||code==EAGAIN||code==EWOULDBLOCK?"timeout":code==ECONNREFUSED?"connection refused":code==ECONNRESET?"connection reset":"network error";
    error_set(e,type,strerror(code));
}
static void add_error(J *o,Error *e) { char buffer[300]; snprintf(buffer,sizeof(buffer),"%s: %s",e->type,e->message); str(o,"error_type",e->type); str(o,"error",buffer); }
static J *measurement(bool ok,int ms,const char *ip) { J *o=json_object_new_object(); boolean(o,"ok",ok); num(o,"ms",ms); if(ip)str(o,"ip",ip); return o; }
static J *technical(Error *e,double started) { J *o=measurement(false,0,NULL); json_object_object_del(o,"ms"); str(o,"summary","Проверка завершилась технической ошибкой"); add_error(o,e); num(o,"total_ms",elapsed(started)); return o; }

static bool in_net(const char *ip,const char *cidr) {
    char net[64]; snprintf(net,sizeof(net),"%s",cidr); char *slash=strchr(net,'/'); if(!slash)return false; *slash++=0;
    int af=strchr(ip,':')?AF_INET6:AF_INET, bits=atoi(slash); unsigned char a[16],b[16];
    if(inet_pton(af,ip,a)!=1||inet_pton(af,net,b)!=1)return false;
    int whole=bits/8, part=bits%8; return !memcmp(a,b,(size_t)whole)&&(!part||((a[whole]^b[whole])&(0xff<<(8-part)))==0);
}
/* ipaddress policy pinned to CPython 3.12.3 (Ubuntu security updates).
 * Older/newer CPython versions differ on special-purpose ranges. */
static bool public_ip(const char *ip) {
    unsigned char bin[16]; int af=strchr(ip,':')?AF_INET6:AF_INET; if(inet_pton(af,ip,bin)!=1)return false;
    static const char *v4[]={"0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8","169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4",NULL};
    if(af==AF_INET) {
        if(!strcmp(ip,"192.0.0.9")||!strcmp(ip,"192.0.0.10"))return true;
        for(int i=0;v4[i];i++)if(in_net(ip,v4[i]))return false;
        return true;
    }
    if(!in_net(ip,"2000::/3"))return false;
    static const char *exceptions[]={"2001:1::1/128","2001:1::2/128","2001:3::/32","2001:4:112::/48","2001:20::/28","2001:30::/28",NULL};
    for(int i=0;exceptions[i];i++)if(in_net(ip,exceptions[i]))return true;
    return !in_net(ip,"2001::/23")&&!in_net(ip,"2001:db8::/32")&&!in_net(ip,"2002::/16");
}
static int normalize_host(const char *raw,char out[254],Error *e) {
    size_t n=strlen(raw); while(n&&isspace((unsigned char)*raw)){raw++;n--;}
    while(n&&isspace((unsigned char)raw[n-1]))n--; while(n&&raw[n-1]=='.')n--;
    if(!n||n>253)goto invalid;
    char input[254]; memcpy(input,raw,n); input[n]=0; for(size_t i=0;i<n;i++)if((unsigned char)input[i]<=32)goto invalid;
    unsigned char bin[16]; int af=strchr(input,':')?AF_INET6:AF_INET;
    if(inet_pton(af,input,bin)==1){inet_ntop(af,bin,out,254);return 0;}
    char *ascii=NULL; /* IDNA 2003, matching Python's built-in codec (not IDNA 2008). */
    if(idna_to_ascii_8z(input,&ascii,0)!=IDNA_SUCCESS)goto invalid;
    if(strlen(ascii)>253){free(ascii);goto invalid;}
    snprintf(out,254,"%s",ascii);free(ascii);
    size_t label=0;for(size_t i=0;;i++) {
        unsigned char c=(unsigned char)out[i];out[i]=(char)tolower(c);
        if(!c||c=='.'){if(!label||label>63||out[i-label]=='-'||out[i-1]=='-')goto invalid;label=0;if(!c)break;}
        else {if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'))goto invalid;label++;}
    }return 0;
invalid:error_set(e,"HTTP error","invalid target");return -1;
}
static int cmp_ip(const void *a,const void *b) { return strcmp(a,b); }
static int resolve_public(const char *host,Addresses *out,Error *e) {
    unsigned char bin[16]; int af=strchr(host,':')?AF_INET6:AF_INET;out->count=0;
    if(inet_pton(af,host,bin)==1) {
        if(!public_ip(host)){error_set(e,"HTTP error","target resolved to a non-public address");return -1;}
        snprintf(out->ip[0],sizeof(out->ip[0]),"%s",host);out->count=1;return 0;
    }
    struct addrinfo hints={0},*list=NULL;hints.ai_socktype=SOCK_STREAM;
    int code=getaddrinfo(host,NULL,&hints,&list);if(code){error_set(e,"DNS error",gai_strerror(code));return -1;}
    /* Validate ALL answers before selecting four, including duplicates. */
    for(struct addrinfo *p=list;p;p=p->ai_next) {
        char ip[INET6_ADDRSTRLEN];void *addr;
        if(p->ai_family==AF_INET)addr=&((struct sockaddr_in *)p->ai_addr)->sin_addr;
        else if(p->ai_family==AF_INET6)addr=&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;else continue;
        inet_ntop(p->ai_family,addr,ip,sizeof(ip));
        if(!public_ip(ip)){freeaddrinfo(list);error_set(e,"HTTP error","target resolved to a non-public address");return -1;}
        bool duplicate=false;for(int i=0;i<out->count;i++)if(!strcmp(out->ip[i],ip))duplicate=true;
        if(duplicate)continue;
        if(out->count<MAX_ADDR)snprintf(out->ip[out->count++],sizeof(out->ip[0]),"%s",ip);
        else if(strcmp(ip,out->ip[out->count-1])<0)snprintf(out->ip[out->count-1],sizeof(out->ip[0]),"%s",ip);
        qsort(out->ip,(size_t)out->count,sizeof(out->ip[0]),cmp_ip);
    }freeaddrinfo(list);
    if(!out->count){error_set(e,"DNS error","DNS returned no addresses");return -1;}return 0;
}
static int wait_io(int fd,short events,double deadline,Error *e) {
    while(!stopping) {
        int ms=(int)ceil(deadline-now_ms()); if(ms<=0){os_error(e,ETIMEDOUT);return -1;}
        struct pollfd p={fd,events,0};int rc=poll(&p,1,ms);
        if(rc>0)return 0;if(!rc){os_error(e,ETIMEDOUT);return -1;}if(errno!=EINTR){os_error(e,errno);return -1;}
    }os_error(e,EINTR);return -1;
}
static int connect_ip(const char *ip,int port,double timeout,Error *e) {
    struct sockaddr_storage address={0};socklen_t len;int af=strchr(ip,':')?AF_INET6:AF_INET;
    if(af==AF_INET){struct sockaddr_in *a=(void *)&address;a->sin_family=AF_INET;a->sin_port=htons((uint16_t)port);inet_pton(af,ip,&a->sin_addr);len=sizeof(*a);}
    else {struct sockaddr_in6 *a=(void *)&address;a->sin6_family=AF_INET6;a->sin6_port=htons((uint16_t)port);inet_pton(af,ip,&a->sin6_addr);len=sizeof(*a);}
    int fd=socket(af,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0){os_error(e,errno);return -1;}
    fcntl(fd,F_SETFD,FD_CLOEXEC);fcntl(fd,F_SETFL,O_NONBLOCK);
    if(connect(fd,(void *)&address,len)<0) {
        if(errno!=EINPROGRESS){os_error(e,errno);close(fd);return -1;}
        if(wait_io(fd,POLLOUT,now_ms()+timeout*1000,e)){close(fd);return -1;}
        int code=0;socklen_t size=sizeof(code);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&code,&size)<0)code=errno;
        if(code){os_error(e,code);close(fd);return -1;}
    }return fd;
}
static int ssl_wait(SSL *ssl,int rc,int fd,double deadline,Error *e) {
    int code=SSL_get_error(ssl,rc);
    if(code==SSL_ERROR_WANT_READ||code==SSL_ERROR_WANT_WRITE)return wait_io(fd,code==SSL_ERROR_WANT_READ?POLLIN:POLLOUT,deadline,e);
    if(code==SSL_ERROR_SYSCALL&&errno){os_error(e,errno);return -1;}
    unsigned long ssl_code=ERR_get_error();char message[240];
    if(ssl_code)ERR_error_string_n(ssl_code,message,sizeof(message));else snprintf(message,sizeof(message),"TLS peer closed connection");
    error_set(e,"TLS error",message);return -1;
}
static SSL *handshake(int fd,const char *host,double timeout,Error *e) {
    SSL *ssl=SSL_new(tls_context);if(!ssl){error_set(e,"TLS error","SSL allocation failed");return NULL;}
    SSL_set_fd(ssl,fd);unsigned char bin[16];
    if(inet_pton(AF_INET,host,bin)==1||inet_pton(AF_INET6,host,bin)==1)X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),host);
    else {SSL_set_tlsext_host_name(ssl,host);SSL_set1_host(ssl,host);}
    X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(ssl),X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    double deadline=now_ms()+timeout*1000;
    for(;;){ERR_clear_error();errno=0;int rc=SSL_connect(ssl);if(rc==1)return ssl;if(ssl_wait(ssl,rc,fd,deadline,e)){SSL_free(ssl);return NULL;}}
}
static int stream_write(int fd,SSL *ssl,const char *data,size_t n,double deadline,Error *e) {
    size_t sent=0;
    while(sent<n) {
        if(now_ms()>=deadline){os_error(e,ETIMEDOUT);return -1;}
        errno=0;int rc=ssl?SSL_write(ssl,data+sent,(int)(n-sent)):(int)send(fd,data+sent,n-sent,0);
        if(rc>0){sent+=(size_t)rc;continue;}
        if(ssl){if(ssl_wait(ssl,rc,fd,deadline,e))return -1;}
        else if(errno==EAGAIN||errno==EWOULDBLOCK){if(wait_io(fd,POLLOUT,deadline,e))return -1;}
        else {os_error(e,errno);return -1;}
    }return 0;
}
static int stream_read(int fd,SSL *ssl,char *data,size_t n,double deadline,Error *e) {
    for(;;) {
        if(now_ms()>=deadline){os_error(e,ETIMEDOUT);return -1;}
        errno=0;int rc=ssl?SSL_read(ssl,data,(int)n):(int)recv(fd,data,n,0);if(rc>0)return rc;
        if(!ssl&&rc==0)return 0;
        if(ssl&&SSL_get_error(ssl,rc)==SSL_ERROR_ZERO_RETURN)return 0;
        /* Python suppress_ragged_eofs=True: an unclean EOF is end of stream. */
        if(ssl&&rc==0&&SSL_get_error(ssl,rc)==SSL_ERROR_SYSCALL&&errno==0)return 0;
        if(ssl){if(ssl_wait(ssl,rc,fd,deadline,e))return -1;}
        else if(errno==EAGAIN||errno==EWOULDBLOCK){if(wait_io(fd,POLLIN,deadline,e))return -1;}
        else {os_error(e,errno);return -1;}
    }
}
static J *tcp_check(const char *ip,int port,double timeout) {
    double started=now_ms();Error e={0};int fd=connect_ip(ip,port,timeout,&e);if(fd>=0)close(fd);
    J *o=measurement(fd>=0,elapsed(started),ip);if(fd<0)add_error(o,&e);return o;
}
static J *aggregate(J *attempts,bool all) {
    J *best=NULL,*last=NULL;size_t n=json_object_array_length(attempts);
    for(size_t i=0;i<n;i++){last=json_object_array_get_idx(attempts,i);if(!best&&truth(last))best=last;}
    if(all){J *o=json_object_new_object();json_object_object_foreach(best?best:last,key,val){put(o,key,val?json_object_get(val):NULL);}put(o,"attempts",attempts);return o;}
    J *o=measurement(best!=NULL,json_object_get_int(get(best?best:last,"ms")),NULL);put(o,"attempts",attempts);
    if(!best){copyfield(o,last,"error");copyfield(o,last,"error_type");}return o;
}
static J *best_tcp(const Addresses *a,int port,double timeout) {
    J *attempts=json_object_new_array();for(int i=0;i<a->count;i++){J *r=tcp_check(a->ip[i],port,timeout);json_object_array_add(attempts,r);if(truth(r))break;}return aggregate(attempts,false);
}
static J *ping_check(const char *ip,double timeout) {
    double started=now_ms();Error e={0};int pipes[2];
    if(pipe2(pipes,O_CLOEXEC)){os_error(&e,errno);J *r=measurement(false,elapsed(started),ip);add_error(r,&e);return r;}
    /* posix_spawn avoids unsafe library calls in a child of a multithreaded process. */
    extern char **environ;
    char seconds[16];snprintf(seconds,sizeof(seconds),"%d",(int)fmax(1,(int)(timeout+0.999)));
    char *argv4[]={"ping","-n","-c","1","-W",seconds,(char *)ip,NULL};
    char *argv6[]={"ping","-6","-n","-c","1","-W",seconds,(char *)ip,NULL};
    posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,pipes[1],STDOUT_FILENO);posix_spawn_file_actions_adddup2(&actions,pipes[1],STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions,pipes[0]);posix_spawn_file_actions_addclose(&actions,pipes[1]);
    pid_t pid;int rc=posix_spawnp(&pid,"ping",&actions,NULL,strchr(ip,':')?argv6:argv4,environ);
    posix_spawn_file_actions_destroy(&actions);close(pipes[1]);
    if(rc){close(pipes[0]);J *r=measurement(false,rc==ENOENT?0:elapsed(started),ip);
        if(rc==ENOENT){str(r,"error_type","unavailable");str(r,"error","ping utility is unavailable");}else{os_error(&e,rc);add_error(r,&e);}return r;}
    fcntl(pipes[0],F_SETFL,O_NONBLOCK);char output[4097]={0};size_t used=0;double deadline=started+(timeout+2)*1000;bool timedout=false;int status=0;
    for(;;){char buffer[1024];ssize_t n=read(pipes[0],buffer,sizeof(buffer));
        if(n>0){size_t keep=(size_t)n;if(keep>4096-used)keep=4096-used;memcpy(output+used,buffer,keep);used+=keep;continue;}
        if(n==0)break;if(errno==EINTR)continue;
        if(wait_io(pipes[0],POLLIN,deadline,&e)){timedout=true;kill(pid,SIGKILL);break;}
    }close(pipes[0]);while(waitpid(pid,&status,0)<0&&errno==EINTR){}
    bool ok=!timedout&&WIFEXITED(status)&&WEXITSTATUS(status)==0;int ms=elapsed(started);char *p=output;
    while((p=strcasestr(p,"time"))){p+=4;if(*p=='='||*p=='<'){char *end;double value=strtod(p+1,&end);while(*end==' ')end++;if(end!=p+1&&!strncasecmp(end,"ms",2)){ms=(int)nearbyint(value);break;}}}
    J *r=measurement(ok,ms,ip);if(timedout){os_error(&e,ETIMEDOUT);add_error(r,&e);}else if(!ok){str(r,"error_type","no reply");str(r,"error","No ICMP reply; ping may be disabled");}return r;
}
static J *best_ping(const Addresses *a,double timeout) { J *attempts=json_object_new_array();for(int i=0;i<a->count;i++)json_object_array_add(attempts,ping_check(a->ip[i],timeout));return aggregate(attempts,false); }
static J *tls_check(const char *host,const Addresses *a,double timeout) {
    J *attempts=json_object_new_array();for(int i=0;i<a->count;i++) {
        Error e={0};double started=now_ms();int fd=connect_ip(a->ip[i],443,timeout,&e);SSL *ssl=fd<0?NULL:handshake(fd,host,timeout,&e);
        J *r=measurement(ssl!=NULL,0,a->ip[i]);if(ssl){X509 *cert=SSL_get1_peer_certificate(ssl);char subject[1024];
            int index=-1,last=-1;while((index=X509_NAME_get_index_by_NID(X509_get_subject_name(cert),NID_commonName,index))>=0)last=index;
            if(last>=0){ASN1_STRING *s=X509_NAME_ENTRY_get_data(X509_NAME_get_entry(X509_get_subject_name(cert),last));unsigned char *utf8=NULL;int len=ASN1_STRING_to_UTF8(&utf8,s);if(len>=0){snprintf(subject,sizeof(subject),"%.*s",len,utf8);str(r,"subject",subject);OPENSSL_free(utf8);}else str(r,"subject",NULL);}else str(r,"subject",NULL);
            BIO *bio=BIO_new(BIO_s_mem());ASN1_TIME_print(bio,X509_get0_notAfter(cert));char expires[128]={0};BIO_read(bio,expires,sizeof(expires)-1);str(r,"expires",expires);BIO_free(bio);X509_free(cert);SSL_free(ssl);
        }else add_error(r,&e);if(fd>=0)close(fd);num(r,"ms",elapsed(started));json_object_array_add(attempts,r);if(truth(r))break;
    }return aggregate(attempts,true);
}

static int parse_url(const char *url,Url *u,Error *e) {
    /* CURLU handles URL syntax only: target traffic never goes through curl. */
    CURLU *h=curl_url();char *scheme=NULL,*host=NULL,*port=NULL,*path=NULL,*query=NULL,*user=NULL,*password=NULL;int rc=-1;
    if(strlen(url)>=URL_LIMIT||curl_url_set(h,CURLUPART_URL,url,CURLU_PATH_AS_IS))goto unsafe;
    curl_url_get(h,CURLUPART_SCHEME,&scheme,0);curl_url_get(h,CURLUPART_HOST,&host,0);
    if(!scheme||!host|| (strcmp(scheme,"http")&&strcmp(scheme,"https")))goto unsafe;
    if(curl_url_get(h,CURLUPART_USER,&user,0)==CURLUE_OK||curl_url_get(h,CURLUPART_PASSWORD,&password,0)==CURLUE_OK)goto unsafe;
    u->tls=!strcmp(scheme,"https");u->port=u->tls?443:80;
    if(curl_url_get(h,CURLUPART_PORT,&port,0)==CURLUE_OK){char *end;long n=strtol(port,&end,10);if(*end)goto unsafe;u->port=n?(int)n:u->port;}
    if(u->port!=80&&u->port!=443){error_set(e,"HTTP error","unsafe port");goto done;}
    if(host[0]=='['){size_t n=strlen(host);memmove(host,host+1,n-2);host[n-2]=0;}
    if(normalize_host(host,u->host,e))goto done;
    curl_url_get(h,CURLUPART_PATH,&path,0);curl_url_get(h,CURLUPART_QUERY,&query,0);
    if(snprintf(u->path,sizeof(u->path),"%s%s%s",path&&*path?path:"/",query?"?":"",query?query:"")>=(int)sizeof(u->path))goto unsafe;
    /* Python sends an ASCII request; reject CR/LF/control injection. */
    for(const unsigned char *p=(void *)u->path;*p;p++)if(*p<32||*p>=127){error_set(e,"HTTP error","non-ASCII or control character in URL");goto done;}
    rc=0;goto done;
unsafe:error_set(e,"HTTP error","unsafe URL");
done:curl_free(scheme);curl_free(host);curl_free(port);curl_free(path);curl_free(query);curl_free(user);curl_free(password);curl_url_cleanup(h);return rc;
}
static char *trim(char *s) { while(isspace((unsigned char)*s))s++;size_t n=strlen(s);while(n&&isspace((unsigned char)s[n-1]))s[--n]=0;return s; }
static int join_url(const char *base,const char *location,char out[URL_LIMIT],Error *e) {
    /* libcurl treats fragment-only references as a relative path. urljoin keeps
     * the full base path and query in this case. */
    if(!*location||*location=='#') {
        size_t n=strcspn(base,"#");
        if(!*location)n=strlen(base);
        if(n+strlen(location)>=URL_LIMIT){error_set(e,"HTTP error","unsafe URL");return -1;}
        memcpy(out,base,n);snprintf(out+n,URL_LIMIT-n,"%s",location);return 0;
    }
    CURLU *h=curl_url();char *next=NULL;int rc=-1;
    if(!curl_url_set(h,CURLUPART_URL,base,0)&&!curl_url_set(h,CURLUPART_URL,location,0)&&!curl_url_get(h,CURLUPART_URL,&next,0)&&strlen(next)<URL_LIMIT){snprintf(out,URL_LIMIT,"%s",next);rc=0;}
    if(rc)error_set(e,"HTTP error","unsafe URL");curl_free(next);curl_url_cleanup(h);return rc;
}
static double http_remaining(double deadline,double cap,Error *e) {
    double left=(deadline-now_ms())/1000;
    if(left<=0){os_error(e,ETIMEDOUT);return 0;}return fmin(left,cap);
}
static J *http_once(const char *url,double timeout,double chain_deadline,Error *fatal) {
    double deadline=fmin(chain_deadline,now_ms()+timeout*1000);
    Url u;if(parse_url(url,&u,fatal))return NULL;Addresses a;if(resolve_public(u.host,&a,fatal))return NULL;
    J *last=NULL;for(int i=0;i<a.count;i++) {
        double started=now_ms();Error e={0};int fd=-1;SSL *ssl=NULL;J *r=NULL;char *header=NULL;char request[URL_LIMIT+512];
        double left=http_remaining(deadline,timeout,&e);if(left<=0)goto failed;
        fd=connect_ip(a.ip[i],u.port,left,&e);
        if(fd<0)goto failed;if(u.tls){left=http_remaining(deadline,timeout,&e);if(left<=0)goto failed;ssl=handshake(fd,u.host,left,&e);if(!ssl)goto failed;}
        int n=snprintf(request,sizeof(request),"GET %s HTTP/1.1\r\nHost: %s%s%s\r\nUser-Agent: " UA "\r\nAccept: */*\r\nConnection: close\r\n\r\n",u.path,strchr(u.host,':')?"[":"",u.host,strchr(u.host,':')?"]":"");
        if(stream_write(fd,ssl,request,(size_t)n,deadline,&e))goto failed;
        header=calloc(1,HEADER_LIMIT+1);if(!header){error_set(&e,"network error","out of memory");goto failed;}size_t used=0;
        while(!strstr(header,"\r\n\r\n")&&used<HEADER_LIMIT){int got=stream_read(fd,ssl,header+used,fmin(4096,HEADER_LIMIT-used),deadline,&e);if(got<0)goto failed;if(!got)break;used+=(size_t)got;header[used]=0;}
        char *end=strstr(header,"\r\n\r\n");if(end)*end=0;char *cursor=NULL,*line=strtok_r(header,"\r\n",&cursor),*status_text=line;
        if(status_text){while(*status_text&&!isspace((unsigned char)*status_text))status_text++;while(isspace((unsigned char)*status_text))status_text++;}
        char *status_end=NULL;long status=status_text?strtol(status_text,&status_end,10):0;
        if(!status_text||status_end==status_text||(*status_end&&!isspace((unsigned char)*status_end))){error_set(&e,"HTTP error","invalid HTTP response");goto failed;}
        r=measurement(true,elapsed(started),a.ip[i]);num(r,"status",status);str(r,"location",NULL);
        while((line=strtok_r(NULL,"\r\n",&cursor))){char *colon=strchr(line,':');if(!colon)continue;*colon=0;if(!strcasecmp(trim(line),"location"))str(r,"location",trim(colon+1));}
        free(header);if(ssl)SSL_free(ssl);close(fd);if(last)json_object_put(last);return r;
failed:free(header);if(ssl)SSL_free(ssl);if(fd>=0)close(fd);r=measurement(false,elapsed(started),a.ip[i]);num(r,"status",0);add_error(r,&e);if(last)json_object_put(last);last=r;
        if(now_ms()>=deadline)break;
    }return last;
}
static J *http_chain(const char *initial,double timeout,Error *fatal) {
    char url[URL_LIMIT];snprintf(url,sizeof(url),"%s",initial);J *chain=json_object_new_array(),*last=NULL;int ms=0;double deadline=now_ms()+timeout*6000;
    for(int count=0;count<=5;count++) {
        last=http_once(url,timeout,deadline,fatal);if(!last){json_object_put(chain);return NULL;}str(last,"url",url);json_object_array_add(chain,last);ms+=json_object_get_int(get(last,"ms"));
        int code=json_object_get_int(get(last,"status"));const char *location=textval(last,"location");if(!*location||!(code==301||code==302||code==303||code==307||code==308)||count==5)break;
        char next[URL_LIMIT];Url u;if(join_url(url,location,next,fatal)||parse_url(next,&u,fatal)){json_object_put(chain);return NULL;}snprintf(url,sizeof(url),"%s",next);
    }J *r=measurement(truth(last),ms,NULL);copyfield(r,last,"status");str(r,"final_url",url);put(r,"chain",chain);if(!truth(last)){copyfield(r,last,"error");copyfield(r,last,"error_type");}return r;
}
typedef struct { const Addresses *a;int port;double timeout;J *result; } TcpTask;
static void *tcp_worker(void *arg) { TcpTask *t=arg;t->result=best_tcp(t->a,t->port,t->timeout);return NULL; }
typedef struct { char url[300];double timeout;J *result;Error error; } WebTask;
static void *web_worker(void *arg) { WebTask *t=arg;t->result=http_chain(t->url,t->timeout,&t->error);return NULL; }
static int start_thread(pthread_t *thread,void *(*worker)(void *),void *task) {
    pthread_attr_t attr;pthread_attr_init(&attr);pthread_attr_setstacksize(&attr,128*1024);int rc=pthread_create(thread,&attr,worker,task);pthread_attr_destroy(&attr);return rc;
}
static J *run_check(J *item,double timeout) {
    double started=now_ms();Error e={0};char host[254];J *dns=NULL,*ping=NULL,*tcp=NULL,*tls=NULL,*http=NULL,*https=NULL;
    if(normalize_host(textval(item,"target"),host,&e))return technical(&e,started);
    const char *expected=public_ip(host)?"ip":"domain";if(strcmp(textval(item,"type"),expected)){error_set(&e,"HTTP error","target type mismatch");return technical(&e,started);}
    int ports[MAX_PORTS]={80,443},nports=2;J *raw=get(item,"ports");J *ignored=NULL;bool ports_present=json_object_object_get_ex(item,"ports",&ignored);
    if(ports_present&&(!json_object_is_type(raw,json_type_array)||json_object_array_length(raw)>8)){error_set(&e,"HTTP error","invalid ports");return technical(&e,started);}
    if(raw)for(size_t i=0;i<json_object_array_length(raw);i++){J *p=json_object_array_get_idx(raw,i);int64_t port=json_object_get_int64(p);
        if(!json_object_is_type(p,json_type_int)||port<1||port>65535){error_set(&e,"HTTP error","invalid port");return technical(&e,started);}
        bool found=false;for(int k=0;k<nports;k++)if(ports[k]==port)found=true;if(!found)ports[nports++]=(int)port;
    }
    double ds=now_ms();Addresses addresses;if(resolve_public(host,&addresses,&e))return technical(&e,started);
    dns=measurement(true,elapsed(ds),NULL);J *a=json_object_new_array(),*aaaa=json_object_new_array();for(int i=0;i<addresses.count;i++)json_object_array_add(strchr(addresses.ip[i],':')?aaaa:a,json_object_new_string(addresses.ip[i]));put(dns,"a",a);put(dns,"aaaa",aaaa);
    double check_timeout=fmin(timeout,3.0);ping=best_ping(&addresses,fmin(check_timeout,2.0));tcp=json_object_new_object();
    TcpTask tasks[MAX_PORTS];pthread_t threads[MAX_PORTS];bool launched[MAX_PORTS]={0};
    for(int i=0;i<nports;i++){tasks[i]=(TcpTask){&addresses,ports[i],fmin(check_timeout,2.0),NULL};launched[i]=start_thread(&threads[i],tcp_worker,&tasks[i])==0;if(!launched[i])tcp_worker(&tasks[i]);}
    for(int i=0;i<nports;i++){if(launched[i])pthread_join(threads[i],NULL);char key[8];snprintf(key,sizeof(key),"%d",ports[i]);put(tcp,key,tasks[i].result);}
    if(truth(get(tcp,"443")))tls=tls_check(host,&addresses,check_timeout);
    else {tls=measurement(false,0,NULL);str(tls,"error_type","connection refused");str(tls,"error","TCP 443 is closed or filtered");put(tls,"attempts",json_object_new_array());}
    WebTask web[2]={0};pthread_t wt[2];bool wl[2];
    for(int i=0;i<2;i++){snprintf(web[i].url,sizeof(web[i].url),"%s://%s%s%s/",i?"https":"http",strchr(host,':')?"[":"",host,strchr(host,':')?"]":"");web[i].timeout=check_timeout;wl[i]=start_thread(&wt[i],web_worker,&web[i])==0;if(!wl[i])web_worker(&web[i]);}
    for(int i=0;i<2;i++)if(wl[i])pthread_join(wt[i],NULL);http=web[0].result;https=web[1].result;
    if(!http||!https){e=!http?web[0].error:web[1].error;json_object_put(dns);json_object_put(ping);json_object_put(tcp);json_object_put(tls);if(http)json_object_put(http);if(https)json_object_put(https);return technical(&e,started);}
    bool ok=truth(get(tcp,"80"))||truth(get(tcp,"443"))||truth(http)||truth(https)||truth(ping);
    J *r=json_object_new_object();boolean(r,"ok",ok);str(r,"target_type",expected);str(r,"summary",ok?"Узел получил сетевой ответ":"Ответ на проверенные запросы не получен");put(r,"dns",dns);put(r,"ping",ping);put(r,"tcp",tcp);put(r,"tls",tls);put(r,"http",http);put(r,"https",https);num(r,"total_ms",elapsed(started));return r;
}

typedef struct { char *data;size_t length; } Buffer;
static size_t api_write(char *data,size_t size,size_t count,void *user) {
    Buffer *b=user;if(size&&count>SIZE_MAX/size)return 0;size_t n=size*count;if(n>API_LIMIT-b->length)return 0;
    char *p=realloc(b->data,b->length+n+1);if(!p)return 0;b->data=p;memcpy(p+b->length,data,n);b->length+=n;p[b->length]=0;return n;
}
static J *parse_json(const char *data,size_t size) {
    struct json_tokener *tok=json_tokener_new();json_tokener_set_flags(tok,JSON_TOKENER_STRICT|JSON_TOKENER_VALIDATE_UTF8);J *o=json_tokener_parse_ex(tok,data,(int)size);
    if(json_tokener_get_error(tok)!=json_tokener_success){if(o)json_object_put(o);o=NULL;}
    json_tokener_free(tok);return o;
}
static J *api_request(J *config,const char *path,J *payload) {
    char url[URL_LIMIT],authorization[256];if(snprintf(url,sizeof(url),"%s%s",textval(config,"server"),path)>=(int)sizeof(url))return NULL;
    snprintf(authorization,sizeof(authorization),"Authorization: Bearer %s",textval(config,"api_key"));CURL *curl=curl_easy_init();Buffer buffer={0};struct curl_slist *headers=NULL,*resolve=NULL;
    /* API transport override only: retain URL hostname, SNI and TLS verification. */
    const char *connect_ip=textval(config,"api_connect_ip");
    if(*connect_ip){CURLU *u=curl_url();char *host=NULL,*port=NULL;char entry[512];
        if(curl_url_set(u,CURLUPART_URL,url,0)==CURLUE_OK&&curl_url_get(u,CURLUPART_HOST,&host,0)==CURLUE_OK&&curl_url_get(u,CURLUPART_PORT,&port,CURLU_DEFAULT_PORT)==CURLUE_OK){
            snprintf(entry,sizeof(entry),strchr(connect_ip,':')?"%s:%s:[%s]":"%s:%s:%s",host,port,connect_ip);resolve=curl_slist_append(resolve,entry);curl_easy_setopt(curl,CURLOPT_RESOLVE,resolve);}
        curl_free(host);curl_free(port);curl_url_cleanup(u);}
    headers=curl_slist_append(headers,authorization);headers=curl_slist_append(headers,"Accept: application/json");if(payload)headers=curl_slist_append(headers,"Content-Type: application/json");
    curl_easy_setopt(curl,CURLOPT_URL,url);curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);curl_easy_setopt(curl,CURLOPT_USERAGENT,UA);curl_easy_setopt(curl,CURLOPT_TIMEOUT_MS,(long)(json_object_get_double(get(config,"request_timeout"))*1000));
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,api_write);curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buffer);curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_PROTOCOLS_STR,"http,https");curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
    if(payload)curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json_object_to_json_string_ext(payload,JSON_C_TO_STRING_PLAIN));
    CURLcode code=curl_easy_perform(curl);long status=0;curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);J *reply=NULL;
    if(code==CURLE_OK&&status==200&&buffer.data){reply=parse_json(buffer.data,buffer.length);if(reply&&!json_object_is_type(reply,json_type_object)){json_object_put(reply);reply=NULL;}}
    if(!reply)fprintf(stderr,"Temporary API error: HTTP %ld; curl=%d; %s\n",status,(int)code,curl_easy_strerror(code));
    free(buffer.data);curl_slist_free_all(headers);curl_slist_free_all(resolve);curl_easy_cleanup(curl);return reply;
}
static J *read_json_file(const char *path) {
    FILE *f=fopen(path,"rb");if(!f)return NULL;char *data=malloc(API_LIMIT+1);if(!data){fclose(f);return NULL;}size_t n=fread(data,1,API_LIMIT+1,f);bool bad=ferror(f)||n>API_LIMIT;fclose(f);J *o=bad?NULL:parse_json(data,n);free(data);return o;
}
static int number_config(J *o,const char *key,double lo,double hi,bool integral) {
    J *v=get(o,key);if(!v)return -1;double n=json_object_get_double(v);if(!isfinite(n))return -1;n=fmax(lo,fmin(hi,n));put(o,key,integral?json_object_new_int((int)n):json_object_new_double(n));return 0;
}
static J *load_config(const char *path) {
    J *o=read_json_file(path);if(!o||!json_object_is_type(o,json_type_object))goto invalid;
    const char *key=textval(o,"api_key");if(strlen(key)<20||strlen(key)>128||strchr(key,'\r')||strchr(key,'\n'))goto invalid;
    J *connect=get(o,"api_connect_ip");if(connect){if(!json_object_is_type(connect,json_type_string))goto invalid;const char *ip=json_object_get_string(connect);unsigned char address[16];if(*ip&&inet_pton(AF_INET,ip,address)!=1&&inet_pton(AF_INET6,ip,address)!=1)goto invalid;}
    CURLU *u=curl_url();char *scheme=NULL,*host=NULL,*user=NULL,*pass=NULL;bool bad=curl_url_set(u,CURLUPART_URL,textval(o,"server"),0)!=CURLUE_OK;
    curl_url_get(u,CURLUPART_SCHEME,&scheme,0);curl_url_get(u,CURLUPART_HOST,&host,0);
    bad=bad||!scheme||!host||(strcmp(scheme,"http")&&strcmp(scheme,"https"));
    if(curl_url_get(u,CURLUPART_USER,&user,0)==CURLUE_OK||curl_url_get(u,CURLUPART_PASSWORD,&pass,0)==CURLUE_OK)bad=true;
    curl_free(scheme);curl_free(host);curl_free(user);curl_free(pass);curl_url_cleanup(u);if(bad)goto invalid;
    char *server=strdup(textval(o,"server"));size_t n=strlen(server);while(n&&server[n-1]=='/')server[--n]=0;str(o,"server",server);free(server);
    if(number_config(o,"poll_interval",5,3600,true)||number_config(o,"request_timeout",2,60,false)||number_config(o,"max_parallel_checks",1,20,true))goto invalid;
    return o;
invalid:if(o)json_object_put(o);return NULL;
}
typedef struct { J *item;J *result;double timeout; } CheckTask;
static void *check_worker(void *arg) { CheckTask *t=arg;t->result=run_check(t->item,t->timeout);return NULL; }
static void stop_signal(int sig) { (void)sig;stopping=1; }
static void sleep_seconds(int seconds) { struct timespec t={seconds,0};while(!stopping&&nanosleep(&t,&t)<0&&errno==EINTR){} }
static int initialize(void) {
    signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);
    curl_global_init(CURL_GLOBAL_DEFAULT);tls_context=SSL_CTX_new(TLS_client_method());if(!tls_context)return -1;
    SSL_CTX_set_verify(tls_context,SSL_VERIFY_PEER,NULL);SSL_CTX_set_min_proto_version(tls_context,TLS1_2_VERSION);
    /* CPython 3.12.3 / Ubuntu reference policy; distributions may customize it. */
    SSL_CTX_set_cipher_list(tls_context,"ALL:!COMPLEMENTOFDEFAULT:!eNULL");
    SSL_CTX_set_security_level(tls_context,2);return SSL_CTX_set_default_verify_paths(tls_context)==1?0:-1;
}
#ifndef PROBE_NO_MAIN
int main(int argc,char **argv) {
    if(initialize()){fprintf(stderr,"TLS initialization failed\n");return 2;}
    if(argc==3&&!strcmp(argv[1],"--validate-config")){J *c=load_config(argv[2]);if(!c){fprintf(stderr,"Invalid configuration\n");return 2;}json_object_put(c);SSL_CTX_free(tls_context);curl_global_cleanup();return 0;}
    if(argc==3&&!strcmp(argv[1],"--check")){J *item=read_json_file(argv[2]);if(!item){fprintf(stderr,"Invalid check JSON\n");return 2;}J *r=run_check(item,10);puts(json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN));json_object_put(r);json_object_put(item);SSL_CTX_free(tls_context);curl_global_cleanup();return 0;}
    bool once=argc>1&&!strcmp(argv[1],"--once");const char *path=once?(argc>2?argv[2]:"/etc/roskompozor-probe/config.json"):(argc>1?argv[1]:"/etc/roskompozor-probe/config.json");
    J *config=load_config(path);if(!config){fprintf(stderr,"Configuration error (check JSON and required fields)\n");return 2;}
    int parallel=json_object_get_int(get(config,"max_parallel_checks")),interval=json_object_get_int(get(config,"poll_interval"));double timeout=json_object_get_double(get(config,"request_timeout"));
    fprintf(stderr,"Native Probe started\n");
    do {
        J *reply=api_request(config,"/api/probe/checks",NULL),*checks=reply?get(reply,"checks"):NULL;bool failed=!reply||(checks&&!json_object_is_type(checks,json_type_array));
        size_t count=checks&&json_object_is_type(checks,json_type_array)?json_object_array_length(checks):0;J *results=json_object_new_array();
        if(!failed&&count)fprintf(stderr,"Received %zu checks\n",count);
        if(!failed&&count)for(size_t offset=0;offset<count&&!stopping;offset+=(size_t)parallel) {
            CheckTask tasks[20]={0};pthread_t threads[20];bool launched[20]={0};size_t batch=count-offset;if(batch>(size_t)parallel)batch=(size_t)parallel;
            for(size_t k=0;k<batch;k++){J *item=json_object_array_get_idx(checks,offset+k);if(!json_object_is_type(item,json_type_object)||!get(item,"id"))continue;tasks[k]=(CheckTask){item,NULL,timeout};if(parallel==1)check_worker(&tasks[k]);else {launched[k]=start_thread(&threads[k],check_worker,&tasks[k])==0;if(!launched[k])check_worker(&tasks[k]);}}
            for(size_t k=0;k<batch;k++){if(launched[k])pthread_join(threads[k],NULL);if(tasks[k].result){J *o=json_object_new_object();str(o,"check_id",json_object_get_string(get(tasks[k].item,"id")));put(o,"result",tasks[k].result);json_object_array_add(results,o);}}
        }
        if(json_object_array_length(results)&&!stopping){J *payload=json_object_new_object();put(payload,"results",results);results=NULL;J *ack=api_request(config,"/api/probe/results",payload);failed=!ack;if(ack){fprintf(stderr,"Submitted: accepted=%d duplicates=%d rejected=%d\n",json_object_get_int(get(ack,"accepted")),json_object_get_int(get(ack,"duplicates")),json_object_get_int(get(ack,"rejected")));json_object_put(ack);}json_object_put(payload);}
        if(results)json_object_put(results);if(reply)json_object_put(reply);if(once){json_object_put(config);SSL_CTX_free(tls_context);curl_global_cleanup();return failed?1:0;}
        if(!count||failed)sleep_seconds(interval);
    }while(!stopping);
    json_object_put(config);SSL_CTX_free(tls_context);curl_global_cleanup();return 0;
}
#endif
