#define PROBE_NO_MAIN
#include "../src/probe.c"
int main(int argc,char **argv) {
    if(initialize())return 2;
    Error e={0};J *r=NULL;
    if(argc==3&&!strcmp(argv[1],"public")) { r=json_object_new_boolean(public_ip(argv[2])); }
    else if(argc==3&&!strcmp(argv[1],"normalize")) { char host[254];r=json_object_new_object();if(normalize_host(argv[2],host,&e))add_error(r,&e);else str(r,"host",host); }
    else if(argc==3&&!strcmp(argv[1],"resolve")) { Addresses a;r=json_object_new_object();if(resolve_public(argv[2],&a,&e))add_error(r,&e);else {J *list=json_object_new_array();for(int i=0;i<a.count;i++)json_object_array_add(list,json_object_new_string(a.ip[i]));put(r,"addresses",list);} }
    else if(argc==3&&!strcmp(argv[1],"url")) { Url u;r=json_object_new_object();if(parse_url(argv[2],&u,&e))add_error(r,&e);else {str(r,"scheme",u.tls?"https":"http");str(r,"host",u.host);num(r,"port",u.port);str(r,"path",u.path);} }
    else if(argc==4&&!strcmp(argv[1],"join")) { char url[URL_LIMIT];r=json_object_new_object();if(join_url(argv[2],argv[3],url,&e))add_error(r,&e);else str(r,"url",url); }
    else if(argc==3&&!strcmp(argv[1],"chain")) { r=http_chain(argv[2],2,&e);if(!r){r=json_object_new_object();add_error(r,&e);} }
    else if(argc==3&&!strcmp(argv[1],"config")) { r=load_config(argv[2]);if(!r){r=json_object_new_object();str(r,"error","invalid config");}else json_object_object_del(r,"api_key"); }
    else if(argc==3&&!strcmp(argv[1],"tls")) { Addresses a;if(resolve_public(argv[2],&a,&e))r=technical(&e,now_ms());else r=tls_check(argv[2],&a,2); }
    else return 2;
    puts(json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN));json_object_put(r);SSL_CTX_free(tls_context);curl_global_cleanup();return 0;
}
