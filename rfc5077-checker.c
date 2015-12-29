#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


enum RETCODES {
    RET_SUCCESS = 0,
    RET_ERROR
};

int getStoredSession(char * fileName, SSL_SESSION ** session)
{
    int ticketExists = 0;
    struct stat st;
    unsigned char *pp = NULL;
    int ret = lstat(fileName,&st);
    if (ret < 0){
	ticketExists = 0;
    }else{
	ticketExists = 1;
    }

    if (ticketExists){
	fprintf(stderr,"Read stored ssl session\n");
	int fd = open(fileName,O_RDONLY,0);
	if (fd < 0 ){
	    fprintf(stderr,"Error %s\n",strerror(errno));
	    return RET_ERROR;
	}


	pp = malloc(st.st_size);
	int n = read(fd,pp,st.st_size);
	close(fd);

	*session = d2i_SSL_SESSION(session,(const unsigned char **)&pp,n);
	if (*session == NULL){
	    fprintf(stderr,"Restore session error %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
	    return RET_ERROR;
	}
    }

    return RET_SUCCESS;
}

int storeSession(char * fileName,unsigned char * session,int len)
{
    int fd = open(fileName,O_WRONLY|O_CREAT|O_TRUNC,S_IRWXU);
    if (fd < 0 ){
	fprintf(stderr,"Error %s\n",strerror(errno));
	return RET_ERROR;
    }

    write(fd,session,len);
    close(fd);
    return RET_SUCCESS;
}

//return addr in network bite order
int resolve(char * host,char **addr)
{
    struct hostent * ht = gethostbyname2(host, AF_INET);

    if ( !ht ){
	fprintf(stderr,"Error:%s\n",strerror(errno));
	return RET_ERROR;
    }
    if( !ht->h_addr ){
	fprintf(stderr,"Can`t get address \n ");
	return RET_ERROR;
    }
    *addr = malloc(ht->h_length);
    memcpy(*addr,ht->h_addr,ht->h_length);
    return RET_SUCCESS;
}

int testTicket(SSL_CTX *ctx,char *sni,char *host, char * hostAddr,int port)
{

    char ticketFile[128];
    struct sockaddr_in raddr;
    SSL*                ssl = NULL;
    SSL_SESSION*        ssl_session = NULL;


    snprintf(ticketFile,128,"rfc5077-ticken-%s.asn",sni);
    getStoredSession(ticketFile,&ssl_session);

    int s = socket(AF_INET,
		   SOCK_STREAM,
		   0);
    if (s < 0 ){
	fprintf(stderr,"Error: %s\n",strerror(errno));
	return RET_ERROR;
    }


    memset(&raddr,0,sizeof(raddr));
    raddr.sin_family = AF_INET;
    memcpy(&raddr.sin_addr.s_addr,hostAddr,4);
    raddr.sin_port = htons(port);

    int ret = connect(s,(struct sockaddr  *)&raddr,
		  sizeof(raddr));
    if (ret < 0){
	fprintf(stderr,"Error: %s\n",strerror(errno));
	return RET_ERROR;
    }

    /* SSL handshake */
    if ((ssl = SSL_new(ctx)) == NULL)
        fprintf(stderr,"Unable to create new SSL struct:\n%s",
		ERR_error_string(ERR_get_error(),NULL));
    if (sni) {
        if (SSL_set_tlsext_host_name(ssl, sni) != 1) {
	    fprintf(stderr,"Unable to set SNI name to %s", sni);
        }
    }
    SSL_set_fd(ssl, s);
    if (ssl_session){
	if (!SSL_set_session(ssl, ssl_session)) {
	    fprintf(stderr,"Unable to set session to previous one:\n%s",
		 ERR_error_string(ERR_get_error(), NULL));
        }

    }

    if (SSL_connect(ssl) != 1){
        fprintf(stderr,"Unable to start TLS renegotiation with ‘%s’:\n%s",
             host,
             ERR_error_string(ERR_get_error(), NULL));
	return RET_ERROR;
    }


    if (!(ssl_session = SSL_get1_session(ssl))){
	fprintf(stderr,"No session available");
	return RET_ERROR;
    }

    unsigned long tls_ticket_time  = SSL_SESSION_get_ticket_lifetime_hint(ssl_session);
    printf("SSL Session reused %ld lifetime hint %ld\n",SSL_session_reused(ssl),tls_ticket_time);


    int need_len =  i2d_SSL_SESSION(ssl_session,NULL);
    printf("Sessin len %d\n",need_len);

    unsigned char * session_buf = malloc(need_len);
    unsigned char * pp = session_buf;
    need_len =  i2d_SSL_SESSION(ssl_session,&pp);

    ret = storeSession(ticketFile,session_buf,need_len);
    if (ret != RET_SUCCESS){
	return RET_ERROR;
    }

    return RET_SUCCESS;
}

void usage()
{
    fprintf(stderr,"rfc5077-checker -p <port> -s <sni> -h <hostname>\n");
}

int main(int argc, char ** argv)
{

    char * host = NULL;
    char * sni = NULL;
    int port = 0;
    char opt;
    SSL_CTX *ctx;

    if (argc < 4){
	usage();
	exit(1);
    }

    while ((opt = getopt(argc, argv, "p:s:h:")) != -1) {
	switch (opt) {
	case 'p':
	    port = atoi(optarg);
	    break;
	case 's':
	    sni = strdup(optarg);
	    break;
	case 'h':
	    host = strdup(optarg);
	    break;
	default:
	    fprintf(stderr,"Unknown option %c\n",opt);
	    usage();
	    exit(1);
	}
    }


    if (port == 0 || !host || !sni){
	usage();
	exit(1);
    }

    printf("Try check rfc5077:\n");
    printf("host: %s port: %d SNI: %s\n",host,port,sni);

    char * hostAddr = NULL;//4 byte for address
    int ret = resolve(host,&hostAddr);
    if ( ret != RET_SUCCESS ){
	return RET_ERROR;
    }


    SSL_load_error_strings();
    SSL_library_init();
    if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL)
	fprintf(stderr,"Unable to initialize SSL context:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));


    testTicket(ctx,sni,host,hostAddr,port);
    return RET_SUCCESS;
}
