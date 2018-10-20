/* pty version */
# define BLEH

/****************************************************************/
/*			   R S H S R V . C			*/
/*								*/
/*		     Phil Budne @ Boston U / DSG		*/
/*                    (c) 1986 Boston University.		*/
/*          Permission granted to copy for non-profit use.	*/
/*								*/
/*	This program  is  CRJOB'ed not-logged-in  by  RSHD.	*/
/*	The monitor must include support for a special  bit	*/
/*	for the CRJOB JSYS so  that when CJ%LWP is set  the	*/
/*	job may log in without a password.			*/
/*								*/
/*	After  reading   and   vaidating   data   we   fork	*/
/*	SYSTEM:RSHEXEC.EXE, and start it at +2 (Version!!).	*/
/*	RSHEXEC is an  EXEC which reads  one command,  then	*/
/*	exits it also never prompts or heralds.			*/
/*								*/
/*	This program was written using UTAH TOPS-20 PCC		*/
/*								*/
/****************************************************************/

# include <stdio.h>
# include <signal.h>
# include <ctype.h>

# include "pcc:tops20.h"
# include "pcc:mon_files.h"
# include "pcc:mon_fork.h"
# include "mon_networks.h"
# include "mon_crjob.h"

# define RC_emo 01:35-17
# define PRast 2
# define RSini 0

/* # define DEBUG 1			/* define to enable debugging */

main() {
    int jfn;

# ifndef DEBUG
    if( logged_in() ) {
	printf("Foo! you are already logged in!!\n");
	exit(999);
    } /* already logged in */
# endif

    setname("RSHSRV");			/* Set up name so not LOGOUT */

    epcap(FHslf,-1);			/* Enable all privs (needs ABS-SOCK) */

    jfn = openttyraw();			/* get raw tty jfn */
    if( jfn < 0 ) punt(PRiou, "Could not open TTY:");
    doit(jfn);
# ifndef DEBUG
    keel();
# endif
} /* main */

logged_in() {
    int acs[5];

    JSYS(JSgjinf, acs);			/* get job info */
    if( ac1 == 0 )
	return( 0 );
    else
	return( 1 );

} /* logged_in */

keel() {
    int acs[5];

    JSYS(JSdtach, acs);			/* hide embarrassing LOGOUT mess */
    logout(-1);				/* log self out */
    JSYS(JShaltf, acs);			/* halt?! */
} /* keel */

int openttyraw() {
    int acs[5], jfn;

    ac1 = Value(GJ_sht);		/* short form */
    ac2 = POINT("TTY:");		/* get TTY: */
    if( JSYS(JSgtjfn, acs) == JSerr )	/* get jfn */
	return( -1 );			/* sigh! */
    jfn = ac1;				/* save jfn */

    ac2 = makefield(OF_bsz,8) | makefield(OF_mod, 010) |
	Value(OF_rd) | Value(OF_wr);	/* 8bit, image mode, read/write */
    if( JSYS(JSopenf, acs) == JSerr ) {	/* open! */
	reljfn(jfn);			/* failed, release jfn */
	return( -1 );			/* return failure */
    } /* openf failed */

    if( JSYS(JSrfmod,acs) != JSerr ) {
	ac3 &= ~0300;			/* clear TT%DAM (image) */
	JSYS(JSsfmod,acs);
    }

    return( jfn );			/* return jfn */
} /* openttyraw */

# define VALJFN jfn			/* JFN for validation (0/1) */

doit(jfn)
int jfn;
{
    char buff[10], foreign[30], fnuser[17], lcuser[39], command[200],cmd2[200];
    char fhnstr[20];
    int errport, errjfn, acs[5], fhno, execfork, userno;

# ifndef DEBUG
    signal(SIGHUP, keel);		/* logout if detached */
					/* Doesn't work? Check library.. */
/*    signal(SIGALRM, keel);		/* keel when time runs out */
/*    alarm( 5 * 60 );			/* set clock for 5 minutes */

    if( getstr(jfn, fhnstr, 20 ) )
	return( punt(jfn, "could not get 4n host number") );
    fhno = atoi( fhnstr );
# ifdef BLEH
    printf("fhno: %d\n", fhno);
# endif

    if( getstr(jfn, buff, 10) )
	return( punt(jfn, "could not read error socket number") );

    errport = atoi(buff);
# ifdef BLEH
    printf("errport: %d\n", errport); /**/
# endif

    if( errport > 0 ) {
	errjfn = getcon(fhno, errport);	/* establish error stream */
	if( errjfn < 0 )
	 return( punt(jfn, "could not open error socket") );
    } /* wants socket for errors */
    else errjfn = jfn;

# ifdef NOTDEF
    if( hostname(foreign, fhno) < 0 )
	return( punt(VALJFN, "Could not get name for client host") );
    lowerify(foreign);
# endif

    if( getstr(jfn, lcuser, 39) )
	return( punt(VALJFN, "bad locuser") );
# ifdef BLEH
    printf("lc: %s\n", lcuser); /**/
# endif

    if( getstr(jfn, fnuser, 17) )
	return( punt(VALJFN, "bad frnuser") );
# ifdef BLEH
    printf("fn: %s\n", fnuser); /**/
# endif

    if( getstr(jfn, command, 200) )
	return( punt(VALJFN, "bad command") );
# ifdef BLEH
    printf("cm: %s\n", command); /**/
# endif

    ac1 = Value(RC_emo);
    ac2 = POINT(lcuser);
    if( JSYS(JSrcusr, acs) == JSerr )
	return( punt(VALJFN, "local user does not exist") );
    userno = ac3;

# ifndef DEBUG
    if( ruserok(foreign, 0, fnuser, lcuser ) != 0 )
	return( punt(VALJFN, "Permission denied.") );

    ac1 = userno;			/* get user # in ac1 */
    ac2 = POINT("");			/* null password */
    ac3 = POINT("");			/* null account */
    if( JSYS(JSlogin, acs) == JSerr )
	return( punt(VALJFN, "LOGIN failed") );
# endif

    ac1 = CR_cap;			/* pass caps */
    if( JSYS(JScfork, acs) == JSerr )	/* create a fork */
	return( punt(VALJFN, "Could not create EXEC fork") );
    execfork = ac1;

    ac1 = Value(GJ_sht) + Value(GJ_old);
    ac2 = POINT("SYSTEM:RSHEXEC.EXE");
    if( JSYS(JSgtjfn, acs) == JSerr )
	return( punt(VALJFN, "Could not find SYSTEM:RSHEXEC.EXE") );

    ac1 = makeword( execfork, getright(ac1) );
    if( JSYS(JSget, acs) == JSerr )
	return( punt(VALJFN, "Could not GET EXEC") );

/*  doprarg(execfork); */

    fnstd(cmd2, command);		/* convert unix path to '20 form */
    if( rcstring(cmd2) < 0 )		/* place in rscan buffer */
	return( punt(VALJFN, "Could not set up command") );

    write(VALJFN, "", 1);		/* send null (validated ok) */

    ac1 = execfork;
    ac2 = 2;				/* start at +2 */
    if( JSYS(JSsfrkv, acs) == JSerr )
	return( punt2(VALJFN, "Could not start EXEC") );

    ac1 = execfork;
    if( JSYS(JSwfork, acs) == JSerr )
	return( punt2(VALJFN, "Could not wait for EXEC") );

    write(errjfn, "", 1);

    if( errjfn != jfn )			/* if we have an error jfn */
	close(errjfn, Value(CZ_abt));	/* close (and abort) it */
} /* doit */

int tvtstat(tvt, word)
int tvt, word;
{
    int acs[5], result;

    ac1 = tvt + Value(TCP_tv);		/* get TVT number in A */
    ac2 = makeword(-1,word);		/* get specified word */
    ac3 = makeword(-1,(int) &result);	/* result */
    if( JSYS(JSstat, acs) == JSerr )	/* read TCP connection 4n host */
	return( -1 );
    else
	return( result );
} /* tvtstat */


setname(s)
char *s;
{
    int acs[5];

    ac1 = ac2 = makesix(s);
    JSYS(JSsetsn, acs);
} /* setname */

int makesix(s)
register char *s;
{
    register int i, j;
    register char c;

    j = 0;
    for( i = 0; i < 6; i++ ) {
        if( (c = *s++) != NULL ) {
	    if( c < 040 ) c = '?';
	    if( c > '_' ) c = c - 040;
	    j = (j << 6) + c - 040;
	} /* if got a char */
	else break;
    } /* for */

    if( i < 6 ) j = j << (6 - i);
} /* makesix */

int getstr(jfn, buff, len)		/* read counted string, or till NUL */
char buff[];
int jfn;
{
    int acs[5];

    ac1 = jfn;
    ac2 = POINT(buff);
    ac3 = len;
    ac4 = 0;

    if( JSYS(JSsin,acs) == JSerr )
	return( -1 );

    if( ac3 == 0 || (len - ac3) == 0 )	/* overflow or read nothing? */
	return( -1 );
    else
        return( 0 );
} /* getstr */


/**************** FROM RCMD.C ****************/

extern char *index();

ruserok(rhost, superuser, ruser, luser)
	char *rhost;
	int superuser;
	char *ruser, *luser;
{
	FILE *hostf;
	char ahost[32];
	int first = 1;

	hostf = superuser ? (FILE *)0 : fopen("/etc/hosts.equiv", "r");
again:
	if (hostf) {
		while (fgets(ahost, sizeof (ahost), hostf)) {
			char *user, *idx;
			if ( (idx = index(ahost, '\n')) )
				*idx = 0;
			user = index(ahost, ' ');
			if (user)
				*user++ = 0;
			if (!strcmp(rhost, ahost) &&
			    !strcmp(ruser, user ? user : luser)) {
				(void) fclose(hostf);
				return (0);
			}
		}
		(void) fclose(hostf);
	}
	if (first == 1) {
		char buf[100];		/* BUDD */
		sprintf(buf, "ps:<%s>\026.rhosts", luser); /* BUDD */
		first = 0;
		hostf = fopen(buf, "r"); /* BUDD */
		goto again;
	}
	return (-1);
} /* ruserok */

int getcon(fhost, fsock)
int fhost, fsock;
{
    char buffer[50];
    int lsock, jfn;

    for( lsock = 1; lsock < 1024; lsock++ ) {
	sprintf(buffer,"TCP:%d\026#.%o-%d;CONN:ACT", lsock, fhost, fsock );
	if( (jfn = trytcp(buffer)) > 0 )
	    return( jfn );
    } /* for */
    return( -1 );
} /* getcon */

int punt2(jfn, s)
int jfn;
char *s;
{
    write(jfn, s, strlen(s));		/* pass failure string */
    return( -1 );
} /* punt2 */

doprarg(fork)
int fork;
{
    int scjprb[8], acs[5];
    register int *sp;

    sp = scjprb;

    *sp++ = 4;				/* 0 - 4 words.. */
    *sp++ = makeword(0414100, 02545);	/* 1 - very magic word */
    *sp++ = 4;				/* 2 - word 4 is data */
    *sp++ = 0;				/* 3 - nothing */
    *sp++ = (1 << 35);			/* 4 - suppress exec herald */

    ac1 = makeword(PRast, fork);
    ac2 = (int) scjprb;
    ac3 = 6;
    JSYS(JSprarg, acs);

} /* doprarg */

lowerify(s)
register char *s;
{
    register char c;

    while( (c = *s) != NULL ) {
	if( isupper( c ) ) *s = tolower( c );
	s++;
    } /* while */
} /* lowerify */


rcstring(s)				/* place string in RSCAN buffer */
register char *s;
{
    char bigbuf[500], lc;
    register char c, *d;
    int acs[5];

    d = bigbuf;
    while( (c = *s++) != NULL ) {
	lc = c;
	if( c == '\n' ) {		/* convert NL to CRLF */
	    *d++ = '\r';
	    *d++ = '\n';
	}
	else if( c != '\r' )		/* discard CR */
	    *d++ = c;
    } /* while */

    if( lc != '\n' ) {			/* if last was not NL, add CRLF */
	*d++ = '\r';
	*d++ = '\n';
    } /* last not NL */

    *d++ = '\0';			/* tie off with NUL */

    ac1 = POINT(bigbuf);		/* insert string into RSCAN */
    if( JSYS(JSrscan, acs) == JSerr )
	return( -1 );

    ac1 = RSini;			/* make RSCAN available as input */
    if( JSYS(JSrscan, acs) == JSerr )
	return( -1 );
    return( 0 );

} /* rcstring */

/** Local Modes: * */
/** Comment Column:40 * */
/** End: * */
