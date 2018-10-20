/* pty version */

/*
 *	RSHD.C -- Phil Budne @ BostonU / Distributed Systems
 *	BSD Un*x style remote shell daemon for Twenex
 *
 *	(c) 1986 Boston University.
 *	Permission granted to copy for non-profit use.
 *
 *	Written using UTAH PCC-20. Link with RSHLIB.
 *
 *	Scenario:
 *	Wait for connection, then spawn a new job loaded with RSHSRV,
 *	NLI with the CJ%LWP (BU -- login without password).
 */

# include "pcc:stdio.h"
# include "pcc:tops20.h"
# include "pcc:mon_files.h"
# include "pcc:mon_fork.h"
# include "mon_crjob.h"

main() {
    int jfn;

    epcap(FHslf,-1);			/* wheel up */

    for( ; ; ) {
	jfn = srvjfn();			/* wait for connect */
	if( jfn < 0 ) {
	    perror("could not get jfn");
	    exit(1);
	} /* could not open server */
	worker(jfn);
    } /* forever */
} /* main */

worker(jfn)
int jfn;
{
    char foreign[30], fhnstr[20];
    int host, sock, pty;

    if( (sock = get_fsock(jfn)) > 1023 || (host = get_fhost(jfn)) < 0 ||
      hostname(foreign, host) < 0 )
	return( punt(jfn,"Permission denied.") );

    printf("RSHD: contact from %s, port %d\n", foreign, sock);
/***** SHOULD FORK HERE *****/
    if( (pty = makjob(jfn, "USR0:<BUDD>RSHSRV.EXE")) < 0 )
	perror("RSHD: could not create job");

    fhnstr[0] = 0;
    sprintf(fhnstr, "%d", host);
    printf("fhnstr: %s\n", fhnstr);

    {
	register char *cp;
	cp = fhnstr;
	do {
	    ac1 = pty;
	    ac2 = *cp;
	    if( *cp == '\0' ) break;
	    JSYS(JSbout, acs);
/*	    printf("putting %c (%d)\n", *cp, *cp ); /**/
	} while( *cp++ != '\0' );
	jflush(jfn);
    }

    if( fork() > 0 ) {			/* parent */
	for( ; ; ) {
	    int i, acs[5];
	    ac1 = pty;			/* get from pty to net */
	    if( JSYS(JSbin, acs) == JSerr )
		return;
	    i = ac2;
	    ac1 = jfn;
	    if( JSYS(JSbout, acs) == JSerr )
		return;
	    jflush(jfn);
/*	    printf("pty -> net: %o (%c)\n", i, i); /**/
	} /* forever parent */
    } /* parent */
    else {
	for( ; ; ) {
	    ac1 = jfn;
	    if( JSYS(JSbin, acs) == JSerr )
		return;
/*	    printf("net -> pty: %o (%c)\n", ac2, ac2); /**/
	    ac1 = pty;
	    if( JSYS(JSbout, acs) == JSerr )
		return;
	} /* forever parent */
    } /* child */
} /* worker */

/*
 *	jfn	jfn of TCP: connection
 *	prog	name of .EXE file or NULL
 */

int makjob(jfn, prog)
char *prog;
int jfn;
{
    int pty, job;
    int crjblk[015], acs[5];
    register int i;

    for( i = 0; i < sizeof( crjblk ); i++ )
	crjblk[i] = 0;

    /* wait 'till attached, load file, give my caps, login w/o password */
    ac1 = Value(CJ_wta) | Value(CJ_fil) | Value(CJ_cap) | Value(CJ_lwp);
    ac2 = (int) crjblk;

    crjblk[CJfil] = POINT(prog);	/* BP to program to load */
    crjblk[CJtty] = NUlio;		/* new job is detached */

    if( JSYS(JScrjob,acs) == JSerr )
	return( punt(jfn, "Could not create job") );
    job = ac1;				/* save job number */

    pty = attpty(jfn, job);		/* create pty and attach */
    if( pty < 0 ) {
	logout(job);			/* could not create pty, kill job */
	return( punt(jfn, "Could not create pseudo terminal") );
    } /* attpty failed */
    return( pty );
} /* makjob */

int attpty(jfn, job)
int jfn, job;
{
    int acs[5];
    int pty, ptyoff, maxpty;
    register int i;

    ac1 = 026;				/* 0,,.PTYPA */
    if( JSYS(JSgetab, acs) == JSerr )
	return( -1 );

    maxpty = (ac1 >> 18) - 1;
    ptyoff = ac1 & 0777777;

    pty = ac1;
    for( i = 0; i < maxpty; i++ ) {
	char fname[100];

	fname[0] = 0;
	sprintf(fname, "PTY%o:", i);
	ac1 = Value(GJ_sht);
	ac2 = POINT(fname);
	if( JSYS(JSgtjfn,acs) == JSerr )
	    return( -1 );

	pty = ac1;
	ac2 = makefield(OF_bsz,8) | /* makefield(OF_mod, 010) | */
		Value(OF_rd) | Value(OF_wr); /* 8bit, image mode, read/write */
	if( JSYS(JSopenf, acs) != JSerr )
	    break;

	reljfn(pty);
	pty = -1;
    } /* for i */

    if( pty < 0 )
	return( -1 );

    ac1 = job | (0100000 << 18);	/* AT%TRM */
    ac2 = 0;
    ac3 = 0;
    ac4 = i + ptyoff;			/* terminal on pty */
    if( JSYS(JSatach,acs) == JSerr ) {	/* attach job to terminal */
	close( pty );			/* toss pty */
	return( -1 );
    } /* atach failed */
    return( pty );
}

int get_fsocket(jfn)
int jfn;
{
    int acs[5];

    ac1 = jfn;
    if( JSYS(JSgdsts,acs) == JSerr )
	return( 0377777777777 );	/* +INF as local socket */
    else
	return( ac4 );
} /* get_fsocket */

int get_fhost(jfn)
int jfn;
{
    int acs[5];

    ac1 = jfn;
    if( JSYS(JSgdsts,acs) == JSerr )
	return( -1 );
    else
	return( ac3 );
} /* get_fhost */

int srvjfn() {
    return( trytcp( "TCP:514\026#;CONNECT:PASSIVE" ) );
} /* srvjfn */

jflush(jfn)
int jfn;
{
    char c[2];
    c[0] = 0;
    ac1 = jfn;
    ac2 = POINT(c);
    ac3 = 0;
    JSYS(JSsoutr, acs);
}

/** Local Modes: * */
/** Comment Column:40 * */
/** End: * */
