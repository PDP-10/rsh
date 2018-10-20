/*
 *	RSHLIB.C -- Phil Budne @ BostonU / Distributed Systems
 *	Common routines for RSHSRV/RSHD
 *
 *	(c) 1986 Boston University.
 *	Permission granted to copy for non-profit use.
 *
 *	Written using UTAH PCC-20.
 *
 */

# include "pcc:stdio.h"
# include "pcc:tops20.h"
# include "pcc:mon_files.h"
# include "pcc:mon_fork.h"
# include "mon_crjob.h"
# include "mon_networks.h"

int punt(jfn, s)
int jfn;
char *s;
{
    write(jfn, "\01", 1);		/* pass failure code */
    write(jfn, s, strlen(s));		/* pass failure string */
    write(jfn, "\n", 1);		/* send newline */
    return( -1 );
}

reljfn(j)
int j;
{
    int acs[5];

    acs[1] = j;
    JSYS(JSrljfn,acs);
} /* reljfn */


int trytcp(name)
char *name;
{
    int acs[5], jfn;

    ac1 = Value(GJ_sht);
    ac2 = POINT(name);
    if( JSYS(JSgtjfn,acs) == JSerr )
	return( -1 );
    jfn = ac1;				/* save jfn */

    ac2 = 0100400300000;		/* 8bit, interactive, rd/wr */
    if( JSYS(JSopenf,acs) == JSerr ) {
	reljfn(jfn);
        return( -1 );
    } /* openf failed */
    return( jfn );
} /* trytcp */

epcap(fork,i)				/* enable process capabilities */
int fork, i;
{
    int acs[5];

    ac1 = fork;
    ac3 = i;				/* enable mask */
    JSYS(JSepcap,acs);			/* perform enable */
} /* epcap */

logout(job)
int job;
{
    int acs[5];

    ac1 = job;
    JSYS(JSlgout,acs);			/* blast job */
} /* logout */

int hostname(str, numb)			/* convert address to name */
char *str;
int numb;
{
    int acs[5];

    ac1 = GThns;			/* string from address */
    ac2 = POINT(str);			/* bp to string */
    ac3 = numb;				/* address */
    if( JSYS(JSgthst, acs) == JSerr )
	return( -1 );
    else
	return( 0 );
} /* hostname */

/** Local Modes: * */
/** Comment Column:40 * */
/** End: * */
