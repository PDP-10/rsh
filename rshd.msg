I have tried to implement an RSHD using NVTs also.  I ended up with
the same technique that MRC suggested, RSHD just listens for a connect
and verifies that it comes from a 'secure' port (<1024.)  on a host we
have a name for, and then CRJOBs a job loaded with "RSHSRV", creates
an NVT and ATACHes the two.

Problem;
Since we have not read any data we don't know who to log in as.

Solution;
I added a bit CR%LWP to CRJOB (Login Without Password), this sets a
bit in the SYSFK word of the created fork.

Problem 2;
Some huge number of useful things under TOPS-20 are not programs but
EXEC commands.. So you hack up your EXEC to read one command from the
RSCAN buffer and then quit when entered in a new entry vector
position.

Problem 3;
Ok so you have this running, everything looks fine -- but you notice
that when a BSD user types "rsh twenex foo", they get output, then you
see a logout message, and the connection hangs.

So, you have RSHSRV detach and LGOUT when the hacked EXEC returns.

Fix this, you still hang, the job never detaches.

Well, you see TVTs are expected to talk TELNET protocol.  DTACH does a
DOBE, which sends a TELNET mark-time command, to which RSHD does not
know how to respond.  (You might have noticed that TVT-SMTP jobs hung
for the same reason).

Cure; have DOBE on a TVT be a NOOP.

Now the job logs out cleanly, but you STILL hang on your UNIX system.
This may simply be a misfeature of the BSD RSH program, it doesn't
expect anyone to implement RSH for a system that can not 'half close'
a connection.

But wait, just try to write something that transfers large amounts of
data, say 'RCP' or 'RMT' BINARY DATA... You will find that TVT thruput
is well, awful, and you will lose data espcially anything containing
IAC.

Problem N.1;
You want to write an RSH for tops-20 do you?  Well RSH is
a secure protocol, and depends on the fact that only SuperUser can
open a connection with a local port of <1024.  Any connection with a
remote local port of <1024. is to be trusted, and when the data says
the remote user name is "foo" it is to be believed.

So you can either; leave the monitor the way it came (only ports <512
protected), or add a new magic bit in SYSFK.  If we have just done an
execute only GET% we look at the FDB of the EXE file, if it has a
special (priv'ed) bit lit, we light the SYSFK bit, and the fork is
ENCHANTED.  This bit is checked at the same places (several) that
check for WOPR on a TCP open.

Problem N.2;

The RSH protocol (and this is used by BSD rsh), specifies that the
first data item is a foreign port (or zero) for sending back data from
the forks stderr, in fact the rsh will wait for a connect on that port
until it proceeds.  This connection must originate from a secure port
.. so that the RSHSRV must be created with pre-login WOPR, or be
enchanted (note since enchanted-ness is not a capability it is never
inherited by children).

TOPS-20 only checks local ports for uniqueness within a job, BSD never
creates the same local port twice.  For a reason that escapes me (but
has to do with the STDERR connection), this causes problems.  OK,
remove that code too.  Whew!! FTP continues to work.

--
Moral, Or how I would try to do it next if I had the strength;

First and foremost this proves that Un*x software and concepts are
completely transportable... between any two Un*x systems :-)

a) Have RSHD listen for connects, process the data and drop a PTY
connect a job logged into whoever we please and just pass the data.
Feature; require NO monitor changes.  'Bit nasty to have the process
in between handling all the data for all the RSHs.

b) Create a not logged in job loaded with RSHSRV, CJ%LWP set, and
either WOPR or enchanted.  Does a passive listen for RSH connects.
When a connect is received, either spawn a another like us, or notify
an authority via IPCF to do so (DEC DTRSRV (datatrieve) and the new
RMSFAL do just this).  RSHSRV then reads and validates the data,
creates the error pipe if needed, and LOGs in.  Get a PTY, and assign
it as controlling for an EXEC, and ferry data back and forth between
the PTY and the TCP connection.  This avoids having on central octopus
hacking the PTYs.


	Good Guys	RSH
	0		34359738367

I wrote all my code using the UTAH PCC-20 compiler, you're welcome to it!!

	Philip Budne
	Boston University / Distributed Systems
