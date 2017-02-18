# myip-fakedns
Fake DNS server answering every query with the IP of the client

Run this script with administrative privileges (to be able to bind to UDP port 53), and from any client do a `nslookup nomatterwh.at 1.2.3.4` (1.2.3.4 being the IP the server is listening on) and receive the IP you are querying from as the answer. This is intended to be a private alternative to using the `dig +short myip.opendns.com @resolver1.opendns.com` command.

This is a minor modification of the Python recipie found [here](http://code.activestate.com/recipes/491264-mini-fake-dns-server/), which is licensed under PSF. Since I'm not good with all those licensing stuff I just hope marking this as MIT is fine.
Additionally I have mixed the code with snippets from [here](https://github.com/Crypt0s/FakeDns), which seems to also have taken some parts of the code mentioned above.
