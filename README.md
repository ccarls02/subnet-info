# subnet-info
will return subnet info for an ip/cidr or for the subnet two ips belong to

  Usage:

    ./subnet.pl <ip_address/cidr>

       This will return all subnet info

    ./subnet.pl <ip_address> <ip_address>

       This will compare the IPs, show what subnet they belong to
        and print all info about the subnet

    ./subnet.pl explain <ip_address/cidr>

        This will return all subnet info and
         will also print calculation information

------------------------------------------------------------
~~~
ccarls02$ ./subnet.pl 144.230.82.244/28

   /28 Subnet Mask: 255.255.255.240
     Wildcard Mask: 0.0.0.15

        Entered IP: 144.230.82.244/28

            Subnet: 144.230.82.240

      Subnet Range: 144.230.82.241 -
                    144.230.82.254

    Broadcast Addy: 144.230.82.255

 Next Network Addy: 144.230.83.0

        Usable IPs: 16 - 2


ccarls02$ ./subnet.pl 144.230.82.244 144.230.82.242

                                     --><--
   IP1: 10010000.11100110.01010010.11110100 | 144.230.82.244
   IP2: 10010000.11100110.01010010.11110010 | 144.230.82.242

   IPs are both in subnet: 144.230.82.240 / 29


   /29 Subnet Mask: 255.255.255.248
     Wildcard Mask: 0.0.0.7

            Subnet: 144.230.82.240

      Subnet Range: 144.230.82.241 -
                    144.230.82.246

    Broadcast Addy: 144.230.82.247

 Next Network Addy: 144.230.82.248

        Usable IPs: 8 - 2

~~~
