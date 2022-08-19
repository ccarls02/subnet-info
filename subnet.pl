#!/usr/bin/perl

use warnings;
use strict; 

our $inip = $ARGV[0];
our $xflag; 

if ($inip =~ /explain/) {
	$xflag = shift @ARGV;
	$inip = shift @ARGV;
	}



$inip =~ m{(\d+)(\.)(\d+)(\.)(\d+)(\.)(\d+)(\/)(\d+)};
our $oct1 = $1;
my $div1 = $2;
our $oct2 = $3;
my $div2 = $4;
our $oct3 = $5;
my $div3 = $6;
our $oct4 = $7;
my $cslash = $8;
our $subnet = $9;


## check if good ip/cidr
if ($div1 && $div2 && $div3 && $cslash) { 
	if ($subnet < 1 || $subnet > 32) {
		print "\n\n  Invalid Subnet!:  /$subnet\n\n";
		&usage;
		exit;
		}
	&print_subnetinfo;  
	} 

elsif ($ARGV[0] && $ARGV[1]) { 

	if ($ARGV[0] =~ m{(\d+)(\.)(\d+)(\.)(\d+)(\.)(\d+)} && $ARGV[1] =~ m{(\d+)(\.)(\d+)(\.)(\d+)(\.)(\d+)} ) {	
		&compareaddys; 
		}
	else { &usage; exit; }
	}  

else { 	
	&usage;
	exit; 
	}


######################################
## if 2 IPs entered, find the subnet
##

sub compareaddys {

(my $ip1,my $ip2) = @ARGV;

my $bip1 = ip2bin($ip1);
my $bip2 = ip2bin($ip2);

my $marker=2;

my @bip1 = split //, $bip1;
my @bip2 = split //, $bip2;
my $cidr_match=0;

my @ctr = (0..31);

for (@ctr) {
	if ($bip1[$_] == $bip2[$_]) { 
		$cidr_match++;
		}
	else {last;}
	}


my $actualsubnet = getdecsubnet($bip1,$cidr_match);
$marker += $cidr_match;

## correct for periods between octets
if ($cidr_match > 8) { $marker++; }
if ($cidr_match > 16) { $marker++; }
if ($cidr_match > 24) { $marker++; }

my $markerline = (" " x $marker) . "--><--\n";

print "\n";
print "   " . $markerline;
print "   IP1: " . format_bip($bip1) . " | $ip1\n";
print "   IP2: " . format_bip($bip2) . " | $ip2\n";
print "\n";
print "   IPs are both in subnet: $actualsubnet / $cidr_match\n\n";

(my $subnetdec,my $wilddec) = cidr2dec($cidr_match);


print "\n";
printf("%20s%s\n"," /$cidr_match Subnet Mask: ",$subnetdec);
printf("%20s%s\n\n"," Wildcard Mask: ",$wilddec);

fullsubnetinfo($actualsubnet,$cidr_match);

}


#####################################################
## if ip/cidr print the subnet

sub print_subnetinfo {

(my $subnetdec,my $wilddec) = cidr2dec($subnet);

print "\n";
printf("%20s%s\n"," /$subnet Subnet Mask: ",$subnetdec);
printf("%20s%s\n\n"," Wildcard Mask: ",$wilddec);
printf("%20s%s\n\n"," Entered IP: ",$inip);

## not used YET
## get hex vals
#@hexos = dec2hex($oct1,$oct2,$oct3,$oct4);

## get bin vals
my $binoct1 = dec2bin($oct1);
my $binoct2 = dec2bin($oct2);
my $binoct3 = dec2bin($oct3);
my $binoct4 = dec2bin($oct4);

my $fullbin = join("",$binoct1,$binoct2,$binoct3,$binoct4);

my $actualsubnet = getdecsubnet($fullbin,$subnet);

fullsubnetinfo($actualsubnet,$subnet);
}

#######################################
## main sub to calculate info
##

sub fullsubnetinfo {

my $subnetaddy = shift;
my $cidr = shift;

my @subnet = split /\./, $subnetaddy;
my $activeoctet = 0;
my $activecidr = 0;
my $cct = $cidr;

###
###  INVALID FOR CIDR > 30
###
if ($cidr > 31) { 
	return;
	}

##
## examine IP for active octet/mask and calculate block size
##
for my $x (1..4) {
   if ($cct >= 8) { 
	$cct -= 8;
	}	
   elsif ($cct < 8) { 
	$activeoctet = $x;
	$activecidr = $cct;
	if (!$activecidr) { $activecidr = 8; $activeoctet--;}
	last;
	}
}

my $blocksize = 2**(8-$activecidr);

## for debug:
my $workingoctetbin = dec2bin($subnet[$activeoctet-1]);
my $workingoctetdec = $subnet[$activeoctet-1];
##
## calculate next network from block size
##

my @nextnetwork = @subnet;
$nextnetwork[$activeoctet-1] += $blocksize;

##  account for increments above 255
if ($nextnetwork[3] eq 256) {
	$nextnetwork[3] = 0;
	$nextnetwork[2]++;
	}
if ($nextnetwork[2] eq 256) {
	$nextnetwork[2] = 0;
	$nextnetwork[1]++;
	}
if ($nextnetwork[1] eq 256) {
	$nextnetwork[1] = 0;
	$nextnetwork[0]++;
	}
my $nextnetdec = join(".", @nextnetwork);
if ($nextnetwork[0] eq 256) { $nextnetdec = "N/A"; }

## debug info
#print " (active octet: $activeoctet)\n";
#print " (localcidr:$activecidr)\n";
#print " (workingoctet:$workingoctetdec / $workingoctetbin)\n";
#print " (blocksize: $blocksize)\n";


## calculate broadcast
my @broadcast = @nextnetwork;
my $broadcastdec = decrement_ip(join(".", @broadcast));


## calculate subnet range
my @rangehi = split /\./, $broadcastdec;
my @rangelow = @subnet;

my $rangehidec = decrement_ip(join(".", @rangehi));
my $rangelowdec= increment_ip(join(".", @rangelow));



printf("%20s%s\n\n"," Subnet: ",$subnetaddy);
printf("%20s%s\n"," Subnet Range: ","$rangelowdec -");
printf("%20s%s\n\n","", $rangehidec);
printf("%20s%s\n\n"," Broadcast Addy: ",$broadcastdec);
printf("%20s%s\n\n"," Next Network Addy: ",$nextnetdec);

my $hostsavail = hostslookuptable($cidr);
printf("%20s%s\n"," Usable IPs: ",$hostsavail);
print "\n\n";

###
### EXPLANATION SECTION
###

if ($xflag) { 
## get bin vals
my $binoct1 = dec2bin($oct1);
my $binoct2 = dec2bin($oct2);
my $binoct3 = dec2bin($oct3);
my $binoct4 = dec2bin($oct4);
my $explanationoctet = "";
my $begstr = "";
my $endstr = "";

if ($activeoctet == 1) {
	$begstr = substr($binoct1,0,$activecidr);
	$endstr = substr($binoct1,$activecidr);
	$binoct1 = $begstr . "|" . $endstr;
	$explanationoctet = $binoct1;
	}
elsif ($activeoctet == 2) {
        $begstr = substr($binoct2,0,$activecidr);
        $endstr = substr($binoct2,$activecidr);
        $binoct2 = $begstr . "|" . $endstr;
	$explanationoctet = $binoct2;
	}
elsif ($activeoctet == 3) {
        $begstr = substr($binoct3,0,$activecidr);
        $endstr = substr($binoct3,$activecidr);
        $binoct3 = $begstr . "|" . $endstr;
	$explanationoctet = $binoct3;
	}
elsif ($activeoctet == 4) {
        $begstr = substr($binoct4,0,$activecidr);
        $endstr = substr($binoct4,$activecidr);
        $binoct4 = $begstr . "|" . $endstr;
	$explanationoctet = $binoct4;
	}


 #  11 is length(label), $activeoctet-1 to compensate for '.'
my $submarker = (" " x ($subnet+$activeoctet-1)) . " network <-|-> hosts";  
my $msp = (" " x 15);
my $netbits = $subnet;
my $nonets = 2**$netbits;
my $hostbits = 32-$subnet;
my $nohosts = 2**$hostbits;
my $aap = "";
if ($activeoctet == 1) { $aap = "1st"; }
elsif ($activeoctet == 2) { $aap = "2nd"; }
elsif ($activeoctet == 3) { $aap = "3rd"; }
elsif ($activeoctet == 4) { $aap = "4th"; }
	print <<XOUT;

	-------------------------------------------
	Explanation: 

	       IP: $oct1.$oct2.$oct3.$oct4   SUBNET: $subnet
	
XOUT

print $msp . $submarker . "\n";
print $msp . "Binary IP: $binoct1.$binoct2.$binoct3.$binoct4 \n";
print "\n";
#print $msp . "   Subnet: " . ip2bin($subnetaddy,"dots") . "\n";
print $msp . " Active Octet: $aap\n";
print $msp . " Active CIDR : $activecidr bit(s) of this octet are NETWORK\n";
print "\n";	
#print $msp . "Active Octet decimal: $workingoctetdec\n";
print $msp . " Active Octet binary: $explanationoctet\n";
print $msp . "                     " . (" " x $activecidr) . "↑\n";
print $msp . "        " . (" " x $activecidr) ."Blocksize Bit|\n";
print $msp . "\n";
print $msp . "Blocksize bit value: $blocksize\n";
print $msp . "  (Increment blocksize bit for next network address)\n";
print "\n";
print $msp . "for /$subnet => \n";
print $msp . sprintf("%16s %3s %8s %s %10s\n","Network bits:","$netbits","2^$netbits","=",addcommas($nonets) . " networks");
print $msp . sprintf("%16s %3s %8s %s %10s\n",   "Host bits:","$hostbits","(2^$hostbits)-2","=",addcommas($nohosts) . " - 2 hosts");
print "        -------------------------------------------\n";
print "\n\n";

	}
}

#################################
##

sub increment_ip {

my $ip = shift;
my @lip = split /\./, $ip;
$lip[3]++;

if ($lip[3] eq 256) {
	$lip[2]++;
	$lip[3] = 0;
	}	
if ($lip[2] eq 256) {
	$lip[1]++;
	$lip[2] = 0;
	}
if ($lip[1] eq 256) {
	$lip[0]++;
	$lip[1] = 0;
	}
return join(".", @lip);
}
# # # # # # ###  # # # #
sub decrement_ip {
my $ip = shift;
my @lip = split /\./, $ip;
$lip[3]--;

if ($lip[3] eq -1) {
        $lip[2]--;
        $lip[3] = 255;
        }
if ($lip[2] eq -1) {
        $lip[1]--;
        $lip[2] = 255;
        }
if ($lip[1] eq -1) {
        $lip[0]--;
        $lip[1] = 255;
        }

return join(".", @lip);
}
######################################
sub usage {
print <<COUT;

  Usage:

    $0 <ip_address/cidr>

       This will return all subnet info

    $0 <ip_address> <ip_address>
 
       This will compare the IPs, show what subnet they belong to
	and print all info about the subnet

    $0 explain <ip_address/cidr>

	This will return all subnet info and
	 will also print calculation information


COUT

}

#############################################
## input: binary IP, decimal cidr subnet
## output: decimal subnet

sub getdecsubnet {

my $bin = shift;
my $subnet = shift;

my $result = substr($bin,0,$subnet);
my $subsubnet = sprintf("%s", $result);

my $padlen = 32 - length($subsubnet);
my $rightpad =  "0" x $padlen;


my $dec_subnet = &bin2ip("$subsubnet$rightpad");
return $dec_subnet; 

}


###############################################
## input: decimal IP
## output: binary IP

sub ip2bin {

my $ip = shift;
my $dotflag = shift;

my @splitip = split /\./, $ip;
my $binip = "";

foreach my $dip (@splitip) {
	$binip .= dec2bin($dip);
	if ($dotflag) { $binip .= "."; }
	}

if ($dotflag) { $binip = substr($binip,0,length($binip)-1); }
return $binip;
}

#############################################
## input: binary IP
## output: decimal IP

sub bin2ip {

my $bin = shift;

my $boct1 = substr($bin,0,8);
my $boct2 = substr($bin,8,8);
my $boct3 = substr($bin,16,8);
my $boct4 = substr($bin,24,8,);

my $deco1 = oct("0b".$boct1);
my $deco2 = oct("0b".$boct2);
my $deco3 = oct("0b".$boct3);
my $deco4 = oct("0b".$boct4);

return $deco1 . "." . $deco2 . "." . $deco3 . "." . $deco4;
}

#######################################
## add period delimiters to octets in binary IP

sub format_bip {
my $bin = shift;
my $b1 = substr($bin,0,8);
my $b2 = substr($bin,8,8);
my $b3 = substr($bin,16,8);
my $b4 = substr($bin,24,8,);
return $b1 . "." . $b2 . "." . $b3. "." . $b4
}

####################################################
## in: decimal out: binary octet (padded to 8 chars)
sub dec2bin {
my $dec = shift;
return sprintf("%0*b",8,$dec);
}


###########################################
## input: array of IP octets in decimal
## output: IP in HEX

sub dec2hex {

(my $d1,my $d2,my $d3,my $d4) = @_;
my $converted = sprintf("%X %X %X %X", $d1,$d2,$d3,$d4);
my @retstr = split(' ', $converted);
return @retstr;

}

#######################################
## hosts lookup table

sub hostslookuptable {

my $cidr = shift;

if ($cidr eq 32) {
        return "(/32 points to one address)";
        }
elsif ($cidr eq 31) {
        return "0";
        }
else {

	$cidr = 32-$cidr;
	my $cidnets = addcommas(2**$cidr);

	return "$cidnets - 2";
	}

}

################################
##  subnet cidr to dec

sub cidr2dec {

my $cidr = shift;

my $binsub = ("1" x $cidr);
my $padlen = 32 - length($binsub);
my $rightpad =  "0" x $padlen;

my $subnetdec = &bin2ip("$binsub$rightpad");

my $wcsub = ("0" x $cidr);
my $wcpad = "1" x $padlen;
my $wildcarddec = &bin2ip("$wcsub$wcpad");
return $subnetdec,$wildcarddec;
}

##################################

sub addcommas {
my $int = shift;
my @intarr = split //, $int;
my $lc = 1;
my $retstr;
for (my $i = $#intarr;$i>-1;$i-- ) {
	$retstr .= $intarr[$i];
	if (!($lc % 3) && ($i != 0)) { $retstr.= ","; }
	$lc++;
	}
return reverse($retstr);
}


