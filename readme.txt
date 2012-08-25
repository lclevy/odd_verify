odd_verify.py, a tool to recompute Original Decision data from your Canon EOS DSLR
----------------------------------------------------------------------------------                                                              

Introduction
************

This tool has been written in december 2010 based on february 2010 experiments 
on Canon Original Decision Data (ODD) algorithms. Close to the solution, I was not 
able to understand that hmac_rand was the missing value to compute the 550d keys.
The work is part of the more general goal to document the Canon Raw format
http://lclevy.free.fr/cr2/.
the Original Decision Data (ODD) are stored in tag 0x0083 of the Makernote. 

Dmitry Sklyarov explained most of the algorithms at Confidence 2.0 in Prague 
http://201002.confidence.org.pl/prelegenci/dmitry-sklyarov
see the related press release here
http://www.elcomsoft.com/canon.html
                                                       
But, despite Dmitry's presentation is excellent, there are missing pieces and 
one error that prevent everybody to recompute or verify ODD.


Usage
*****

IMPORTANT:     
In order to recompute ODD, you'll need to extract keys for your camera 
(60D, 550D, 7D) or model (20D). This is done by dumping keys in RAM or Flash.
See the last section of this document.


Syntax: python odd_verif.py image_file device_key


Example:
$ python odd_verif.py IMG_0006.JPG ce5969180f38bbab2a28f08b44b536dc407cd9ee54843226505ec35a820fd801

BodyID=0x22970ba2
hmac_key=1493d665407600fa692d05b06cee9df3ee8e2e3f9faa3685c65eac2ca9a0df29

0xffffffff , version = 0x00000003
0x00000014 206db1a10e33d4add1866b3287aad9b23fc00936 (file hmac)
0x00000014 dc3c05470d3617d727b2f98ce71f894b09868fc7 (ODD hmac)
tag len=0x000001c8  4=0x00000004  rand=0x3a636871  3=0x00000003  filesize=0x00839896
vhash=0x00000003  keyid=0x00000004  boardid=0x820fd801  hmac_rand=0x68f00e32

ODD size = 0x1c8, offset = 0xd16
 sha256=6f5b1c6d43a4778b780536b919037d9980a36879228ec781b12a9c9acc4041e4
 hmac=dc3c05470d3617d727b2f98ce71f894b09868fc7
file hmac=  206db1a10e33d4add1866b3287aad9b23fc00936 ok


a more verbose example:
$ python odd_verif.py -v 1 60d/IMG_0006.JPG ce5969180f38bbab2a28f08b44b536dc407cd9ee54843226505ec35a820fd801

BodyID=0x22970ba2
hmac_key=1493d665407600fa692d05b06cee9df3ee8e2e3f9faa3685c65eac2ca9a0df29

0xffffffff , version = 0x00000003
0x00000014 206db1a10e33d4add1866b3287aad9b23fc00936 (file hmac)
0x00000014 dc3c05470d3617d727b2f98ce71f894b09868fc7 (ODD hmac)
tag len=0x000001c8  4=0x00000004  rand=0x3a636871  3=0x00000003  filesize=0x00839896
vhash=0x00000003  keyid=0x00000004  boardid=0x820fd801  hmac_rand=0x68f00e32

n_area = 6
 1   4  salt=0x39041501 0x14  f5b4377d57c0ae1a03620d5a7b37fe29d180625a  1  0x00006422 0x00833472
     sha256=0c5aad11c9c98b209dcc6d16542f74da5ca86191d4782a06f9e1650282ce13bd
     hmac=f5b4377d57c0ae1a03620d5a7b37fe29d180625a
 2   4  0xa33b44bd  0x14  f765426b60910cf7b563188eeb6493ef30666bf7 n_other = 7
0x00000000 0x00000036,  0x0000003a 0x0000059c,  0x000005da 0x00000704,  0x00000ede 0x000012c0,  0x000022a6 0x0000012c,  0x00005a11 0x00000a11,  0x0083
9894 0x00000002,
 sha256=c8f3e0b463b3bbd98c651638c54f9a766807be9a54e963ff26ce75ca98d1d138
 hmac=f765426b60910cf7b563188eeb6493ef30666bf7
 3   4  salt=0xd0478d10 0x14  23a93a3aa7d3a8bbe3753ecfbc571166e196ba0e  1  0x00000036 0x00000004
     sha256=67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450
     hmac=23a93a3aa7d3a8bbe3753ecfbc571166e196ba0e
 4   4  salt=0xcfd242ad 0x14  0a245bdd4c366931cb08e16eda749e4ddc1ea6a0  1  0x0000219e 0x00000108
     sha256=44b8aa4d28701168922acf61435ea4bb442f97b0b14ad7a2510ed68874ee2a72
     hmac=0a245bdd4c366931cb08e16eda749e4ddc1ea6a0
 5   4  salt=0xcf1f7d95 0x14  03a013ab309475c210d2aa9f0a3d5641209f2ee3  1  0x000005d6 0x00000004
     sha256=df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
     hmac=03a013ab309475c210d2aa9f0a3d5641209f2ee3
 6   4  salt=0x0de79869 0x14  8847541582cb131bec5b5757f641f1f278b90d16  1  0x000023d2 0x0000363f
     sha256=8c54bcdb8a4ef9c53b521ed5b50f8156db77d055552f9473210632e4cac00dc4
     hmac=8847541582cb131bec5b5757f641f1f278b90d16
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
0000000000
ODD size = 0x1c8, offset = 0xd16
 sha256=6f5b1c6d43a4778b780536b919037d9980a36879228ec781b12a9c9acc4041e4
 hmac=dc3c05470d3617d727b2f98ce71f894b09868fc7
file hmac=  206db1a10e33d4add1866b3287aad9b23fc00936 ok

Installation
************

written for python 2.6

provided files:
- odd_verify.py
- PyTiffParser.py, a class to parse metadata information from jpeg and TIFF files.


Compatibility
*************

Tested with the following cameras and image formats :

      version     vhash   keyid    jpg    cr2
     -----------------------------------------
1Ds  | ODDv1       NA       NA                   ODD tag parsing only, .TIF (unknown model key)
20D  | ODDv2       NA       NA      bug    OK    Thanks to Dmitry for the 20D key !
5D   | ODDv2       NA       NA                   unknown model key
1Dm3 | ODDv3       1        1
40D  | ODDv3       1        1
450D | ODDv3       1        2        ?     ?     unknown algorithm, different than with vhash>1. under investigation
5Dm2 | ODDv3       2        1       OK     OK
1Dm4 | ODDv3       2        3                    no device key available
550D | ODDv3       2        4       OK     OK    (tested with 2 different bodies)
7D   | ODDv3       2        4       OK     OK
60D  | ODDv3       3        4       OK     OK


Where to dump to find the keys ?
********************************

Using Magic Lantern for example, http://magiclantern.wikia.com/wiki/Unified

* 5D Mark II, 2.1.2
FF984ED8                 LDR     R4, =0x7CFC
FF984EDC                 LDR     R0, [R4,#8]    ; 140 bytes from R0. IkboardID is at offset 44 (32 bytes)

* 550D, 1.0.9
FF19EC70                 LDR     R4, =0x5BB4
FF19EC74                 LDR     R0, [R4,#8]

* 60D, 1.1.0
FF1A500C                 LDR     R4, =0x5AD0
FF1A5010                 LDR     R0, [R4,#8]

look for the MAC_SelfCheck function...
