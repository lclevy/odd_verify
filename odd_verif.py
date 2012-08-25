# odd_verif.py
# version 0.6 (24jun2012)
# Laurent Clevy, http://lclevy.free.fr/cr2
#
# under GPLv2 license. http://www.gnu.org/licenses/gpl-2.0.html
#
# check Original Decision Data hash values from Canon DSLR in CR2 and jpeg
# syntax: python odd_verif.py image_file device_key

from struct import unpack
import os
import sys
from hashlib import sha1, md5, sha256
from binascii import hexlify, unhexlify
import hmac
from struct import pack
import PyTiffParser
from optparse import OptionParser

#read 4 bytes and return them as a long in little endian order
def fGetLongLE( f ):
   m = f.read(4)
   return unpack('<L',m)[0]

def fGetLongBE( f ):
   m = f.read(4)
   return unpack('>L',m)[0]

#debug only
def printArea( pic, verbose):
   v = fGetLongLE ( pic.file )
   if verbose:
      print "%2d " % ( v ),
   v = fGetLongLE ( pic.file )
   if verbose:
      print "%2d " % ( v ),
   salt = fGetLongLE ( pic.file )
   if verbose:
      print "salt=0x%08x" % ( salt ),
   v = fGetLongLE ( pic.file )
   if verbose:
      print "0x%02x " % ( v ),
   hashv = pic.file.read(20)
   if verbose:
      print hexlify(hashv),
   v = fGetLongLE ( pic.file )
   if verbose:
      print "%2d " % ( v ),
   offset = fGetLongLE ( pic.file )
   length = fGetLongLE ( pic.file )
   if verbose:
      print "0x%08x 0x%08x" % ( offset, length )
   return hashv, offset, length, salt

#get ODD header
def getODDheader( pic, offset ):
   old_pos = pic.file.tell()
   pic.file.seek(offset) # base is 0, unlike IFD offsets!
   #information in ODD is in Intel order
   minusOne = fGetLongLE ( pic.file )
   if minusOne != 0xffffffff:
      print "ODD format error, not starting with 0xffffffff"
      sys.exit()
   version = fGetLongLE ( pic.file )
   if version==3:
      fGetLongLE ( pic.file )  
      filehash = pic.file.read(20)
      fGetLongLE ( pic.file )
      oddhash = pic.file.read(20)
      tag_len = fGetLongLE ( pic.file )
      four = fGetLongLE ( pic.file )
      rand1 = fGetLongLE ( pic.file )
      three = fGetLongLE ( pic.file )
      filesize = fGetLongLE ( pic.file )
      vhash = fGetLongLE ( pic.file )
      keyid = fGetLongLE ( pic.file )
      boardid = fGetLongLE ( pic.file )
      hmac_rand = fGetLongLE ( pic.file )
      n_area = fGetLongLE ( pic.file )
   elif version == 2:
      filehash = pic.file.read(20)
      hmac_rand = 0
      vhash = 0
      tag_len = 0xa0    
   else:  #version = 1 (1Ds)
      filehash = pic.file.read(20)
      hmac_rand = 0
      vhash = 0
      tag_len = 96    
   pic.file.seek(old_pos)
   return hmac_rand, vhash, version, filehash, tag_len 

# main function: parse the ODD tag and recompute all hash values  
def parseODD( pic, offset, len, verbose=False ):
   odd_offset = offset 
   pic.file.seek( odd_offset )
   v = fGetLongLE ( pic.file )
   print "0x%08x" % ( v ),
   if pic.order==0x4949:
      version = fGetLongLE ( pic.file )
   else:   
      version = fGetLongBE ( pic.file )
   print ", version = 0x%08x " % ( version )
   if version==3:
      sh2 = sha256()
      v = fGetLongLE ( pic.file )
      h = pic.file.read(20)
      print "0x%08x %s (file hmac)" % ( v, hexlify(h) )
      v = fGetLongLE ( pic.file )
      h = pic.file.read(20)
      print "0x%08x %s (ODD hmac)" % ( v, hexlify(h) )

      tag_len = fGetLongLE ( pic.file )
      print "tag len=0x%08x " % ( tag_len ),
      v = fGetLongLE ( pic.file )
      print "4=0x%08x " % ( v ),
      rand1 = fGetLongLE ( pic.file )
      print "rand=0x%08x " % ( rand1 ),
      v = fGetLongLE ( pic.file )
      print "3=0x%08x " % ( v ) ,
      filesize = fGetLongLE ( pic.file )
      print "filesize=0x%08x " % ( filesize )

      vhash = fGetLongLE ( pic.file )
      print "vhash=0x%08x " % ( vhash ),
      keyid = fGetLongLE ( pic.file )
      print "keyid=0x%08x " % ( keyid ),
      boardid = fGetLongLE ( pic.file )
      print "boardid=0x%08x " % ( boardid ),
      hmac_rand = fGetLongLE ( pic.file )
      print "hmac_rand=0x%08x " % ( hmac_rand )
      nbArea  = fGetLongLE ( pic.file )
      if verbose:      
         print
         print "n_area = %d " % ( nbArea )

      for k in range( nbArea ):
         if k != 1:
            ohmac, offset, length, salt = printArea(pic, verbose)
            if vhash>1:
               hashv, nhmac = hmac256(pic.file, hmac_key, offset, length)
               sh2.update(hashv)
               if verbose:      
                  print '     sha256='+hexlify(hashv)
                  print '     hmac='+nhmac     
            else:  #vhash=1, like 450D, does not work yet
               hashv, nhmac = area_md5_salted(pic.file, hmac_key, offset, length, pack('>L',salt) )
               if verbose:      
                  print '     md5='+hexlify(hashv)
                  print '     hmac='+hexlify(nhmac)     
         else:
            v1 = fGetLongLE ( pic.file )    
            v2 = fGetLongLE ( pic.file )    
            v3 = fGetLongLE ( pic.file )    
            v4 = fGetLongLE ( pic.file )    
            h = pic.file.read(20)
            if verbose:  
               print "%2d " % ( v1 ),
               print "%2d " % ( v2 ),
               print "0x%08x " % ( v3 ),
               print "0x%02x " % ( v4 ),
               print hexlify(h),

            n = fGetLongLE ( pic.file )
            if verbose:
               print "n_other = %x" % (n)
            sh = sha256()
            for j in range(n):
               offset = fGetLongLE ( pic.file )
               size = fGetLongLE ( pic.file )
               if verbose:
                  print "0x%08x 0x%08x, " % ( offset, size ),
               old_pos = pic.file.tell()
               pic.file.seek(offset)
               m = pic.file.read(size)
               pic.file.seek(old_pos)
               sh.update(m)
            print
            h1 = sh.digest()
            sh2.update(h1)
            if verbose:
               print ' sha256='+hexlify(h1)
               print ' hmac='+hmac.new( hmac_key, h1, sha1 ).hexdigest()
      
      #TODO: use tag_len
      here = pic.file.tell()
      tail = pic.file.read((len+0x38)-(here-odd_offset))
      if verbose:
         print hexlify(tail)  
      return sh2    
   elif version==2:
      #ODD v2
      filehash = pic.file.read(20)
      print "filehash=" + hexlify(filehash)
      print
      nb_hash = fGetLongLE ( pic.file )
      if verbose:
         print "hash_nb = 0x%08x " % ( nb_hash )
      imagehash = ''
      for j in range(nb_hash):
         n = fGetLongLE ( pic.file )
         offset = fGetLongLE ( pic.file )
         size = fGetLongLE ( pic.file )
         if verbose:
            print "i=%02d, offset=0x%08x, length=0x%08x " % ( n, offset, size )
            print "hash= ",
         hash = pic.file.read(20)
         if verbose:
            print hexlify(hash)
         chash = area_md5(  pic.file, offset, size)
         imagehash = imagehash + chash 
         if verbose:
            print ' md5=%s' % hexlify( chash )
            print ' hmac='+hmac.new( hmac_key, chash*4, sha1 ).hexdigest()
            print
      #hmac_rand = 0 
      filehmac = hmac.new( hmac_key, imagehash, sha1 ).digest()
      print 'computed filehmac='+hexlify(filehmac),
      return filehmac
   else:  #version 1
      filehash = pic.file.read(20)
      print "filehash=" + hexlify(filehash)
      print
      nb_hash = fGetLongBE ( pic.file )
      if verbose:
         print "hash_nb = 0x%08x " % ( nb_hash )
      imagehash = ''
      for j in range(nb_hash):
         n = fGetLongBE ( pic.file )
         offset = fGetLongBE ( pic.file )
         size = fGetLongBE ( pic.file )
         if verbose:
            print "i=%02d, offset=0x%08x, length=0x%08x " % ( n, offset, size )
            print "hash= ",
         hash = pic.file.read(20)
         if verbose:
            print hexlify(hash)
         chash = area_md5(  pic.file, offset, size)
         imagehash = imagehash + chash 
         if verbose:
            print ' md5=%s' % hexlify( chash )
            print

def sha1sums(m):   
  sh = sha1(m)
  sh.update('\x01')
  r1 = sh.digest()
  sh = sha1(m)
  sh.update('\x02')
  r2 = sh.digest()
  return r1+r2[0:12]

#compute h1 = sha256(region), hmac-sha1(key, h1)
def hmac256(f, key, offset, size):
  old_pos = f.tell()
  f.seek(offset)
  m = f.read(size)
  f.seek(old_pos)
  h1 = sha256(m).digest()
  return h1, hmac.new( key, h1, sha1 ).hexdigest()

# for ODDv2, compute md5(region)
def area_md5(f, offset, size):
  old_pos = f.tell()
  f.seek(offset)
  m = f.read(size)
  f.seek(old_pos)
  return md5(m).digest()

# ODDv3, vhash=1
def area_md5_salted(f, key, offset, size, salt):
  old_pos = f.tell()
  f.seek(offset)
  m = f.read(size)
  f.seek(old_pos)
  h1 = md5(m).digest()
  md = md5(h1)
  md.update(salt)
  return h1, hmac.new( key, md.digest(), sha1 ).digest()

# MAIN
# open the image file and parse the TIFF or jpeg structure for existing exif/makernote tags   

#TODO: 20d jpg fix, 5dm2

parser = OptionParser(usage="usage: %prog [options] image_filename device_key")
parser.add_option("-v", "--verbose", type="int", dest="verbose", default=0, help="verbose level")
(options, args) = parser.parse_args()

f = open(args[0], 'rb')
f.seek(0, 2) #End of file
filesize = f.tell()
pic = PyTiffParser.PyTiffParser( f, options.verbose>1 )
# fill pic.tags with tag values
pic.parse()

modelId = pic.tags[('maker',16)][3]

if options.verbose>1:
   for i in pic.tags.keys():
      print '%16s = 0x%x, 0x%x, 0x%x, 0x%x' % (i, pic.tags[i][0], pic.tags[i][1], pic.tags[i][2], pic.tags[i][3])
   print


#get general information from ODD to compute the hmac_key 
odd_offset = pic.tags[('maker',0x83)][3]

#with ODDv2 (here 20D) and jpg: ODD offset from exif is wrong. must use EOF-0xa0
if modelId==0x80000175 and pic.type=='jpeg':
   odd_offset = filesize - 0xa0

hmac_rand, vhash, version, filehash, tag_len = getODDheader( pic, odd_offset  )

BodyID = pic.tags[('maker',12)][3]
print "BodyID=0x%08x" % BodyID

if version == 3:
   IKBoardID = unhexlify(args[1])
   hmac_key = sha1sums( IKBoardID + pack('>L',BodyID) + pack('>L',hmac_rand) )
elif version == 2:
   key_20d = unhexlify(args[1])
   hmac_key = key_20d[:28]+ pack('>L',BodyID) 
else:
   hmac_key = unhexlify(32*'15')
   
print 'hmac_key='+hexlify(hmac_key)+'\n'

# return result for ODDv2 and intermediate value for ODDv3
res = parseODD( pic, odd_offset, tag_len, options.verbose )

if version==3:
   #ODDv3: recompute odd_data hash and file hash
   offset = odd_offset + 0x38
   print 'ODD size = 0x%x, offset = 0x%x' % (tag_len, offset)
   hashv, hmacv = hmac256(pic.file, hmac_key, offset, tag_len)
   print ' sha256='+hexlify(hashv)
   print ' hmac='+hmacv

   res.update(hashv)
   r3 = res.digest()
   print 'file hmac= ',
   r3 = hmac.new( hmac_key, r3, sha1 ).digest()
   print hexlify(r3),
   if r3==filehash:
      print "ok"
   else:
      print "ko"
elif version == 2:  #jpeg not work yet
   if res==filehash:
      print "ok"
   else:
      print "ko"

f.close()   