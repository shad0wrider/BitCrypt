#!/bin/python3
#This is BitCrypt v5
#By https://github.com/shad0wrider
#Can encrypt small to large files efficiently and securely

#Whats New: -- 1.Uses Gmac + Hmac for large and small file verification for checking File Integrity
#              2.Uses New Extremely Efficient Password Extending Algorithm saltyV3
#              3.Using sha3_512 with 64 bit hmac key , somewhat quantam secure...
#              4.Dropped AES-CBC alltogether

#Info : Master iv is generated when headercreate function is called

import secrets , time , os , sys
import argon2 , hmac , hashlib , base64 as b64
from cryptography.hazmat.primitives import hashes, serialization , padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.exceptions import InvalidKey , InvalidSignature , InvalidTag
import time , os , sys , json , io , base64 , getpass , math
import saltyv2 as mixpass
import secrets , gc
from colorama import Fore , Style , Back





version = "v5.3-5-25-linux-cli"


help = """
enc - Encrypt Files
dec - Decrypt Files
showinfo - Show Header Info
"""



try:
    passconstant = b'seckeyok'

    def verify(srcfile:str):
        srcpath = srcfile
        veri = open(srcpath,"rb",buffering=4096)
        veri.seek(0)
        startheader = veri.read(6)
        startbit = startheader[:4]
        veri.seek(os.path.getsize(srcpath)-20,0)
        endheader = veri.read(200)
        endbit = endheader[-4::+1]
        if endbit ==b'nz0X' and startbit ==b'hs0X':
            return 0
        else:
            return 1



    def askpass():
        while True:
            d = getpass.getpass("Enter a password: ")
            if len(d) < 6:
                print("Password must have more than 6 characters..")
                return askpass()
            else:
                fa = getpass.getpass("Re-enter Same Password: ")
                if fa == d:
                    if os.name =="nt":
                        os.system("cls")
                    else:
                        if os.name =="posix":
                            os.system("clear")
                    genkey = mixpass.passmixer(fa)[:32].encode('utf-8')
                    break
                else:
                    print("Password Did not match..retry...")
                    return askpass()
        return genkey
    
    def chkpass(val:bytes):
        #A Decryption Function
        try:
            tmpval = b64.standard_b64decode(val)
            if tmpval == passconstant:
                return 0
            else:
                return 1
            
        except Exception as ia:
            return 1
        
    def recovery():
        pass


    def genpass(passw:bytes,saltoriv:bytes):
        #A Decryption/Encryption Function
        """
        saltoriv: This is the master iv/salt and should be 16 bytes minimum
        """
        tmpmaspas = argon2.hash_password(
            password=passw,
            salt=saltoriv,
            time_cost=argon2.DEFAULT_TIME_COST,
            memory_cost=argon2.DEFAULT_MEMORY_COST,
            parallelism=argon2.DEFAULT_PARALLELISM,
            hash_len=32,
            type=argon2.Type.ID
        )

        dollarcount = tmpmaspas.count(b'$')
        tmpparse = tmpmaspas.split(b'$')[dollarcount]
        if len(tmpparse)%4 !=0:
            tmpparse = tmpparse + b'='*(4-len(tmpparse)%4)
        try:
            themaskey = b64.b64decode(tmpparse)
            return themaskey
        except Exception as eor:
            print("Master Key generation Failed :( , Line 111")
            return 1




    def hashverifier(srcfile:str,hmackey:bytes):
        #A Decryption Function
        filecheck = open(srcfile,"rb")
        tmpfilesize = os.path.getsize(filecheck.name)

        try:
            tmp = filecheck.read(4096)
            filetypem = tmp[tmp.index(b'extys0X')+len(b'extys0X'):tmp.index(b'extye0X')].decode('utf-8')

            if filetypem =="smoll":
                filecheck.seek(0)
                data = filecheck.read()
                filehmachash = data[data.index(b'ihms0X')+len(b'ihms0X'):data.index(b'ihme0X')]
                endpoint = data.rindex(b'ihms0X')
                filecheck.seek(0)
                datatocheck = io.BytesIO(data[:endpoint])
                calculatehmac = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)
                while readit := datatocheck.read():
                    calculatehmac.update(readit)
                if hmac.compare_digest(filehmachash,calculatehmac.digest()):
                    print(Fore.GREEN+"File Integrity Check: Passed"+Fore.RESET)
                    return 0
                else:
                    print(Fore.RED+"File Integrity Check: Failed"+Fore.RESET)
                    return 1
                
            elif filetypem =="biigg":
                filecheck.seek(0)
                filecheck.seek(tmpfilesize-112,0)
                data = filecheck.read(4096)
                filehmachash = data[data.index(b'ihms0X')+len(b'ihms0X'):data.index(b'ihme0X')]
                calculatehmac = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)
                endpoint = tmpfilesize-80
                filecheck.seek(0)
                while True:
                    filepos = filecheck.tell()
                    if filepos < endpoint:
                        chunksize = min(4096,endpoint-filepos)
                        tmpdata = filecheck.read(chunksize)
                        calculatehmac.update(tmpdata)
                    else:
                        break
                if hmac.compare_digest(filehmachash,calculatehmac.digest()):
                    print(Fore.GREEN+"HMAC Integrity Check: Passed"+Fore.RESET)
                    return 0
                else:
                    print(Fore.RED+"HMAC Integrity Check: Failed"+Fore.RESET)
                    return 1


        except ValueError as ia:
            print("File is Corrupted")
            print("Error: Hmac Verification Failed :(")
            return 1

    




    def hashgenerator(filepath:str,encfiletype:str,etag:bytes,hmackey:bytes):
        """
        smoll -  For Files Under certain size limit (No chunking)
        
        biigg -  For Files above certain size which needs (chunking)

        """
        if encfiletype =="smoll":
            try:
                #Appending Gmac Tag TO File
                hashfile = open(filepath,"ab")
                hashcontent = b'ihgs0X'+etag+b'ihge0X'
                hashfile.write(hashcontent)
                hashfile.close()
                #Done Appending Gmac Tag to File
                #----------------------------------
                #Reading File Content Up Until Gmac Tag
                hashfile = open(filepath,"rb").read()
                hashfilewrite = open(filepath,"ab")
                datatohash = hashfile
                #Calculating Hmac Hash
                hmhash = hmac.new(key=hmackey,msg=datatohash,digestmod=hashlib.sha3_512)
                hashcontent = b'ihms0X'+hmhash.digest()+b'ihme0Xnz0X'
                hashfilewrite.write(hashcontent)
                hashfilewrite.close()
                #Done Appending Hmac Hash to File
                print("\nHmac File Hash Written")
                return 0
            except Exception as error:
                print(error)
                return 1
        
        elif encfiletype =="biigg":
            try:
                #Appending Gmac Tag TO File
                hashfile = open(filepath,"ab")
                hashcontent = b'ihgs0X'+etag+b'ihge0X'
                hashfile.write(hashcontent)
                hashfile.close()
                #Done Appending Gmac Tag to File
                #----------------------------------
                #Reading File Content Up Until Gmac Tag
                tmpfilesize = os.path.getsize(filepath)
                hashfile = open(filepath,"rb")               
                hashfilewrite = open(filepath,"ab")

                hmhash = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)

                while True:
                    filepointer = hashfile.tell()

                    if filepointer < tmpfilesize:
                        chunksize = min(4096,tmpfilesize-filepointer)
                        tmphashdata = hashfile.read(chunksize)
                        hmhash.update(tmphashdata)
                    else:
                        break

                hashcontent = b'ihms0X'+hmhash.digest()+b'ihme0Xnz0X'
                hashfilewrite.write(hashcontent)
                hashfilewrite.close()
                #Done Appending Hmac Hash to File
                print("\nHmac File Hash Written")
                return 0
            except Exception as oe:
                print(oe)
                return 1


    def headercreate(data:bytes,key:bytes,filetype:bytes,bitcrypt_version:bytes,etype:bytes,hmac_secret_key:bytes):
        #The Headers are always encrypted in AES-CTR
        #Master iv is generated here
     
        try:
            mainiv = os.urandom(16)
            masterkeysalt = os.urandom(16)
            hmkeyiv = os.urandom(16)
            passconsiv = os.urandom(16)
            #Master Key Generation Using argon2
            actualmaster = genpass(passw=key,saltoriv=masterkeysalt)
            if actualmaster !=1:
            #Generating Master Key Done
                thekeymaster = actualmaster
                head = Cipher(algorithm=algorithms.AES256(key=thekeymaster),mode=modes.CTR(mainiv)).encryptor()
                #Encrypting Pass Constant and Hmac Key
                passencryptor = Cipher(algorithm=algorithms.AES256(key=thekeymaster),mode=modes.CTR(passconsiv)).encryptor()
                hmkeyencryptor = Cipher(algorithm=algorithms.AES256(key=thekeymaster),mode=modes.CTR(hmkeyiv)).encryptor()
                finalpass = passencryptor.update(b64.standard_b64encode(passconstant))+passencryptor.finalize()
                #Encrypting Pass Constant and Hmac Key Done
                datacrypt = head.update(data)
                enchmackey = hmkeyencryptor.update(hmac_secret_key)
                head.finalize()
                return b'hs0X'+mainiv+datacrypt+b'mskysslt0X'+masterkeysalt+b'mskyeslt0X'+b'tys0X'+filetype+b'tye0X'+b'pskys0X'+finalpass+b'pskye0X'+b'pskysiv0X'+passconsiv+b'pskyeiv0X'+b'bvs0X'+bitcrypt_version+b'bve0X'+b'extys0X'+etype+b'extye0X'+b'hmkys0X'+enchmackey+b'hmkye0X'+b'hmkysiv0X'+hmkeyiv+b'hmkyeiv0X'+b'he0X'
            else:
                print(Fore.RED+"Header Creation Failed , Reason: Master Key Gen Error"+Fore.RESET)
        
        except Exception as ka:
            return ka


    def headerinfo(filepath:str):
        try:
            if os.path.isfile(filepath):
                print("Getting Header Info...")
                if verify(filepath) ==0:
                    headread = open(filepath,"rb").read()
                    filetype = headread[headread.index(b'tys0X')+len(b'tys0X'):headread.index(b'tye0X')]
                    appversion = headread[headread.index(b'bvs0X')+len(b'bvs0X'):headread.index(b'bve0X')]
                    enctype = headread[headread.index(b'extys0X')+len(b'extys0X'):headread.index(b'extye0X')]
                    gmintegrityval = headread[headread.index(b'ihgs0X')+len(b'ihgs0X'):headread.index(b'ihge0X')]
                    hmintegrityval = headread[headread.index(b'ihms0X')+len(b'ihms0X'):headread.index(b'ihme0X')]                                        
                    print("File Type:",filetype.decode('utf-8'))
                    print("BitCrypt Version:",appversion.decode('utf-8'))
                    print("File Type:",enctype.decode('utf-8'))
                    print("Gmac Intergrity Hash:",gmintegrityval)
                    print("Hmac Intergrity Hash:",hmintegrityval)
                else:
                    print("File is not a BitCrypt File :(")
        except Exception as eror:
            print(eror,"Happened :)")



    def enc(srcfile:str,filename:str):
        dotcount = filename.count(".")
        fileextension = filename.split(".")[dotcount]
        filename = filename.split(".")[0]
        f = open(filename+".byt","wb")
        filesize = os.path.getsize(srcfile)
        cryptfilepath = os.path.abspath(filename+".byt")
        try:
            mixkey = askpass()
            if mixkey :
                iv = os.urandom(16)
                enckey = os.urandom(32)
                mixdat = enckey+iv
                if os.path.getsize(srcfile) < 212806066:

                    #Small File Mode
                    print("small file mode")
                    hmckey = os.urandom(64)
                    far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'smoll',hmac_secret_key=hmckey)
                    if far:
                        f.write(far)
                        f.write(b'ds0X')                      
                        encdatacipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv)).encryptor()
                        with open(srcfile,"rb") as fileread:
                                datatocrypt = encdatacipher.update(fileread.read())
                                f.write(datatocrypt)
                                #Status Code
                                tmpval = fileread.tell()/filesize*100
                                tmplog = math.floor(tmpval*10)/10
                                status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                sys.stdout.write(f"\r{status}")                                  
                                sys.stdout.flush()
                                #Status Code
                        encdatacipher.finalize()
                        f.write(b'de0X')
                        f.close()
                        gcmtag = encdatacipher.tag
                        print("\n")
                        hashgenerator(filepath=cryptfilepath,encfiletype="smoll",hmackey=hmckey,etag=gcmtag)
                else:
                        
                        #Large File Mode
                        hmckey = os.urandom(64)
                        print("Large file mode")
                        far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'biigg',hmac_secret_key=hmckey)
                        if far:
                            f.write(far)
                            f.write(b'ds0X')
                            srcdatafile = open(srcfile,"rb")
                            gcmcipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv)).encryptor()
                            while True:
                                curpos = srcdatafile.tell()
                                if curpos < filesize:
                                    tmpchunksize = min(4096,filesize-srcdatafile.tell())
                                    encdata = srcdatafile.read(tmpchunksize)
                                    f.write(gcmcipher.update(encdata))
                                    tmpval = curpos/filesize*100
                                    tmplog = math.floor(tmpval*10)/10
                                    status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                    sys.stdout.write(f"\r{status}")                                  
                                    sys.stdout.flush()
                                else:
                                    break
                            gcmcipher.finalize()
                            f.write(b'de0X')
                            f.close()
                            gcmfiletag = gcmcipher.tag
                            done = hashgenerator(filepath=cryptfilepath,encfiletype="biigg",etag=gcmfiletag,hmackey=hmckey)

                            if done !=0:
                                print("Error Occured at Large file mode hashgenerator function")
                                                          
                            
                enckey , iv , mixdat , mixkey = 0 , 0 , 0 , 0
                print("\n")
                print(Fore.YELLOW+"Encrypted file written to..."+Fore.RESET,os.path.abspath(filename+'.byt'))
            

        except Exception as oa:
            print(oa)
        
                

    def dec(srcfile:str):
        if os.path.exists(srcfile):
            if os.path.isfile(srcfile):
                fchk = verify(srcfile=srcfile)
                if fchk ==0:
                    #Reading the Headers and decrypting the File Key
                    print(Fore.GREEN+"File is a BitCrypt File"+Fore.RESET)
                    fileheader = open(srcfile,"rb")
                    decfilesize = os.path.getsize(fileheader.name)
                    headers = fileheader.read(4096)
                    try:
                        masterkeyslt = headers[headers.index(b'mskysslt0X')+len(b'mskysslt0X'):headers.index(b'mskyeslt0X')]
                        encpsval = headers[headers.index(b'pskys0X')+len(b'pskys0X'):headers.index(b'pskye0X')]
                        start = headers.index(b'ds0X')
                        hmkey = headers[headers.index(b'hmkys0X')+len(b'hmkys0X'):headers.index(b'hmkye0X')]
                        passconsiv = headers[headers.index(b'pskysiv0X')+len(b'pskysiv0X'):headers.index(b'pskyeiv0X')]
                        hmkeyiv = headers[headers.index(b'hmkysiv0X')+len(b'hmkysiv0X'):headers.index(b'hmkyeiv0X')]
                        filext = headers[headers.index(b'tys0X')+len(b'tys0X'):headers.index(b'tye0X')].decode('utf-8').replace(" ","")
                        mainheaders = headers[4:68]
                        masteriv = mainheaders[:16]
                        datacrypt = mainheaders[16:64]
                        #Seeking TO 112 bytes from the end as the hash lengths are fixed
                        fileheader.seek(decfilesize-112,0)
                        end = decfilesize-112
                        headers = fileheader.read(4096)                        
                        gmactag = headers[headers.index(b'ihgs0X')+len(b'ihgs0X'):headers.index(b'ihge0X')]
                        
                    except ValueError as iae:
                        print(Fore.RED+"File Header is Corrupted :(\n Try Recovery Mode"+Fore.RESET)
                        return shell()
                    decryptfilesize = decfilesize
                    passkey = getpass.getpass("Enter Decryption Password: ")
                    mixkey = mixpass.passmixer(password=passkey)[:32].encode('utf-8')
                    #Deriveing the Master Key
                    tmptopkey = genpass(passw=mixkey,saltoriv=masterkeyslt) 
                    if tmptopkey !=1:
                        themasterkey = tmptopkey
                    else:
                        print("Master key Derivation Error")
                        return shell()

                    #Initializing Ciphers 
                    try:
                        decipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(passconsiv)).decryptor()
                        datadecipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(masteriv)).decryptor()
                        hmkeydecipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(hmkeyiv)).decryptor()
                    except ValueError as us:
                        print(Fore.RED+"File Headers are Corrupted :(\nTry Recovery Mode"+Fore.RESET)

                    passcons = decipher.update(encpsval)
                    if chkpass(passcons) == 0:
                        print(Fore.GREEN+"Correct Password Entered...Decrypting File"+Fore.RESET)

                        tmphmkey = hmkeydecipher.update(hmkey)
                        print("Verifying HMAC File Integrity...")

                        #Verifying Layer 2 Integrity via HMAC
                        hashverify = hashverifier(srcfile=srcfile,hmackey=tmphmkey)

                        if hashverify ==0:
                       
                            #Decrypting File Key and IV
                            decinfo = datadecipher.update(datacrypt)
                            datadecipher.finalize()
                                                        
                            #File Key and IV
                            ekey = decinfo[:32]
                            ivv = decinfo[32:48]
                            filename = os.path.basename(srcfile).split(".")[0]
                            #Decryption Mode
                            if os.path.getsize(srcfile) < 212806066:
                                print("Small file mode")
                                with open(filename+"."+filext,'wb') as outfile:
                                    filedata = io.BytesIO(headers[headers.index(b'ds0X')+len(b'ds0X'):headers.index(b'de0X')])
                                    try:                                        
                                        pcmp = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.GCM(ivv,gmactag)).decryptor()                                
                                        while decdata := filedata.read():                                    
                                            datpad = pcmp.update(decdata)
                                            outfile.write(datpad)
                                            tmpval = filedata.tell()/decryptfilesize*100
                                            tmplog = math.floor(tmpval*10)/10
                                            status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                            sys.stdout.write(f"\r{status}")                                  
                                            sys.stdout.flush()
                                        pcmp.finalize()
                                        
                                    except InvalidTag as excep:
                                        print(Fore.RED+"\nData Has Been Corrupted :("+Fore.RESET)
                                        print("Error: GCM Verification Failed")
                                        
                                # passkey , mixkey , df , decinfo , ekey , ivv , pcmp = 0
                                outfile.close()
                                print("\n")
                                print(Fore.YELLOW+"Decrypted file written to..."+Fore.RESET,os.path.abspath(filename+"."+filext))

                            else:
                                print("large file mode")
                                filedec =  open(filename+"."+filext,'wb')
                                filedata = fileheader
                                filedata.seek(start+4)
                                try:
                                    decryptcipher = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.GCM(ivv,gmactag)).decryptor()
                                    while True:
                                        filepointer = filedata.tell()
                                        if filepointer < end:
                                            
                                                chunksize = min(4096,end-filepointer)
                                                tmpdata = filedata.read(chunksize)
                                                decryptedata = decryptcipher.update(tmpdata)
                                                filedec.write(decryptedata)
                                                tmpval = filepointer/end*100
                                                tmplog = math.floor(tmpval*10)/10
                                                status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                                sys.stdout.write(f"\r{status}")                                  
                                                sys.stdout.flush()
                                        else:
                                            break

                                except InvalidTag as eis:
                                        print(Fore.RED+"\nData Has Been Corrupted :("+Fore.RESET)
                                        print("Error: GCM Verification Failed")

                                # passkey , mixkey , df , decinfo , ekey , ivv = 0
                                print("\n")
                                decryptcipher.finalize()
                                filedec.close()
                                print(Fore.YELLOW+"Decrypted file written to..."+Fore.RESET,os.path.abspath(filename+"."+filext))
                        else:
                            return shell()
                    else:
                        print(Fore.RED+"Wrong Password Entered :("+Fore.RESET)

                else:
                    print(Fore.RED+"Your file has been corrupted\nNot a BitCrypt File :("+Fore.RED)

    def shell():
        d = input(Fore.GREEN+"BitCrypt> "+Fore.RESET)

        if d =="help":
            print(help)

        elif d =="version" or d =="v":
            print(version)

        elif d =="enc":
            p = input("Enter Normal File path: ")
            if os.path.exists(p):
                if os.path.isfile(p):

                    if os.name =="posix":
                        basename = os.path.basename(p)
                        enc(p,basename)



                    elif os.name =="nt":
                        basename = os.path.basename(p)
                        enc(p,basename)


                    else:
                        print("We dont support this os...")


                else:
                    print("The file path is a folder..not a file..:(")
            else:
                print("File path ",p,"Does not exist :(")
                
        elif d =='dec':
            da = input("Enter BitCrypt File path: ")
            if os.path.exists(da):
                if os.path.isfile(da):
                    dec(srcfile=da)
                else:
                    print("path is not file...:(")
            else:
                print("Path doesn't exist...:(")

        elif d =="showinfo":
            dae = input("Enter BitCrypt File Path: ")
            if os.path.isfile(dae):
                headerinfo(dae)

        elif d =="author":
            print("https://github.com/shad0wrider")


        elif d =="clear":
            os.system("clear")

        elif d =="exit":
            sys.exit(0)
        
        else:
            print("Invalid Option",d)
        

        return shell()

    shell()

# except ValueError as ss:
#     print(Fore.RED+"Wrong Password Entered.."+Fore.RESET)
#     shell()

except Exception as aps:
    print(aps,"occured...")
    shell()

except KeyboardInterrupt as ao:
    print("Exiting..on keyboard interrupt..")
