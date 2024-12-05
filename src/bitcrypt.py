#This is BitCrypt v2 
#By shad0wrider.github.io
#Can encrypt small to large files efficiently and securely

from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography import fernet
import time , os , sys , json , io , base64 , getpass
import salty as mixpass
import secrets
from colorama import Fore , Style , Back



help = """
enc - Encrypt Files
dec - Decrypt Files
"""

try:

    def verify(srcfile:str):
        veri = open(srcfile,"rb").read()
        endbit = veri[-4::+1]
        startbit = veri[:2]
        if endbit ==b'denz' and startbit ==b'hs':
            return 0
        else:
            return 1



    def askpass():
        d = getpass.getpass("Enter a password: ")
        if len(d) < 6:
            print("Password must have more than 6 characters..")
            askpass()
        else:
            fa = getpass.getpass("Re-enter Same Password: ")
            if fa == d:
                if os.name =="nt":
                    os.system("cls")
                else:
                    if os.name =="posix":
                        os.system("clear")
                genkey = mixpass.hash(fa)[:32].encode('utf-8')
                return genkey
            else:
                print("Password Did not match..retry...")
                askpass()


    def headercreate(data:bytes,key:bytes):
        try:
            head = fernet.Fernet(key=base64.urlsafe_b64encode(s=key))
            datacrypt = head.encrypt(data)
            return b'hs'+datacrypt+b'he'
        except Exception as ka:
            return ka


    def headerfind():
        pass

    def largefileworker(data:bytes,enckey:bytes,iv:bytes):
        mpcp = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.CTR(iv)).encryptor()
        # padder = sympadding.PKCS7(algorithms.AES256.block_size).padder()
        # datpad = padder.update(data)+padder.finalize()
        findat = mpcp.update(data)+mpcp.finalize()
        return findat
    
    def largefiledecryptor(data:bytes,enckey:bytes,iv:bytes):
        pcmp = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.CTR(iv)).decryptor()
        # findat = pcmp.update(data)+pcmp.finalize()
        # decpad = sympadding.PKCS7(algorithms.AES256.block_size).unpadder()
        datpad = pcmp.update(data)+pcmp.finalize()
        return datpad


    def enc(srcfile:str,filename:str):
        f = open(filename+".byt","wb")
        mixkey = askpass()
        if mixkey:
            iv = secrets.token_bytes(16)
            enckey = secrets.token_bytes(32)
            mixdat = enckey+iv
            far = headercreate(mixdat,mixkey)
            if far:
                f.write(far)
                f.write(b'ds')
                if os.path.getsize(srcfile) < 212806066:
                    print("small file mode")
                    tmpcp = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.CBC(iv)).encryptor()
                    with  open(srcfile,"rb") as fileread:
                        padder = sympadding.PKCS7(algorithms.AES256.block_size).padder()
                        datpad = padder.update(fileread.read())+padder.finalize()
                        findat = tmpcp.update(datpad)+tmpcp.finalize()
                        f.write(findat)
                else:
                    print("Large file mode")
                    fileread = open(srcfile,"rb")
                    while pa := fileread.read(4096):
                        f.write(largefileworker(data=pa,enckey=enckey,iv=iv))

                f.write(b'denz')
                enckey , iv , mixdat , mixkey = 0 , 0 , 0 , 0
                f.close()
                print(Fore.YELLOW+"Encrypted file written to..."+Fore.RESET,os.path.abspath(filename+'.byt'))
                

    def dec(srcfile:str):
        if os.path.exists(srcfile):
            if os.path.isfile(srcfile):
                fchk = verify(srcfile=srcfile)
                if fchk ==0:
                    print(Fore.GREEN+"File is a BitCrypt File"+Fore.RESET)
                    fileheader = open(srcfile,"rb")
                    headers = fileheader.read()
                    headinfo = headers[headers.index(b'hs')+len(b'hs'):headers.index(b'heds')]
                    passkey = getpass.getpass("Enter Decryption Password: ")
                    mixkey = mixpass.hash(password=passkey)
                    df = fernet.Fernet(key=base64.urlsafe_b64encode(mixkey[:32].encode('utf-8')))
                    decinfo = df.decrypt(headinfo)
                    ekey = decinfo[:32]
                    ivv = decinfo[32:48]
                    if os.path.getsize(srcfile) < 212806066:
                        print("Small file mode")
                        with open(os.path.basename(srcfile).replace(".byt",''),'wb') as outfile:
                            filedata = headers[headers.index(b'heds')+len(b'heds'):headers.index(b'denz')]
                            pcmp = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.CBC(ivv)).decryptor()
                            datpad = pcmp.update(filedata)+pcmp.finalize()
                            decpad = sympadding.PKCS7(algorithms.AES256.block_size).unpadder()
                            findat = decpad.update(datpad)+decpad.finalize()
                            outfile.write(findat)
                        # passkey , mixkey , df , decinfo , ekey , ivv , pcmp = 0
                        outfile.close()
                        print(Fore.YELLOW+"Decrypted file written to..."+Fore.RESET,os.path.abspath(srcfile).replace(".byt",''))

                    else:
                        print("large file mode")
                        filedec =  open(os.path.basename(srcfile).replace(".byt",''),'wb')
                        filedata = io.BytesIO(headers[headers.index(b'heds')+len(b'heds'):headers.index(b'denz')])
                        while muffer := filedata.read(4096):
                            if muffer == io.BufferedWriter:
                                pass
                            elif muffer == b'':
                                pass
                            else:
                                filedec.write(largefiledecryptor(data=muffer,enckey=ekey,iv=ivv))
                        # passkey , mixkey , df , decinfo , ekey , ivv = 0

                        filedec.close()
                        print(Fore.YELLOW+"Decrypted file written to..."+Fore.RESET,os.path.abspath(srcfile).replace(".byt",''))



                    



                
                else:
                    print(Fore.RED+"Your file has been corrupted\nNot a BitCrypt File :("+Fore.RED)





    def shell():
        d = input(Fore.GREEN+"BitCrypt> "+Fore.RESET)

        if d =="help":
            print(help)

        if d =="enc":
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

        elif d =="exit":
            sys.exit(0)
        
        else:
            print("Invalid Option",d)
        

        return shell()

    shell()

except fernet.InvalidToken as k:
    print(Fore.RED+"Wrong Decryption Key provided..."+Fore.RESET)
    shell()


except Exception as aps:
    print(aps,"occured...")
    shell()
except KeyboardInterrupt as ao:
    print("Exiting..on keyboard interrupt..")
