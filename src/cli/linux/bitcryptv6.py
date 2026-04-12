#!/bin/python3
#This is BitCrypt v5
#By https://github.com/shad0wrider
#Can encrypt small to large files efficiently and securely

#Whats New: -- 1.New Revamped rich based TUI
#              2.Fixed header parsing slowdown in showinfo and dec function

#Info : Master iv is generated when headercreate function is called

##-----------## Core Libraries ##-----------##

import argon2 , hmac , hashlib , base64 as b64
from cryptography.hazmat.primitives import hashes, serialization , padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.exceptions import InvalidKey , InvalidSignature , InvalidTag
import time , os , sys , json , io , getpass , math
import saltyv2 as mixpass
import secrets , gc , subprocess as sp

##==========## Core Libraries ##===========##


##----------## Rich Libraries ##-----------##

from rich.panel import Panel
from rich.console import Console
from rich.progress_bar import ProgressBar
from rich.progress import Progress , ProgressColumn ,TaskProgressColumn , BarColumn , TextColumn , SpinnerColumn , DownloadColumn
from rich.prompt import Prompt ,PromptBase ,PromptError
from rich.spinner import Spinner
from rich.prompt import Confirm
from rich.markdown import Markdown ,MarkdownElement ,MarkdownContext
from rich.text import Text
from rich.live import Live
##==========## Rich Libraries ##===========##


version = "Bitcrypt Cli v6.13-4-26"

whats_new = """
# Whats New:
   - ## 1.New Revamped cli interface using rich
   - ## 2.Fixed header parsing slowdown in showinfo and dec function
"""


help = """

# Cli Menu

   ## Command Line: 
    bitc [OPTIONS] <filename> 

   ## Bitcrypt Shell: 
    bitc>> [OPTIONS]                   

## Options

  - ### enc - Encrypt Files

  - ### dec - Decrypt Files

  - ### showinfo - Show Header Info

  - ### verify - Verify a files hmac hash

  - ### recovery - attempt to decrypt corrupted data

"""

def helpmenu(console:Console) -> Console.print:


    help_panel = Panel(renderable=Markdown(help),title="Help",title_align="left",border_style="green")

    return console.print(help_panel)


def throwerror(console:Console,error:str) -> Console.print:
    tmppanel = Panel.fit(renderable=Text(str(error),style="yellow"),title="Error Occured",border_style="red",title_align="left")

    return console.print(tmppanel)

def printit(console:Console,texts:str,text_color:str,border_color:str) -> Console.print:
    if text_color == None:
        tmpprinter = Panel(renderable=None).fit(title="Success",title_align="left",renderable=Text(texts,style="green"),border_style=border_color)
        return console.print(tmpprinter)
    else:
        tmpprinter = Panel(renderable=None).fit(title="Info",title_align="left",renderable=Text(texts,style=text_color),border_style=border_color)
        return console.print(tmpprinter)

def cliversion(console:Console):
    t = Panel(renderable=None).fit(title="Version",title_align="left",renderable=version,border_style="green")
    return console.print(t)

mainconsole = Console()


try:


    passconstant = b'seckeyok'


    def verify(srcfile:str):
        """
        srcfile: Path of the File
        """
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
    
    def get_data_position(infile:str):

        previousdata = b""
        dspos = 0
        depos = 0
        totalread = 0
        tmpfile = open(infile,"rb")
        depos = os.path.getsize(tmpfile.name)-112
        while x := tmpfile.read(4096):
            try:
                
                if depos != 0 and dspos == 0:
                    data_start = x.index(b"ds0X")+len(b"ds0X")
                    dspos = data_start
                    break
                
                totalread+= len(x)
                previousdata = x
            
                
            except (IndexError,ValueError) as ie:
                totalread+= len(x)
                previousdata= x
                continue

        dsposfinal = totalread - len(previousdata) + data_start
        return [dsposfinal,depos]

        

    def get_headers(infile:str,/) -> bytes:
        """
        **`infile`**: The file whose header needs to be returned
        
        """
        previousdata = b""
        hspos = 0
        hepos = 0
        totalread = 0
        tmpfile = open(infile,"rb")
        while x := tmpfile.read(4096):
            try:
                if hspos != 0 and hepos == 0:
                    combined = previousdata+x
                    tmphepos = combined.index(b"he0X")+len(b"he0X")
                    hepos = tmphepos
                    break

                else:
                    combined = previousdata+x
                    tmphspos = combined.index(b"hs0X")+len(b"hs0X")
                    hspos = tmphspos
                
                totalread+= len(x)
                previousdata = x

            
                
            except (IndexError,ValueError) as ie:
                totalread+= len(x)
                previousdata= x
                continue

        heposfinal = totalread - len(previousdata) + hepos
        tmpfile.seek(hspos-4,0)
        start_heads = tmpfile.read(heposfinal+4)
        tmpfile.seek(os.path.getsize(tmpfile.name)-112,0)
        end_heads = tmpfile.read(112)
        return(start_heads+end_heads)
    

    def askpass():
        while True:
            d = Prompt.ask("[bold green]Enter a password: [/bold green]",console=mainconsole,password=True)
            if len(d) < 6:
                printit(mainconsole,"Password must have more than 6 characters..","yellow","red")
                return askpass()
            else:
                fa = Prompt.ask("[bold green]Re-enter Same Password: [/bold green]",console=mainconsole,password=True)
                if fa == d:
                    if os.name =="nt":
                        os.system("cls")
                    else:
                        if os.name =="posix":
                            os.system("clear")
                    genkey = mixpass.passmixer(fa)[:32].encode('utf-8')
                    break
                else:
                    printit(mainconsole,"Password Did not match..retry...","yellow","red")
                    return askpass()
        return genkey

    def chkpass(val:bytes):
        #A Password checking func
        """
        ## **`val`**: takes decrypted pass constant and tells if it matches or not 
        """
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
        **`passw`**: The actual password used to generate the master key

        **`saltoriv`**: This is the master iv/salt and should be 16 bytes minimum
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
            return 1




    def hashverifier(srcfile:str,hmackey:bytes):
        #A Decryption Function
        """
        **`srcfile`** - Path to File

        **`hmackey`** - The key to use to verify the hmac hash
        """
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
                    printit(mainconsole,"File Integrity Check: Passed","green","green")
                    return 0
                else:
                    throwerror(mainconsole,"File Integrity Check: Failed")
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
                    printit(mainconsole,"HMAC Integrity Check: Passed","green","green")
                    return 0
                else:
                    throwerror(mainconsole,"HMAC Integrity Check: Failed")
                    return 1


        except ValueError as ia:
            errortext = """
            File is Corrupted
            Error: Hmac Verification Failed :("""
            throwerror(mainconsole,errortext)
            return 1






    def hashgenerator(filepath:str,encfiletype:str,etag:bytes,hmackey:bytes):
        """
        **`hmackey`** - The key to use to generate the hmac hash
            
        **`etag`** - The tag generated after gmac data encryption

        **`encfiletype`** - The type of file

        **`encfiletypes`**:-
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
                printit(mainconsole,"\nHmac File Hash Written","yellow","green")
                return 0
            except Exception as error:
                throwerror(mainconsole,str(error))
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
                printit(mainconsole,"\nHmac File Hash Written","yellow","green")
                return 0
            except Exception as oe:
                throwerror(mainconsole,str(oe))
                return 1


    def headercreate(data:bytes,key:bytes,filetype:bytes,bitcrypt_version:bytes,etype:bytes,hmac_secret_key:bytes):
        #The Headers are always encrypted in AES-CTR
        #Master iv is generated here
        """
        **`data`** - The actual data key + data iv

        **`key`** - The password given by saltyv2 algorithm

        **`filetype`** - The type of File ex:-mp4,pdf,jpg

        **`hmac_secret_key`** - The key to use to generate the hmac hash
        """
        
        try:
            #Generating Multiple IV's to encrypt Different Values and avoid IV reuse
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
                throwerror(mainconsole,"Header Creation Failed , Reason: Master Key Gen Error")
        
        except Exception as ka:
            return ka


    def headerinfo(filepath:str):
        try:
            if os.path.isfile(filepath):
                printit(mainconsole,"Getting Header Info...","yellow","green")
                if verify(filepath) ==0:
                    header_info = get_headers(filepath)
                    headread = header_info
                    filetype = headread[headread.index(b'tys0X')+len(b'tys0X'):headread.index(b'tye0X')]
                    appversion = headread[headread.index(b'bvs0X')+len(b'bvs0X'):headread.index(b'bve0X')]
                    enctype = headread[headread.index(b'extys0X')+len(b'extys0X'):headread.index(b'extye0X')]
                    gmintegrityval = headread[headread.index(b'ihgs0X')+len(b'ihgs0X'):headread.index(b'ihge0X')]
                    hmintegrityval = headread[headread.index(b'ihms0X')+len(b'ihms0X'):headread.index(b'ihme0X')]                                        
                    
                    fileinfo = f"""
                    [bold yellow]File Type[/bold yellow]: {filetype.decode('utf-8')}
                    [bold yellow]BitCrypt Version[/bold yellow]:{appversion.decode('utf-8')})
                    [bold yellow]File Type[/bold yellow]: {enctype.decode('utf-8')})
                    [bold yellow]Gmac Intergrity Hash[/bold yellow]: {gmintegrityval})
                    [bold yellow]Hmac Intergrity Hash[/bold yellow]: {hmintegrityval})
                    """
                    mainconsole.print(Panel(renderable=None).fit(title="File Info",title_align="left",renderable=fileinfo,border_style="green"))

                else:
                    throwerror(mainconsole,"File is not a BitCrypt File :(")
        except Exception as eror:
            throwerror(mainconsole,f"{str(eror)} Happened :)")



    def enc(srcfile:str,folderpath:str):
        """
        **`srcfile`** - Path To File

        **`password`** - The Original Typed Password

        **`ipcfile`** - Socket file for IPC Communication

        **`folderpath`** - Folder to save encrypted file in
        """
        
        dotcount = os.path.basename(srcfile).count(".")
        fileextension = os.path.basename(srcfile).split(".")[dotcount]
        filename = os.path.basename(srcfile).split(".")[0]
        f = open(folderpath+"//"+filename+".byt","wb")
        filesize = os.path.getsize(srcfile)
        cryptfilepath = os.path.abspath(folderpath+"//"+filename+".byt")
        try:
            mixkey = askpass()
            if mixkey :
                iv = os.urandom(16)
                enckey = os.urandom(32)
                mixdat = enckey+iv
                if os.path.getsize(srcfile) < 212806066:

                    #Small File Mode
                    
                    mainconsole.print("[bold yellow]Small File Mode[/bold yellow]")
                    hmckey = os.urandom(64)
                    far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'smoll',hmac_secret_key=hmckey)
                    if far:
                        f.write(far)
                        f.write(b'ds0X')                      
                        encdatacipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv)).encryptor()
                        tmpprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}[/bold green] [purple]{task.percentage:.1f}% [/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                        progressmybar = tmpprogress.add_task("Encrypting...",start=True,total=filesize)

                        with Live(Panel(renderable=None).fit(tmpprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                            with open(srcfile,"rb") as fileread:
                                    datatocrypt = encdatacipher.update(fileread.read())
                                    f.write(datatocrypt)
                                    tmpprogress.update(progressmybar,advance=len(datatocrypt))
                                    #Status Code
                                    # tmpval = fileread.tell()/filesize*100
                                    # tmplog = math.floor(tmpval*10)/10
                                    # status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                    # sys.stdout.write(f"\r{status}")                                  
                                    # sys.stdout.flush()
                                
                                #Status Code
                        # status = "Progress : "+str(100)+" "+"#"*int(100)
                        # sys.stdout.write(f"\r{status}")
                        # sys.stdout.flush()
                        encdatacipher.finalize()
                        f.write(b'de0X')
                        f.close()
                        gcmtag = encdatacipher.tag

                        with mainconsole.status(status="[bold yellow]Generating HMAC hash...[/bold yellow]",spinner="dots"):

                            smalldone = hashgenerator(filepath=cryptfilepath,encfiletype="smoll",hmackey=hmckey,etag=gcmtag)
                        
                        if smalldone != 0:
                            
                            throwerror(mainconsole,"Error Occured at Small file mode hashgenerator function")
                    
                    printit(mainconsole,f"\nEncrypted File Written to {os.path.abspath(os.path.join(folderpath, filename + '.byt'))}","yellow","green")

                        
                
                
                else:
                        
                    #Large File Mode
                    mainconsole.print("[bold yellow]Large File Mode[/bold yellow]")
                    hmckey = os.urandom(64)
                    
                    far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'biigg',hmac_secret_key=hmckey)
                    if far:
                        f.write(far)
                        f.write(b'ds0X')
                        srcdatafile = open(srcfile,"rb")
                        gcmcipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv)).encryptor()
                        tmplargeprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}[/bold green] [purple]{task.percentage:.1f}% [/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                        progressmylargebar = tmplargeprogress.add_task("Encrypting...",start=True,total=filesize)
                        with Live(Panel(renderable=None).fit(tmplargeprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                            while True:
                                curpos = srcdatafile.tell()
                                if curpos < filesize:
                                    tmpchunksize = min(4096,filesize-srcdatafile.tell())
                                    encdata = srcdatafile.read(tmpchunksize)
                                    f.write(gcmcipher.update(encdata))
                                    tmplargeprogress.update(progressmylargebar,advance=len(encdata))
                                    # tmpval = curpos/filesize*100
                                    # tmplog = math.floor(tmpval*10)/10
                                    # status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                    # sys.stdout.write(f"\r{status}")                                  
                                    # sys.stdout.flush()
                                
                                else:
                                    break
                        # status = "Progress : "+str(100)+" "+"#"*int(100)
                        # sys.stdout.write(f"\r{status}")
                        # sys.stdout.flush()
                        gcmcipher.finalize()
                        f.write(b'de0X')
                        f.close()
                        gcmfiletag = gcmcipher.tag

                        with mainconsole.status(status="[bold yellow]Generating HMAC hash...[/bold yellow]",spinner="dots"):

                           done = hashgenerator(filepath=cryptfilepath,encfiletype="biigg",etag=gcmfiletag,hmackey=hmckey)

                        if done !=0:
                            
                            throwerror(mainconsole,"Error Occured at Large file mode hashgenerator function")
                    printit(mainconsole,f"\nEncrypted File Written to {os.path.abspath(os.path.join(folderpath,filename+'.byt'))}","yellow","green")

                                                            
                            
                enckey , iv , mixdat , mixkey = 0 , 0 , 0 , 0
            

        except Exception as oa:
            
            throwerror(mainconsole,f"{str(oa)} Happened :(")   

    def dec(srcfile:str,folderpath:str):
        """
        **`srcfile`** - Path To File

        **`passw`** - The Original Typed Password

        **`ipcfile`** - Socket file for IPC Communication

        **`folderpath`** - Folder to save encrypted file in
        """
        
        if os.path.exists(srcfile):
            if os.path.isfile(srcfile):
                fchk = verify(srcfile=srcfile)
                if fchk ==0:
                    #Reading the Headers and decrypting the File Key
                    printit(mainconsole,"File is a BitCrypt File","green","green")
                    fileheader = open(srcfile,"rb")
                    decfilesize = os.path.getsize(fileheader.name)
                    headers = get_headers(srcfile)
                    dpostion = get_data_position(srcfile)
                    try:
                        masterkeyslt = headers[headers.index(b'mskysslt0X')+len(b'mskysslt0X'):headers.index(b'mskyeslt0X')]
                        encpsval = headers[headers.index(b'pskys0X')+len(b'pskys0X'):headers.index(b'pskye0X')]
                        start = dpostion[0]
                        hmkey = headers[headers.index(b'hmkys0X')+len(b'hmkys0X'):headers.index(b'hmkye0X')]
                        passconsiv = headers[headers.index(b'pskysiv0X')+len(b'pskysiv0X'):headers.index(b'pskyeiv0X')]
                        hmkeyiv = headers[headers.index(b'hmkysiv0X')+len(b'hmkysiv0X'):headers.index(b'hmkyeiv0X')]
                        filext = headers[headers.index(b'tys0X')+len(b'tys0X'):headers.index(b'tye0X')].decode('utf-8').replace(" ","")
                        mainheaders = headers[4:68]
                        masteriv = mainheaders[:16]
                        datacrypt = mainheaders[16:64]
                        #Seeking TO 112 bytes from the end as the hash lengths are fixed
                        end = dpostion[1]                     
                        gmactag = headers[headers.index(b'ihgs0X')+len(b'ihgs0X'):headers.index(b'ihge0X')]
                        
                    except ValueError as iae:
                        throwerror(mainconsole,"File Header is Corrupted :(\n Try Recovery Mode")
                        

                    decryptfilesize = decfilesize
                    passkey = Prompt.ask("[bold green]Enter Decryption Password [/bold green]",console=mainconsole,password=True)
                    mixkey = mixpass.passmixer(password=passkey)[:32].encode("utf-8")
                    #Deriveing the Master Key
                    tmptopkey = genpass(passw=mixkey,saltoriv=masterkeyslt) 
                    if tmptopkey !=1:
                        themasterkey = tmptopkey
                    else:
                        throwerror(mainconsole,"Master key Derivation Error")
                        

                    #Initializing Ciphers 
                    try:
                        decipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(passconsiv)).decryptor()
                        datadecipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(masteriv)).decryptor()
                        hmkeydecipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(hmkeyiv)).decryptor()
                    except ValueError as us:
                        throwerror(mainconsole,"File Headers are Corrupted :(\nTry Recovery Mode")
                        

                    passcons = decipher.update(encpsval)
                    if chkpass(passcons) == 0:
                        printit(mainconsole,"Correct Password Entered...Decrypting File","green","green")
                        

                        tmphmkey = hmkeydecipher.update(hmkey)
     
                        with mainconsole.status("[bold yellow]Verifying HMAC File Integrity...[/bold yellow]",spinner="dots"):
                
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
                                mainconsole.print("[bold yellow]Small file mode[/bold yellow]")

                                tmpdecprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}% [/bold green] [purple]{task.percentage:.1f}%[/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                                progressmysmalldecbar = tmpdecprogress.add_task("Decrypting...",start=True,total=decryptfilesize)
                                with open(filename+"."+filext,'wb') as outfile:
                                    filedata = io.BytesIO(headers[headers.index(b'ds0X')+len(b'ds0X'):headers.index(b'de0X')])
                                    try:
                                        with Live(Panel(renderable=None).fit(tmpdecprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                                            pcmp = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.GCM(ivv,gmactag)).decryptor()                                
                                            while decdata := filedata.read():                                    
                                                datpad = pcmp.update(decdata)
                                                outfile.write(datpad)
                                                tmpdecprogress.update(progressmysmalldecbar,advance=len(decdata))
                                                # tmpval = filedata.tell()/decryptfilesize*100
                                                # tmplog = math.floor(tmpval*10)/10
                                                # status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                                # sys.stdout.write(f"\r{status}")                                  
                                                # sys.stdout.flush()
                                                

                                            pcmp.finalize()
                                        
                                    except InvalidTag as excep:
                                        throwerror(mainconsole,"\nData Has Been Corrupted :(")
                                        throwerror(mainconsole,"Error: GCM Verification Failed")
                                        
                                        
                                # passkey , mixkey , df , decinfo , ekey , ivv , pcmp = 0
                                # status = "Progress : "+str(100)+" "+"#"*int(100)
                                # sys.stdout.write(f"\r{status}")
                                # sys.stdout.flush()
                                outfile.close()
                                # print("\n")
                                printit(mainconsole,f"Decrypted file written to...{os.path.abspath(os.path.join(filename,'.'+filext))}","yellow","green")
                                

                            else:
                                mainconsole.print("[bold yellow]large file mode[/bold yellow]")
                                filedec =  open(filename+"."+filext,'wb')
                                filedata = fileheader
                                filedata.seek(start)
                                try:
                                    decryptcipher = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.GCM(ivv,gmactag)).decryptor()
                                    tmpdeclargeprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}[/bold green] [purple]{task.percentage:.1f}% [/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                                    progressmylargedecbar = tmpdeclargeprogress.add_task("Decrypting...",start=True,total=decryptfilesize)
                                    with Live(Panel(renderable=None).fit(tmpdeclargeprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                                        while True:
                                            filepointer = filedata.tell()
                                            if filepointer < end:
                                                
                                                    chunksize = min(4096,end-filepointer)
                                                    tmpdata = filedata.read(chunksize)
                                                    decryptedata = decryptcipher.update(tmpdata)
                                                    filedec.write(decryptedata)
                                                    tmpdeclargeprogress.update(progressmylargedecbar,advance=len(tmpdata))
                                                    # tmpval = filepointer/end*100
                                                    # tmplog = math.floor(tmpval*10)/10
                                                    # status = "Progress : "+str(tmplog)+" "+"#"*int(tmplog)
                                                    # sys.stdout.write(f"\r{status}")                                  
                                                    # sys.stdout.flush()
                                                    
                                                    
                                            else:
                                                break

                                except InvalidTag as eis:
                                        throwerror(mainconsole,"\nData Has Been Corrupted :(")
                                        throwerror(mainconsole,"Error: GCM Verification Failed")
                                        
                                except Exception as ieae:
                                        
                                        throwerror(mainconsole,str(ieae))

                                # passkey , mixkey , df , decinfo , ekey , ivv = 0
                                # status = "Progress : "+str(100)+" "+"#"*int(100)
                                # sys.stdout.write(f"\r{status}")
                                # sys.stdout.flush()
                                # print("\n")
                                decryptcipher.finalize()
                                filedec.close()
                                printit(mainconsole,f"Decrypted file written to...{os.path.abspath(os.path.join(filename,'.'+filext))}","yellow","green")
                                
                        else:
                            throwerror(mainconsole,"Hash Verification Failed")
                            

                    else:
                        throwerror(mainconsole,"Wrong Password Entered :(")
                        

                else:
                    throwerror(mainconsole,"Your file has been corrupted\nNot a BitCrypt File :(")

    def doverifyhmac(srcfile:str) -> Console.print:

        try:
            if os.path.exists(srcfile):
                if os.path.isfile(srcfile):
                    bitcheck = verify(srcfile=srcfile)
                    if bitcheck == 0:
                        printit(mainconsole,"File is a BitCrypt File","green","green")
                        
                        file_headers = get_headers(srcfile)

                        data_start_and_end = get_data_position(srcfile)

                        passconsdecrypt = file_headers[file_headers.index(b'pskys0X')+len(b'pskys0X'):file_headers.index(b'pskye0X')]
                        passconsdecrypt_iv = file_headers[file_headers.index(b'pskysiv0X')+len(b'pskysiv0X'):file_headers.index(b'pskyeiv0X')]

                        hmacseckey = file_headers[file_headers.index(b'hmkys0X')+len(b'hmkys0X'):file_headers.index(b'hmkye0X')]
                        
                        hmacseckeyiv = file_headers[file_headers.index(b'hmkysiv0X')+len(b'hmkysiv0X'):file_headers.index(b'hmkyeiv0X')]

                        master_key_salt = file_headers[file_headers.index(b'mskysslt0X')+len(b'mskysslt0X'):file_headers.index(b'mskyeslt0X')]

                        enter_passwd = Prompt.ask("[bold green]Enter Decryption Password [/bold green]",console=mainconsole,password=True)

                        actualpasswd = genpass(mixpass.passmixer(enter_passwd)[:32].encode("utf-8"),master_key_salt)

                        if actualpasswd != 1:
                            pass_cons_cipher = Cipher(algorithm=algorithms.AES256(actualpasswd),mode=modes.CTR(passconsdecrypt_iv)).decryptor()
                            passconschk = pass_cons_cipher.update(passconsdecrypt)
                            if chkpass(passconschk) != 1:
                                printit(mainconsole,"Correct Password Entered","green","green")
                                hmackeydecrypt = Cipher(algorithm=algorithms.AES256(actualpasswd),mode=modes.CTR(hmacseckeyiv)).decryptor()
                                thehmackey = hmackeydecrypt.update(hmacseckey)
                                with mainconsole.status("[bold yellow] Verifying HMAC hash[/bold yellow]",spinner="dots"):
                                    chk = hashverifier(srcfile,thehmackey)
                  
                            else:
                                throwerror(mainconsole,"Wrong Password Entered")
                        else:
                            throwerror(mainconsole,"Something Happened internally")
                    else:
                        throwerror(mainconsole,f"File {srcfile} isn't a bitcrypt file")
                else:
                    throwerror(mainconsole,f"Path {srcfile} isn't a file...:(")
            else:
                throwerror(mainconsole,f"Path {srcfile} doesn't exist....(")
             
        except (Exception,IndexError,ValueError) as oe:
            throwerror(mainconsole,str(oe))
            shell()

    def shell():
        try:
            prompt = Prompt.ask("[bold green]bitc>>[/bold green]",console=mainconsole,password=False)

            match prompt:

                case "enc":
                    p = Prompt.ask("[bold green]Enter Normal File path [/bold green]")
                    if os.path.exists(p):
                       if os.path.isfile(p):

                          if os.name =="posix":
                            basename = os.path.basename(p)
                            enc(p,os.path.dirname(p))
                            shell()

                          elif os.name =="nt":
                            basename = os.path.basename(p)
                            enc(p,os.path.dirname(p))

                          else:
                            throwerror(mainconsole,"We dont support this os...")

                       else:
                        throwerror(mainconsole,"The file path is a folder..not a file..:(")
                        shell()
                    else:
                     throwerror(mainconsole,f"File path {str(p)} Does not exist :(")
                     shell()

                case "dec":
                    da = Prompt.ask("[bold green]Enter BitCrypt File path: [/bold green]")
                    if os.path.exists(da):
                        if os.path.isfile(da):
                            dec(srcfile=da,folderpath=os.path.dirname(da))
                            shell()
                        else:
                            throwerror(mainconsole,f"path {da} is not file...:(")
                    else:
                        throwerror(mainconsole,f"Path {da} doesn't exist...:(")

                case "showinfo":
                    tprom = Prompt.ask("[bold green]Enter File Path [/bold green]",password=None,console=mainconsole)
                    if os.path.exists(tprom):
                        if os.path.isfile(tprom):
                            headerinfo(tprom)
                        else:
                            throwerror(mainconsole,f"Path {tprom} isn't a file..:(")
                            shell()
                    else:
                        throwerror(mainconsole,f"File path {tprom} doesn't exist...:(")
                        shell()
                case "author": 
                    printit(mainconsole,"Built With ❤️  by shad0wrider\nhttps://github.com/shad0wrider","white","green")
                    shell()
                
                case "clear":
                    if os.name == "posix":
                        os.system("clear")
                    elif os.name =="nt":
                        os.system("cls")
                    else:
                        os.system("")
                    shell()
                
                case "verify":
                    vfile = Prompt.ask("[bold green]Enter Bitcrypt File Path [/bold green]")
                    doverifyhmac(vfile)

                case "help":
                    helpmenu(mainconsole)
                
                case "h":
                    helpmenu(mainconsole)
                
                case "v":
                    cliversion(mainconsole)

                case "version":
                    cliversion(mainconsole)

                case "":
                    pass          
        

                case _:
                    sprun = sp.Popen(prompt,shell=True,stdout=sp.PIPE,stderr=sp.PIPE)
                    

                    if sprun.stderr.read() == b'':
                        xyz = io.BufferedReader(sprun.stdout)

                        while x := xyz.read(4096):
                            printit(mainconsole,x.decode("utf-8"),"white","yellow")
                    else:
                        throwerror(mainconsole,f"Unknown Option {prompt}")
                        helpmenu(mainconsole)
                    shell()
            shell()
        
        except Exception as ie:
            throwerror(mainconsole,str(ie))
            shell()

        except KeyboardInterrupt as ie:
            printit(mainconsole,"Exiting...","yellow","white")
            sys.exit(0)

    if len(sys.argv) > 1:
        args = sys.argv
        match args[1]:
            case "enc":
                try:
                    if len(args) >= args.index("enc") + 1:
                        filepath = args[args.index("enc")+1]
                        if os.path.isfile(filepath):
                            enc(filepath,os.path.dirname(filepath))
                        else:
                            throwerror(mainconsole,f"{filepath} is not a file")
                        
                except (Exception,ValueError,IndexError) as ie:
                    throwerror(mainconsole,"File Path Missing")

            case "dec":
                try:
                  if len(args) >= args.index("dec") + 1:

                    filepath = args[args.index("dec")+1]
                    if os.path.isfile(filepath):
                        dec(filepath,os.path.dirname(filepath))
                    else:
                        throwerror(mainconsole,f"{filepath} is not a file")
                except (Exception,ValueError,IndexError) as ie:
                    throwerror(mainconsole,"File Path Missing")        

            case "verify":
                try:
                  if len(args) >= args.index("verify") + 1:
                    filepath = args[args.index("verify")+1]
                    if os.path.isfile(filepath):
                        verify(filepath)
                    else:
                        throwerror(mainconsole,f"{filepath} is not a file ")
                except Exception as ie:
                    throwerror(mainconsole,f"File Path Missing")
            case "exit":
                printit(mainconsole,"Exiting...","white","green")
                sys.exit(0)

            case "bye":
                printit(mainconsole,"Exiting...","white","green")
                sys.exit(0)
                    
            case "help":
                cliversion(mainconsole)
                helpmenu(mainconsole)
            
            case _:
                helpmenu(mainconsole)


                        
    shell()


except Exception as eror:
    throwerror(mainconsole,f"{eror} Occured")
    shell()

except KeyboardInterrupt as whatevs:
    printit(mainconsole,"Exiting...","yellow","white")
    sys.exit(0)


