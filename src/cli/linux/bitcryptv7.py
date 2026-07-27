#!/bin/python3
#This is BitCrypt v5
#By https://github.com/shad0wrider
#Can encrypt small to large files efficiently and securely

#Whats New: -- 1.New Revamped rich based TUI
#              2.Fixed header parsing slowdown in showinfo and dec function

#Info : Master iv is generated when headercreate function is called

##-----------## Core Libraries ##-----------##

from io import BufferedReader
import argon2 , hmac , hashlib , base64 as b64
from cryptography.hazmat.primitives import hashes, serialization , padding as sympadding
from cryptography.hazmat.primitives.ciphers import Cipher , algorithms , modes
from cryptography.exceptions import InvalidKey , InvalidSignature , InvalidTag
import time , os , sys , json , io
import secrets , gc , subprocess as sp
import sqlite3 as sq3
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


version = "Bitcrypt Cli v7.20-7-26"

whats_new = """
# Whats New:
   - ``New Revamped cli interface using rich``
   - ``New Revamped File Container Format``
   - ``Faster Encryption and Decryption``

# What Went:
   - ``Removed saltyv2``


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
        startbit = startheader[:6]
        veri.seek(-6,2)
        endheader = veri.read(6)
        endbit = endheader[0:6]
        if endbit ==b'byte0X' and startbit ==b'byts0X':
            return 0
        else:
            return 1
    
        

    def get_headers(infile:str,/) -> dict:
        """
        **`infile`**: The file whose header needs to be returned
        
        """
        file = open(infile,"rb")


        # Size = 192 bytes (All Offsets) + 64 bytes (HMAC Hash Length) + 6 Bytes (End File b'byte0X' Marker) = 262 bytes

        # file.seek(os.path.getsize(file.name)-262,0)

        try:

                file.seek(-262,os.SEEK_END)

                footer = file.read(262)

                bytemap = {}

                #Main IV and Offset + Length
                mainiv_ofs = int.from_bytes(footer[0:8],"little")
                mainiv_len = int.from_bytes(footer[8:16],"little")

                file.seek(mainiv_ofs,0)

                mainiv = file.read(mainiv_len)

                bytemap["mainiv"] = mainiv

                # datacrypt Offset + Length

                datacrypt_ofs = int.from_bytes(footer[16:24],"little")
                datacrypt_len = int.from_bytes(footer[24:32],"little")

                file.seek(datacrypt_ofs,0)

                datacrypt = file.read(datacrypt_len)

                bytemap["datacrypt"] = datacrypt

                # masterkeysalt Offset + Length

                masterkeysalt_ofs = int.from_bytes(footer[32:40],"little")
                masterkeysalt_len = int.from_bytes(footer[40:48],"little")
                
                file.seek(masterkeysalt_ofs,0)

                masterkeysalt = file.read(masterkeysalt_len)

                bytemap["masterkeysalt"] = masterkeysalt

                # filetype Offset + Length

                filetype_ofs = int.from_bytes(footer[48:56],"little")
                filetype_len = int.from_bytes(footer[56:64],"little")
                
                file.seek(filetype_ofs,0)

                filetype = file.read(filetype_len)

                bytemap["filetype"] = filetype

                # finalpass offset + Length
                
                finalpass_ofs = int.from_bytes(footer[64:72],"little")
                finalpass_len = int.from_bytes(footer[72:80],"little")

                file.seek(finalpass_ofs,0)

                finalpass = file.read(finalpass_len)

                bytemap["finalpass"] = finalpass

                # passcons IV Offset + Length
                
                passconsiv_ofs = int.from_bytes(footer[80:88],"little")
                passconsiv_len = int.from_bytes(footer[88:96],"little")

                file.seek(passconsiv_ofs,0)

                passconsiv = file.read(passconsiv_len)

                bytemap["passconsiv"] = passconsiv

                # bitcrypt_version Offset + Length

                bitcrypt_version_ofs = int.from_bytes(footer[96:104],"little")
                bitcrypt_version_len = int.from_bytes(footer[104:112],"little")

                file.seek(bitcrypt_version_ofs,0)

                bitcrypt_version = file.read(bitcrypt_version_len)
                
                bytemap["bitcrypt_version"] = bitcrypt_version

                # etype Offset + Length

                etype_ofs = int.from_bytes(footer[112:120],"little")
                etype_len = int.from_bytes(footer[120:128],"little")

                file.seek(etype_ofs,0)

                etype = file.read(etype_len)

                bytemap["etype"] = etype

                # hmac key iv Offset + Length

                hmkeyiv_ofs = int.from_bytes(footer[128:136],"little")
                hmkeyiv_len = int.from_bytes(footer[136:144],"little")
                
                file.seek(hmkeyiv_ofs,0)

                hmkeyiv = file.read(hmkeyiv_len)

                bytemap["hmkeyiv"] = hmkeyiv

                # header gcm tag Offset + Length

                header_gcm_tag_ofs = int.from_bytes(footer[144:152],"little")
                header_gcm_tag_len = int.from_bytes(footer[152:160],"little")

                file.seek(header_gcm_tag_ofs,0)

                header_gcm_tag = file.read(header_gcm_tag_len)

                bytemap["header_gcm_tag"] = header_gcm_tag

                # Encrypted Data Offset + Length

                enc_data_ofs = int.from_bytes(footer[160:168],"little")
                enc_data_len = int.from_bytes(footer[168:176],"little")

                bytemap["enc_data"] = [enc_data_ofs,enc_data_len]

                # Encryted Data GCM Tag Offset + Length


                enc_data_gcm_tag_ofs = int.from_bytes(footer[176:184],"little")
                enc_data_gcm_tag_len = int.from_bytes(footer[184:192],"little")

                file.seek(enc_data_gcm_tag_ofs,0)

                enc_data_gcm_tag = file.read(enc_data_gcm_tag_len)

                bytemap["enc_data_gcm_tag"] = enc_data_gcm_tag

                # HMAC hash Partial

                hmac_hash = footer[192:256]

                bytemap["hmac_hash"] = hmac_hash

                # File End Marker

                #print(footer[256:262])
        except Exception as ienw:
                throwerror(mainconsole,"Header Data was not found , file is probably corrupt!!")

        file.close()
        return bytemap
    

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
                    genkey = fa.encode("utf-8")
                    break
                else:
                    printit(mainconsole,"Password Did not match..retry...","yellow","red")
        return genkey

    def chkpass(val:bytes):
        #A Password checking func
        """
        ## **`val`**: takes decrypted pass constant and tells if it matches or not 
        """
        try:
            if val == passconstant:
                return 0
            else:
                return 1
            
        except Exception as ia:
            return 1
        
    def recovery():
        pass


    def genpass(passw:bytes,saltoriv:bytes) ->  bytes:
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
        file_headers = get_headers(srcfile)

        try:
            filetypem = file_headers.get("etype",b"na")

            match filetypem:

                case b"smoll":

                    filehmachash = file_headers.get("hmac_hash",b"na")
                    
                    filecheck.seek(0,0)

                    datatocheck = io.BytesIO(filecheck.read(tmpfilesize-70))

                    calculatehmac = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)
                    while readit := datatocheck.read():
                        calculatehmac.update(readit)
                    if hmac.compare_digest(filehmachash,calculatehmac.digest()):
                        printit(mainconsole,"File Integrity Check: Passed","green","green")
                        return 0
                    else:
                        throwerror(mainconsole,"File Integrity Check: Failed")
                        return 1
                
                case b"biigg":

                    filehmachash = file_headers.get("hmac_hash",b"na")

                    calculatehmac = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)
                    endpoint = tmpfilesize-70

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
                
                case b"na":
                    throwerror(mainconsole,"File Seems to be Corrupted :(")


        except ValueError as ia:
            errortext = """
            File is Corrupted
            Error: Hmac Verification Failed :("""
            throwerror(mainconsole,errortext)
            return 1






    def hashgenerator(filepath:str,encfiletype:str,hmackey:bytes):
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

                #Reading File Content Up Until Gmac Tag
                hashfile = open(filepath,"rb")
                hashfile.seek(0,0)
                hashfile = hashfile.read()
                datatohash = hashfile
                #Calculating Hmac Hash
                hmhash = hmac.new(key=hmackey,msg=datatohash,digestmod=hashlib.sha3_512)
                hashcontent = hmhash.digest()
                print(hashcontent)
                
                #Returns computed Hmac Hash

                printit(mainconsole,"\nHmac File Hash Computed","yellow","green")
                return hashcontent

            except Exception as error:
                throwerror(mainconsole,str(error))
                return False
        
        elif encfiletype =="biigg":
            try:
                #----------------------------------
                #Reading File Content Up Until Gmac Tag
                tmpfilesize = os.path.getsize(filepath)
                hashfile = open(filepath,"rb")               
                hmhash = hmac.new(key=hmackey,digestmod=hashlib.sha3_512)

                while True:
                    filepointer = hashfile.tell()

                    if filepointer < tmpfilesize:
                        chunksize = min(4096,tmpfilesize-filepointer)
                        tmphashdata = hashfile.read(chunksize)
                        hmhash.update(tmphashdata)
                    else:
                        break

                hashcontent = hmhash.digest()
                #Returns the HMAC Hash

                printit(mainconsole,"\nHmac File Hash Computed","yellow","green")
                return hashcontent

            except Exception as oe:
                throwerror(mainconsole,str(oe))
                return False


    def headercreate(data:bytes,key:bytes,filetype:bytes,bitcrypt_version:bytes,etype:bytes):
        #The Headers are always encrypted in AES-CTR
        #Master iv is generated here
        """
        **`data`** - The actual data key + data iv

        **`key`** - The password given by the user

        **`filetype`** - The type of File ex:-mp4,pdf,jpg

        **`hmac_secret_key`** - The key to use to generate the hmac hash
        """
        
        try:
            #Generating Multiple IV's to encrypt Different Values and avoid IV reuse
            itemsarray = []
            computed_array = []
            mainiv = os.urandom(16)
            masterkeysalt = os.urandom(16)
            hmkeyiv = os.urandom(16)
            passconsiv = os.urandom(16)
            #Master Key Generation Using argon2
            actualmaster = genpass(passw=key,saltoriv=masterkeysalt)
            #Dereiveing HMAC key from user password with hmac key iv
            actualhmackey = genpass(passw = key , saltoriv= hmkeyiv)
            if actualmaster !=1:
            #Generating Master Key Done
                thekeymaster = actualmaster
                head = Cipher(algorithm=algorithms.AES256(key=thekeymaster),mode=modes.GCM(mainiv,min_tag_length=16)).encryptor()
                finalpass = Cipher(algorithm=algorithms.AES256(key=thekeymaster),mode=modes.CTR(passconsiv)).encryptor()
                finalpasss = finalpass.update(passconstant)
                datacrypt = head.update(data)
                head.finalize()
                headergcmtag = head.tag
                itemsarray.extend([mainiv,datacrypt,masterkeysalt,filetype,finalpasss,passconsiv,bitcrypt_version,etype,hmkeyiv,headergcmtag])

                last_position = 6 # Since the first 6 bytes of a every file encrypted in normal mode start with b'byts0X'

                for x in itemsarray:
                    current_position = last_position
                    the_length = len(x)
                    computed_array.extend([int(current_position).to_bytes(8,"little"),int(the_length).to_bytes(8,"little")])
                    last_position = current_position + len(x)

                return (itemsarray,computed_array,actualhmackey)

                

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
                    filetype = header_info.get("filetype",b"na")
                    appversion = header_info.get("bitcrypt_version",b"na")
                    enctype = header_info.get("etype",b"na")                              
                    
                    fileinfo = f"""
                    [bold yellow]File Type[/bold yellow]: {filetype.decode('utf-8')}
                    [bold yellow]BitCrypt Version[/bold yellow]:{appversion.decode('utf-8')}
                    [bold yellow]File Type[/bold yellow]: {enctype.decode('utf-8')}
                    """
                    mainconsole.print(Panel(renderable=None).fit(title="File Info",title_align="left",renderable=fileinfo,border_style="green"))

                else:
                    throwerror(mainconsole,"File is not a BitCrypt File :(")
        except Exception as eror:
            throwerror(mainconsole,f"{str(eror)} Happened :)")



    def enc(srcfile:str,folderpath:str):
        """
        **`srcfile`** - Path To File

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
                    far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'smoll')
                    if far:
                        f.write(b"byts0X")
                        f.write(b"".join(far[0]))

                        
                        encdatacipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv,min_tag_length=16)).encryptor()
                        
                        tmpprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}[/bold green] [purple]{task.percentage:.1f}% [/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                        
                        progressmybar = tmpprogress.add_task("Encrypting...",start=True,total=filesize)

                        data_start_position = int.from_bytes(far[1][-1],"little") + int.from_bytes(far[1][-2],"little")
                        data_length = 0

                        with Live(Panel(renderable=None).fit(tmpprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                            with open(srcfile,"rb") as fileread:
                                    datatocrypt = encdatacipher.update(fileread.read())
                                    data_length += len(datatocrypt)
                                    f.write(datatocrypt)
                                    tmpprogress.update(progressmybar,advance=len(datatocrypt))

                        encdatacipher.finalize()
                        gcmtag = encdatacipher.tag
                        f.write(gcmtag)

                        tagoffset = data_start_position + data_length

                        taglength = len(gcmtag)

                        data_position_int_to_bytes = int(data_start_position).to_bytes(8,"little")

                        data_length_int_to_bytes = int(data_length).to_bytes(8,"little")

                        tagoffset_int_to_bytes = int(tagoffset).to_bytes(8,"little")

                        taglength_int_to_bytes = int(taglength).to_bytes(8,"little")

                        all_offsets = far[1]
                        all_offsets.extend([data_position_int_to_bytes,data_length_int_to_bytes,tagoffset_int_to_bytes,taglength_int_to_bytes])

                        f.write(b"".join(all_offsets))

                        f.flush() # Makes sure we push all existing data to file before hmac reads the file


                        with mainconsole.status(status="[bold yellow]Generating HMAC hash...[/bold yellow]",spinner="dots"):

                            smalldone = hashgenerator(filepath=cryptfilepath,encfiletype="smoll",hmackey=far[2])
                        
                            if smalldone:
                                
                                f.write(smalldone)
                                f.write(b'byte0X')
                                f.close()

                            else:
                                throwerror(mainconsole,"Error Occured at Small file mode hashgenerator function")
                    printit(mainconsole,f"Actual HMAC KEY {far[2].hex()}","green","yellow")
                    
                    printit(mainconsole,f"\nEncrypted File Written to {os.path.abspath(os.path.join(folderpath, filename + '.byt'))}","yellow","green")

                    
            
            
                else:
                        
                    #Large File Mode
                    mainconsole.print("[bold yellow]Large File Mode[/bold yellow]")
                    hmckey = os.urandom(64)
                    
                    far = headercreate(data=mixdat,key=mixkey,filetype=fileextension.encode('utf-8'),bitcrypt_version=version.encode('utf-8'),etype=b'biigg')
                    if far:

                        f.write(b"byts0X")
                        f.write(b"".join(far[0]))

                        srcdatafile = open(srcfile,"rb")
                        
                        gcmcipher = Cipher(algorithm=algorithms.AES256(enckey),mode=modes.GCM(iv,min_tag_length=16)).encryptor()
                        
                        tmplargeprogress = Progress(SpinnerColumn("dots",style="yellow",speed=2),TextColumn("[bold green]{task.description}[/bold green] [purple]{task.percentage:.1f}% [/purple]"),BarColumn(),DownloadColumn(binary_units=True))
                        
                        progressmylargebar = tmplargeprogress.add_task("Encrypting...",start=True,total=filesize)

                        data_start_position = int.from_bytes(far[1][-1],"little") + int.from_bytes(far[1][-2],"little")
                        data_length = 0
                        
                        with Live(Panel(renderable=None).fit(tmplargeprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                            while True:
                                curpos = srcdatafile.tell()
                                if curpos < filesize:
                                    tmpchunksize = min(4096,filesize-srcdatafile.tell())
                                    encdata = srcdatafile.read(tmpchunksize)
                                    f.write(gcmcipher.update(encdata))
                                    tmplargeprogress.update(progressmylargebar,advance=len(encdata))

                                    data_length += len(encdata)

                                
                                else:
                                    break

                        gcmcipher.finalize()
                        gcmfiletag = gcmcipher.tag
                        f.write(gcmfiletag)

                        tagoffset = data_start_position + data_length

                        taglength = len(gcmfiletag)

                        data_position_int_to_bytes = int(data_start_position).to_bytes(8,"little")

                        data_length_int_to_bytes = int(data_length).to_bytes(8,"little")

                        tagoffset_int_to_bytes = int(tagoffset).to_bytes(8,"little")

                        taglength_int_to_bytes = int(taglength).to_bytes(8,"little")

                        all_offsets = far[1]

                        all_offsets.extend([data_position_int_to_bytes,data_length_int_to_bytes,tagoffset_int_to_bytes,taglength_int_to_bytes])

                        f.write(b"".join(all_offsets))

                        f.flush() # Makes sure we push all existing data to file before hmac reads the file


                        with mainconsole.status(status="[bold yellow]Generating HMAC hash...[/bold yellow]",spinner="dots"):

                            done = hashgenerator(filepath=cryptfilepath,encfiletype="biigg",hmackey=far[2])

                            if done:
                                f.write(done)
                                f.write(b'byte0X')
                                f.close()

                            else:
                            
                                throwerror(mainconsole,"Error Occured at Large file mode hashgenerator function")
                    
                    printit(mainconsole,f"\nEncrypted File Written to {os.path.abspath(os.path.join(folderpath,filename+'.byt'))}","yellow","green")

                                                        
                        
            enckey , iv , mixdat , mixkey = 0 , 0 , 0 , 0

        except Exception as iwner:
            throwerror(mainconsole,f"{str(iwner)} Happened :(")
            

        

    def dec(srcfile:str,folderpath:str):
        """
        **`srcfile`** - Path To File

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
                    file_headers = get_headers(srcfile)
                    try:
                        masterkeyslt = file_headers.get("masterkeysalt",b"na")
                        encpsval = file_headers.get("finalpass",b"na")
                        start = file_headers.get("enc_data",b"na")[0]
                        passconsiv = file_headers.get("passconsiv",b"na")
                        hmkeyiv = file_headers.get("hmkeyiv",b"na")
                        filext = file_headers.get("filetype",b"na").decode("utf-8")
                        masteriv = file_headers.get("mainiv",b"na")
                        datacrypt = file_headers.get("datacrypt",b"na")
                        start = file_headers.get("enc_data",b"na")[0]
                        end = file_headers.get("enc_data",b"na")[1]                    
                        gmactag = file_headers.get("enc_data_gcm_tag",b"na")
                        header_gcmtag = file_headers.get("header_gcm_tag",b"na")

                        for x , y in file_headers.items():
                            if y == b"na":
                                print(x," is na")

                        printit(mainconsole,"Reading Headers Done","green","white") # Checkpoint : 1
                        
                    except ValueError as iae:
                        throwerror(mainconsole,"File Header is Corrupted :(\n Try Recovery Mode")
                        

                    decryptfilesize = decfilesize

                    passkey = Prompt.ask("[bold green]Enter Decryption Password [/bold green]",console=mainconsole,password=True)
                    #Deriveing the Master Key
                    tmptopkey = genpass(passw=passkey.encode("utf-8"),saltoriv=masterkeyslt) 

                    if tmptopkey !=1:
                        themasterkey = tmptopkey
                    else:
                        throwerror(mainconsole,"Master key Derivation Error")
                        

                    #Initializing Ciphers 
                    try:
                        decipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.CTR(passconsiv)).decryptor()
                        datadecipher = Cipher(algorithm=algorithms.AES256(themasterkey),mode=modes.GCM(masteriv,header_gcmtag)).decryptor()
                    except ValueError as us:
                        throwerror(mainconsole,"File Headers are Corrupted :(\nTry Recovery Mode")
                        
                        

                    passcons = decipher.update(encpsval)
                    if chkpass(passcons) == 0:
                        printit(mainconsole,"Correct Password Entered...Decrypting File","green","green")


                        hmkey = genpass(passkey.encode("utf-8"),hmkeyiv)                      

        
                        with mainconsole.status("[bold yellow]Verifying HMAC File Integrity...[/bold yellow]",spinner="dots"):
                
                        #Verifying Layer 2 Integrity via HMAC
                
                            hashverify = hashverifier(srcfile=srcfile,hmackey=hmkey)
                        
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
                                    fileheader.seek(start,0)
                                    filedata = io.BytesIO(fileheader.read(end))
                                    try:
                                        with Live(Panel(renderable=None).fit(tmpdecprogress,title="Progress",title_align="left",border_style="green"),refresh_per_second=10):
                                            pcmp = Cipher(algorithm=algorithms.AES256(ekey),mode=modes.GCM(ivv,gmactag)).decryptor()                                
                                            while decdata := filedata.read():                                    
                                                datpad = pcmp.update(decdata)
                                                outfile.write(datpad)
                                                tmpdecprogress.update(progressmysmalldecbar,advance=len(decdata))

                                            pcmp.finalize()
                                        
                                    except InvalidTag as excep:
                                        throwerror(mainconsole,"\nData Has Been Corrupted :(")
                                        throwerror(mainconsole,"Error: GCM Verification Failed")
                                        
                                        

                                outfile.close()
                                printit(mainconsole,f"Decrypted file written to...{os.path.abspath(os.path.join(filename,'.'+filext))}","yellow","green")
                                

                            else:
                                mainconsole.print("[bold yellow]large file mode[/bold yellow]")
                                filedec =  open(filename+"."+filext,'wb')
                                filedata = fileheader
                                filedata.seek(start)

                                end = file_headers.get("enc_data",b"na")[0] + file_headers.get("enc_data",b"na")[1]
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

                                                    
                                            else:
                                                break

                                except InvalidTag as eis:
                                        throwerror(mainconsole,"\nData Has Been Corrupted :(")
                                        throwerror(mainconsole,"Error: GCM Verification Failed")
                                        
                                except Exception as ieae:
                                        
                                        throwerror(mainconsole,str(ieae))


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

                        passconsdecrypt = file_headers.get("finalpass",b"na")
                        passconsdecrypt_iv = file_headers.get("passconsiv",b"na")
                        
                        hmacseckeyiv = file_headers.get("hmkeyiv",b"na")

                        master_key_salt = file_headers.get("masterkeysalt",b"na")

                        enter_passwd = Prompt.ask("[bold green]Enter Decryption Password [/bold green]",console=mainconsole,password=True)

                        actualpasswd = genpass(enter_passwd.encode("utf-8"),master_key_salt)

                        if actualpasswd != 1:
                            pass_cons_cipher = Cipher(algorithm=algorithms.AES256(actualpasswd),mode=modes.CTR(passconsdecrypt_iv)).decryptor()
                            passconschk = pass_cons_cipher.update(passconsdecrypt)
                            if chkpass(passconschk) != 1:
                                printit(mainconsole,"Correct Password Entered","green","green")
                                thehmackey = genpass(enter_passwd.encode("utf-8"),hmacseckeyiv)
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

                case "new":
                    mainconsole.print(Panel(renderable=Markdown(whats_new),title=f"Changes in {version} ",title_align="left",border_style="green"))

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

            case "new":
                print(mainconsole,whats_new)
            
            case _:
                helpmenu(mainconsole)


                        
    shell()


except Exception as eror:
    throwerror(mainconsole,f"{eror} Occured")
    shell()

except KeyboardInterrupt as whatevs:
    printit(mainconsole,"Exiting...","yellow","white")
    sys.exit(0)


