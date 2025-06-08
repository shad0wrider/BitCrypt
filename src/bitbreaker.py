import os , sys , io , math

#This program is used to Demonstrate the HMAC integrity feature of BitCrypt
#Run a file Encrypted using BitCrypt through this program and it writes half of the encrypted data to a new file
#Try to decrypt that new file with BitCrypt and the HMAC integrity of that file will fail

#THIS CODE DOES NOT BREAK ANY SORT OF ENCRYPTION , this code only simulates what errors BitCrypt Would throw if it tried to Decrypt a Corrupt or Tampered File

#Not for Noobs , Don't try running this if you don't understand what cryptography is.


f = input("Enter File to Corrupt: ")

if os.path.exists(f):
    newcorrupt = open(os.path.basename(f).split(".")[0]+"-corrupt"+".byt","wb")
    originalfile = open(f,"rb")
    filesize = os.path.getsize(f)
    x = originalfile.read()
    start = x.index(b'ds0X')
    end = x.index(b'de0X')
    #Moving File Pointer to Start
    originalfile.seek(0)
    while True:
        pointer = originalfile.tell()
        if pointer < start+4:
            chunksize = min(4096,start+4-pointer)
            tmp = originalfile.read(chunksize)
            newcorrupt.write(tmp)
        else:
            break
    print("Half Portion Written")
    print("Data start byte",start+4)
    print("Data end byte",end)
    tmpval = end - (start+4)
    halfval = math.floor(tmpval/2)
    print(halfval)
    while True:
        pointer2 = originalfile.tell()
        if pointer2 < halfval:
            chunk2ize = min(4096,halfval-pointer2)
            tmp2 = originalfile.read(chunk2ize)
            newcorrupt.write(tmp2)
        else:
            break
    print("Completing write Data")
    #Moving Pointer to End of data sector
    originalfile.seek(end,0)
    while True:
        pointer3 = originalfile.tell()
        if pointer3 < filesize:
            chunk3ize = min(4096,filesize-pointer3)
            tmp3 = originalfile.read(chunk3ize)
            newcorrupt.write(tmp3)
        else:
            break
    print("Half Data written successfully")
    newcorrupt.close()

    
