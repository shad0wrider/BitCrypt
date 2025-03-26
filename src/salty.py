#This is a Password Extending Algorithm used to Extend inputted passwords in a way such that it extends passwords
# as small as 6 characters to a jumbled password of 32+ characters
#This is NOT a hashing algorithm

import time
import random , secrets , json

mixed = []


def hash(password):
    passw = password[::-1]
    newpass = list(password)
    po = list(passw)

    for i in range(len(password)):
          mixed.insert(i,passw[i]+newpass[i])    
       
    

    for i in range(1,len(mixed)):
            gh = int(len(mixed)/2)
            mixed.insert(i*i,str(i))
            mixed.insert(i*i+1,f"*{len(mixed)}*")
            
    f = str(mixed).replace("[","").replace("]","").replace("'","").replace(",","").replace(" ","")      
    return str(f)

