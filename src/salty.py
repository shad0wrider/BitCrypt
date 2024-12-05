#This is a custom Salting Algorithm used to jumble passwords in a way such that it cannot be gussed back
#Yet provides the same value every single time

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

