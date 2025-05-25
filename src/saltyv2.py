#This is a Deterministic Password Generating Algorithm used to Extend inputted passwords in a way such that it extends passwords
# as small as 6 characters to a jumbled password of 32+ characters and still maintains randomness
#This is NOT a hashing algorithm

import time
import getpass


#Latest SaltyV2 Implementation




vowels = ["a","e","i","o","u"]
nonvowels = ["b","c","d","f","g","h","j","k","l","m","n","p","q","r","s","t","v","w","x","y","z"]

letterbind = {'a':1,'b':2,'c':3,'d':4,'e':5,'f':6,'g':7,'h':8,'i':9,'j':10,'k':11,'l':12,'m':13,'n':14,'o':15,'p':16,'q':17,'r':18,'s':19,'t':20,'u':21,'v':22,'w':23,'x':24,'y':25,'z':26}

symbind = {'a': '`', 'b': '~', 'c': '!', 'd': '@', 'e': '#', 'f': '$', 'g': '%', 'h': '^', 'i': '&', 'j': '*', 'k': '(', 'l': ')', 'm': '_', 'n': '-', 'o': '+', 'p': '=', 'q': '|', 'r': ']', 's': '}', 't': '[', 'u': '{', 'v': ':', 'w': ';', 'x': '?', 'y': '>', 'z': '<'}

symbindreverse = {'`':'a','~':'b','!':'c','@':'d','#':'e','$':'f','%':'g','^':'h','&':'i','*':'j','(':'k',')':'l','_':'m','-':'n','+':'o','=':'p','|':'q',']':'r','}':'s','[':'t','{':'u',':':'v',';':'w','?':'x','>':'y','<':'z'}

symnumbind = {0:'&#',1: '`', 2: '~', 3: '!', 4: '@', 5: '#', 6: '$', 7: '%', 8: '^', 9: '&', 10: '*', 11: '(', 12: ')', 13: '_', 14: '-', 15: '+', 16: '=', 17: '|', 18: ']', 19: '}', 20: '[', 21: '{', 22: ':', 23: ';', 24: '?', 25: '>', 26: '<'}

digitbind = {0:'zx',1:'a',2:'b',3:'c',4:'d',5:'e',6:'f',7:'g',8:'h',9:'i',10:'j',11:'k',12:'l',13:'m',14:'n',15:'o',16:'p',17:'q',18:'r',19:'s',20:'t',21:'u',22:'v',23:'w',24:'x',25:'y',26:'z'}

def passmixer(password:str):
  jumbpass = []
  passw = password.lower()
    
  if len(passw) % 2 ==0:

    #Function for passwords with Even Number length

    for i in range(len(passw)-1):
        
        if i ==0:
        
            #Character One Processing
            char1 = passw[i]
            char2 = passw[i+1]

            if str(char1) in list(letterbind.keys()):
                part1 = str(letterbind.get(str(char1)))+str(char1)
                
            elif char1 in list(symbindreverse.keys()):
                part1 = symbindreverse.get(char1)+str(char1)

            elif int(char1) in list(digitbind.keys()):
                part1 = str(digitbind.get(int(char1)))+str(char1)
            

            #Character Two Processing

            if str(char2) in list(letterbind.keys()):
                part2 = str(letterbind.get(str(char2)))+str(char2)
                
            elif char2 in list(symbindreverse.keys()):
                part2 = symbindreverse.get(char2)+str(char2)

            elif int(char2) in list(digitbind.keys()):
                part2 = str(digitbind.get(int(char2)))+str(char2)
            
            #Calculating Middle Value

            if str(char1) in list(letterbind.keys()) and str(char2) in list(letterbind.keys()):
                #Middle Value when both are Letters
                if int(letterbind.get(char1)) > int(letterbind.get(char2)):
                    middlevalue = int(letterbind.get(char1)) - int(letterbind.get(char2))
                
                elif int(letterbind.get(char2)) > int(letterbind.get(char1)):
                    middlevalue = int(letterbind.get(char2)) - int(letterbind.get(char1))

                else:
                    middlevalue = int(letterbind.get(char1)) + int(letterbind.get(char2))

            elif char1 in list(symbindreverse.keys()) and char2 in list(symbindreverse.keys()):
                #Middle Value Calculation when both are symbols
                middlevalue = str(symbindreverse.get(char1)) + str(symbindreverse.get(char2))
            
            else:
                middlevalue = str(char1)+str(char2)

            evenfunc1 = str(part1) + str(middlevalue) + str(part2)
            jumbpass.append(evenfunc1)


        elif i % 2 ==0:

            #Character One Processing
            char1 = passw[i]
            char2 = passw[i+1]

            if str(char1) in list(letterbind.keys()):
                part1 = str(letterbind.get(str(char1)))+str(char1)
                
            elif char1 in list(symbindreverse.keys()):
                part1 = symbindreverse.get(char1)+str(char1)

            elif int(char1) in list(digitbind.keys()):
                part1 = str(digitbind.get(int(char1)))+str(char1)
            

            #Character Two Processing

            if str(char2) in list(letterbind.keys()):
                part2 = str(letterbind.get(str(char2)))+str(char2)
                
            elif char2 in list(symbindreverse.keys()):
                part2 = symbindreverse.get(char2)+str(char2)

            elif int(char2) in list(digitbind.keys()):
                part2 = str(digitbind.get(int(char2)))+str(char2)
            

            #Calculating Middle Value

            if str(char1) in list(letterbind.keys()) and str(char2) in list(letterbind.keys()):
                #Middle Value when both are Letters
                if int(letterbind.get(char1)) > int(letterbind.get(char2)):
                    middlevalue = int(letterbind.get(char1)) - int(letterbind.get(char2))
                
                elif int(letterbind.get(char2)) > int(letterbind.get(char1)):
                    middlevalue = int(letterbind.get(char2)) - int(letterbind.get(char1))

                else:
                    middlevalue = int(letterbind.get(char1)) + int(letterbind.get(char2))

            elif char1 in list(symbindreverse.keys()) and char2 in list(symbindreverse.keys()):
                #Middle Value Calculation when both are symbols
                middlevalue = str(symbindreverse.get(char1)) + str(symbindreverse.get(char2))
            
            else:
                middlevalue = str(char1)+str(char2)

            evenfunc2 = str(part1) + str(middlevalue) + str(part2)
            jumbpass.append(evenfunc2)

        else:
            continue


  else:

    #Function for passwords with Odd Number length

    for i in range(len(passw)-1):
        
        if i ==0:
      
            continue
        elif i % 2 ==0:
            continue
        else:
            #Character One Processing
            char1 = passw[i]
            char2 = passw[i+1]
            if str(char1) in list(letterbind.keys()):
                part1 = str(letterbind.get(str(char1)))+str(char1)
              
            elif char1 in list(symbindreverse.keys()):
                part1 = symbindreverse.get(char1)+str(char1)

            elif int(char1) in list(digitbind.keys()):
                part1 = str(digitbind.get(int(char1)))+str(char1)
            
            #Character Two Processing

            if str(char2) in list(letterbind.keys()):
                part2 = str(letterbind.get(str(char2)))+str(char2)
                
            elif char2 in list(symbindreverse.keys()):
                part2 = symbindreverse.get(char2)+str(char2)

            elif int(char2) in list(digitbind.keys()):
                part2 = str(digitbind.get(int(char2)))+str(char2)
           
            #Calculating Middle Value
            if str(char1) in list(letterbind.keys()) and str(char2) in list(letterbind.keys()):
                #Middle Value when both are Letters
                if int(letterbind.get(char1)) > int(letterbind.get(char2)):
                    middlevalue = int(letterbind.get(char1)) - int(letterbind.get(char2))
                
                elif int(letterbind.get(char2)) > int(letterbind.get(char1)):
                    middlevalue = int(letterbind.get(char2)) - int(letterbind.get(char1))

                else:
                    middlevalue = int(letterbind.get(char1)) + int(letterbind.get(char2))

            elif char1 in list(symbindreverse.keys()) and char2 in list(symbindreverse.keys()):
                #Middle Value Calculation when both are symbols
                middlevalue = str(symbindreverse.get(char1)) + str(symbindreverse.get(char2))
            
            else:
                middlevalue = str(char1)+str(char2)

            oddfunc1 = str(part1) + str(middlevalue) + str(part2)
            jumbpass.append(oddfunc1)

  d = ""

  finalpass = ""

  for x in jumbpass:
      d = d + x

      d = d[::-1]

  for y in d:
      if str(y) in list(symbind.keys()):
            finalpass = finalpass + str(symbind.get(str(y)))
      else:
            finalpass = finalpass + str(y)

  scram1 = list(finalpass)
  finalcompute = []
  for xyz in scram1:
      if str(xyz) in list(symbindreverse.keys()):
            #If xyz is a symbol
        finalcompute.append(str(xyz)+str(symbindreverse.get(xyz)))

      elif int(xyz) in list(digitbind.keys()):
            # If xyz is a number
            finalcompute.append(str(digitbind.get(int(xyz)+5))+str(xyz)+str(symnumbind.get(int(xyz)+5)))

  return str(finalcompute).removeprefix("[").removesuffix("]").replace("'",'').replace(", ",'')

