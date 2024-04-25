#------------------------
# Vigenere Cipher
#------------------------

#------------------------

#------------------------


from utilities import get_positions
from utilities import clean_text
from utilities import insert_positions
from utilities import ENGLISH_FREQ
from utilities import compare_texts
import math
from utilities import get_chars
class Cryptanalysis:
    """
    ----------------------------------------------------
    Description: Class That contains cryptanalysis functions
                 Mainly for Vigenere and Shift Cipher 
                     but can be used for other ciphers
    ----------------------------------------------------
    """
    @staticmethod    
    def index_of_coincidence(text,base_type = None):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   text(str)
                      base_type(str): default = None
        Return:       I (float): Index of Coincidence
        Description:  Computes and returns the index of coincidence 
                      Uses English alphabets by default, otherwise, given base_type
        Asserts:      text is a string
        ----------------------------------------------------
        """
        if len(text) < 1:
            return 0.0

        text = text.lower()
        seq = 0.0
        un = get_chars('nonalpha')+' '+'\n'+'\t'
        text = clean_text(text,un)
        l = len(text)
        rrr = (l*l-l)
        for i in range(26):
            x = text.count(chr(97+i))
            seq += (x*(x-1))/rrr
        return seq

    @staticmethod
    def IOC(text):
        """
        ----------------------------------------------------
        Same as Cryptanalysis.index_of_coincidence(text)
        ----------------------------------------------------
        """
        return Cryptanalysis.index_of_coincidence(text)
    
    @staticmethod
    def friedman(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext(str)
        Return:       list of two key lengths [int,int]
        Description:  Uses Friedman's test to compute key length
                      returns best two candidates for key length
                        Best candidates are the floor and ceiling of the value
                          Starts with most probable key, for example: 
                          if friedman = 3.2 --> [3, 4]
                          if friedman = 4.8 --> [5,4]
                          if friedman = 6.5 --> [6, 5]
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        if len(ciphertext) < 1 :
            return [0,0]
        un = get_chars('nonalpha')+' '+'\n'+'\t'
        ciphertext = clean_text(ciphertext,un)
        n = len(ciphertext)
        I = Cryptanalysis.IOC(ciphertext)
        k = (0.0265*n) / ((0.065-I) + (n*I-n*0.0385))
        if round(k) > k:
            return [math.ceil(k),math.floor(k)]
        else:
            return [math.floor(k), math.ceil(k)]


    @staticmethod
    def chi_squared(text,language='English'):

        """
        ----------------------------------------------------
        Parameters:   text (str)
        Return:       result (float)
        Description:  Calculates the Chi-squared statistics 
                      for given text
                      Only alpha characters are considered
        Asserts:      text is a string
        ----------------------------------------------------
        """
        if len(text) == 0:
            return -1.00
        i = len(text)
        j = 0
        while j < i:
            if text[j].isalpha():
                j += 1
                continue
            else:
                text = clean_text(text,text[j])
                i = len(text)
                j += 1
        text = text.upper()
        equation = 0.0
        for i in range(26):
            counter = text.count(chr(65+i))
            f = ((counter - ENGLISH_FREQ[i]*len(text))*(counter - ENGLISH_FREQ[i]*len(text))) / (ENGLISH_FREQ[i]*len(text))
            equation += f
        return equation

    @staticmethod
    def cipher_shifting(ciphertext,args =[20,26]):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
                      args (lsit):
                          max_key_length (int): default = 20
                          factor (int): default = 26
        Return:       Best two key lengths [int,int]
        Description:  Uses Cipher shifting to compute key length
                      returns best two candidates for key length
                      cipher shift factor determines how many shifts should be made
                      Cleans the text from all non-alpha characters before shifting
                      Upper and lower case characters are considered different chars
                      The returned two keys, are the ones that produced highest matches
                          if equal, start with smaller value
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        un = get_chars('nonalpha') + ' ' + '\n' +'\t'
        ciphertext = utilities.clean_text(ciphertext,un)
        shift =  ciphertext
        mostMatches = 0
        max1 = 0
        mostMatchess = 0
        max2 = 0

        for i in range(1,args[1]):
            shift = ' ' + shift[:-1]
            n = compare_texts(ciphertext, shift)
            if i > args[0]:
                x = i % args[0]
            else:
                x = i

            if n > mostMatches:
                mostMatchess = mostMatches
                max2 = max1
                mostMatches = n
                max1 = x
            elif n > mostMatchess:
                mostMatchess = n
                max2 = x
        return [max1,max2]
class Shift:
    """
    ----------------------------------------------------
    Cipher name: Shift Cipher
    Key:         (int,int,int): shifts,start_index,end_index
    Type:        Shift Substitution Cipher
    Description: Generalized version of Caesar cipher
                 Uses a subset of BASE for substitution table
                 Shift base by key and then substitutes
                 Case sensitive
                 Preserves the case whenever possible
                 Uses circular left shift
    ----------------------------------------------------
    """
    BASE = utilities.get_chars('pascii')
    DEFAULT_KEY = (3,26,51) #lower case Caesar cipher
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (int,int,int): 
                        #shifts, start_index, end_indx 
                        (inclusive both ends of indices)
        Description:  Shift constructor
                      sets _key
        ---------------------------------------------------
        """
        if self.valid_key(key):
            self._key = key
        else:
            self._key = self.DEFAULT_KEY
            #maybe we just take one of tuple to default


    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str)
        Description:  Returns a copy of the Shift key
        ---------------------------------------------------
        """
        return self._key

    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Shift cipher key to given key
                      #shifts is set to smallest value
                      if invalid key --> set to default key
        ---------------------------------------------------
        """
        if self.valid_key(key):
            self._key = key
            if key[0] < 0:
                self._key = (key[2]-key[1]+key[0]+1, key[1], key[2])
            return True
        else:
            self._key = self.DEFAULT_KEY
        return False

    def get_base(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       base (str)
        Description:  Returns a copy of the base characters
                      base is the subset of characters from BASE
                      starting at start_index and ending with end_index
                      (inclusive both ends)
        ---------------------------------------------------
        """
        return self.BASE[self._key[1]:self._key[2]+1]

    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Shift object. Used for testing
                      output format:
                      Shift Cipher:
                      key = <key>
                      base = <base>
                      sub  = <sub>
        ---------------------------------------------------
        """
        sub = ''
        i = 0
        l = len(self.get_base())
        while i < l:
            sub += self.get_base()[(self._key[0]+i)%l]
            i+=1
        return 'Shift Cipher:\nkey = {}\nbase = {}\nsub  = {}'.format(self._key,self.get_base(),sub)
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Shift key
                      A valid key is a tuple consisting of three integers
                          shifts, start_index, end_index
                      The shifts can be any integer
                      The start and end index should be positive values
                      such that start is smaller than end and both are within BASE
        ---------------------------------------------------
        """
        if type(key) == tuple and len(key) == 3:
            if type(key[0]) == int and type(key[1]) == int and type(key[2]) == int:
                if 0 <= key[1] < key[2] and key[2] > 0:
                    l = len(Shift.BASE)
                    if key[2] < l:
                        return True
        return False

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Shift Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        sub = ''
        i = 0
        l = len(self.get_base())
        while i < l:
            sub += self.get_base()[(self._key[0] + i) % l]
            i += 1
        ciphertext = ''
        for j in range(len(plaintext)):
            if self.get_base().find(plaintext[j]) == -1:
                ciphertext += plaintext[j]
                continue
            ciphertext += sub[self.get_base().index(plaintext[j])]

        return ciphertext

    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Shift Cipher
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        self._key = (self._key[2]-self._key[1]-self._key[0]+1, self._key[1], self._key[2])
        plaintext = self.encrypt(ciphertext)
        self._key = (self._key[2]-self._key[1]-self._key[0]+1, self._key[1], self._key[2])
        return plaintext

    @staticmethod
    def cryptanalyze(ciphertext,args=['',-1,-1]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                            base: (str): default = ''
                            shifts: (int): default = -1
                            base_length (int): default = -1
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the Chi-square method
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """
        un = ' ' + '\n' + '\t'
        position = get_positions(ciphertext,un)
        ciphertext = clean_text(ciphertext,un)
        tst = Shift()
        st = 0
        ed = 0
        plain = ''
        ret_plain = ''
        minichi = 0
        k = (0,0,0)
        # Base & #shift
        if args[0] != '' and args[1] != -1:
            st = Shift.BASE.index(args[0][0])
            ed = Shift.BASE.index(args[0][len(args[0])-1])
            key = (args[1],st,ed)
            tst.set_key(key)
            plain = tst.decrypt(ciphertext)
            return key,insert_positions(plain,position)
        # base
        elif args[0] != '':
            st = Shift.BASE.index(args[0][0])
            ed = Shift.BASE.index(args[0][len(args[0]) - 1])
            minichi = Cryptanalysis.chi_squared(ciphertext)
            for i in range(1,ed-st-1):
                key = (i,st,ed)
                tst.set_key(key)
                plain = tst.decrypt(ciphertext)
                x = Cryptanalysis.chi_squared(plain)
                if  x < minichi:
                    minichi = x
                    k = (i,st,ed)
                    ret_plain = plain
            return k, insert_positions(ret_plain,position)
        # shift and l
        elif args[1] != -1:
            key = (0,0,0)
            minichi = Cryptanalysis.chi_squared(ciphertext)
            for i in range(len(Shift.BASE)):
                key = (args[1], 0+i, args[2]+i-1)
                tst.set_key(key)
                plain = tst.decrypt(ciphertext)
                x = Cryptanalysis.chi_squared(plain)
                if x < minichi:
                    minichi = x
                    k = key
                    ret_plain = plain
            return k , insert_positions(ret_plain,position)
        # only l
        elif args[2] != -1:
            minichi = Cryptanalysis.chi_squared(ciphertext)
            for i in range(len(Shift.BASE)):
                for j in range(1,args[2]-1):
                    key = (j,0+i,args[2]+i-1)
                    tst.set_key(key)
                    plain = tst.decrypt(ciphertext)
                    x = Cryptanalysis.chi_squared(plain)
                    if x < minichi:
                        ret_plain = plain
                        k = key
                        minichi = x
            return k , insert_positions(ret_plain,position)
        # else
        else :
            return '',''

class Vigenere:
    """
    ----------------------------------------------------
    Cipher name: Vigenere Cipher
    Key:         (str): a character or a keyword
    Type:        Polyalphabetic Substitution Cipher
    Description: if key is a single characters, uses autokey method
                    Otherwise, it uses a running key
                 In autokey: key = autokey + plaintext (except last char)
                 In running key: repeat the key
                 Substitutes only alpha characters (both upper and lower)
                 Preserves the case of characters
    ----------------------------------------------------
    """
    
    DEFAULT_KEY = 'k'
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (str): default value: 'k'
        Description:  Vigenere constructor
                      sets _key
                      if invalid key, set to default key
        ---------------------------------------------------
        """
        if self.valid_key(key):
            self.set_key(key)
        else:
            self._key = self.DEFAULT_KEY
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str)
        Description:  Returns a copy of the Vigenere key
        ---------------------------------------------------
        """
        # your code here
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Vigenere cipher key to given key
                      All non-alpha characters are removed from the key
                      key is converted to lower case
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if self.valid_key(key):
            if key.isalpha() and key.islower():
                self._key = key
            else:
                k = ''
                for i in range(len(key)):
                    if key[i].islower() and key[i].isalpha():
                        k += key[i]
                    elif key[i].isalpha():
                        k += key[i].lower()
                    else:
                        continue
                self._key=k
            return True
        else:
            self._key = self.DEFAULT_KEY
            return False
    
    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Vigenere object. Used for testing
                      output format:
                      Vigenere Cipher:
                      key = <key>
        ---------------------------------------------------
        """

        return 'Vigenere Cipher:\nkey = {}'.format(self.get_key())
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Vigenere key
                      A valid key is a string composing of at least one alpha char
        ---------------------------------------------------
        """
        if type(key) == str:
            if len(key) >= 1:
                if key.isalpha():
                    return True
                else:
                    for i in range(len(key)):
                        if key[i].isalpha():
                            return True
        return False

    @staticmethod
    def get_square():
        """
        ----------------------------------------------------
        static method
        Parameters:   -
        Return:       vigenere_square (list of string)
        Description:  Constructs and returns vigenere square
                      The square contains a list of strings
                      element 1 = "abcde...xyz"
                      element 2 = "bcde...xyza" (1 shift to left)
        ---------------------------------------------------
        """
        alphab = get_chars('lower')
        tbl = []
        sh = Shift()
        st = Shift.BASE.index(alphab[0])
        ed = Shift.BASE.index(alphab[len(alphab)-1])
        for i in range(26):
            sh.set_key((i,st,ed))
            tbl.append(sh.encrypt(alphab))
        return tbl

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) == str, 'invalid plaintext'
        
        if len(self._key) == 1:
            return self._encrypt_auto(plaintext)
        else:
            return self._encrypt_run(plaintext)

    def _encrypt_auto(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using an autokey
        ---------------------------------------------------
        """
        un = get_chars('nonalpha') + ' '
        position = get_positions(plaintext,un)
        plaintext = clean_text(plaintext,un)
        ciphertext = ''
        base = get_chars('lower')
        for i in range(len(plaintext)-1):
            if plaintext[i].isupper():
                ciphertext += base[(base.index(plaintext[i].lower()) + base.index(self._key)) % len(base)].upper()
            else:
                ciphertext+=base[(base.index(plaintext[i]) + base.index(self._key)) % len(base)]
        ciphertext = insert_positions(ciphertext,position)
        return ciphertext

    def _encrypt_run(self, plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using a running key
        ---------------------------------------------------
        """
        alphab = get_chars('lower')
        k = self._key
        k_l = len(k)
        ciphertext = ''
        j = 0
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                cindex = alphab.index(plaintext[i].lower())
                kk = k[j%k_l]
                j+=1
                key_s = alphab.index(kk)
                encrypt = (cindex + key_s) % 26
                encryptc = alphab[encrypt]
                if plaintext[i].isupper():
                    ciphertext += encryptc.upper()
                else:
                    ciphertext += encryptc
            else:
                ciphertext += plaintext[i]
        return ciphertext
    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) == str, 'invalid input'
        
        if len(self._key) == 1:
            return self._decryption_auto(ciphertext)
        else:
            return self._decryption_run(ciphertext)

    def _decryption_auto(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using autokey
        ---------------------------------------------------
        """
        un = get_chars('nonalpha') + ' '
        position = get_positions(ciphertext, un)
        ciphertext = clean_text(ciphertext, un)
        plaintext = ''
        base = get_chars('lower')
        for i in range(len(plaintext) - 1):
            if ciphertext[i].isupper():
                plaintext += base[(base.index(ciphertext[i].lower()) - base.index(self._key)) % len(base)].upper()
            else:
                plaintext += base[(base.index(ciphertext[i]) - base.index(self._key)) % len(base)]
        plaintext = insert_positions(plaintext, position)
        return plaintext

    def _decryption_run(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using running key
        ---------------------------------------------------
        """
        alphab = get_chars('lower')
        k = self._key
        k_l = len(k)
        plain = ''
        j = 0
        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                cindex = alphab.index(ciphertext[i].lower())
                kk = k[j % k_l]
                j += 1
                key_s = alphab.index(kk)
                encrypt = (cindex - key_s) % 26
                encryptc = alphab[encrypt]
                if ciphertext[i].isupper():
                    plain += encryptc.upper()
                else:
                    plain += encryptc
            else:
                plain += ciphertext[i]
        return plain
    @staticmethod
    def cryptanalyze_key_length(ciphertext):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   ciphertext (str)
        Return:       key_lenghts (list)
        Description:  Finds key length for Vigenere Cipher
                      Combines results of Friedman and Cipher Shifting
                      Produces a list of key lengths from the above two functions
                      Start with Friedman and removes duplicates
        ---------------------------------------------------
        """
        #your code here
        return []

    @staticmethod
    def cryptanalyze(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the key lengths produced by Vigenere.cryptanalyze_key_length
                      Finds out the key, then apply chi_squared
                      The key with the lowest chi_squared value is returned
        Asserts:      ciphertext is a non-empty string
        ---------------------------------------------------
        """
        #your code here
        return '',''
