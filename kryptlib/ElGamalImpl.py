from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from kryptlib import ZKP
#https://github.com/JHUISI/charm
debug = False
class ElGamalCipher(dict):
    def __init__(self, ct):
        if type(ct) != dict: assert False, "Not a dictionary!"
        if not set(ct).issubset(['c1', 'c2']): assert False, "'c1','c2' keys not present."
        dict.__init__(self, ct)

    def __add__(self, other):
        if type(other) == int:
           lhs_c1 = dict.__getitem__(self, 'c1')
           lhs_c2 = dict.__getitem__(self, 'c2')
           return ElGamalCipher({'c1':lhs_c1, 'c2':lhs_c2 + other})
        else:
           pass 

    def __mul__(self, other):
        if type(other) == int:
           lhs_c1 = dict.__getitem__(self, 'c1')
           lhs_c2 = dict.__getitem__(self, 'c2')
           return ElGamalCipher({'c1':lhs_c1, 'c2':lhs_c2 * other})
        else:
           lhs_c1 = dict.__getitem__(self, 'c1') 
           rhs_c1 = dict.__getitem__(other, 'c1')

           lhs_c2 = dict.__getitem__(self, 'c2') 
           rhs_c2 = dict.__getitem__(other, 'c2')
           return ElGamalCipher({'c1':lhs_c1 * rhs_c1, 'c2':lhs_c2 * rhs_c2})
        return None

class ElGamal(PKEnc):
    def __init__(self, par,p=0):
        '''
        initializes an ElGamal object with the number of parameters and the pairing group
        '''
        PKEnc.__init__(self)
        global group
        self.params=par
        group = PairingGroup('BN254')

    def keygen(self, secparam=1024):
        '''
        generates an ElGamal encryption keypair and returns it
        :return: the keypair
        '''
        g = group.random(G1)
        x = group.random(); vk = g ** x
        pk = {'g':g, 'vk':vk }
        sk = {'x':x}
        return (pk, sk)
    
    def encrypt(self, pk, m):
        '''
        ElGamal encrypts a vote
        :param pk: public encryption key
        :param m: the message
        :return: the encrypted vote
        '''
        o=[]
        c1=[]
        s=[]
        c2=[]
        for i in range(0,self.params):
            o.append(group.random(ZR))
            c1.append( pk['g'] ** o[i])
            s.append( pk['vk'] ** o[i])
            c2.append(self.encode(m[i]) * s[i])
        return (ElGamalCipher({'c1':c1, 'c2':c2}),o)
    
    def encode(self, message):
        '''
        encodes a message (string --> pairing.Element)
        :param message: the message
        :return: the encoded message
        '''
        h=group.hash(message,G1)
        return h

    def generateLookupTable(self, attributePossibilities):
        '''
        generates a lookup table for the plaintexts
        :param attributePossibilities: list of possible strings
        :return: the lookup table
        '''
        table=[]
        for i in range(0,len(attributePossibilities)):
            table.append(group.hash(attributePossibilities[i],G1))
        return table 

    def lookup(self,message, attributePossibilities):
        '''
        searches for the right string matching the point on the EC
        :param message: the decrypted message
        :param attriibutePossibilities: list of possible strings
        :return: returns the matching string
        '''
        table=self.generateLookupTable(attributePossibilities)
        for i in range(0,len(table)):
            if(table[i]==message):
                return attributePossibilities[i]
        return -1

    def decrypt(self, pk, sk, c, attributePossibilities):
        '''
        decrypts the EV
        :param pk: the public encryption key
        :param sk: the secret decryption key
        :param c: the encrypted vote
        :param attributePossibilities: list of possible strings
        :return: the decrypted vote
        '''
        s=[]
        m=[]
        M=[]
        for i in range(0, self.params):
            s.append( c['c1'][i] ** sk['x'])
            m.append( c['c2'][i] * (s[i] ** -1) )
            M.append(self.decode(m[i], attributePossibilities[i]))
        return M

    def decode(self,message, attributePossibilities):
        '''
        decoding a vote (pairing.Element -> string)
        :param message: the message
        :param attributePossiblities: list of possible strings
        :return: the decoded message
        '''
        return self.lookup(message, attributePossibilities)

    def ZKPsk(self,c,g,sk):
        '''
        calcualtion of the ZKP for the correct encryption
        :param c: the encrypted vote
        :param g: the public parameter from G1
        :param sk: the secred decryption key
        :return: the calculated challenge and the response
        '''
        return ZKP.ZKP_correctVote(c,g,sk,self.params)

    def ZKPsk_verify(self,c,m,pk,ch,r,g):
        '''
        verification of the correct decryption ZKP
        :param c: the encrypted vote
        :param m: the public attributes
        :param pk: the public encryption key
        :param ch: the challenge
        :param r: the response
        :param g: the public parameter from G1
        :return: the verification result
        '''
        return ZKP.verifyZKP_correctVote(c,m,pk,ch,r,g,self.params)