from kryptlib.ElGamalImpl import ElGamal, ElGamalCipher
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
from kryptlib import ZKP

class AGHO(ElGamal):
    def __init__(self,eg):
        self.el=eg
        self.pairing=PairingGroup('BN254')
        self.params=self.el.params
    
    def keygen(self,h):
        '''
        generates an AGHO signature keypair
        :param h: the public parameter from G2
        :return: the AGHO keypair
        '''
        v=self.pairing.random(ZR)
        w=[]
        W=[]
        for i in range(0,self.params*2):
            w.append(self.pairing.random(ZR))
            W.append(h**w[i])
        z=self.pairing.random(ZR)
        V=h**v
        Z=h**z
        sk={'v':v, 'w':w, 'z':z}
        pk={'V':V, 'W':W, 'Z':Z}
        return (sk,pk)
    
    def sign(self,g, sk, c,h):
        '''
        signs an encrypted ElGamal vote
        :param g: the public parameter from G1
        :param sk: the secret signing key
        :param c: the encrypted vote
        :param h: the public parameter from G2
        :return: the AGHO keypair
        '''
        r=self.pairing.random(ZR)
        R=g**r
        S=(g**(sk['z']-r*sk['v']))*self.mprod(c,sk['w'])
        T=h**(1/r)
        sig={'R':R, 'S':S,'T': T}
        return (sig,r) 

    def mprod(self,c, w):
        '''
        calculates the product of the encrypted votes power w
        :param c: the encrypted vote
        :param w: the exponent
        :return: the product
        '''
        tmp=1
        for i in range(0, self.params):
            tmp=tmp*(c['c1'][i]**(-w[i]))*(c['c2'][i]**(-w[i+self.params]))
        return tmp

    def verify(self, pk, sig, g, h, cipher):
        '''
        verifies the AGHO signature by checking the verification euquations
        :param pk: the verification key
        :param sig: the AGHO signature
        :param g: the public parameter from G1
        :param h: the public parameter from G2
        :param cipher: the encrypted vote
        :return: result of the verification
        '''
        ve1_1=(self.pairing.pair_prod(sig['R'], pk['V']))
        ve1_2=self.pairing.pair_prod(sig['S'], h)
        ve1_3=self.ciwi_prod(cipher, pk)
        ve1_4=self.pairing.pair_prod(g,pk['Z'])
        ve1=((ve1_1*ve1_2*ve1_3)==ve1_4)
        ve2_1=self.pairing.pair_prod(sig['R'], sig['T'])
        ve2_2=self.pairing.pair_prod(g, h)
        ve2=(ve2_1==ve2_2)
        return (ve1 and ve2)

    def ciwi_prod(self, c, pk):
        '''
        calculates the product of the pairing product from the ciphers and the Wis
        :param c: the encrypted voted
        :param pk: the verification key
        :return: the product
        '''
        tmp=1
        for i in range(0,self.params):
            tmp=tmp*self.pairing.pair_prod(c['c1'][i], pk['W'][i])*self.pairing.pair_prod(c['c2'][i], pk['W'][i+self.params])
        return tmp 