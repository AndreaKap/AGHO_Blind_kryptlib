from kryptlib.ElGamalImpl import ElGamal, ElGamalCipher
from charm.toolbox.pairinggroup import PairingGroup, G1, ZR
from kryptlib import ZKP

class AGHOBlind(ElGamal):
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

    def blind(self,vote,g):
        '''
        blinds the EV and calculates all needed parameters
        signs an encrypted ElGamal vote
        :param vote:  the encrypted vote
        :param g: the public parameter from G1
        :return: the blinded vote, the binded pad, G, e and the random decompositition f1, f2
        '''
        #blind Vote
        P1=[]
        P2=[]
        c1_bar=[]
        c2_bar=[]
        P1_bar=[]
        P2_bar=[]
        for i in range(0,self.params):
            P1.append(self.pairing.random(G1))
            P2.append(self.pairing.random(G1))
        P={'P1': P1, 'P2': P2}
        for i in range(0,self.params):
            c1_bar.append((vote['c1'][i])* (P['P1'][i]**(-1)))
            c2_bar.append((vote['c2'][i])* (P['P2'][i]**(-1)))
        c_bar={'c1_bar':c1_bar, 'c2_bar':c2_bar}
        #blind Pad
        e=self.pairing.random(ZR)
        f=self.pairing.random(ZR)
        (f1,f2)=self.randdecomp(f)
        for i in range(0,self.params):
            P1_bar.append(P['P1'][i]**e)
            P2_bar.append(P['P2'][i]**e)
        P_bar={'P1_bar':P1_bar, 'P2_bar':P2_bar}
        #calculate G
        G={'G1':g**e, 'G2':g**(f1), 'G3':g**(e*f2)}
        return (c_bar, P_bar, G, e, f1, f2)    

    def sign(self,g, sk, c_bar,h, G, P_bar):
        '''
        signs a blinded EV
        :param g: the public parameter from G1
        :param sk: the secret signing key
        :param c_bar: the blinded encrypted vote
        :param h: the public parameter from G2
        :param G: the client side signature randomness
        :param P_bar: the blinded Pad
        :return: the AGHO blind signature
        '''
        r=self.pairing.random(ZR)
        (z1,z2)=self.randdecomp(sk['z'])
        R_bar=g**r
        S1_bar=(g**z1)*(G['G2']**(-(r*sk['v'])))*self.mprod(c_bar,sk['w'])
        S2_bar=(G['G1']**z2)*(G['G3']**((-r)*sk['v']))*self.pprod(P_bar, sk['w'])
        T_bar=h**(1/r)
        sig={'R_bar':R_bar, 'S1_bar':S1_bar, 'S2_bar':S2_bar,'T_bar': T_bar}
        return (sig,z1, z2,r) 

    def mprod(self,c_bar, w):
        '''
        calculates the product of the encrypted votes power w
        :param c_bar: the blinded EV
        :param w: the exponent
        :return: the product
        '''
        tmp=1
        for i in range(0, self.params):
            tmp=tmp*(c_bar['c1_bar'][i]**(-w[i]))*(c_bar['c2_bar'][i]**(-w[i+self.params]))
        return tmp

    def pprod(self,P_bar, w):
        '''
        calculates the product of the blinded pads power w
        :param P_bar: the blinded pad
        :param w: the exponent
        :return: the product
        '''
        tmp=1
        for i in range(0, self.params):
            tmp=tmp*(P_bar['P1_bar'][i]**(-w[i]))*(P_bar['P2_bar'][i]**(-w[i+self.params]))
        return tmp

    def deblindSig(self, sig_bar, e, f):
        '''
        deblinds the signature received from the server
        :param sig_bar: the blinded signature
        :param e: the secret exponent for blinding the pad
        :param f: the secret client side siganture randomness
        :return: the deblinded signature
        '''
        R=sig_bar['R_bar']**f
        S=sig_bar['S1_bar']*(sig_bar['S2_bar']**(1/e))
        T=sig_bar['T_bar']**(1/f)
        sig={'R':R, 'S':S, 'T':T}
        return sig

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
        ve1_4=ve1_4=self.pairing.pair_prod(g,pk['Z'])
        ve1=(ve1_1*ve1_2*ve1_3==ve1_4)
        ve2_1=self.pairing.pair_prod(sig['R'], sig['T'])
        ve2_2=self.pairing.pair_prod(g, h)
        ve2=(ve2_1==ve2_2)
        return (ve1 and ve2)

    def randdecomp(self,f):
        '''
        creates a random decomposition of a value f in ZR
        :param f: the value to be decomposed
        :return: the decomposition
        '''
        f1=self.pairing.random(ZR)
        f2=f-f1
        return (f1,f2)

    def ciwi_prod(self, c, pk):
        '''
        calculates the product of the pairing product from the ciphers and the Wis
        :param c: the encrypted voted
        :param pk: the verification key
        :return: the product
        '''
        tmp=1
        for i in range(0,self.params):
            tmp=tmp*self.pairing.pair_prod(c['c1'][i], pk['W'][i])*self.pairing.pair_prod(c['c2'][i], pk['W'][self.params+i])
        return tmp
    
    def ZKPU(self,g,P_bar,pk,o,e,G,f1,f2):
        '''
        calculates the ZKP for the correct format of the blinded EV
        :param g: the public parameter from G1
        :param P_bar: the blinded pad
        :param pk: the verification key
        :param o: the secret client side encryption randomness
        :param e: secret parameter for pad blinding
        :param G: the client side signature randomness
        :param f1: first part of the random decomposition of the secret client signature parameter
        :param f2: second part of the random decomposition of the secret client signature parameter
        :return: the ZKP parameters challenge and response
        '''
        (ch,r)=ZKP.ZKP_correctFormatU(g,P_bar,pk,o,e,G,f1,f2,self.params)
        return (ch,r)
        
    def ZKPU_verify(self, ch, G, r, c_bar, P_bar, m, pk, g):
        '''
        verifies a ZKP for the correct format of a vote
        :param ch: the challenge
        :param G: the client side signing randomness 
        :param r: the response
        :param c_bar: the blinded EV
        :param P_bar: the blinded pad
        :param m: the message (public attributes)
        :param pk: the public encryption key
        :param g: the public parameter from G1
        :return: the result of the verification
        '''
        return ZKP.verifyZKP_FormatU(ch,G,r,c_bar,P_bar,m,pk,g,self.params)

    def ZKPS(self,h,g,sig,pk,G,c_bar, sk, z1, z2, ri, P_bar):
        '''
        calculates the ZKP for the correct format of the signature
        :param h: the public parameter from G2
        :param g: the public parameter from G1
        :param sig: the signature  
        :param pk: the verification key
        :param G: the client side signature randomness
        :param c_bar: the blinded EV
        :param sk: the secret signature key
        :param z1: first part of the random decomposition of the secret signature parameter
        :param z2: second part of the random decomposition of the secret signature parameter
        :param ri: the server side signature randomness
        :param P_bar: the blinded pad
        :return: the ZKP parameters challenge and response
        '''
        (ch,r)=ZKP.ZKP_correctFormatS(h,g,sig,pk,G,c_bar,sk,z1,z2,ri,P_bar, self.params)
        return (ch,r)

    def ZKPS_verify(self,h,g,pk,ch,r,c_bar,P_bar, G, sig):
        '''
        verifies a ZKP for the correct format of a signature
        :param h: the public parameter from G2
        :param g: the public parameter from G1
        :param pk: the verification key
        :param ch: the challenge
        :param r: the response
        :param c_bar: the blinded EV
        :param P_bar: the blinded pad
        :param G: the client side signature randomness
        :param sig: the signature
        :return: the result of the verification
        '''
        return ZKP.verifyZKP_FormatS(h,g,pk,ch,r,c_bar,P_bar,G,sig, self.params)