
from kryptlib.ElGamalImpl import ElGamal
from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
import unittest
from kryptlib.AGHOBlind import AGHOBlind
class ZKPTest(unittest.TestCase):
    def testZKPG1(self):
        groupObj=PairingGroup('BN254')
        params=1
        el = ElGamal(params) 
        (pk, sk)=el.keygen()
        (ch,r)=self.ZKP_exponentG1(pk['g'],sk['x'], pk['vk'])
        isTrue=self.ZKP_exponentG1_verify(ch,r, pk['vk'],pk['g'])
        print("Single exponent ZKP proof in G1", isTrue)
    
    def testZKPG2(self):
        groupObj=PairingGroup('BN254')
        params=1
        el = ElGamal(params) 
        agho = AGHOBlind(el) 
        h=groupObj.random(G2)
        (sk, pk)=agho.keygen(h)
        (ch,r)=self.ZKP_exponentG2(h,sk['v'], pk['V'])
        isTrue=self.ZKP_exponentG2_verify(ch,r, pk['V'],h)
        print("Single exponent ZKP proof in G2", isTrue)
    
    def testZKPGT(self):
        groupObj=PairingGroup('BN254')
        params=1
        el = ElGamal(params) 
        agho = AGHOBlind(el) 
        h=groupObj.random(G2)
        g=groupObj.random(G1)
        (sk, pk)=agho.keygen(h)
        (ch,r)=self.ZKP_exponentGT(h,sk['v'], pk['V'],g)
        isTrue=self.ZKP_exponentGT_verify(ch,r, pk['V'],h,g)
        print("Single exponent ZKP proof in GT", isTrue)
    
    def ZKP_exponentG1(self,g, sk, pk):
        group=PairingGroup('BN254')
        nu=group.random(ZR)
        N=g**nu
        ch=group.hash(str(N).encode('utf-8'),ZR)
        r=ch*sk+nu
        return (ch,r)
    
    def ZKP_exponentG1_verify(self,ch,r,pk,g):
        group=PairingGroup('BN254')
        N=(g**r)*(pk**(-ch))
        return ch==group.hash(str(N).encode('utf-8'),ZR)
    
    def ZKP_exponentG2(self,h, sk, pk):
        group=PairingGroup('BN254')
        nu=group.random(ZR)
        N=h**nu
        ch=group.hash(group.serialize(N),ZR)
        r=ch*sk+nu
        return (ch,r)
    
    def ZKP_exponentG2_verify(self,ch,r,pk,h):
        group=PairingGroup('BN254')
        N=(h**r)*(pk**(-ch))
        return ch==group.hash(group.serialize(N),ZR)
    
    def ZKP_exponentGT(self,h, sk, pk,g):
        group=PairingGroup('BN254')
        nu=group.random(ZR)
        N=h**nu
        N2=group.pair_prod(g,N)
        ch=group.hash(group.serialize(N2),ZR)
        r=ch*sk+nu
        return (ch,r)
    
    def ZKP_exponentGT_verify(self,ch,r,pk,h,g):
        group=PairingGroup('BN254')
        N=group.pair_prod(g,(h**r)*(pk**(-ch)))
        return ch==group.hash(group.serialize(N),ZR)

class PairingTest(unittest.TestCase):
    def testPairingBilinearity1(self):
        groupObj=PairingGroup('BN254')
        isLin1=True
        for i in range(0,10):
            g1=groupObj.random(G1)
            g2=groupObj.random(G1)
            h1=groupObj.random(G2)
            isLin1=isLin1 and (groupObj.pair_prod(g1*g2, h1)==(groupObj.pair_prod(g1, h1)*groupObj.pair_prod(g2, h1)))
        print("Linearity in 1st Argument:", isLin1)
    
    def testPairingBilinearity2(self):
        groupObj=PairingGroup('BN254')
        isLin2=True
        for i in range(0,10):
            g1=groupObj.random(G1)
            h1=groupObj.random(G2)
            h2=groupObj.random(G2)
            isLin2=isLin2 and(groupObj.pair_prod(g1, h1*h2)==(groupObj.pair_prod(g1, h1)*groupObj.pair_prod(g1, h2)))
        print("Linearity in 2nd Argument:", isLin2)      
    
    def testScalarMultiplication1(self):
        groupObj=PairingGroup('BN254')
        isScalar1=True
        for i in range(0,10):
            k=groupObj.random(ZR)
            g=groupObj.random(G1)
            h=groupObj.random(G2)
            isScalar1=isScalar1 and (groupObj.pair_prod(g**k, h)==groupObj.pair_prod(g, h)**k)
        print("Scalar multiplication in 1st Argument:", isScalar1)
    
    def testScalarMultiplication2(self):
        groupObj=PairingGroup('BN254')
        isScalar2=True
        for i in range(0,10):
            k=groupObj.random(ZR)
            g=groupObj.random(G1)
            h=groupObj.random(G2)
            isScalar2=isScalar2 and (groupObj.pair_prod(g, h**k)==groupObj.pair_prod(g, h)**k)
        print("Scalar multiplication in 2nd Argument:", isScalar2)
    
    def testScalarMultiplication3(self):
        groupObj=PairingGroup('BN254')
        isScalarBoth=True
        for i in range(0,10):
            k=groupObj.random(ZR)
            g=groupObj.random(G1)
            h=groupObj.random(G2)
            isScalarBoth=isScalarBoth and (groupObj.pair_prod(g, h**k)==groupObj.pair_prod(g**k, h))
        print("Scalar multiplication in both Arguments:", isScalarBoth)
    
    def testExponentiation1(self):
        groupObj=PairingGroup('BN254')
        expoG1_1=True
        for i in range(0,10):
            k1=groupObj.random(ZR)
            k2=groupObj.random(ZR)
            g=groupObj.random(G1)
            expoG1_1=expoG1_1 and (g**(k1+k2)==(g**k1)*(g**k2)) 
        print("Exponentiation equation (g**(k1+k2)==(g**k1)*(g**k2)) in G1", expoG1_1)    
    
    def testExponentiation2(self):
        groupObj=PairingGroup('BN254')
        expoG1_2=True
        for i in range(0,10):
            k1=groupObj.random(ZR)
            k2=groupObj.random(ZR)
            g=groupObj.random(G1)
            expoG1_2=expoG1_2 and (g**(k1*k2)==(g**k1)**k2) 
        print("Exponentiation equation (g**(k1*k2)==(g**k1)**k2) in G1", expoG1_2)    
    
    def testExponentiation3(self):
        groupObj=PairingGroup('BN254')
        expoG2_1=True
        for i in range(0,10):
            k1=groupObj.random(ZR)
            k2=groupObj.random(ZR)
            h=groupObj.random(G2)
            expoG2_1=expoG2_1 and (h**(k1+k2)==(h**k1)*(h**k2)) 
        print("Exponentiation equation (h**(k1+k2)==(h**k1)*(h**k2)) in G2", expoG2_1)       
    
    def testExponentiation4(self):
        groupObj=PairingGroup('BN254')
        expoG2_2=True
        for i in range(0,10):
            k1=groupObj.random(ZR)
            k2=groupObj.random(ZR)
            h=groupObj.random(G2)
            expoG2_2=expoG2_2 and (h**(k1*k2)==(h**k1)**k2) 
        print("Exponentiation equation (h**(k1*k2)==(h**k1)**k2)  in G2", expoG2_2)  
    
    def testSerializationG1(self):
        groupObj=PairingGroup('BN254')
        for i in range(0,10):
            g=groupObj.random(G1)
            l=groupObj.serialize(g).decode('utf-8')
            m=groupObj.deserialize(l.encode('utf-8'))
        print("Serialization Test Result G1", m==g)  

    def testSerializationG2(self):
        groupObj=PairingGroup('BN254')
        for i in range(0,10):
            g=groupObj.random(G2)
            l=groupObj.serialize(g).decode('utf-8')
            m=groupObj.deserialize(l.encode('utf-8'))
        print("Serialization Test Result G2", m==g)  

if __name__ == "__main__":
    unittest.main()