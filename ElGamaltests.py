from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from kryptlib.ElGamalImpl import ElGamal
import unittest
class ElGamalTest(unittest.TestCase):
    def testElGamalEncryptionDecryption_oneParameter(self):
        groupObj=PairingGroup('BN254')
        params=1
        el = ElGamal(1) 
        (pk, sk) = el.keygen()
        g=groupObj.random(G1)
        msg=[]
        msg.append("the hello world msg1")
        attrs=[[]]
        attrs[0].append("theasd hello world msg1")
        attrs[0].append("the hello world msg1")
        (cipher1,o) = el.encrypt(pk, msg)
        m = el.decrypt(pk, sk, cipher1, attrs) 
        assert(m==msg)
        print("ElGamal_Result one parameter:",m==msg)  
    def testElGamalEncryptionDecryption_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=3
        msg=[]
        attrs=[]
        attrsVote=[]
        attrsSex=[]
        attrsAge=[]
        msg.append("28")
        msg.append("weiblich")
        msg.append("Kandidat1")
        attrsVote.append("Kandidat1")
        attrsVote.append("Kandidat2")
        attrsVote.append("Kandidat3")
        attrsSex.append("männlich")
        attrsSex.append("weiblich")
        attrsAge.append("25")
        attrsAge.append("26")
        attrsAge.append("27")
        attrsAge.append("28")
        attrs.append(attrsAge)
        attrs.append(attrsSex)
        attrs.append(attrsVote)
        el = ElGamal(params) 
        (pk, sk) = el.keygen()
        (c,o) = el.encrypt(pk, msg)
        m = el.decrypt(pk, sk, c, attrs)  
        assert(m==msg) 
        print("ElGamal_Result more parameters:",m==msg)
if __name__ == "__main__":
    unittest.main()