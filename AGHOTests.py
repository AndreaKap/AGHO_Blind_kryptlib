from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from ElGamalImpl import ElGamal
from AGHOSignature import AGHO
from AGHOBlind import AGHOBlind
import unittest

class AGHOSignature(unittest.TestCase):
    def testAGHO_oneParam(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testitest")
        el = ElGamal(params) 
        agho=AGHO(el)
        h=groupObj.random(G2)
        (pk_EV, sk_EV) = el.keygen()
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (sig, r)=agho.sign(pk_EV['g'],sk_sig,c,h)
        vf=agho.verify(pk_sig, sig, pk_EV['g'], h, c)
        assert(vf)
        print("AGHO Signature Test Result with one parameter:",vf)
    def testAGHO_moreParams(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        msg.append("testitest")
        msg.append("weiblich")
        el = ElGamal(params) 
        agho=AGHO(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (sig, r)=agho.sign(pk_EV['g'], sk_sig, c, h)
        vf=agho.verify(pk_sig, sig, pk_EV['g'],h,c)
        assert(vf)
        print("AGHO Signature Test Result with more parameters:",vf)
class AGHOBlindTest(unittest.TestCase):
    def testAGHOBlind_oneParameter(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testitest")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        h=groupObj.random(G2)
        (pk_EV, sk_EV) = el.keygen()
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (sig_bar,z1,z2, r)=agho.sign(pk_EV['g'],sk_sig,c_bar,h,G,P_bar)
        sig=agho.deblindSig(sig_bar,e,f1+f2)
        vf=agho.verify(pk_sig, sig, pk_EV['g'], h, c)
        assert(vf)
        print("AGHOBlind Test Result with one parameter:",vf)
    def testAGHOmoreComponents(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        msg.append("testitest")
        msg.append("weiblich")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (sig_bar,z1,z2, r)=agho.sign(pk_EV['g'],sk_sig,c_bar,h,G,P_bar)
        sig=agho.deblindSig(sig_bar,e,f1+f2)
        vf=agho.verify(pk_sig, sig, pk_EV['g'], h, c)
        assert(vf)
        print("AGHOBlind Test Result with more parameters:",vf)
if __name__ == "__main__":
    unittest.main()