from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from kryptlib.ElGamalImpl import ElGamal
from kryptlib.AGHOSignature import AGHO
from kryptlib.AGHOBlind import AGHOBlind
from kryptlib import ZKP
import unittest

class ZKPTest(unittest.TestCase):
    def testZKPU_oneParameter(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testmessage")
        msg_zkp=[]
        for i in range(0,params-1):
            msg_zkp.append(msg[i])
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (ch,r)=ZKP.ZKP_correctFormatU(pk_EV['g'],P_bar,pk_EV,o,e,G,f1,f2,params)
        isCorrect=ZKP.verifyZKP_FormatU(ch,G,r,c_bar,P_bar,msg_zkp,pk_EV,pk_EV['g'],params)
        assert(isCorrect)
        print("ZKPU Test Result with one parameter:", isCorrect)
    
    def testZKPU_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        msg.append("testmessage")
        msg.append("female")
        msg_zkp=[]
        for i in range(0,params-1):
            msg_zkp.append(msg[i])
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (ch,r)=ZKP.ZKP_correctFormatU(pk_EV['g'],P_bar,pk_EV,o,e,G,f1,f2,params)
        isCorrect=ZKP.verifyZKP_FormatU(ch,G,r,c_bar,P_bar,msg_zkp,pk_EV,pk_EV['g'],params)
        assert(isCorrect)
        print("ZKPU Test Result with more parameters:", isCorrect)
    
    def testZKPUInAGHOLib_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        msg.append("testmessage")
        msg.append("female")
        msg_zkp=[]
        for i in range(0,params-1):
            msg_zkp.append(msg[i])
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (ch,r)=agho.ZKPU(pk_EV['g'],P_bar,pk_EV,o,e,G,f1,f2)
        isCorrect=agho.ZKPU_verify(ch,G,r,c_bar,P_bar,msg_zkp,pk_EV,pk_EV['g'])
        assert(isCorrect)
        print("ZKPU Test Result from library with more parameters:", isCorrect)

    def testZKPS_oneParameter(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testmessage")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (sig_bar, z1, z2, ri)=agho.sign(pk_EV['g'],sk_sig,c_bar,h,G,P_bar)
        (ch,r)=ZKP.ZKP_correctFormatS(h,pk_EV['g'],sig_bar,pk_sig, G, c_bar, sk_sig, z1, z2,ri, P_bar, params)
        isCorrect=ZKP.verifyZKP_FormatS(h,pk_EV['g'],pk_sig,ch,r,c_bar,P_bar,G,sig_bar, params)
        print("ZKPS Test Result with one Parameter:", isCorrect)
    
    def testZKPS_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testmessage")
        msg.append("female")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (sig_bar,z1,z2, ri)=agho.sign(pk_EV['g'],sk_sig,c_bar,h,G,P_bar)
        (ch,r)=ZKP.ZKP_correctFormatS(h,pk_EV['g'],sig_bar,pk_sig, G, c_bar, sk_sig, z1, z2,ri, P_bar, params)
        isCorrect=ZKP.verifyZKP_FormatS(h,pk_EV['g'],pk_sig,ch,r,c_bar,P_bar,G,sig_bar, params)
        print("ZKPS Test Result with more parameters:", isCorrect)
    
    def testZKPSInLib_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        msg.append("testmessage")
        msg.append("female")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (sk_sig, pk_sig)=agho.keygen(h)
        (c,o) = el.encrypt(pk_EV, msg)
        (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,pk_EV['g'])
        (sig_bar,z1,z2, ri)=agho.sign(pk_EV['g'],sk_sig,c_bar,h,G,P_bar)
        (ch,r)=agho.ZKPS(h,pk_EV['g'],sig_bar,pk_sig, G, c_bar, sk_sig, z1, z2,ri, P_bar)
        isCorrect=agho.ZKPS_verify(h,pk_EV['g'],pk_sig,ch,r,c_bar,P_bar,G,sig_bar)
        print("ZKPS Test Result from Library with more parameters:", isCorrect)
    
    def testZKPVote_oneParameter(self):
        groupObj=PairingGroup('BN254')
        params=1
        msg=[]
        attrs=[[]]
        msg.append("testmessage")
        attrs[0].append("testmessage")
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (c,o) = el.encrypt(pk_EV, msg)
        m = el.decrypt(pk_EV, sk_EV, c, attrs)
        (ch,r)=ZKP.ZKP_correctVote(c,pk_EV['g'], sk_EV, params)
        isCorrect=ZKP.verifyZKP_correctVote(c, m ,pk_EV, ch, r,pk_EV['g'], params)
        assert(isCorrect)
        print("ZKPVote Test Result with one parameter:", isCorrect)
    
    def testZKPVote_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        attrs=[]
        attr1=[]
        attr2=[]
        msg.append("testmessage")
        msg.append("female")
        attr1.append("testmessage")
        attr2.append("male")
        attr2.append("female")
        attrs.append(attr1)
        attrs.append(attr2)
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (c,o) = el.encrypt(pk_EV, msg)
        m = el.decrypt(pk_EV, sk_EV, c, attrs)
        (ch,r)=ZKP.ZKP_correctVote(c,pk_EV['g'], sk_EV, params)
        isCorrect=ZKP.verifyZKP_correctVote(c,msg ,pk_EV, ch, r,pk_EV['g'], params)
        assert(isCorrect)
        print("ZKPVote Test Result with more parameters:", isCorrect)
    
    def testZKPVoteInLib_moreParameters(self):
        groupObj=PairingGroup('BN254')
        params=2
        msg=[]
        attrs=[]
        attr1=[]
        attr2=[]
        msg.append("testmessage")
        msg.append("female")
        attr1.append("testmessage")
        attr2.append("male")
        attr2.append("female")
        attrs.append(attr1)
        attrs.append(attr2)
        el = ElGamal(params) 
        agho=AGHOBlind(el)
        (pk_EV, sk_EV) = el.keygen()
        h=groupObj.random(G2)
        (c,o) = el.encrypt(pk_EV, msg)
        m = el.decrypt(pk_EV, sk_EV, c, attrs)
        (ch,r)=el.ZKPsk(c,pk_EV['g'], sk_EV)
        isCorrect=el.ZKPsk_verify(c,msg ,pk_EV, ch, r,pk_EV['g'])
        assert(isCorrect)
        print("ZKPVote Test Result from Library with more parameters:", isCorrect)

if __name__ == "__main__":
    unittest.main()