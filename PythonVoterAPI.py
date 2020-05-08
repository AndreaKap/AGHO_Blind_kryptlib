import requests
from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from kryptlib.ElGamalImpl import ElGamal
from kryptlib.AGHOBlind import AGHOBlind

URL="http://127.0.0.1:5002" # server url
group=PairingGroup('BN254') # pairing group
can=["Eric Example", "Max Mustermann", "Conrand Candidate"] # ist of candidates
sex=["male", "female"] # list of possible sexes
params=2 # parameters
el=ElGamal(params) # elgamal instance
agho=AGHOBlind(el) # agho instance

def deser(var):
    '''
    deserializinig variables to get <pairing.Element> types
    '''
    return group.deserialize(var.encode('utf-8'))
def ser(var):
    '''
    serializinig variables to get base64 encoded strings
    '''
    return group.serialize(var).decode('utf-8')

def mainmenu():
    '''
    main menu of the CLI
    '''
    try:
        print("------What would you like to do?------")
        print("[1] Vote")
        print("[2] Counting")
        print("[3] Web Bulletin Board")
        print("[4] Reset Vote-status")
        print("[5] Quit Client")
        print("Notice that this is a test-application for the protocol")
        print("->")
        i=input()
        if i=="1":
            vote()
        elif i=="2":
            count()
        elif i=="3":
            wbb()
        elif i=="4":
            reset()
        elif i=="5":
            return
        else:
            print("Please enter a valid option!")
        mainmenu()
    except KeyboardInterrupt:
        print()
        print("Bye")
        return

def voteOptions():
    '''
    cli candidate selection
    '''
    print("----Please enter your choice---")
    print("[1] ", can[0])
    print("[2] ",can[1])
    print("[3] ",can[2])
    print("[4] quit")
    print("->")
    i=input()
    if i!="1" and i!="2" and i!="3" and i!="4":
        print("Please enter a valid choice!")
        voteOptions()
    else:
        if i=="1":
            return can[0]
        elif i=="2":
            return can[1]
        elif i=="3":
            return can[2]
        elif i=="4":
            mainmenu()

def getUsrAndPass():
    '''
    cli credential input
    '''
    print("Please enter your username")
    usr=input()
    print("please enter your password")
    pwd=input()
    return usr, pwd

def sexOptions():
    '''
    cli sex selection
    '''
    print("----Please enter your choice---")
    print("[1] ", sex[0])
    print("[2] ",sex[1])
    print("[3] quit")
    print("->")
    i=input()
    if i!="1" and i!="2" and i!="3":
        print("Please enter a valid choice!")
        sexOptions()
    else:
        if i=="1":
            return sex[0]
        elif i=="2":
            return sex[1]
        elif i=="3":
            mainmenu()
            
def vote():
    '''
    voting:
    the client requests the encryptio  key and encrypts the vote
    teh cliient blinds the vote and requests a signature with a client side zkp
    then the client submits the vote at the counting server
    '''
    m=[]
    m.append(sexOptions())
    m.append(voteOptions())
    (usr, pwd)=getUsrAndPass()
    (pk_sig, h)=getSigninigKey()
    pk=getEncryptionKey()
    if pk==-1:
        return
    try:
        (c,c_bar, P_bar, G, e, f1, f2,o)=encryptAndBlindVote(pk,m,pk['g'])
    except:
        return
    m_bar=[]
    m_bar.append(m[0])
    (ch,r)=ZKPu(pk['g'],P_bar,pk,o,e,G,f1,f2)
    (sig)=signVoteAndDeblind(usr, pwd, c_bar, P_bar,pk['g'], G, ch, r, e, f1+f2, pk,h, pk_sig, m_bar)
    if sig==-1:
        return
    isCorrect=submitVote(c, sig, pk_sig, h)
    if isCorrect:
        print("Vote submitted successfully")
    else:
        print("An unexpected error happened!")
    mainmenu()

def count():
    '''
    counting:
    the client sends a request with the possible candidates and sexes to the server
    the server sends back the counting results and the client printts the results and the counts
    '''
    par={'cand1': can[0], 'cand2': can[1], 'cand3': can[2], 'sex1': sex[0], 'sex2': sex[1]}
    r=requests.post(url=(URL+"/count"), data=par)
    if 200 != r.status_code:
        print("Counting was not sucessful", r.status_code, r.json()['message'])
        return
    data=r.json()
    if data['cand1V']>data['cand2V'] and data['cand1V']>data['cand3V']:
        winner=can[0]
    elif data['cand2V']>data['cand1V'] and data['cand2V']>data['cand3V']:
        winner=can[1] 
    elif data['cand3V']>data['cand1V'] and data['cand3V']>data['cand2V']:
        winner=can[2]
    else:
        winner="draw"
    print("-------Voting-Results------")
    print(can[0],": ",data['cand1V'])
    print(can[1],": ",data['cand2V'])
    print(can[2],": ",data['cand3V'])
    print("The winner is: ", winner)
    return

def wbb():
    '''
    wbb:
    the client sends a request with the possible candidates and sexes to the server
    the server sends back the counting results and the client printts the results and the counts
    '''
    par={'cand1': can[0], 'cand2': can[1], 'cand3': can[2], 'sex1': sex[0], 'sex2': sex[1]}
    r=requests.post(url=(URL+"/wbb"), data=par)
    if 200 != r.status_code:
        print("Getting Web Bulletin Board Failied", r.status_code, r.json()['message'])
        return
    data=r.json()
    print("------WEB-BULLETIN-BOARD------")
    print("------------------------------")
    print("-------Encrypted-Votes--------")
    print(data['Evs'])
    print("----------Signatures----------")
    print(data['Sigs'])
    print("--------Decrypted-Votes-------")
    print(data['Votes'])
    print("-----Zero-Knowledge-Proof-----")
    print(data['ZKP_ch'])
    print(data['ZKP_r'])
    print("-------Verifications----------")
    r2=requests.get(url=(URL+"/pkEV"))
    if 200 != r2.status_code:
        print("Getting public key for ZKP failed", r.status_code, r.json()['message'])
        return
    data2=r2.json()
    pk={'vk': deser(data2['vk']), 'g': deser(data2['g'])}
    ZKPval=[]
    for i in range(0,len(data['ZKP_ch'])):
        c1=[]
        c2=[]
        c1.append(deser(data['Evs'][i][0]))
        c1.append(deser(data['Evs'][i][1]))
        c2.append(deser(data['Evs'][i][2]))
        c2.append(deser(data['Evs'][i][3]))
        c={'c1':c1, 'c2':c2}
        m=data['Votes'][i]
        ch=deser(data['ZKP_ch'][i])
        r=deser(data['ZKP_r'][i])
        res=el.ZKPsk_verify(c,m,pk,ch,r,pk['g'])
        ZKPval.append(res)
    print(ZKPval)
    return 

def reset(): 
    '''
    requests a vote reset at the server
    '''
    r=requests.get(url=(URL+"/reset"))
    if 200!= r.status_code:
        print("Reset failed:", r.status_code)
    return

def getEncryptionKey():
    '''
    requests the public encryption key from the server and returns the key
    :return: pk public encryption key
    '''
    r=requests.get(url=(URL+"/pkEV"))
    if 200!= r.status_code:
        print("Encryption Key could not be found", r.status_code)
        return
    data=r.json()
    vk=data['vk']
    g=data['g']
    pk={'vk': deser(vk), 'g': deser(g)}
    return pk

def getSigninigKey():
    '''
    requests the verification key from the server and returns the key and the pubic parameter from G2 h
    :return: pk verification key and h public parameter from G2
    '''
    r=requests.get(url=(URL+"/pkSig"))
    if 200!= r.status_code:
        print("Signinig Key could not be found", r.status_code)
        return -1
    data=r.json()
    r1=data['V']
    r2=data['W1']
    r3=data['W2']
    r4=data['W3']
    r5=data['W4']
    r6=data['Z']
    r7=data['h']
    V=deser(r1)
    W=[]
    W.append(deser(r2))
    W.append(deser(r3))
    W.append(deser(r4))
    W.append(deser(r5))
    Z=deser(r6)
    pk={'V': V, 'W': W, 'Z': Z}
    h=deser(r7)
    return (pk,h)

def encryptAndBlindVote(pk,m,g):
    '''
    does the ElGamal encryption of a vote m and blinids the vote
    :param pk: the public encryption key
    :param m: the vote
    :param g: the public parameter from G1
    :return: the encrypted vote, the blinded vote, the pad, the client side signature randomnesses G and the secret parameters e, f1, f2, o
    '''
    (c,o)=el.encrypt(pk,m)
    (c_bar, P_bar, G, e, f1, f2)=agho.blind(c,g)
    return (c,c_bar, P_bar, G, e, f1, f2,o)

def ZKPu(g,P_bar,pk,o,e,G,f1,f2):
    '''
    generates a NIZKP for the correct format of the vote
    :param g: the public parameter from G1
    :param P_bar: the pad
    :param pk: the public encryption key
    :param o: the encryption randomness
    :param e: the randomness for blinding the pad
    :param G: the client side signing randomness   
    :param f1: first part of the random decomposition of f
    :param f2: second part of the random decomposition of f
    :return: the ZKP parameters challenge and response
    '''
    (ch,r)=agho.ZKPU(g,P_bar,pk,o,e,G,f1,f2)
    return (ch,r)

def signVoteAndDeblind(usr, pwd, c_bar, P_bar,g, G, ch, resp, e, f, pk,h, pk_sig,msg):
    '''
    The clinet requests a signature for the Encrypted and blinded vote and sends the
    credentiials, 
    the blinded vote, 
    the client side ZKP parameters
    the pad
    the clinet signing randomnesses and
    the message to the server and verifies the zero knowledge proof of the response
    the client deblinds the blinded signature and returns it
    :param usr: the user
    :param pwd: the password
    :param c_bar: the blinded vote
    :param P_bar: the blinded Pad
    :param g: the public parameter from G1
    :param G: the client siide randomness signing parameters
    :param ch: the challennge for the clinet side ZKP
    :param resp: the response for the clinet side ZKP
    :param e: the secret randomness for blinding the pad
    :param f: the secret randomness for the sgnature
    :param pk: the public encryption key
    :param h: the public parameter from G2
    :param pk_sig: the verification siigning key
    :param msg: the message with the public attributes
    :return: deblinded signature
    '''
    c11=ser(c_bar['c1_bar'][0])
    c12=ser(c_bar['c1_bar'][1])
    c21=ser(c_bar['c2_bar'][0])
    c22=ser(c_bar['c2_bar'][1])
    P11=ser(P_bar['P1_bar'][0])
    P12=ser(P_bar['P1_bar'][1])
    P21=ser(P_bar['P2_bar'][0])
    P22=ser(P_bar['P2_bar'][1])
    G1=ser(G['G1'])
    G2=ser(G['G2'])
    G3=ser(G['G3'])
    g1=ser(g)
    vk=ser(pk['vk'])
    chal=ser(ch)
    par={'username':usr, 'password':pwd, 'c11':c11 , 'c12':c12, 'c21':c21, 'c22':c22, 'P11':P11, 'P12':P12, 'P21':P21, 'P22':P22, 'g':g1,'vk':vk, 'G1':G1, 'G2':G2, 'G3':G3, 'ch':chal, 'r1':ser(resp[0]), 'r2':ser(resp[1]), 'r3':ser(resp[2]), 'r4':ser(resp[3]), 'r5':ser(resp[4]), 'm': msg}
    r=requests.post(url=(URL+"/sign"), data=par)
    if 200!= r.status_code:
        print("An error happened during signature", r.status_code, r.json()['message'])
        return -1
    data=r.json()
    r=[]
    R_b=data['R_bar']
    S1_b=data['S1_bar']
    S2_b=data['S2_bar']
    T_b=data['T_bar']
    zkpC=data['ZKP_ch']
    r.append(deser(data['ZKP_r1']))
    r.append(deser(data['ZKP_r2']))
    r.append(deser(data['ZKP_r3']))
    r.append(deser(data['ZKP_r4']))
    r.append(deser(data['ZKP_r5']))
    r.append(deser(data['ZKP_r6']))
    r.append(deser(data['ZKP_r7']))
    r.append(deser(data['ZKP_r8']))
    ch=deser(zkpC)
    sig_bar={'R_bar':deser(R_b), 'S1_bar':deser(S1_b), 'S2_bar':deser(S2_b), 'T_bar':deser(T_b)}
    if verifyZKPs(ch, r, h, g, pk_sig, c_bar, P_bar, G, sig_bar)==False:
        print("Verification of server side ZKP failed!")
        return -1
    else:
        sig=agho.deblindSig(sig_bar, e, f)
    return sig 

def verifyZKPs(ch,r, h, g, pk, c_bar, P_bar, G, sig_bar):
    '''
    verifies the server side ZKP
    :param ch: the challenge from the server
    :param r: the response from the server
    :param h: the public parameter from G2
    :param g: the public parameter from G1
    :param pk: the pubic signature key
    :param c_bar: the blinded vote
    :param P_bar: the blinded Pad
    :param G: the radminess client side parameters
    :param sig_bar: te signature
    :reutrn: the result from the verification
    '''
    return agho.ZKPS_verify(h,g,pk,ch,r,c_bar,P_bar, G, sig_bar)

def submitVote(c, sig, pk, h):
    '''
    Submits the vote and the signatutre at the counting server
    :param c: Encrypted Vote.
    :param sig: AGHO Signature.
    :param pk: public encryption key.
    :param h: random value from G2.
    :return: 1 at success -1 otherwise.
    '''
    par={'c11':ser(c['c1'][0]), 'c12':ser(c['c1'][1]), 'c21':ser(c['c2'][0]), 'c22':ser(c['c2'][1]), 'R': ser(sig['R']), 'S':ser(sig['S']), 'T':ser(sig['T']), 'V':ser(pk['V']), 'W0':ser(pk['W'][0]), 'W1':ser(pk['W'][1]), 'W2':ser(pk['W'][2]), 'W3':ser(pk['W'][3]), 'Z':ser(pk['Z']), 'h':ser(h)}
    r=requests.post(url=(URL+"/vote"), data=par)
    if 200!= r.status_code:
        print("Vote could not be submitted", r.status_code, r.json()['message'])
        return -1
    return 1

if __name__ == "__main__":
    mainmenu()