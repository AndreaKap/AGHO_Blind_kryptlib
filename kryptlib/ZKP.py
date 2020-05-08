from charm.toolbox.pairinggroup import PairingGroup,G1, ZR 

def ZKP_correctFormatU(g,P_bar,pk, o, e,G, f1, f2, params):
    '''
    verifies a ZKP for the correct format of a vote
    :param g: the public parameter from G1 
    :param P_bar: blinded pad
    :param pk: the public encryption key
    :param o: secret client side encryption randomness
    :param e: secret parameter for pad blinding
    :param G: the client side signing randomness
    :param f1: first part of the random decompilation of the secret client signature parameter
    :param f2: second part of the random decompilation of the secret client signature parameter
    :param params: the number of parameters (attributes)
    :return: the result of the verification
    ''' 
    group=PairingGroup('BN254')
    nu=[]
    N=[]
    r=[]
    N_bar=""
    for i in range(0, params+3):
        nu.append(group.random(ZR))
    N.append(G['G1']**nu[0])
    N.append(g**nu[1])
    N.append(G['G1']**nu[2])
    for i in range(0,params):
        N.append((g**nu[3+i])*(P_bar['P1_bar'][i]**(-nu[0])))
    for i in range(0,params-1):
        N.append((pk['vk']**nu[3+i])*(P_bar['P2_bar'][i]**(-nu[0])))
    for i in range(len(N)):
        N_bar=N_bar+str(N[i])
    ch=H(N_bar.encode('utf-8'))
    r.append(ch*(1/e)+nu[0])
    r.append(ch*f1+nu[1])
    r.append(ch*f2+nu[2])
    for i in range(0,params):
        r.append(ch*o[i]+nu[3+i])
    return (ch,r)

def ZKP_correctFormatS(h,g, sig, pk, G, c_bar, sk, z1, z2,ri, P_bar, params):
    '''
    calculates a NIZKP for the correct format of the signature
    :param h: the public parameter from G2
    :param g: the public parameter from G1 
    :param sig: the AGHO signature
    :param pk: the public verificatiion parameter
    :param G: the client side signing randomness 
    :param c_bar: the blinded encrpted vote
    :param sk: the secret siging key
    :param z1: first part of the random decompilation of the secret signature parameter
    :param z2: second part of the random decompilation of the secret signature parameter
    :param ri: the servier side randomness
    :param P_bar: the blinded pad
    :param params: the number of parameters (attributes)
    :return: the zKP parameters
    '''
    group=PairingGroup('BN254')
    nu=[]
    N=[]
    r=[]
    N_bar=""
    for i in range(0,params*2+4): #params*2 für die wi's +r + r*v+z1+z2
        nu.append(group.random(ZR))
    for i in range(0, params*2): #für die wi's
        N.append(mapToGT(g,h**nu[i])) # N0
    N.append(mapToGT(g,(h**nu[2*params])*(h**nu[2*params+1]))) #N1
    N.append(g**nu[2*params+2]) #N2
    N.append(mapToGT(g,sig['T_bar']**nu[2*params+2])) #N3
    tmp=(pk['V']**nu[2*params+2])*(h**(nu[2*params+3]))
    N.append(mapToGT(g,tmp)) #N4 
    cprod=calcCprod(c_bar, nu, params)
    N.append((g**nu[2*params])*(G['G2']**(nu[2*params+3]))*cprod) # N5
    pprod=calcPprod(P_bar,nu, params)
    N.append((G['G1']**nu[2*params+1])*(G['G3']**(nu[2*params+3]))*pprod)#N6
    for i in range(len(N)):
        N_bar=N_bar+str(N[i])
    ch=H(N_bar.encode('utf-8'))
    for i in range(0, 2*params):
        r.append(ch*sk['w'][i]+nu[i])
    r.append(ch*z1+nu[2*params])
    r.append(ch*z2+nu[2*params+1])
    r.append(ch*ri+nu[2*params+2])
    r.append(ch*(-sk['v']*ri)+nu[2*params+3])
    return (ch,r)

def mapToGT(g,m):
    '''
    calculates the pairing product of g and m because of serialisation problems in G2
    :param g: the public parameter from G1 
    :param m: ta message from G2
    :return: the pairing product
    '''
    group=PairingGroup('BN254')
    N=group.pair_prod(g,m)
    return N

def calcCprod(c_bar, nu, params):
    '''
    calculates the product of the blinded EVs
    :param c_bar: the blinded EV
    :param nu: the exponent
    :param params: the number of parameters (attributes)
    :return: the product
    '''
    tmp=1
    for i in range(0, params):
        tmp=tmp*(c_bar['c1_bar'][i]**(-nu[i]))*(c_bar['c2_bar'][i]**(-nu[i+params]))
    return tmp

def calcPprod(P_bar, nu, params):
    '''
    calculates the product of the blinded pads
    :param P_bar: the blinded pad
    :param nu: the exponent 
    :param params: the number of parameters (attributes)
    :return: the product
    '''
    tmp=1
    for i in range(0, params):
        tmp=tmp*(P_bar['P1_bar'][i]**(-nu[i]))*(P_bar['P2_bar'][i]**(-nu[i+params]))
    return tmp

def ZKP_correctVote(c, g, sk, params):
    '''
    calculates a NIZKP for the correct decryption of a vote
    :param c: the encrypted vote
    :param g: the public parameter from G1 
    :param sk: the secret decryption key
    :param params: the number of parameters (attributes)
    :return: the ZKP parameters
    '''
    group=PairingGroup('BN254')
    N=[]
    N_bar=""
    nu=group.random(ZR)
    for i in range(0,params):
        N.append(c['c1'][i]**nu)
    N.append(g**nu)
    for i in range(len(N)):
        N_bar=N_bar+str(N[i])
    ch=H(N_bar.encode('utf-8'))
    r=ch*sk['x']+nu
    return (ch,r)

def verifyZKP_FormatU(ch,G, r, c_bar, P_bar, m, pk,g, params):
    '''
    verifies a ZKP for the correct format of a vote
    :param ch: the challenge
    :param G: the client side signing randomness 
    :param r: the response
    :param c_bar: the blinded EV
    :param P_bar: the blinded pad
    :param m: the message (public attrbutes)
    :param pk: the public encryption key
    :param g: the public parameter from G1
    :param params: the number of parameters (attributes)
    :return: the result of the verification
    '''
    group=PairingGroup('BN254')
    v=[]
    v_bar=""
    helpi=(G['G1']**r[0])*g**(-ch)
    v.append((G['G1']**r[0])*g**(-ch))
    v.append((g**r[1])*(G['G2']**(-ch)))
    v.append((G['G1']**r[2])*(G['G3']**(-ch)))
    for i in range(0,params):
        v.append((g**r[3+i])*(P_bar['P1_bar'][i]**(-r[0]))*(c_bar['c1_bar'][i]**(-ch)))
    for i in range(0,params-1):
        v.append((pk['vk']**r[3+i])*(P_bar['P2_bar'][i]**(-r[0]))*((c_bar['c2_bar'][i]**(-ch)))*group.hash(m[i], G1)**(ch))
    for i in range(len(v)):
        v_bar=v_bar+str(v[i])
    return ch==H(v_bar.encode('utf-8'))

def verifyZKP_FormatS(h,g,pk, ch, r, c_bar, P_bar, G, sig, params): 
    '''
    verifies a ZKP for the correct format of a signature
    :param h: the public parameter fromo G2
    :param g: the public parameter from G1
    :param pk: the verification key
    :param ch: the challenge
    :param r: the response
    :param c_bar: the blinded EV
    :param P_bar: the blinded pad
    :param G: the client side signature randomness
    :param sig: the signature
    :param params: the number of parameters (attributes)
    :return: the result of the verification
    '''
    v=[]
    v_bar=""
    for i in range(0, 2*params):
        v.append(mapToGT(g,(h**r[i])*((pk['W'][i]**(-ch))))) #v1
    v.append(mapToGT(g,(h**(r[2*params]))*(h**r[2*params+1])*((pk['Z']**(-ch))))) #v2
    v.append((g**r[2*params+2])*(sig['R_bar']**(-ch))) #v3
    v.append(mapToGT(g,(sig['T_bar']**r[2*params+2])*(h**(-ch)))) #v4
    v.append(mapToGT(g,(pk['V']**r[2*params+2])*(h**r[2*params+3]))) #v5
    cprod=calcCprod(c_bar,r,params)
    pprod=calcPprod(P_bar,r,params)
    v.append((g**r[2*params])*(G['G2']**(r[2*params+3]))*cprod*(sig['S1_bar']**(-ch))) #v6
    v.append((G['G1']**r[2*params+1])*(G['G3']**(r[2*params+3]))*pprod*(sig['S2_bar']**(-ch))) #v7
    for i in range(len(v)):
        v_bar=v_bar+str(v[i])
    return ch==H(v_bar.encode('utf-8'))

def verifyZKP_correctVote(c, m, pk, ch, r,g, params):
    '''
    verifies a ZKP for correct decryption of an EV
    :param c: the encrypted vote
    :param m: the decrypted vote
    :param pk: the public encryption key
    :param ch: the challenge
    :param r: the response
    :param g: the public parameter from G1
    :param params: the number of parameters (attributes)
    :return: the result of the verification
    '''
    group=PairingGroup('BN254')
    v_bar=""
    v=[]
    for i in range(0, params):
        m_bar=group.hash(m[i],G1)
        v.append(((c['c1'][i]**r)*((c['c2'][i]*(m_bar**(-1)))**(-ch))))
    v.append((g**r)*(pk['vk']**(-ch)))
    for i in range(len(v)):
        v_bar=v_bar+str(v[i])
    return ch==H(v_bar.encode('utf-8'))

def H(N):
    '''
    hashes a string to the curve
    :param N: the string that has to be hashed
    :return: the hashed string
    '''
    group=PairingGroup('BN254')
    i=group.hash(N,ZR)
    return i
