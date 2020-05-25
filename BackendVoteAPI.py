from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from sqlalchemy import create_engine
from charm.toolbox.pairinggroup import PairingGroup,G1,G2, ZR
from flask_jsonpify import jsonify
from kryptlib.ElGamalImpl import ElGamal
from kryptlib.AGHOBlind import AGHOBlind

connectionA = create_engine('sqlite:///AKeyData.db') # Database for the encryption key
connectionW = create_engine('sqlite:///WKeyData.db') # Database for the signing key
connectionA2 = create_engine('sqlite:///AVoteData.db') # Database for saving the encrypted voted
connectionW2 = create_engine('sqlite:///WVoterData.db') # Database for Userdata
app = Flask(__name__)
api = Api(app)
params=2 # Voting parameters
group=PairingGroup('BN254') # Pairing group
el=ElGamal(params) # ElGamal instance
agho=AGHOBlind(el) # agho signature instance
parser = reqparse.RequestParser() # parser for request parameters
VoteFinished=False # stores voting status
def deser(var):
    '''
    deserializing variables to get <pairing.Element> types
    '''
    return group.deserialize(var.encode('utf-8'))

def ser(var):
    '''
    serializing variables to get base64 encoded strings
    '''
    return group.serialize(var).decode('utf-8')

class EVPublicKey(Resource):
    '''
    class for the client to access the encryption pyblic key.
    If a table exsts the secret key can be accessed and the public key is determined. Otherwise a table and a secret key is created
    the server returns vk and g to the client
    '''
    
    def get(self): 
        initDBs()
        conn = connectionA.connect() 
        query=conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='EVKey';")
        if len(query.cursor.fetchall())==0:
            (pk, sk)=el.keygen()
            g=ser(pk['g'])
            x=ser(sk['x'])
            query=conn.execute("CREATE TABLE EVKey (keyid INTEGER PRIMARY KEY,sk TEXT,g_pub TEXT);")  
            query2=conn.execute("INSERT INTO EVKey (keyid, sk, g_pub) VALUES(1, '%s', '%s')" %(x, g))  
        query3=conn.execute("SELECT * FROM EVKey")
        i=query3.cursor.fetchall()[0]
        g2=deser(i[2])
        vk=(g2**deser(i[1]))
        return {'vk': ser(vk), 'g': i[2]}

class SignaturePublicKey(Resource):    
    '''
    class for the client to access the verification pyblic key.
    If a table exsts the secret key can be accessed and the public key is determined. Otherwise a table and a secret key is created
    the server returns (V,W,Z) and h to the client
    '''
    
    def get(self):
        initDBs()
        conn = connectionW.connect() # connect to database  
        query=conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='SignKey';")
        if len(query.cursor.fetchall())==0:
            h=group.random(G2)
            (sk, pk)=agho.keygen(h)
            h=ser(h)
            v=ser(sk['v'])
            w1=ser(sk['w'][0])
            w2=ser(sk['w'][1])
            w3=ser(sk['w'][2])
            w4=ser(sk['w'][3])
            z=ser(sk['z'])
            query=conn.execute("CREATE TABLE SignKey (keyid INTEGER PRIMARY KEY, v TEXT,w1 TEXT, w2 TEXT, w3 TEXT, w4 TEXT, z TEXT, h TEXT);")  
            query2=conn.execute("INSERT INTO SignKey (keyid, v, w1, w2, w3, w4, z, h) VALUES(1, '%s', '%s', '%s', '%s', '%s', '%s', '%s')" %(v,w1,w2,w3,w4,z, h))  
        query3=conn.execute("SELECT * FROM SignKey")
        i=query3.cursor.fetchall()[0]
        h_s=i[7]
        h=deser(h_s)
        V=h**deser(i[1])
        W1=h**deser(i[2])
        W2=h**deser(i[3])
        W3=h**deser(i[4])
        W4=h**deser(i[5])
        Z=h**deser(i[6])
        return {'V': ser(V),'W1': ser(W1),'W2': ser(W2),'W3': ser(W3),'W4': ser(W4),'Z': ser(Z),'h': h_s}

class signVote(Resource):
    '''
    the client submits
    username and password - the voting credentials
    (c1_bar, c2-bar) the blinded vote,
    g the parameter from G1
    vk the public key for the encrypted vote
    G1, G2, G3 client side signature randomness parameters
    ch, ri challenge and responses for verifying the client side ZKP
    m the unencrypted public attributes

    the server checks if the User is allowed to vote and if the ZKP is valid
    when successed the Server updates the voter status and signs the vote
    the server sends back the blinded signature and a challenge and a response for the server side ZKP
    '''
    
    def post(self):
        if VoteFinished:
            return {'message': "Vote has already been finished! Please reset Vote Status for Voting!"}, 400
        initDBs()
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        parser.add_argument('c11', type=str)
        parser.add_argument('c12', type=str)
        parser.add_argument('c21', type=str)
        parser.add_argument('c22', type=str)
        parser.add_argument('P11', type=str)
        parser.add_argument('P12', type=str)
        parser.add_argument('P21', type=str)
        parser.add_argument('P22', type=str)
        parser.add_argument('g', type=str)
        parser.add_argument('vk', type=str)
        parser.add_argument('G1', type=str)
        parser.add_argument('G2', type=str)
        parser.add_argument('G3', type=str)
        parser.add_argument('ch', type=str)
        parser.add_argument('r1', type=str)
        parser.add_argument('r2', type=str)
        parser.add_argument('r3', type=str)
        parser.add_argument('r4', type=str)
        parser.add_argument('r5', type=str)
        parser.add_argument('m', type=str)
        args = parser.parse_args()

        conn=connectionW2.connect()
        query=conn.execute("SELECT * FROM Voter WHERE user = '%s' AND passwd = '%s'" %(args['username'], args['password']))
        i=query.cursor.fetchall()
        if len(i)==0:
            return{'message': "Authentication failed!"}, 401 
        voterID=i[0][0]
        if i[0][3]==False or i[0][4]==True:
            return{'message':"You are not entitled to vote or have already voted"}, 401
        g=deser(args['g'])
        vk=deser(args['vk'])
        pk_EV={'vk':vk, 'g':g}
        c1=[deser(args['c11']), deser(args['c12'])]
        c2=[deser(args['c21']), deser(args['c22'])]
        P1=[deser(args['P11']), deser(args['P12'])]
        P2=[deser(args['P21']), deser(args['P22'])] 
        conn2 = connectionW.connect()  
        query2=conn2.execute("SELECT * FROM SignKey")
        w=[]
        W=[]
        G={'G1':deser(args['G1']), 'G2':deser(args['G2']), 'G3':deser(args['G3'])}
        c_bar={'c1_bar':c1, 'c2_bar': c2}
        for i in query2.cursor.fetchall():
            v=deser(i[1])
            w.append(deser(i[2]))
            w.append(deser(i[3]))
            w.append(deser(i[4]))
            w.append(deser(i[5]))
            z=deser(i[6])
            h=deser(i[7])
        V=h**v
        Z=h**z
        for i in range(0, len(w)):
            W.append(h**w[i])
        sk={'v':v, 'w':w, 'z':z}
        pk={'V':V, 'W':W, 'Z':Z}
        P_bar={'P1_bar': P1, 'P2_bar':P2}
        r2=[]
        r2.append(deser(args['r1']))
        r2.append(deser(args['r2']))
        r2.append(deser(args['r3']))
        r2.append(deser(args['r4']))
        r2.append(deser(args['r5']))
        m=[]
        m.append(args['m'])
        
        iscorrect=agho.ZKPU_verify(deser(args['ch']), G, r2, c_bar, P_bar, m, pk_EV, g)
        if iscorrect==False:
            return {'message': "ZKP not verified"}, 400 
        query3=conn.execute("UPDATE Voter SET voted=%s WHERE keyid=%s" %(True,voterID))

        (sig, z1, z2, ri)=agho.sign(g,sk,c_bar, h, G, P_bar)
        (ch,r)=agho.ZKPS(h,g,sig,pk,G,c_bar, sk, z1, z2, ri, P_bar)
        return {'R_bar':ser(sig['R_bar']), 'S1_bar':ser(sig['S1_bar']), 'S2_bar':ser(sig['S2_bar']), 'T_bar':ser(sig['T_bar']), 'ZKP_ch':ser(ch), 'ZKP_r1':ser(r[0]),'ZKP_r2':ser(r[1]),'ZKP_r3':ser(r[2]),'ZKP_r4':ser(r[3]),'ZKP_r5':ser(r[4]),'ZKP_r6':ser(r[5]),'ZKP_r7':ser(r[6]),'ZKP_r8':ser(r[7])}

class submitVote(Resource):
    '''
    class for submitting a vote
    the client submits:
    the encrypted vote (c1, c2)
    the Verification key (V,W,Z)
    the signature (R,S,T)
    h the pubic parameter from G2
    the server checks the validity of the signature and stores the encryped vote in the database
    '''
    
    def post(self):
        if VoteFinished:
            return {'message': "Vote has already been finished! Please reset Vote Status for Voting!"}, 400
        initDBs()
        parser.add_argument('c11', type=str)
        parser.add_argument('c12', type=str)
        parser.add_argument('c21', type=str)
        parser.add_argument('c22', type=str)
        parser.add_argument('R', type=str)
        parser.add_argument('S', type=str)
        parser.add_argument('T', type=str)
        parser.add_argument('V', type=str)
        parser.add_argument('W0', type=str)
        parser.add_argument('W1', type=str)
        parser.add_argument('W2', type=str)
        parser.add_argument('W3', type=str)
        parser.add_argument('Z', type=str)
        parser.add_argument('h', type=str)
        args = parser.parse_args()
        c1=[deser(args['c11']), deser(args['c12'])]
        c2=[deser(args['c21']), deser(args['c22'])]
        c={'c1': c1, 'c2': c2}
        sig={'R': deser(args['R']), 'S': deser(args['S']), 'T': deser(args['T'])}
        h=deser(args['h'])
        W=[deser(args['W0']),deser(args['W1']), deser(args['W2']), deser(args['W3'])]
        pk={'V': deser(args['V']), 'W': W, 'Z': deser(args['Z'])}

        conn = connectionA.connect()
        query=conn.execute("SELECT * FROM EVKey")
        i=query.cursor.fetchall()[0]
        g1=deser(i[2])
        isCorrect=agho.verify(pk, sig, g1, h, c)
        if isCorrect==False:
            return {'message': "Signature not correct"}, 400 

        conn=connectionA2.connect()
        query3=conn.execute("SELECT * FROM Vote WHERE R = '%s' AND S = '%s' AND T = '%s'" %(args['R'], args['S'], args['T']))
        results=query3.cursor.fetchall()
        if len(results)!=0:
            return {'message': "Signature already submitted"}, 400 
        query=conn.execute("INSERT INTO Vote (keyid,c11, c12, c21, c22, R, S, T) VALUES(NULL, '%s', '%s', '%s', '%s', '%s', '%s', '%s')" %(args['c11'], args['c12'], args['c21'], args['c22'], args['R'], args['S'], args['T'])) 
        return {'message': "Vote submitted successfully"} 

class countVotes(Resource):
    '''
    class for counting the votes 
    the client sends all components for the lookup table.
    cand1-can3 possble candidates
    sex1-sex2 possible sexes
    the global varable VoteFinished is set to true, so no votes can be done anymore and the web Bulletin board can be accessed
    the votes are encrypted and counted and the number of votes for each candidate is sent back to the client
    '''
    
    def post(self):
        parser.add_argument('cand1', type=str)
        parser.add_argument('cand2', type=str)
        parser.add_argument('cand3', type=str)
        parser.add_argument('sex1', type=str)
        parser.add_argument('sex2', type=str)
        args = parser.parse_args()
        global VoteFinished
        VoteFinished=True
        initDBs()
        attrs=[]
        attrsVote=[]
        attrsSex=[]
        attrsVote.append(args['cand1'])
        attrsVote.append(args['cand2'])
        attrsVote.append(args['cand3'])
        attrsSex.append(args['sex1'])
        attrsSex.append(args['sex2'])
        attrs.append(attrsSex) 
        attrs.append(attrsVote)
        conn2=connectionA.connect()
        query3=conn2.execute("SELECT * FROM EVKey")
        i=query3.cursor.fetchall()[0]
        g=deser(i[2])
        sk={'x':deser(i[1])}
        pk= {'vk':g**sk['x'] , 'g': g}
        conn = connectionA2.connect()  
        query=conn.execute("SELECT * FROM Vote;")
        cipherVotes=[]
        m=[]
        results=query.cursor.fetchall()
        for i in results:
            cipherVotes.append([i[1], i[2], i[3], i[4]])
            c1=[]
            c2=[]
            c1.append(deser(i[1]))
            c1.append(deser(i[2]))
            c2.append(deser(i[3]))
            c2.append(deser(i[4]))
            c={'c1':c1, 'c2':c2}
            m_temp=el.decrypt(pk, sk, c,attrs)
            m.append(m_temp)
        cand1V=0
        cand2V=0
        cand3V=0
        for i in range(0, len(m)):
            if m[i][1]==args['cand1']:
                cand1V+=1
            elif m[i][1]==args['cand2']:
                cand2V+=1
            elif m[i][1]==args['cand3']:
                cand3V+=1
        return {'cand1V':cand1V, 'cand2V':cand2V,'cand3V':cand3V}

class resetVote(Resource):
    '''
    class for resetting the voting parameters in the database (only for testing purposes)
    all votes from the vote database are removed
    all voting status are resetted in the voters Database
    '''
    
    def get(self):
        global VoteFinished
        VoteFinished=False 
        initDBs()
        conn = connectionA2.connect()  
        query=conn.execute("DELETE FROM Vote;")
        conn2 = connectionW2.connect()
        query2=conn2.execute("UPDATE Voter SET voted=%s" %(False))
        return {}

class WebBulletinBoard(Resource):
    '''
    Class for gettinig parameters for the web bulletin board. User sends 
    cand1-cand3: possible candidates
    sex1-sex2: possible sexes
    the server creates the attribute vector, takes the secret key for encryption from the database and takes all votes
    the server decrypts the votes, creates a challenge and a corresponsing response for each vote 
    the server returns: Encrypted Votes, Decrypted Votes, and zero knowledge components back to the user
    '''
    
    def post(self):
        if VoteFinished==False:
            return{'message': "Vote has not been finished until now! Please count the votes first."}, 400
        parser.add_argument('cand1', type=str)
        parser.add_argument('cand2', type=str)
        parser.add_argument('cand3', type=str)
        parser.add_argument('sex1', type=str)
        parser.add_argument('sex2', type=str)
        args = parser.parse_args()
        initDBs()
        attrs=[]
        attrsVote=[]
        attrsSex=[]
        attrsVote.append(args['cand1'])
        attrsVote.append(args['cand2'])
        attrsVote.append(args['cand3'])
        attrsSex.append(args['sex1'])
        attrsSex.append(args['sex2'])
        attrs.append(attrsSex) 
        attrs.append(attrsVote)
        conn2=connectionA.connect()
        query3=conn2.execute("SELECT * FROM EVKey")
        i=query3.cursor.fetchall()[0]
        g=deser(i[2])
        sk={'x':deser(i[1])}
        pk= {'vk':g**sk['x'] , 'g': g}
        conn = connectionA2.connect()  
        query=conn.execute("SELECT * FROM Vote;")
        cipherVotes=[]
        sig=[]
        m=[]
        ch=[]
        r=[]
        for i in query.cursor.fetchall():
            cipherVotes.append([i[1], i[2], i[3], i[4]])
            c1=[]
            c2=[]
            c1.append(deser(i[1]))
            c1.append(deser(i[2]))
            c2.append(deser(i[3]))
            c2.append(deser(i[4]))
            c={'c1':c1, 'c2':c2}
            (ch_tmp, r_tmp)=el.ZKPsk(c,g,sk)
            ch.append(ser(ch_tmp))
            r.append(ser(r_tmp))
            m.append(el.decrypt(pk, sk, c,attrs))
            sig.append([i[5],i[6], i[7]])
        return {'Evs':[i for i in cipherVotes] , 'Votes': [i for i in m], 'ZKP_ch': [i for i in ch], 'ZKP_r': [i for i in r], 'Sigs':[i for i in sig]}       

def initDBs():
    '''
    Initialize the databases with the default (test)-users and creating the databases for the votes
    '''
    conn = connectionW2.connect()
    usr="testuser1"
    pwd="supersecurepassword123"
    usr2="testuser2"
    pwd2="reallysecurepassword123"
    query=conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Voter';")
    if len(query.cursor.fetchall())==0:
        query=conn.execute("CREATE TABLE Voter (keyid INTEGER PRIMARY KEY,user TEXT,passwd TEXT, entitled BOOLEAN, voted BOOLEAN);") 
        query2=conn.execute("INSERT INTO Voter (keyid, user, passwd, entitled, voted) VALUES(NULL, '%s', '%s', %s, %s)" %(usr,pwd,True, False))  
        query2=conn.execute("INSERT INTO Voter (keyid, user, passwd, entitled, voted) VALUES(NULL, '%s', '%s', %s, %s)" %(usr2,pwd2,True, False))
    conn2=connectionA2.connect()
    query=conn2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Vote';")
    if len(query.cursor.fetchall())==0:
        query=conn2.execute("CREATE TABLE Vote (keyid INTEGER PRIMARY KEY, c11 TEXT, c12 TEXT, c21 TEXT, c22 TEXT, R TEXT, S TEXT, T TEXT);") 

api.add_resource(EVPublicKey, '/pkEV') #route for requesting the public key for the ElGamal encrytion
api.add_resource(SignaturePublicKey, '/pkSig') #route for requesting the public signing key
api.add_resource(signVote, '/sign') #route for requesting a signature for a given EV
api.add_resource(submitVote, '/vote') #route for submitting the vote
api.add_resource(countVotes, '/count') # route for counting all votes
api.add_resource(resetVote, '/reset') # route for resetting the voting status
api.add_resource(WebBulletinBoard, '/wbb') # route for requestinig data for the web bulletin board

if __name__ == '__main__':
    app.run(port=5002)