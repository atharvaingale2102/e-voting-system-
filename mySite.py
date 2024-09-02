# import the necessary packages
from flask import Flask, render_template, redirect, url_for, request,session,Response,jsonify
from werkzeug import secure_filename
import os
import cv2
from utils import *
import pandas as pd
from playsound import playsound
from sms import *
import random

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import random
import requests

#--------------------------Blockchain Part-------------------------------------------
class Blockchain:
	def __init__(self):
		self.current_transactions = []
		self.chain = []
		self.nodes = set()

		# Create the genesis block
		self.new_block(previous_hash='1', proof=100)

	def register_node(self, address):
		"""
		Add a new node to the list of nodes

		:param address: Address of node. Eg. 'http://192.168.0.5:5000'
		"""

		parsed_url = urlparse(address)
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		elif parsed_url.path:
			# Accepts an URL without scheme like '192.168.0.5:5000'.
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')


	def valid_chain(self, chain):
		"""
		Determine if a given blockchain is valid

		:param chain: A blockchain
		:return: True if valid, False if not
		"""

		last_block = chain[0]
		current_index = 1

		while current_index < len(chain):
			block = chain[current_index]
			print(f'{last_block}')
			print(f'{block}')
			print("\n-----------\n")
			# Check that the hash of the block is correct
			last_block_hash = self.hash(last_block)
			if block['previous_hash'] != last_block_hash:
				return False

			# Check that the Proof of Work is correct
			if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
				return False

			last_block = block
			current_index += 1

		return True

	def resolve_conflicts(self):
		"""
		This is our consensus algorithm, it resolves conflicts
		by replacing our chain with the longest one in the network.

		:return: True if our chain was replaced, False if not
		"""

		neighbours = self.nodes
		new_chain = None

		# We're only looking for chains longer than ours
		max_length = len(self.chain)

		# Grab and verify the chains from all the nodes in our network
		for node in neighbours:
			response = requests.get(f'http://{node}/chain')

			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				# Check if the length is longer and the chain is valid
				if length > max_length and self.valid_chain(chain):
					max_length = length
					new_chain = chain

		# Replace our chain if we discovered a new, valid chain longer than ours
		if new_chain:
			self.chain = new_chain
			return True

		return False

	def new_block(self, proof, previous_hash):
		"""
		Create a new Block in the Blockchain

		:param proof: The proof given by the Proof of Work algorithm
		:param previous_hash: Hash of previous Block
		:return: New Block
		"""

		block = {
			'index': len(self.chain) + 1,
			'timestamp': time(),
			'transactions': self.current_transactions,
			'proof': proof,
			'previous_hash': previous_hash or self.hash(self.chain[-1]),
		}

		# Reset the current list of transactions
		self.current_transactions = []

		self.chain.append(block)
		return block

	def new_transaction(self, sender, recipient, amount):
		"""
		Creates a new transaction to go into the next mined Block

		:param sender: Address of the Sender
		:param recipient: Address of the Recipient
		:param amount: Amount
		:return: The index of the Block that will hold this transaction
		"""
		self.current_transactions.append({
			'sender': sender,
			'recipient': recipient,
			'amount': amount,
		})

		return self.last_block['index'] + 1

	@property
	def last_block(self):
		return self.chain[-1]

	@staticmethod
	def hash(block):
		"""
		Creates a SHA-256 hash of a Block

		:param block: Block
		"""

		# We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
		block_string = json.dumps(block, sort_keys=True).encode()
		return hashlib.sha256(block_string).hexdigest()

	def proof_of_work(self, last_block):
		"""
		Simple Proof of Work Algorithm:

		 - Find a number p' such that hash(pp') contains leading 4 zeroes
		 - Where p is the previous proof, and p' is the new proof
		 
		:param last_block: <dict> last Block
		:return: <int>
		"""

		last_proof = last_block['proof']
		last_hash = self.hash(last_block)

		proof = 0
		while self.valid_proof(last_proof, proof, last_hash) is False:
			proof += 1

		return proof

	@staticmethod
	def valid_proof(last_proof, proof, last_hash):
		"""
		Validates the Proof

		:param last_proof: <int> Previous Proof
		:param proof: <int> Current Proof
		:param last_hash: <str> The hash of the Previous Block
		:return: <bool> True if correct, False if not.

		"""

		guess = f'{last_proof}{proof}{last_hash}'.encode()
		guess_hash = hashlib.sha256(guess).hexdigest()
		return guess_hash[:4] == "0000"



#--------------------APP Code------------------------------------
fname=''
lname=''
adhar=''
voter=''
name=''
contact = ''
otp=''

app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

app.secret_key = '1234'
app.config["CACHE_TYPE"] = "null"
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.route('/', methods=['GET', 'POST'])
def landing():
	return render_template('home.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
	return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
	global name
	global adhar
	global voter
	global contact
	error = ""

	if request.method=='POST':
		name = request.form['name']
		adhar = request.form['adhar']
		voter = request.form['voter']
		contact = request.form['contact']
		#fp = request.form['fingerprint']
		#print(fp)


		if(len(adhar)!=12):
			error += "Adhar number Invalid  "
		if(len(voter)!=10 or voter[0:3].isalpha()==False):
			error += "Voter ID Invalid"
		if(error == ""):	
			df = pd.read_csv('aadhar DB.csv')
			#print(df)
			df1 = pd.read_csv('Voter DB.csv')
			#print(df1)
			count=df.iloc[:,0].astype(str).str.contains(adhar).any()
			count1=df1.iloc[:,0].astype(str).str.contains(voter).any()
			print(count,count1)

			df2 = pd.read_csv('viis.csv')
			count2 = df2.iloc[:,2].astype(str).str.contains(adhar).any()

			if(count and count1 and count2==0):		
				return redirect(url_for('register1'))
			elif(count2!=0):
				error += "This Record is Already Present in VIIS"
			else:
				error += "Adhar/Voter is not in Database"
		
	return render_template('register.html',error=error)

@app.route('/register1', methods=['GET', 'POST'])
def register1():
	global name
	global adhar
	global voter
	global contact	
	if request.method=='POST':

		img = cv2.imread('static/images/test_image.jpg')
		cv2.imwrite('dataset/'+adhar+'.jpg', img)

		data_list = {'name':name,'adhar':adhar,'voter':voter,'vote':0,'contact':contact}
		df = pd.DataFrame(data_list,index=[0])
		df.to_csv('viis.csv', mode='a',header=False)

		return redirect(url_for('register'))

	return render_template('register1.html',name=name,adhar= adhar,voter=voter,contact=contact)


@app.route('/input', methods=['GET', 'POST'])
def input():
	global fname
	global lname
	global adhar
	global voter
	global otp

	df = pd.read_csv('viis.csv')
		
	if request.method=='POST':
		code = int(request.form['otp'])
		face = faceRecognition()
		print(face)
		print(code)
		print(fname)
		if len(face)>0:	
			if (face[0] == adhar) and code == otp:
				for i in range(len(df)):
					if(df.values[i][1]==fname):
						df.iloc[i,4] = 1
						df.to_csv('viis.csv',index=False)
						return redirect(url_for('vote'))
		else:
			return redirect(url_for('video')) 

	return render_template('input.html',fname=fname,lname=lname,adhar= adhar,voter=voter)

@app.route('/video', methods=['GET', 'POST'])
def video():
	global fname
	global lname
	global adhar
	global voter
	global contact
	global otp
	f=0
	
	df = pd.read_csv('viis.csv')
	print(df)
	print(df.values[0][0])
	print(df.iloc[:,3])

	if request.method == 'POST':
		fname = request.form['fname']
		lname = request.form['lname']
		adhar = request.form['adhar']
		voter = request.form['voter']

		for i in range(len(df)):
			if(df.values[i][1]==fname and df.iloc[i,4]==0):
				f=1
				break
		if(f==1):
			otp = random.randrange(1000,9999)
			print(otp)
			#sendSMS('+9188888888', '+91'+contact, 'OTP for Voting:'+str(otp))
			return redirect(url_for('input'))
		else:
			return render_template('video.html',error="No record Found / You have voted already")
	return render_template('video.html')

@app.route('/video_stream')
def video_stream():

	return Response(video_feed(),mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
	if request.method == 'POST':
		df = pd.read_csv('candidate.csv')
		vote_id = int(request.form['can'])
		vote = df._get_value(vote_id,'votes')
		df._set_value(vote_id,'votes',vote+1)
		df.to_csv('candidate.csv',index=False)
		print(df)
		playsound('vote.wav')
		return redirect(url_for('video'))

	return render_template('vote.html')

@app.route('/result', methods=['GET', 'POST'])
def result():
	error = None
	if request.method == 'POST':
		if request.form['login'] == 'Login':
			if request.form['username'] != 'admin' or request.form['password'] != 'admin':
				error = 'Invalid Credentials. Please try again.'
			else:
				df = pd.read_csv('candidate.csv')
				df.sort_values(by=['votes'], inplace=True,ascending=False)
				df.to_html('templates/vote_count.html',index=False)
				return render_template('result.html',tables=[df.to_html(classes='data')], titles=df.columns.values,index=False)

		elif request.form['login']=='Store in Blockchain':
			return redirect(url_for('mine'))
	return render_template('result.html', error=error)


@app.route('/mine', methods=['GET','POST'])
def mine():
	df = pd.read_csv('candidate.csv')
	sec = df.to_dict('list')
	name = sec['candiadate']
	#num = sec['num'][0]
	votes = sec['votes']
	amount = [name,votes]
	# We run the proof of work algorithm to get the next proof...
	last_block = blockchain.last_block
	proof = blockchain.proof_of_work(last_block)

	# We must receive a reward for finding the proof.
	# The sender is "0" to signify that this node has mined a new coin.
	blockchain.new_transaction(
		sender="0",
		recipient=node_identifier,
		#amount=1,
		amount=[name,votes],
	)

	# Forge the new Block by adding it to the chain
	previous_hash = blockchain.hash(last_block)
	block = blockchain.new_block(proof, previous_hash)

	response = {
		'message': "New Block Forged",
		'index': block['index'],
		'transactions': block['transactions'],
		'proof': block['proof'],
		'previous_hash': block['previous_hash'],
	}
	print(block['transactions'][0])
	#return jsonify(response), 200
	message = "New Block Forged"
	index = block['index']
	sender = block['transactions'][0]['sender']
	recipient = block['transactions'][0]['recipient'] 
	proof = block['proof']
	prevHash = block['previous_hash']
	if request.method=='POST':
		return render_template('mine.html',message= message,index = index,sender=sender,recipient=recipient,proof=proof,
		prevHash=prevHash,name=name,report=amount)
	return render_template('mine.html')


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
	values = request.get_json()

	# Check that the required fields are in the POST'ed data
	required = ['recipient', 'amount']
	if not all(k in values for k in required):
		return 'Missing values', 400

	# Create a new Transaction
	index = blockchain.new_transaction(values['recipient'], values['amount'])

	response = {'message': f'Transaction will be added to Block {index}'}
	return jsonify(response), 201


@app.route('/full_chain', methods=['GET'])
def full_chain():
	response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain),
	}
	return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
	values = request.get_json()

	nodes = values.get('nodes')
	if nodes is None:
		return "Error: Please supply a valid list of nodes", 400

	for node in nodes:
		blockchain.register_node(node)

	response = {
		'message': 'New nodes have been added',
		'total_nodes': list(blockchain.nodes),
	}
	return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
	replaced = blockchain.resolve_conflicts()

	if replaced:
		response = {
			'message': 'Our chain was replaced',
			'new_chain': blockchain.chain
		}
	else:
		response = {
			'message': 'Our chain is authoritative',
			'chain': blockchain.chain
		}

	return jsonify(response), 200


# No caching at all for API endpoints.
@app.after_request
def add_header(response):
	# response.cache_control.no_store = True
	response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
	response.headers['Pragma'] = 'no-cache'
	response.headers['Expires'] = '-1'
	return response


if __name__ == '__main__' and run:
	app.run(host='0.0.0.0', debug=True, threaded=True)