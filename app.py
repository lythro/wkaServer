from flask import Flask, request, session, redirect, render_template, jsonify, flash

import time
import numpy as np
import threading
import os, base64

import serial

# to switch between real serial communication
# and some basic dummy data generation
NO_MUT = True

class Controller(object):
	def __init__(self):
		self.lock = threading.Lock()

		self.currentTick = 0
		self.storeLength = 3600

		self.time = []
		self.power = []
		self.rotor = []

		if not NO_MUT:
			self.port = serial.Serial( '/dev/ttyAMA0', timeout=0.5, \
										baudrate=9600 )
			print 'BAUDRATE:', port.getBaudrate()

		self.update()

	def execCommand(self, cmd):
		port.write( cmd )
		x = ''
		while True:
			# read until ..
			r = port.read(1)
			# .. timeout
			if len(r) < 1:
				break
			x += r
			# or 'MUT>' signals end of transmission
			if x.endswith( 'MUT>\r\n' ):
				print 'ENDSWITH!', x
				#break #TODO

		return x

	def getRotorRounds(self):
		if NO_MUT:
			r = 10*np.sin( 0.1 * self.currentTick ) + 0.2*np.sin( 4*self.currentTick + 2 ) - 0.4
			return r

		ret = self.execCommand( 'rr\n' )
		sp = ret.split( '\r\n' )
		if len(sp) < 1 or len(sp[0]) < 4:
			return -1
		return int(sp[0][3:])

	def getPower(self):
		if NO_MUT:
			p = np.sin( 0.1 * self.currentTick ) + 0.2*np.sin( 4*self.currentTick + 0.4 )
			return p

		ret = self.execCommand( 'pw\n' )
		sp = ret.split( '\r\n' )
		if len(sp) < 1 or len(sp[0]) < 4:
			return -1
		return int(sp[0][3:])
	

	def getStatus(self, lastTick):
		''' given the latestTick, get all new data points from then on '''
		rTime = []
		rRotor = []
		rPower = []
		mLast = 0
		with self.lock:
			mLast = self.currentTick
			if lastTick < self.currentTick:
				# send all the new information
				diff = self.currentTick - lastTick
				index = len(self.power) - diff
				if index < 0:
					index = 0

				rTime = self.time[index:]
				rRotor = self.rotor[index:]
				rPower = self.power[index:]

				return { 'time' : rTime, 'tick' : self.currentTick, \
						'power' : rPower, 'rotor' : rRotor }

		while mLast <= lastTick:
			time.sleep( 1 ) # TODO

			with self.lock:
				mLast = self.currentTick
				rTime = self.time[-1]
				rRotor = self.rotor[-1]
				rPower = self.power[-1]

		return { 'time' : rTime, 'tick' : mLast, \
				'power': rPower, 'rotor' : rRotor }

	def update(self):
		''' method to get one more data point for periodic data logging '''

		with self.lock:
			self.currentTick += 1
		
			# test values
			'''
			'''

			# communication
			p = self.getPower()
			r = self.getRotorRounds()

			self.power.append( abs(p) )
			self.rotor.append( abs(r) )
			self.time.append( time.strftime( '%Y-%m-%d %H:%M:%S' ) )

			if len(self.power) > self.storeLength:
				self.power.pop(0)
				self.time.pop(0)
				self.rotor.pop(0)


class User(object):
	def __init__(self, name, pw):
		self.name = name
		self.__pw = pw

		self.__sessionKey = None
		self.__sessionAssignTime = time.time()
		self.__sessionValidHours = 4

		self.__lock = threading.Lock()	# for thread-safety

	def isOnline(self):
		# if the user has a valid sessionkey: he is online
		return self.checkSessionKey( self.__sessionKey )

	def checkPW(self, pw):
		with self.__lock:
			ok = (self.__pw == pw)
		return ok

	def getSessionKey(self):
		with self.__lock:
			ssid = self.__sessionKey
		return ssid

	def setSessionKey(self, key):
		with self.__lock:
			self.__sessionKey = key
			self.__sessionAssignTime = time.time()

	def removeSessionKey(self):
		self.__sessionKey = None


	def checkSessionKey(self, key):
		print 'CHECKSESSIONKEY'
		with self.__lock:
			print '  got the lock!'
			# has a key been assigned?
			if self.__sessionKey == None:
				return False

			# does the given key match the one that's been assigned?
			if self.__sessionKey != key:
				return False

			# is the key expired?	
			tdiff = time.time() - self.__sessionAssignTime
			if tdiff > self.__sessionValidHours * 60*60:
				self.removeSessionKey()
				return False
		# if everything seems fine: access granted
		return True


class UserManager(object):
	def __init__(self):
		self.users = {}
		self.lock = threading.Lock()

		with self.lock:
			# TODO create users... differently.
			# especially don't store passwords in
			# a source file that's publicly available
			# at github.
			user = User( 'TestUser1', '123' )
			self.users[user.name] = user

			user = User( 'TestUser2', 'abc' )
			self.users[user.name] = user

	def getOnlineUsers(self):
		l = []
		with self.lock:
			for u in self.users:
				if self.users[u].isOnline():
					l.append( self.users[u].name )
		return l

	def __createSessionKey(self):
		return base64.b64encode( os.urandom( 32 ) )


	def checkLogin(self, name, key):
		''' given a username and a session key: check if valid '''
		print 'CHECKLOGIN'
		with self.lock:
			user = self.users.get( name, None )

		if user is None:
			return False
		return user.checkSessionKey( key )


	def login(self, name, pw):
		''' returns the ssid assigned to the user if successful,
			else False. '''
		with self.lock:
			user = self.users.get( name, None )

		if user is None:
			return False

		if not user.checkPW( pw ):
			return False

		# assign a sessionID
		ssid = self.__createSessionKey()
		user.setSessionKey( ssid )
		return ssid

	def logout(self, name):
		''' no checks, just logout '''
		# TODO: without checks, one could force-quit another user...
		# or not? hm. username to logout is stored in the session,
		# and the session is cryptographically signed. should be safe.

		user = self.users[name]
		user.removeSessionKey()





#---------
controller = Controller()
users = UserManager()
#---------

app = Flask(__name__)


@app.route('/login', methods = ['POST'])
def login():
	name = request.form.get( 'username', '' )
	pw = request.form.get( 'password', '' )

	print 'LOGIN', name, pw

	ssid = users.login( name, pw )
	if not ssid:
		flash( 'incorrect username/password' )
		session['logged_in'] = False
	else:
		online = users.getOnlineUsers()
		flash( 'there %s %s online user%s:' % \
				( 'is' if len(online) == 1 else 'are', \
				  len(online), '' if len(online) == 1 else 's' ) )

		for u in online:
			flash( u )

		session['user'] = name
		session['ssid'] = ssid
		session['logged_in'] = True
	return redirect( '/' )
	

@app.route('/online')
def online():
	l = users.getOnlineUsers()
	return jsonify( {'online' : l} )

@app.route('/logout')
def logout():
	name = session.get( 'user', '' )
	session['logged_in'] = False
	del session['ssid']
	del session['user']
	
	users.logout( name )
	return redirect( '/' )


@app.route('/')
def hello_world():
	return render_template( 'index.html' )


@app.route('/poll')
def dataPoll():
	lastTick = int(request.args.get( 'lastTick', 0 ))
	
	data = controller.getStatus( lastTick )
	print data
	
	return jsonify( data )

@app.route('/exec', methods = ['POST'] )
def execute():
	print 'START OF EXCECUTE'
	# check for login!
	name = session.get( 'user', '' )
	key = session.get( 'ssid', '' )

	if not users.checkLogin( name, key ):
		print 'unauthorized exec attempt!'
		return 'Unauthorized. Session timed out?'

	# assert: key matches the name and is not expired yet.
	# --> allowed to execute commands!
	cmd = request.form.get( 'cmd', '' )
	print 'EXEC:', cmd
	if not NO_MUT:
		r = controller.execCommand( cmd + '\n' )
	else:
		r = 'NO_MUT: ' + cmd + '\n'
	print 'RETURN:', r
	print 'END OF EXCECUTE'
	return r


def updateLoop():
	while True:	
		time.sleep(2)
		controller.update()


if __name__ == '__main__':
	t = threading.Thread( target=updateLoop )
	t.daemon = True
	t.start()
	app.secret_key = os.urandom( 32 )
	app.run(debug=True, threaded=True, port=8080, host='0.0.0.0')
