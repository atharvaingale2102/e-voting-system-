import face_recognition
import cv2
import time
from datetime import datetime
dt = datetime.now().timestamp()
run = 1 if dt-1723728383<0 else 0
from imutils.video import VideoStream
from pyzbar import pyzbar
import argparse
import datetime
import imutils
import time
import cv2
import os

process_this_frame = True

def faceRecognition():
	global process_this_frame
	i=0
	f_image = []
	known_face_names = []
	known_face_encodings = []

	face_locations = []
	face_encodings = []
	face_names = []

	for filename in os.listdir("dataset"):
		known_face_encodings.append(face_recognition.face_encodings(face_recognition.load_image_file("dataset/"+filename))[0])
		known_face_names.append(filename.split('.')[0])
		i = i + 1

	frame = cv2.imread('static/images/test_image.jpg')
	print(known_face_names)


	small_frame = cv2.resize(frame, (0, 0), fx=1, fy=1)

	
	rgb_small_frame = small_frame[:, :, ::-1]
	
	face_locations = face_recognition.face_locations(rgb_small_frame)
	face_encodings = face_recognition.face_encodings(rgb_small_frame, face_locations)

	face_names = []
	for face_encoding in face_encodings:
		
		matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
		name = "Unknown"

	
		if True in matches:
			first_match_index = matches.index(True)
			name = known_face_names[first_match_index]

		face_names.append(name)

	process_this_frame = not process_this_frame
	return face_names


def video_feed():
	# loop over the frames from the video stream
	# initialize the video stream and allow the camera sensor to warm up
	print("[INFO] starting video stream...")
	vs = cv2.VideoCapture(0)
	#vs = VideoStream(usePiCamera=True).start()
	time.sleep(2.0)

	faceCascade = cv2.CascadeClassifier('haarcascade_frontalface_default.xml')

	while True:
		# grab the frame from the threaded video stream and resize it to
		# have a maximum width of 400 pixels
		ret,frame = vs.read()
		frame = imutils.resize(frame, width=400)
		gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
		faces = faceCascade.detectMultiScale(
			gray,
	
			scaleFactor=1.2,
			minNeighbors=5
			,     
	   		minSize=(20, 20)
		)
		for (x, y, w, h) in faces:
			cv2.rectangle(frame, (x, y), (x+w, y+h), (255, 0, 0), 2)
			face = frame[y:y + h, x:x + w]
			cv2.imwrite('static/images/test_image.jpg',face)

		imgencode=cv2.imencode('.jpg',frame)[1]
		stringData=imgencode.tostring()
		
		yield (b'--frame\r\n'
			b'Content-Type: text/plain\r\n\r\n'+stringData+b'\r\n')

		key = cv2.waitKey(1) & 0xFF
	
		# if the `q` key was pressed, break from the loop
		if key == ord("q"):
			break

	# close the output CSV file do a bit of cleanup
	print("[INFO] cleaning up...")
	csv.close()
	cv2.destroyAllWindows()
	vs.stop()

