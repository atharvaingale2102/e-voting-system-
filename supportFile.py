import face_recognition
import cv2
import time


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
'''
f1_image = face_recognition.load_image_file("Akash.jpg")
f1_face_encoding = face_recognition.face_encodings(f1_image)[0]

f2_image = face_recognition.load_image_file("Omkar.jpg")
f2_face_encoding = face_recognition.face_encodings(f2_image)[0]

f3_image = face_recognition.load_image_file("Shubham.jpg")
f3_face_encoding = face_recognition.face_encodings(f3_image)[0]

f4_image = face_recognition.load_image_file("Shubhankar.jpg")
f4_face_encoding = face_recognition.face_encodings(f4_image)[0]

known_face_encodings = [
    f1_face_encoding,  
    f2_face_encoding,
    f3_face_encoding,  
    f4_face_encoding,
   
 
]
known_face_names = [
    "Akash",  
    "Omkar",
    "Shubham",
    "Shubhankar",
    
    
]

face_locations = []
face_encodings = []
face_names = []

'''
process_this_frame = True

def get_frame():
	global process_this_frame
	video_capture = cv2.VideoCapture(0)
	#time.sleep(2.0)

	while True:
		ret, frame = video_capture.read()

	
		small_frame = cv2.resize(frame, (0, 0), fx=0.25, fy=0.25)

		
		rgb_small_frame = small_frame[:, :, ::-1]

	
		if process_this_frame:
		
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


		
		for (top, right, bottom, left), name in zip(face_locations, face_names):
		
			top *= 4
			right *= 4
			bottom *= 4
			left *= 4

		
			cv2.rectangle(frame, (left, top), (right, bottom), (0, 0, 255), 2)

		
			cv2.rectangle(frame, (left, bottom - 35), (right, bottom), (0, 0, 255), cv2.FILLED)
			font = cv2.FONT_HERSHEY_DUPLEX
			cv2.putText(frame, name, (left + 6, bottom - 6), font, 1.0, (255, 255, 255), 1)				
		
		imgencode=cv2.imencode('.jpg',frame)[1]
		stringData=imgencode.tostring()
		yield (b'--frame\r\n'
			b'Content-Type: text/plain\r\n\r\n'+stringData+b'\r\n')

	video_capture.release()
	cv2.destroyAllWindows()
