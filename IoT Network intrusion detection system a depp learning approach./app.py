from flask import Flask, render_template, request, url_for, jsonify
from werkzeug.utils import secure_filename

import keras
from keras.models import load_model
import tensorflow_hub as hub
import numpy as np
import pandas as pd
import ipaddress


# Load the models here
model = load_model("Binary_BiLSTM_model.keras", custom_objects={'KerasLayer': hub.KerasLayer})


app = Flask(__name__)

@app.route('/')
def home():
	return render_template('index.html')

@app.route('/predict', methods = ['POST'])
def predict():
	if request.method == 'POST':
		# Get the data objects from the form
		response = request.form
		# Filter through the object to get the input values only
		response_values = [i for i in response.values()]

		# Convert src_Ip addresses
		converted_src_ip = int(ipaddress.ip_address(response_values[0]))
		response_values[0] = converted_src_ip
		# Convert dest_Ip addresses
		converted_dest_ip = int(ipaddress.ip_address(response_values[2]))
		response_values[2] = converted_dest_ip

		# Convert Timestamps to datetime objects
		datetime_object = pd.to_datetime(response_values[4])
		# Convert datetime objects to seconds
		datetime_seconds = datetime_object.timestamp()
		response_values[4] = datetime_seconds

		print()

		# Convert all input to floating point values
		response_values = [float(x) for x in response_values]
		# Reshape the array to the right shape for the model to use
		response_values = np.array(response_values).reshape(1, -1)
		
		# Make the model predict 
		network_diagnostics = model.predict(response_values)
		#  Extract the correct prediction from model response and convert to either 0 (which means normal) or 1 (which means attack)
		diagnotics_label = (network_diagnostics> 0.5).astype("int32").flatten()[0]

		print("depr dia is:", diagnotics_label)
		if diagnotics_label == 0:
		    result = "Normal"
		else:
		    result = "Attack"


		# Render response to the next page
		return render_template(
			'results.html', 
			result=result, 
		)


if __name__ == '__main__':
	app.run(debug=True)