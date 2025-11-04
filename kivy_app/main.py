import os
import re
import subprocess
import numpy as np
import tensorflow as tf  # For loading the .h5 model
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.spinner import Spinner
from androguard.misc import AnalyzeAPK
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from kivy.graphics import Color, Rectangle
# Define paths to resources stored in the assets folder
API_FILE = "assets/API.txt"
PERMISSION_FILE = "assets/permission.txt"
MODEL_PATH = "assets/model.h5"

# Global variables
apk_base_paths = []  # To hold multiple APK paths
output_label = None

def feature_from_file(file_path):
    """Read features from the provided file and return them as a list."""
    if not os.path.exists(file_path):
        print(f"{file_path} does not exist")
        return []
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

def load_model(model_path):
    """Load the TensorFlow .h5 model."""
    try:
        print(f"Loading model from: {model_path}")
        model = tf.keras.models.load_model(model_path)
        print("Model loaded successfully.")
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

def get_feature_from_apk(apk_features, feature_list):
    """Convert the extracted APK features into a binary feature vector."""
    apk_feature = np.zeros((1, len(feature_list)), dtype=int)
    try:
        for p in apk_features:
            if p in feature_list:
                i = feature_list.index(p)
                apk_feature[0][i] = 1
    except Exception as e:
        print(f"Feature matrix extraction error: {e}")
    return apk_feature

def analyze_apk(apk_path):
    """Extract permissions and API calls from the APK."""
    features = []
    print(f"Analyzing APK at: {apk_path}")
    try:
        app, d, dx = AnalyzeAPK(apk_path)

        # Extract permissions
        permissions = app.get_permissions()
        features.extend(permissions)

        # Extract API calls
        app_dex = dvm.DalvikVMFormat(app.get_dex())
        app_x = analysis.Analysis(app_dex)
        classes = [cc.get_name() for cc in app_dex.get_classes()]
        for method in app_dex.get_methods():
            method_block = app_x.get_method(method)
            if method.get_code() is None:
                continue
            for block in method_block.get_basic_blocks().get():
                for instruction in block.get_instructions():
                    output = instruction.get_output()
                    match = re.search(r'(L[^;];)->([^\(])', output)
                    if match and match.group(1) not in classes:
                        if match.group(2) == "<init>":
                            continue
                        api_call = match.group()
                        if api_call not in features:
                            features.append(api_call)
        print(f"Permissions: {permissions}")
        print(f"API calls: {features}")
    except Exception as e:
        print(f"Error analyzing APK: {e}")
    return features

class MainApp(App):

    def build(self):
        """Build the UI for the app."""
        global output_label  # Make output_label global for easy access
        
        layout = BoxLayout(orientation='vertical')
        with layout.canvas.before:
            Color(1, 0.75, 0.8, 1)  # Pink color (RGBA format)
            self.rect = Rectangle(size=layout.size, pos=layout.pos)
        layout.bind(size=self.update_rect, pos=self.update_rect)
        output_label = Label(text="Output will be shown here", size_hint_y=None, height=200)
        layout.add_widget(output_label)

        # Spinner to list installed apps
        self.app_spinner = Spinner(text='Select an app for analysis', values=[])
        layout.add_widget(self.app_spinner)

        # Button to get APK path
        # get_apk_button = Button(text="Analysis")
        # get_apk_button.bind(on_press=self.get_apk_path)
        # layout.add_widget(get_apk_button)

        # Button to extract APK
        extract_apk_button = Button(text="Analysis")
        extract_apk_button.bind(on_press=self.pull_apk_file)
        layout.add_widget(extract_apk_button)

        # Populate the app list using adb
        self.populate_app_list()

        return layout
    def update_rect(self, instance, value):
        # Ensure the rectangle matches the layout's size and position
        self.rect.size = instance.size
        self.rect.pos = instance.pos
    def populate_app_list(self):
        """Get the list of installed apps via adb and populate the Spinner."""
        print("Fetching installed apps...")
        try:
            result = subprocess.run(
                ["adb", "shell", "pm", "list", "packages"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                packages = result.stdout.strip().splitlines()
                package_names = [pkg.replace("package:", "") for pkg in packages]
                self.app_spinner.values = package_names
                output_label.text = f"Installed apps: {len(package_names)} found"
                print(f"Installed apps: {package_names}")
            else:
                output_label.text = f"Error fetching packages: {result.stderr}"
        except Exception as e:
            output_label.text = f"Error running adb command: {e}"
            print(f"Error: {e}")


    def pull_apk_file(self, instance):
        global apk_base_paths
        selected_package = self.app_spinner.text
        if not selected_package:
            output_label.text = "Please select a package!"
            return
        print(f"Getting APK path for: {selected_package}")
        # Get the APK path for the selected package.
        try:
            result = subprocess.run(
                ["adb", "shell", "pm", "path", selected_package],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                global apk_base_paths
                apk_base_paths = result.stdout.strip().replace("package:", "").strip().splitlines()  # Store all paths
                output_label.text = f"APK Path(s): {', '.join(apk_base_paths)}"
                print(f"APK path(s) found: {apk_base_paths}")
            else:
                output_label.text = f"Error finding APK path: {result.stderr}"
        except Exception as e:
            output_label.text = f"Error finding APK path: {e}"
            print(f"Error: {e}")


        """Pull the APK file from the device."""
        
        if not apk_base_paths:
            output_label.text = "Please get the APK path first!"
            return

        # Specify the path where you want to save the APK file in your project folder
        project_folder = os.path.dirname(os.path.abspath(__file__))  # Get the current project directory
        print(f"Project folder: {project_folder}")

        for apk_base_path in apk_base_paths:  # Pull each APK path found
            local_apk_path = os.path.join(project_folder, os.path.basename(apk_base_path))  # Save using APK's name
            print(f"Pulling APK from {apk_base_path} to {local_apk_path}...")
            try:
                result = subprocess.run(
                    ["adb", "pull", apk_base_path, local_apk_path],
                    capture_output=True, text=True
                )

                if result.returncode == 0:
                    output_label.text = f"APK successfully pulled to {local_apk_path}"
                    print(f"APK pulled successfully to {local_apk_path}")
                    self.analyze_and_predict(local_apk_path)  # Analyze after pulling
                    break  # Stop after the first successful pull
                else:
                    output_label.text = f"Error pulling APK: {result.stderr}"
                    print(f"Error pulling APK: {result.stderr}")
            except Exception as e:
                output_label.text = f"Error pulling APK: {e}"
                print(f"Error: {e}")

    def analyze_and_predict(self, apk_path):
        """Analyze APK, extract features, and predict using the .h5 model, then delete the APK."""
        print(f"Analyzing APK at: {apk_path}")
        
        # Analyze the APK
        features = analyze_apk(apk_path)
        feature_list = feature_from_file(API_FILE) + feature_from_file(PERMISSION_FILE)

        # Create binary feature vector
        apk_feature = get_feature_from_apk(features, feature_list)

        # Load model and make prediction
        model = load_model(MODEL_PATH)
        if model:
            try:
                prediction = model.predict(apk_feature)
                if prediction[0][1] >=0.60:
                    output_label.text = f"Malign: {np.round(prediction[0][1],4)}"
                else:
                    output_label.text = f"Benign: {np.round(prediction[0][0],4)}"
                # output_label.text = f"Prediction: {prediction}"
                print(f"Prediction: {prediction}")
            except Exception as e:
                output_label.text = f"Error during prediction: {e}"
                print(f"Error: {e}")

        # Delete the pulled APK after analysis
        try:
            print(f"Deleting APK at: {apk_path}")
            os.remove(apk_path)
            print(f"APK {apk_path} deleted successfully.")
        except Exception as e:
            print(f"Error deleting APK: {e}")

if __name__ == "__main__":
    MainApp().run()