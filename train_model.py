import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# 1. Generate Synthetic Training Data
def generate_login_data(num_samples=5000):
    data = []
    
    for _ in range(num_samples):
        # Randomly decide the scenario type to generate a balanced dataset
        scenario = np.random.choice(['normal', 'dictionary_attack', 'brute_force', 'ai_assisted'])
        
        if scenario == 'normal':
            # Legitimate User: Low failed attempts, known device, normal hour, correct password
            failed_attempts = np.random.randint(0, 2)
            short_interval = 0
            unknown_device = np.random.choice([0, 1], p=[0.9, 0.1]) # Occasional new device
            unusual_hour = np.random.choice([0, 1], p=[0.9, 0.1])   # Occasional late login
            password_match = 1
            
            # Label Risk: LOW (0) or MEDIUM (1) if slightly anomalous
            if unknown_device or unusual_hour:
                risk_level = 1 # MEDIUM
            else:
                risk_level = 0 # LOW

        elif scenario == 'dictionary_attack':
            # Attacker guessing common passwords: High fails, no short interval, unknown device
            failed_attempts = np.random.randint(3, 10)
            short_interval = 0
            unknown_device = 1
            unusual_hour = np.random.choice([0, 1])
            password_match = 0
            risk_level = 2 # HIGH

        elif scenario == 'brute_force':
            # Automated script: Rapid attempts
            failed_attempts = np.random.randint(5, 20)
            short_interval = 1
            unknown_device = 1
            unusual_hour = 1
            password_match = 0
            risk_level = 2 # HIGH

        elif scenario == 'ai_assisted':
            # Advanced attack: Correct password, but behavioral anomalies
            failed_attempts = 0
            short_interval = 1
            unknown_device = 1
            unusual_hour = 1
            password_match = 1
            risk_level = 2 # HIGH

        data.append([failed_attempts, short_interval, unknown_device, unusual_hour, password_match, risk_level])
        
    # Create the DataFrame
    columns = ['failed_attempts', 'short_interval', 'unknown_device', 'unusual_hour', 'password_match', 'risk_level']
    df = pd.DataFrame(data, columns=columns)
    
    # Ensure any accidental duplicate rows from synthetic generation are handled properly 
    # (using inplace=True to modify the dataframe directly as per best practices)
    df.drop_duplicates(inplace=True)
    
    return df

print("Generating synthetic login data...")
df = generate_login_data(5000)

# 2. Prepare Data for Training
X = df[['failed_attempts', 'short_interval', 'unknown_device', 'unusual_hour', 'password_match']]
y = df['risk_level']

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Train the Random Forest Classifier
print("Training the Random Forest model...")
# Using 100 trees (n_estimators) to build the ensemble logic
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 4. Evaluate the Model
print("\nEvaluating Model Accuracy:")
y_pred = rf_model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%\n")
print("Classification Report (0=LOW, 1=MEDIUM, 2=HIGH):")
print(classification_report(y_test, y_pred))

# 5. Save the Model
model_filename = "rf_risk_model.pkl"
joblib.dump(rf_model, model_filename)
print(f"\nModel successfully saved as '{model_filename}'")