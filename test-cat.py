# AI_Categorizer.py
# pip install scikit-learn
# pip install evaluate
# pip install --upgrade transformers (got 4.56.1 as a result, need atleast 4.5.0)

import pandas as pd
from datasets import Dataset
from sklearn.model_selection import train_test_split

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import torch
import evaluate

# CONFIGURATION

MODEL_NAME = "bert-base-uncased"
CSV_PATH = "civic_complaints.csv"
NUM_EPOCHS = 3
BATCH_SIZE = 8

# LOAD DATA

print("~~~~~~~~~~~~~~~~~~~~~~~~~Loading dataset...~~~~~~~~~~~~~~~~~~~~~~~~~")
df = pd.read_csv(CSV_PATH)
df = df.dropna(subset=['text', 'department'])  #Cleans any missing rows

# Label encoding
departments = sorted(df['department'].unique().tolist())
label2id = {label: idx for idx, label in enumerate(departments)}
id2label = {idx: label for label, idx in label2id.items()}
df['label'] = df['department'].map(label2id)

# Split
train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
train_dataset = Dataset.from_pandas(train_df[['text', 'label']])
test_dataset = Dataset.from_pandas(test_df[['text', 'label']])

# TOKENIZATION

print("~~~~~~~~~~~~~~~~~~~~~~~~~Tokenizing text...~~~~~~~~~~~~~~~~~~~~~~~~~")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def tokenize(example):
    return tokenizer(example["text"], truncation=True, padding="max_length")

train_dataset = train_dataset.map(tokenize, batched=True)
test_dataset = test_dataset.map(tokenize, batched=True)

# LOAD MODEL

print("~~~~~~~~~~~~~~~~~~~~~~~~~Loading BERT model...~~~~~~~~~~~~~~~~~~~~~~~~~")
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(departments),
    id2label=id2label,
    label2id=label2id
)

# TRAINING

print("~~~~~~~~~~~~~~~~Setting up trainer...~~~~~~~~~~~~~~~~~~~~")
accuracy = evaluate.load("accuracy")

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = logits.argmax(axis=1)
    return accuracy.compute(predictions=preds, references=labels)

training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    weight_decay=0.01,
    logging_dir="./logs"
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    tokenizer=tokenizer,
    compute_metrics=compute_metrics
)

#print("~~~~~~~~~~~~~~~~~~~~~~~~~ Training model...~~~~~~~~~~~~~~~~~~~~~~~~~")
trainer.train()

# PREDICTION FUNCTION

def predict_department(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=1)
        predicted_id = torch.argmax(probs).item()
        return id2label[predicted_id]

# TESTING EXAMPLES

print("\n Trial Predictions:")
examples = [
    "There is garbage piling up near the community center.",
    "The traffic light is not working at the main junction.",
    "Water is leaking from the pipe outside my house.",
    "A pothole is damaging vehicles on the road near the hospital.",
    "Sewage water has flooded the street and it smells horrible."
    "Id like to report that the sidewalk on NGO Quarters, near the community park, has several large cracks and uneven slabs. Its becoming difficult for pedestrians, especially seniors and children, to walk safely. Over the past week Ive seen two people trip. Please send a crew to inspect and repair the damaged sections as soon as possible.","For the past three nights, the streetlights along Palakkad have been flickering or turning off completely. This makes the area very dark and unsafe for residents walking home. It also increases the risk of theft or accidents. Could the Electrical Department check the wiring or replace the faulty lights at the earliest convenience?","Garbage collection in our neighbourhood has been inconsistent for the last two weeks. Several bins remain full even after the scheduled pickup day, leading to foul smells and stray animals scattering trash. This is creating an unsanitary environment for residents. Please address the delays and ensure regular, timely collection going forward.","Weve been experiencing very low water pressure in the Kaloor area, especially during the morning hours. Its becoming difficult for households to complete basic tasks like bathing and cooking. Some neighbours reported murky water yesterday as well. Please investigate any pipeline issues or supply shortages and restore normal water flow promptly.","The traffic signal at the Seaport-Airport Road intersection has been malfunctioning for days. It often stays red for extremely long intervals, causing long queues during rush hour. Drivers become frustrated and some even jump the signal, increasing the risk of accidents. Kindly have the signal system inspected and recalibratedsoon."
]

for text in examples:
    prediction = predict_department(text)
    print(f" Complaint: {text}")
    print(f" Predicted Department: {prediction}\n")