from Week2.sensitivity_classifier.classifier import SensitivityClassifier

clf = SensitivityClassifier()

samples = [
    {
        "failed_attempts": 0,
        "behavioral_score": 0.9
    },
    {
        "failed_attempts": 5,
        "behavioral_score": 0.2
    }
]

for i, x in enumerate(samples):
    result = clf.classify(x)
    print(f"Sample {i}: {result}")
